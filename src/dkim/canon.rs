use super::signature::CanonicalizationMethod;

/// Canonicalize a header for DKIM
pub fn canonicalize_header(name: &str, value: &str, method: CanonicalizationMethod) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            // Simple: no changes, preserve as-is
            format!("{}:{}", name, value)
        }
        CanonicalizationMethod::Relaxed => {
            // Relaxed canonicalization (RFC 6376 Section 3.4.2):
            // 1. Convert header name to lowercase
            // 2. Unfold header (remove CRLF before WSP)
            // 3. Collapse whitespace sequences to single space
            // 4. Remove trailing whitespace
            // 5. Remove whitespace around colon

            let name = name.to_lowercase();
            let value = unfold_header(value);
            let value = collapse_whitespace(&value);
            let value = value.trim();

            format!("{}:{}", name, value)
        }
    }
}

/// Canonicalize body for DKIM
pub fn canonicalize_body(body: &[u8], method: CanonicalizationMethod) -> Vec<u8> {
    match method {
        CanonicalizationMethod::Simple => {
            // Simple body canonicalization (RFC 6376 Section 3.4.3):
            // 1. Remove all trailing empty lines
            // 2. Ensure body ends with CRLF (if non-empty)

            let body = remove_trailing_empty_lines(body);

            if body.is_empty() {
                // Empty body becomes single CRLF
                b"\r\n".to_vec()
            } else {
                // Ensure ends with CRLF
                ensure_trailing_crlf(&body)
            }
        }
        CanonicalizationMethod::Relaxed => {
            // Relaxed body canonicalization (RFC 6376 Section 3.4.4):
            // 1. Remove trailing whitespace from each line
            // 2. Collapse whitespace sequences to single space
            // 3. Remove all trailing empty lines
            // 4. If body is non-empty, ensure trailing CRLF

            let mut result = Vec::new();
            let lines = split_lines(body);

            for line in lines {
                // Remove trailing whitespace
                let trimmed = trim_trailing_whitespace(line);
                // Collapse internal whitespace
                let collapsed = collapse_body_whitespace(trimmed);
                result.extend_from_slice(&collapsed);
                result.extend_from_slice(b"\r\n");
            }

            // Remove trailing empty lines
            let result = remove_trailing_empty_lines(&result);

            if result.is_empty() {
                // Empty body stays empty (no CRLF added)
                Vec::new()
            } else {
                ensure_trailing_crlf(&result)
            }
        }
    }
}

/// Unfold header (remove CRLF followed by whitespace)
fn unfold_header(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next(); // consume \n
                // Check if next char is whitespace (fold continuation)
                if let Some(&next) = chars.peek() {
                    if next == ' ' || next == '\t' {
                        // This is a fold, replace with single space
                        result.push(' ');
                        // Skip the whitespace
                        chars.next();
                        // Skip any additional whitespace
                        while let Some(&c) = chars.peek() {
                            if c == ' ' || c == '\t' {
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        continue;
                    }
                }
                // Not a fold, keep CRLF
                result.push('\r');
                result.push('\n');
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Collapse whitespace sequences to single space
fn collapse_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_whitespace = false;

    for c in s.chars() {
        if c == ' ' || c == '\t' {
            if !in_whitespace {
                result.push(' ');
                in_whitespace = true;
            }
        } else {
            result.push(c);
            in_whitespace = false;
        }
    }

    result
}

/// Split body into lines (handling CRLF and LF)
fn split_lines(body: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;

    for i in 0..body.len() {
        if body[i] == b'\n' {
            // Check if preceded by CR
            let end = if i > 0 && body[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            lines.push(&body[start..end]);
            start = i + 1;
        }
    }

    // Add final segment if any
    if start < body.len() {
        lines.push(&body[start..]);
    }

    lines
}

/// Remove trailing whitespace from a line
fn trim_trailing_whitespace(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b' ' || line[end - 1] == b'\t') {
        end -= 1;
    }
    &line[..end]
}

/// Collapse whitespace in body line
fn collapse_body_whitespace(line: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(line.len());
    let mut in_whitespace = false;

    for &b in line {
        if b == b' ' || b == b'\t' {
            if !in_whitespace {
                result.push(b' ');
                in_whitespace = true;
            }
        } else {
            result.push(b);
            in_whitespace = false;
        }
    }

    result
}

/// Remove trailing empty lines from body
fn remove_trailing_empty_lines(body: &[u8]) -> Vec<u8> {
    let mut end = body.len();

    // Remove trailing CRLF sequences
    while end >= 2 && body[end - 2] == b'\r' && body[end - 1] == b'\n' {
        // Check if this is an empty line
        if end >= 4 {
            if body[end - 4] == b'\r' && body[end - 3] == b'\n' {
                // Previous was also CRLF, this is empty line
                end -= 2;
                continue;
            }
        } else if end == 2 {
            // Just CRLF, remove it
            end = 0;
            break;
        }
        break;
    }

    body[..end].to_vec()
}

/// Ensure body ends with CRLF
fn ensure_trailing_crlf(body: &[u8]) -> Vec<u8> {
    if body.len() >= 2 && body[body.len() - 2] == b'\r' && body[body.len() - 1] == b'\n' {
        body.to_vec()
    } else if !body.is_empty() && body[body.len() - 1] == b'\n' {
        // Just LF, convert to CRLF
        let mut result = body[..body.len() - 1].to_vec();
        result.extend_from_slice(b"\r\n");
        result
    } else {
        let mut result = body.to_vec();
        result.extend_from_slice(b"\r\n");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_header_canonicalization() {
        let result = canonicalize_header("From", " user@example.com ", CanonicalizationMethod::Simple);
        assert_eq!(result, "From: user@example.com ");
    }

    #[test]
    fn test_relaxed_header_canonicalization() {
        // Lowercase name, collapse whitespace, trim trailing
        let result = canonicalize_header("From", "  user@example.com  ", CanonicalizationMethod::Relaxed);
        assert_eq!(result, "from:user@example.com");

        // Folded header
        let result = canonicalize_header("Subject", "Hello\r\n World", CanonicalizationMethod::Relaxed);
        assert_eq!(result, "subject:Hello World");
    }

    #[test]
    fn test_simple_body_canonicalization() {
        // Trailing empty lines removed
        let body = b"Hello\r\n\r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple);
        assert_eq!(result, b"Hello\r\n");

        // Empty body becomes CRLF
        let result = canonicalize_body(b"", CanonicalizationMethod::Simple);
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn test_relaxed_body_canonicalization() {
        // Trailing whitespace removed, whitespace collapsed
        let body = b"Hello   World  \r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        assert_eq!(result, b"Hello World\r\n");

        // Empty body stays empty
        let result = canonicalize_body(b"", CanonicalizationMethod::Relaxed);
        assert_eq!(result, b"");
    }

    #[test]
    fn test_unfold_header() {
        assert_eq!(unfold_header("Hello\r\n World"), "Hello World");
        assert_eq!(unfold_header("Hello\r\n\tWorld"), "Hello World");
        assert_eq!(unfold_header("NoFold"), "NoFold");
    }

    #[test]
    fn test_collapse_whitespace() {
        assert_eq!(collapse_whitespace("Hello   World"), "Hello World");
        assert_eq!(collapse_whitespace("  Leading"), " Leading");
        assert_eq!(collapse_whitespace("Trailing  "), "Trailing ");
    }
}
