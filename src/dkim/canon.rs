use super::signature::CanonicalizationMethod;

/// Canonicalize a header for DKIM
pub fn canonicalize_header(name: &str, value: &str, method: CanonicalizationMethod) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            // No transformation, use as-is
            format!("{}:{}", name, value)
        }
        CanonicalizationMethod::Relaxed => {
            // Lowercase header name
            let name_lower = name.to_lowercase();

            // Unfold header (remove CRLF + whitespace continuation)
            let unfolded = unfold_header(value);

            // Collapse whitespace sequences to single space
            let collapsed = collapse_whitespace(&unfolded);

            // Remove leading/trailing whitespace from value
            let trimmed = collapsed.trim();

            // No space before or after colon (RFC 6376 3.4.2)
            format!("{}:{}", name_lower, trimmed)
        }
    }
}

/// Canonicalize body for DKIM
pub fn canonicalize_body(body: &[u8], method: CanonicalizationMethod, length_limit: Option<u64>) -> Vec<u8> {
    let body_str = String::from_utf8_lossy(body);

    // Normalize line endings to CRLF
    let normalized = normalize_line_endings(&body_str);

    let canonicalized = match method {
        CanonicalizationMethod::Simple => {
            // Remove trailing empty lines, ensure ends with CRLF
            simple_body_canon(&normalized)
        }
        CanonicalizationMethod::Relaxed => {
            // Remove trailing whitespace from lines, collapse whitespace, remove trailing empty lines
            relaxed_body_canon(&normalized)
        }
    };

    // Apply length limit
    match length_limit {
        Some(limit) => {
            let limit = limit as usize;
            if canonicalized.len() > limit {
                canonicalized[..limit].to_vec()
            } else {
                canonicalized
            }
        }
        None => canonicalized,
    }
}

fn normalize_line_endings(s: &str) -> String {
    // Replace bare LF with CRLF, but not if already CRLF
    let mut result = String::with_capacity(s.len());
    let mut prev_cr = false;

    for c in s.chars() {
        if c == '\n' {
            if !prev_cr {
                result.push('\r');
            }
            result.push('\n');
            prev_cr = false;
        } else {
            if c == '\r' {
                prev_cr = true;
            } else {
                prev_cr = false;
            }
            result.push(c);
        }
    }

    result
}

fn simple_body_canon(body: &str) -> Vec<u8> {
    // Remove all trailing CRLF sequences
    let trimmed = body.trim_end_matches("\r\n");

    // If body is not empty, add exactly one CRLF
    if trimmed.is_empty() {
        // Empty body is canonicalized to single CRLF
        return b"\r\n".to_vec();
    }

    let mut result = trimmed.as_bytes().to_vec();
    result.extend_from_slice(b"\r\n");
    result
}

fn relaxed_body_canon(body: &str) -> Vec<u8> {
    let mut lines: Vec<String> = Vec::new();

    for line in body.split("\r\n") {
        // Remove trailing whitespace from each line
        let trimmed_line = line.trim_end_matches(|c| c == ' ' || c == '\t');

        // Collapse whitespace sequences within line to single space
        let collapsed = collapse_whitespace(trimmed_line);

        lines.push(collapsed);
    }

    // Remove trailing empty lines
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }

    // If body is empty after processing, return empty (no CRLF for relaxed)
    if lines.is_empty() || (lines.len() == 1 && lines[0].is_empty()) {
        return Vec::new();
    }

    // Join with CRLF and add trailing CRLF
    let mut result = lines.join("\r\n");
    result.push_str("\r\n");
    result.into_bytes()
}

fn unfold_header(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            chars.next(); // consume \n
            // Replace CRLF + WSP with single space
            if let Some(&ws) = chars.peek() {
                if ws == ' ' || ws == '\t' {
                    // Skip the whitespace, we'll add a single space
                    while let Some(&ws) = chars.peek() {
                        if ws == ' ' || ws == '\t' {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    result.push(' ');
                }
            }
        } else if c == '\n' {
            // Handle LF-only
            if let Some(&ws) = chars.peek() {
                if ws == ' ' || ws == '\t' {
                    while let Some(&ws) = chars.peek() {
                        if ws == ' ' || ws == '\t' {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    result.push(' ');
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_header() {
        let result = canonicalize_header("Subject", " Test  Message ", CanonicalizationMethod::Simple);
        assert_eq!(result, "Subject: Test  Message ");
    }

    #[test]
    fn test_relaxed_header() {
        let result = canonicalize_header("Subject", "  Test  Message  ", CanonicalizationMethod::Relaxed);
        assert_eq!(result, "subject:Test Message");
    }

    #[test]
    fn test_relaxed_header_folded() {
        let result = canonicalize_header("Subject", "Test\r\n Message", CanonicalizationMethod::Relaxed);
        assert_eq!(result, "subject:Test Message");
    }

    #[test]
    fn test_simple_body_trailing_crlf() {
        let body = b"Hello\r\n\r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple, None);
        assert_eq!(result, b"Hello\r\n");
    }

    #[test]
    fn test_simple_body_empty() {
        let body = b"";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple, None);
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn test_relaxed_body_whitespace() {
        let body = b"Hello  World  \r\nTest  \r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed, None);
        assert_eq!(result, b"Hello World\r\nTest\r\n");
    }

    #[test]
    fn test_relaxed_body_empty() {
        let body = b"\r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed, None);
        assert_eq!(result, b"");
    }

    #[test]
    fn test_body_length_limit() {
        let body = b"Hello World\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple, Some(5));
        assert_eq!(result, b"Hello");
    }
}
