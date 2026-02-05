//! DKIM canonicalization (RFC 6376 Section 3.4)

use super::signature::CanonicalizationMethod;

/// Canonicalize a header for DKIM signing/verification
pub fn canonicalize_header(name: &str, value: &str, method: CanonicalizationMethod) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            // No changes - use as-is
            format!("{}:{}", name, value)
        }
        CanonicalizationMethod::Relaxed => {
            // Lowercase header name
            let name_lower = name.to_lowercase();

            // Unfold (already done by caller typically)
            // Collapse whitespace sequences to single space
            // Remove trailing whitespace
            // Remove space around colon
            let value_normalized = normalize_whitespace(value);

            format!("{}:{}", name_lower, value_normalized)
        }
    }
}

/// Canonicalize message body for DKIM
pub fn canonicalize_body(body: &[u8], method: CanonicalizationMethod) -> Vec<u8> {
    // Ensure CRLF line endings
    let body = normalize_line_endings(body);

    match method {
        CanonicalizationMethod::Simple => {
            // Remove trailing empty lines
            let mut result = body.clone();
            while result.ends_with(b"\r\n\r\n") {
                result.truncate(result.len() - 2);
            }

            // Empty body = single CRLF
            if result.is_empty() {
                return b"\r\n".to_vec();
            }

            // Ensure ends with CRLF
            if !result.ends_with(b"\r\n") {
                result.extend_from_slice(b"\r\n");
            }

            result
        }
        CanonicalizationMethod::Relaxed => {
            let mut lines: Vec<Vec<u8>> = Vec::new();

            for line in body.split(|&b| b == b'\n') {
                let line = if line.ends_with(b"\r") {
                    &line[..line.len() - 1]
                } else {
                    line
                };

                // Remove trailing whitespace from line
                let trimmed = trim_trailing_wsp(line);

                // Collapse whitespace sequences to single space
                let collapsed = collapse_whitespace(trimmed);

                lines.push(collapsed);
            }

            // Remove trailing empty lines
            while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
                lines.pop();
            }

            // Empty body = empty (no CRLF added for relaxed)
            if lines.is_empty() || (lines.len() == 1 && lines[0].is_empty()) {
                return Vec::new();
            }

            // Join with CRLF
            let mut result = Vec::new();
            for (i, line) in lines.iter().enumerate() {
                result.extend_from_slice(line);
                if i < lines.len() - 1 || !line.is_empty() {
                    result.extend_from_slice(b"\r\n");
                }
            }

            // Ensure ends with CRLF if non-empty
            if !result.is_empty() && !result.ends_with(b"\r\n") {
                result.extend_from_slice(b"\r\n");
            }

            result
        }
    }
}

fn normalize_line_endings(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
            result.push(b'\r');
            result.push(b'\n');
            i += 2;
        } else if data[i] == b'\n' {
            result.push(b'\r');
            result.push(b'\n');
            i += 1;
        } else if data[i] == b'\r' {
            result.push(b'\r');
            result.push(b'\n');
            i += 1;
        } else {
            result.push(data[i]);
            i += 1;
        }
    }

    result
}

fn normalize_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_whitespace = false;
    let mut first_char = true;

    for c in s.chars() {
        if c.is_whitespace() {
            if !first_char {
                in_whitespace = true;
            }
        } else {
            if in_whitespace {
                result.push(' ');
                in_whitespace = false;
            }
            result.push(c);
            first_char = false;
        }
    }

    result
}

fn trim_trailing_wsp(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b' ' || line[end - 1] == b'\t') {
        end -= 1;
    }
    &line[..end]
}

fn collapse_whitespace(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut in_wsp = false;

    for &b in data {
        if b == b' ' || b == b'\t' {
            if !in_wsp && !result.is_empty() {
                result.push(b' ');
                in_wsp = true;
            }
        } else {
            result.push(b);
            in_wsp = false;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_header_simple() {
        let result = canonicalize_header("From", " user@example.com", CanonicalizationMethod::Simple);
        assert_eq!(result, "From: user@example.com");
    }

    #[test]
    fn test_canonicalize_header_relaxed() {
        let result = canonicalize_header("From", "  user@example.com  ", CanonicalizationMethod::Relaxed);
        assert_eq!(result, "from:user@example.com");
    }

    #[test]
    fn test_canonicalize_header_relaxed_collapse_whitespace() {
        let result = canonicalize_header("Subject", "  Hello   World  ", CanonicalizationMethod::Relaxed);
        assert_eq!(result, "subject:Hello World");
    }

    #[test]
    fn test_canonicalize_body_simple_trailing_lines() {
        let body = b"Hello\r\n\r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple);
        assert_eq!(result, b"Hello\r\n");
    }

    #[test]
    fn test_canonicalize_body_simple_empty() {
        let body = b"";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple);
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn test_canonicalize_body_relaxed_empty() {
        let body = b"";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        assert_eq!(result, b"");
    }

    #[test]
    fn test_canonicalize_body_relaxed_whitespace() {
        let body = b"Hello   World  \r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        assert_eq!(result, b"Hello World\r\n");
    }

    #[test]
    fn test_normalize_line_endings() {
        assert_eq!(normalize_line_endings(b"a\nb"), b"a\r\nb".to_vec());
        assert_eq!(normalize_line_endings(b"a\r\nb"), b"a\r\nb".to_vec());
        assert_eq!(normalize_line_endings(b"a\rb"), b"a\r\nb".to_vec());
    }
}
