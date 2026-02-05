use super::signature::CanonicalizationMethod;

/// Canonicalize a header for DKIM signing/verification
pub fn canonicalize_header(name: &str, value: &str, method: CanonicalizationMethod) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            // No changes
            format!("{}:{}", name, value)
        }
        CanonicalizationMethod::Relaxed => {
            // 1. Convert header name to lowercase
            let name = name.to_lowercase();

            // 2. Unfold header (remove CRLF before whitespace)
            let value = value.replace("\r\n", "").replace('\n', "");

            // 3. Collapse whitespace sequences to single space
            let value = collapse_whitespace(&value);

            // 4. Remove leading/trailing whitespace from value
            let value = value.trim();

            format!("{}:{}", name, value)
        }
    }
}

/// Canonicalize body for DKIM signing/verification
pub fn canonicalize_body(body: &[u8], method: CanonicalizationMethod) -> Vec<u8> {
    // Convert to string for processing, handling invalid UTF-8 gracefully
    let body_str = String::from_utf8_lossy(body);

    // Normalize line endings to CRLF
    let body_str = body_str.replace("\r\n", "\n").replace('\n', "\r\n");

    match method {
        CanonicalizationMethod::Simple => {
            // Remove all trailing empty lines
            let trimmed = body_str.trim_end_matches("\r\n");

            if trimmed.is_empty() {
                // Empty body is treated as single CRLF
                "\r\n".as_bytes().to_vec()
            } else {
                // Ensure body ends with CRLF
                format!("{}\r\n", trimmed).into_bytes()
            }
        }
        CanonicalizationMethod::Relaxed => {
            let mut lines: Vec<String> = Vec::new();

            for line in body_str.split("\r\n") {
                // Remove trailing whitespace from each line
                let line = line.trim_end();

                // Collapse whitespace sequences to single space
                let line = collapse_whitespace(line);

                lines.push(line);
            }

            // Remove trailing empty lines
            while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
                lines.pop();
            }

            if lines.is_empty() {
                // Empty body stays empty (no CRLF added in relaxed)
                Vec::new()
            } else {
                // Join with CRLF and add final CRLF
                let result = lines.join("\r\n");
                format!("{}\r\n", result).into_bytes()
            }
        }
    }
}

fn collapse_whitespace(s: &str) -> String {
    let mut result = String::new();
    let mut in_whitespace = false;

    for c in s.chars() {
        if c.is_whitespace() {
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
    fn test_simple_header_canonicalization() {
        let result = canonicalize_header(
            "Subject",
            " Hello World",
            CanonicalizationMethod::Simple,
        );
        assert_eq!(result, "Subject: Hello World");
    }

    #[test]
    fn test_relaxed_header_canonicalization() {
        let result = canonicalize_header(
            "Subject",
            "  Hello   World  ",
            CanonicalizationMethod::Relaxed,
        );
        // RFC 6376: remove whitespace before and after colon, collapse whitespace in value
        assert_eq!(result, "subject:Hello World");
    }

    #[test]
    fn test_simple_body_trailing_crlf() {
        let body = b"Hello\r\n\r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple);
        assert_eq!(result, b"Hello\r\n");
    }

    #[test]
    fn test_simple_body_empty() {
        let body = b"";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple);
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn test_relaxed_body_whitespace() {
        let body = b"Hello   World  \r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        assert_eq!(result, b"Hello World\r\n");
    }

    #[test]
    fn test_relaxed_body_empty() {
        let body = b"";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        assert_eq!(result, b"");
    }
}
