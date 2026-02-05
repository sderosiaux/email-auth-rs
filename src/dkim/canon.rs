//! DKIM canonicalization (RFC 6376 Section 3.4).

use super::signature::CanonicalizationMethod;

/// Canonicalize a header for DKIM.
pub fn canonicalize_header(name: &str, value: &str, method: CanonicalizationMethod) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            // No changes - use as-is
            format!("{}:{}", name, value)
        }
        CanonicalizationMethod::Relaxed => {
            // 1. Convert header name to lowercase
            let name = name.to_lowercase();
            // 2. Unfold header (remove CRLF before WSP)
            let value = unfold_header(value);
            // 3. Collapse whitespace sequences to single space
            let value = collapse_whitespace(&value);
            // 4. Remove trailing whitespace
            let value = value.trim_end();
            // 5. Remove whitespace before and after colon (no space after colon per RFC 6376)
            format!("{}:{}", name.trim(), value.trim_start())
        }
    }
}

/// Canonicalize message body for DKIM.
pub fn canonicalize_body(body: &[u8], method: CanonicalizationMethod) -> Vec<u8> {
    // Convert to string for processing, handling potential non-UTF8
    let body_str = String::from_utf8_lossy(body);

    // Normalize line endings to CRLF
    let body_str = normalize_line_endings(&body_str);

    match method {
        CanonicalizationMethod::Simple => {
            // Remove trailing empty lines, ensure ends with CRLF
            let trimmed = remove_trailing_empty_lines(&body_str);
            if trimmed.is_empty() {
                // Empty body is treated as single CRLF
                b"\r\n".to_vec()
            } else if !trimmed.ends_with("\r\n") {
                format!("{}\r\n", trimmed).into_bytes()
            } else {
                trimmed.into_bytes()
            }
        }
        CanonicalizationMethod::Relaxed => {
            // Process line by line
            let lines: Vec<&str> = body_str.split("\r\n").collect();
            let mut result_lines: Vec<String> = Vec::new();

            for line in &lines {
                // Remove trailing whitespace from each line
                let line = line.trim_end();
                // Collapse whitespace sequences to single space
                let line = collapse_whitespace(line);
                result_lines.push(line);
            }

            // Join with CRLF
            let mut result = result_lines.join("\r\n");

            // Remove trailing empty lines
            while result.ends_with("\r\n\r\n") {
                result.truncate(result.len() - 2);
            }

            // If body is empty after processing, return empty (no CRLF added for relaxed)
            if result.trim().is_empty() {
                return Vec::new();
            }

            // Ensure ends with CRLF if non-empty
            if !result.ends_with("\r\n") {
                result.push_str("\r\n");
            }

            result.into_bytes()
        }
    }
}

/// Apply body length limit if specified.
pub fn apply_body_limit(body: Vec<u8>, limit: Option<u64>) -> Vec<u8> {
    match limit {
        Some(l) => body.into_iter().take(l as usize).collect(),
        None => body,
    }
}

fn unfold_header(value: &str) -> String {
    // Remove CRLF followed by whitespace (folded headers)
    let mut result = String::new();
    let mut chars = value.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next(); // consume \n
                // Check if next char is whitespace (continuation)
                if let Some(&next) = chars.peek() {
                    if next == ' ' || next == '\t' {
                        // It's a fold - skip the CRLF, keep the whitespace
                        continue;
                    }
                }
                // Not a fold, keep CRLF
                result.push('\r');
                result.push('\n');
            } else {
                result.push(c);
            }
        } else if c == '\n' {
            // Handle bare LF
            if let Some(&next) = chars.peek() {
                if next == ' ' || next == '\t' {
                    continue; // fold
                }
            }
            result.push(c);
        } else {
            result.push(c);
        }
    }

    result
}

fn collapse_whitespace(s: &str) -> String {
    let mut result = String::new();
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

fn normalize_line_endings(s: &str) -> String {
    // Convert LF to CRLF, but don't double CRLF
    let mut result = String::new();
    let mut prev_cr = false;

    for c in s.chars() {
        if c == '\r' {
            prev_cr = true;
            result.push(c);
        } else if c == '\n' {
            if !prev_cr {
                result.push('\r');
            }
            result.push('\n');
            prev_cr = false;
        } else {
            prev_cr = false;
            result.push(c);
        }
    }

    result
}

fn remove_trailing_empty_lines(s: &str) -> String {
    let mut s = s.to_string();
    while s.ends_with("\r\n\r\n") {
        s.truncate(s.len() - 2);
    }
    s
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
        let result = canonicalize_header(
            "From",
            "   user@example.com  ",
            CanonicalizationMethod::Relaxed,
        );
        assert_eq!(result, "from:user@example.com");
    }

    #[test]
    fn test_canonicalize_header_relaxed_collapse_whitespace() {
        let result = canonicalize_header(
            "Subject",
            " test   subject  ",
            CanonicalizationMethod::Relaxed,
        );
        assert_eq!(result, "subject:test subject");
    }

    #[test]
    fn test_canonicalize_body_simple() {
        let body = b"Hello World\r\n\r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple);
        assert_eq!(result, b"Hello World\r\n");
    }

    #[test]
    fn test_canonicalize_body_simple_empty() {
        let body = b"";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple);
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn test_canonicalize_body_relaxed() {
        let body = b"Hello  World  \r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        assert_eq!(result, b"Hello World\r\n");
    }

    #[test]
    fn test_canonicalize_body_relaxed_empty() {
        let body = b"";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        assert!(result.is_empty());
    }

    #[test]
    fn test_unfold_header() {
        let folded = " value\r\n continues";
        let unfolded = unfold_header(folded);
        assert_eq!(unfolded, " value continues");
    }

    #[test]
    fn test_collapse_whitespace() {
        assert_eq!(collapse_whitespace("a   b  c"), "a b c");
        assert_eq!(collapse_whitespace("a\t\tb"), "a b");
    }
}
