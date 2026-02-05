use super::CanonicalizationMethod;

/// Canonicalize a header for DKIM signing/verification
pub fn canonicalize_header(name: &str, value: &str, method: CanonicalizationMethod) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            format!("{}:{}", name, value)
        }
        CanonicalizationMethod::Relaxed => {
            let name = name.to_lowercase();
            // Unfold (already done by caller typically)
            // Collapse whitespace to single space
            let value = collapse_whitespace(value);
            // Trim trailing whitespace
            let value = value.trim_end();
            // No space before/after colon - RFC 6376 says no space after colon
            format!("{}:{}", name, value.trim_start())
        }
    }
}

/// Canonicalize message body for DKIM signing/verification
pub fn canonicalize_body(body: &[u8], method: CanonicalizationMethod, length_limit: Option<u64>) -> Vec<u8> {
    // First ensure CRLF line endings
    let body = ensure_crlf(body);

    let result = match method {
        CanonicalizationMethod::Simple => {
            simple_body_canonicalization(&body)
        }
        CanonicalizationMethod::Relaxed => {
            relaxed_body_canonicalization(&body)
        }
    };

    // Apply length limit if specified
    if let Some(limit) = length_limit {
        let limit = limit as usize;
        if result.len() > limit {
            return result[..limit].to_vec();
        }
    }

    result
}

fn ensure_crlf(body: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(body.len());
    let mut i = 0;

    while i < body.len() {
        if body[i] == b'\r' && i + 1 < body.len() && body[i + 1] == b'\n' {
            // Already CRLF
            result.push(b'\r');
            result.push(b'\n');
            i += 2;
        } else if body[i] == b'\n' || body[i] == b'\r' {
            // Bare LF or bare CR -> normalize to CRLF
            result.push(b'\r');
            result.push(b'\n');
            i += 1;
        } else {
            result.push(body[i]);
            i += 1;
        }
    }

    result
}

fn simple_body_canonicalization(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return b"\r\n".to_vec();
    }

    let mut result = body.to_vec();

    // Remove trailing empty lines
    while result.len() >= 2 && result.ends_with(b"\r\n\r\n") {
        result.pop();
        result.pop();
    }

    // Ensure ends with CRLF
    if result.len() < 2 || !result.ends_with(b"\r\n") {
        result.extend_from_slice(b"\r\n");
    }

    result
}

fn relaxed_body_canonicalization(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }

    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut current_line = Vec::new();

    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\r' && i + 1 < body.len() && body[i + 1] == b'\n' {
            lines.push(current_line);
            current_line = Vec::new();
            i += 2;
        } else {
            current_line.push(body[i]);
            i += 1;
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    // Process each line
    let processed_lines: Vec<Vec<u8>> = lines
        .into_iter()
        .map(|line| {
            // Remove trailing whitespace
            let line = rtrim_whitespace(&line);
            // Collapse whitespace sequences to single space
            collapse_whitespace_bytes(&line)
        })
        .collect();

    // Remove trailing empty lines
    let mut non_empty_end = processed_lines.len();
    while non_empty_end > 0 && processed_lines[non_empty_end - 1].is_empty() {
        non_empty_end -= 1;
    }

    if non_empty_end == 0 {
        return Vec::new();
    }

    // Join with CRLF
    let mut result = Vec::new();
    for (i, line) in processed_lines[..non_empty_end].iter().enumerate() {
        result.extend_from_slice(line);
        if i < non_empty_end - 1 || !line.is_empty() {
            result.extend_from_slice(b"\r\n");
        }
    }

    if !result.is_empty() && !result.ends_with(b"\r\n") {
        result.extend_from_slice(b"\r\n");
    }

    result
}

fn rtrim_whitespace(bytes: &[u8]) -> Vec<u8> {
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    bytes[..end].to_vec()
}

fn collapse_whitespace_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len());
    let mut in_whitespace = false;

    for &b in bytes {
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

fn collapse_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
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
    fn test_simple_header() {
        let result = canonicalize_header("From", " test@example.com", CanonicalizationMethod::Simple);
        assert_eq!(result, "From: test@example.com");
    }

    #[test]
    fn test_relaxed_header() {
        let result = canonicalize_header("FROM", "  test@example.com  ", CanonicalizationMethod::Relaxed);
        assert_eq!(result, "from:test@example.com");
    }

    #[test]
    fn test_simple_body_trailing_blank() {
        let body = b"Hello\r\n\r\n\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple, None);
        assert_eq!(result, b"Hello\r\n");
    }

    #[test]
    fn test_simple_body_empty() {
        let result = canonicalize_body(b"", CanonicalizationMethod::Simple, None);
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn test_relaxed_body_whitespace() {
        let body = b"Hello   World  \r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Relaxed, None);
        assert_eq!(result, b"Hello World\r\n");
    }

    #[test]
    fn test_relaxed_body_empty() {
        let result = canonicalize_body(b"", CanonicalizationMethod::Relaxed, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_body_length_limit() {
        let body = b"Hello World\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple, Some(5));
        assert_eq!(result, b"Hello");
    }
}
