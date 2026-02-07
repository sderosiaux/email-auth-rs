use super::CanonicalizationMethod;

/// Normalize line endings: bare LF -> CRLF, bare CR -> CRLF.
pub fn normalize_line_endings(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\r' {
            if i + 1 < input.len() && input[i + 1] == b'\n' {
                out.push(b'\r');
                out.push(b'\n');
                i += 2;
            } else {
                out.push(b'\r');
                out.push(b'\n');
                i += 1;
            }
        } else if input[i] == b'\n' {
            out.push(b'\r');
            out.push(b'\n');
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Canonicalize a header line (name: value).
pub fn canonicalize_header(
    name: &str,
    value: &str,
    method: CanonicalizationMethod,
) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            format!("{}:{}\r\n", name, value)
        }
        CanonicalizationMethod::Relaxed => {
            let lower_name = name.to_ascii_lowercase();
            // Unfold: remove CRLF before whitespace
            let unfolded = value
                .replace("\r\n ", " ")
                .replace("\r\n\t", "\t");
            // Collapse sequential WSP to single SP, remove trailing WSP
            let collapsed = collapse_whitespace(&unfolded);
            let trimmed = collapsed.trim_end();
            // Remove leading whitespace from value (space around colon)
            let trimmed = trimmed.trim_start();
            format!("{}:{}\r\n", lower_name, trimmed)
        }
    }
}

/// Canonicalize message body.
pub fn canonicalize_body(
    body: &[u8],
    method: CanonicalizationMethod,
    length_limit: Option<u64>,
) -> Vec<u8> {
    // Normalize line endings first
    let normalized = normalize_line_endings(body);
    let body_str = String::from_utf8_lossy(&normalized);

    let result = match method {
        CanonicalizationMethod::Simple => {
            simple_body(&body_str)
        }
        CanonicalizationMethod::Relaxed => {
            relaxed_body(&body_str)
        }
    };

    // Apply length limit after canonicalization
    if let Some(limit) = length_limit {
        let limit = limit as usize;
        if result.len() > limit {
            return result[..limit].to_vec();
        }
    }

    result
}

fn simple_body(body: &str) -> Vec<u8> {
    if body.is_empty() {
        return b"\r\n".to_vec();
    }

    // Remove trailing empty lines
    let mut lines: Vec<&str> = body.split("\r\n").collect();

    // Remove trailing empty elements
    while lines.last() == Some(&"") {
        lines.pop();
    }

    if lines.is_empty() {
        return b"\r\n".to_vec();
    }

    // Rejoin with CRLF and ensure trailing CRLF
    let mut result = lines.join("\r\n");
    result.push_str("\r\n");
    result.into_bytes()
}

fn relaxed_body(body: &str) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }

    let lines: Vec<&str> = body.split("\r\n").collect();
    let mut processed: Vec<String> = Vec::new();

    for line in &lines {
        // Remove trailing WSP
        let trimmed = line.trim_end_matches([' ', '\t']);
        // Collapse sequential WSP to single SP
        let collapsed = collapse_whitespace(trimmed);
        processed.push(collapsed);
    }

    // Remove trailing empty lines
    while processed.last().map(|s| s.is_empty()).unwrap_or(false) {
        processed.pop();
    }

    if processed.is_empty() {
        return Vec::new();
    }

    // Rejoin with CRLF and ensure trailing CRLF
    let mut result = processed.join("\r\n");
    result.push_str("\r\n");
    result.into_bytes()
}

/// Collapse sequential whitespace (SP/HTAB) to single SP.
fn collapse_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            if !in_ws {
                result.push(' ');
                in_ws = true;
            }
        } else {
            result.push(c);
            in_ws = false;
        }
    }
    result
}

/// Select headers from message for DKIM signing/verification.
/// Returns list of (name, value) pairs in h= order, with over-signed headers producing empty values.
pub fn select_headers<'a>(
    message_headers: &'a [(&'a str, &'a str)],
    signed_header_names: &[String],
    method: CanonicalizationMethod,
) -> Vec<String> {
    // Build a map of header name -> list of (index, name, value) in message order
    let mut header_map: std::collections::HashMap<String, Vec<(usize, &str, &str)>> =
        std::collections::HashMap::new();
    for (i, (name, value)) in message_headers.iter().enumerate() {
        header_map
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push((i, name, value));
    }

    // Track consumed count per header name
    let mut consumed: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    let mut result = Vec::new();

    for h_name in signed_header_names {
        let key = h_name.to_ascii_lowercase();
        let count = consumed.entry(key.clone()).or_insert(0);
        let instances = header_map.get(&key);

        if let Some(instances) = instances {
            // Bottom-up selection: take from the end
            let available = instances.len();
            if *count < available {
                let idx = available - 1 - *count;
                let (_, orig_name, value) = instances[idx];
                *count += 1;
                result.push(canonicalize_header(orig_name, value, method));
            } else {
                // Over-signed: contribute empty header
                result.push(match method {
                    CanonicalizationMethod::Simple => format!("{}:\r\n", h_name),
                    CanonicalizationMethod::Relaxed => format!("{}:\r\n", key),
                });
            }
        } else {
            // Header not in message: over-signed empty
            result.push(match method {
                CanonicalizationMethod::Simple => format!("{}:\r\n", h_name),
                CanonicalizationMethod::Relaxed => format!("{}:\r\n", key),
            });
        }
    }

    result
}

/// Strip the b= tag value from a DKIM-Signature header value, keeping "b=" with empty value.
/// Must NOT affect the bh= tag.
pub fn strip_b_tag(header_value: &str) -> String {
    // Find b= that is NOT bh=
    // Strategy: find positions of "b=" where the char before is not 'b' (or it's start/after ; or whitespace)
    let bytes = header_value.as_bytes();
    let mut result = String::with_capacity(header_value.len());
    let mut i = 0;

    while i < bytes.len() {
        // Check for "b=" that isn't "bh="
        if bytes[i] == b'b'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'='
            && (i + 2 >= bytes.len() || bytes[i + 1] != b'h')
        {
            // Check it's not preceded by another letter (i.e., it's the b tag, not bh)
            // Actually check: is the next char after 'b' the '=' sign, and is it NOT "bh="
            // We need to verify that bytes[i] = 'b', bytes[i+1] = '=' (not 'h')
            // This is already our condition. But we need to make sure it's a tag boundary.
            let is_tag_start = i == 0
                || bytes[i - 1] == b';'
                || bytes[i - 1] == b' '
                || bytes[i - 1] == b'\t'
                || bytes[i - 1] == b'\n'
                || bytes[i - 1] == b'\r';

            if is_tag_start {
                // Found b= tag. Keep "b=" and skip the value until ; or end
                result.push('b');
                result.push('=');
                i += 2;
                // Skip whitespace after =
                // Skip value until ; or end
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Line ending normalization ---
    #[test]
    fn test_normalize_bare_lf() {
        assert_eq!(normalize_line_endings(b"a\nb"), b"a\r\nb");
    }

    #[test]
    fn test_normalize_crlf_unchanged() {
        assert_eq!(normalize_line_endings(b"a\r\nb"), b"a\r\nb");
    }

    #[test]
    fn test_normalize_bare_cr() {
        assert_eq!(normalize_line_endings(b"a\rb"), b"a\r\nb");
    }

    // --- Simple header canonicalization ---
    #[test]
    fn test_simple_header() {
        assert_eq!(
            canonicalize_header("From", " user@example.com", CanonicalizationMethod::Simple),
            "From: user@example.com\r\n"
        );
    }

    // --- Relaxed header canonicalization ---
    #[test]
    fn test_relaxed_header() {
        assert_eq!(
            canonicalize_header("From", "  user@example.com  ", CanonicalizationMethod::Relaxed),
            "from:user@example.com\r\n"
        );
    }

    #[test]
    fn test_relaxed_header_collapse_ws() {
        assert_eq!(
            canonicalize_header("Subject", "  hello   world  ", CanonicalizationMethod::Relaxed),
            "subject:hello world\r\n"
        );
    }

    // --- Simple body canonicalization ---
    #[test]
    fn test_simple_body_trailing_empty() {
        let body = b"hello\r\n\r\n\r\n";
        assert_eq!(canonicalize_body(body, CanonicalizationMethod::Simple, None), b"hello\r\n");
    }

    #[test]
    fn test_simple_body_empty() {
        assert_eq!(canonicalize_body(b"", CanonicalizationMethod::Simple, None), b"\r\n");
    }

    #[test]
    fn test_simple_body_only_crlfs() {
        assert_eq!(
            canonicalize_body(b"\r\n\r\n\r\n", CanonicalizationMethod::Simple, None),
            b"\r\n"
        );
    }

    // --- Relaxed body canonicalization ---
    #[test]
    fn test_relaxed_body_trailing_empty() {
        let body = b"hello\r\n\r\n\r\n";
        assert_eq!(canonicalize_body(body, CanonicalizationMethod::Relaxed, None), b"hello\r\n");
    }

    #[test]
    fn test_relaxed_body_empty() {
        assert_eq!(canonicalize_body(b"", CanonicalizationMethod::Relaxed, None), Vec::<u8>::new());
    }

    #[test]
    fn test_relaxed_body_only_crlfs() {
        assert_eq!(
            canonicalize_body(b"\r\n\r\n\r\n", CanonicalizationMethod::Relaxed, None),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn test_relaxed_body_whitespace() {
        let body = b"  \r\n  \r\n";
        assert_eq!(
            canonicalize_body(body, CanonicalizationMethod::Relaxed, None),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn test_relaxed_body_normalize_ws() {
        let body = b"hello  world\t\there\r\n";
        assert_eq!(
            canonicalize_body(body, CanonicalizationMethod::Relaxed, None),
            b"hello world here\r\n"
        );
    }

    // --- Body length limit ---
    #[test]
    fn test_body_length_limit() {
        let body = b"hello world\r\n";
        let result = canonicalize_body(body, CanonicalizationMethod::Simple, Some(5));
        assert_eq!(result, b"hello");
    }

    // --- Header selection ---
    #[test]
    fn test_header_selection_bottom_up() {
        let headers = vec![
            ("From", " first@example.com"),
            ("To", " to@example.com"),
            ("From", " second@example.com"),
        ];
        let signed = vec!["from".to_string(), "to".to_string()];
        let result = select_headers(&headers, &signed, CanonicalizationMethod::Simple);
        assert_eq!(result.len(), 2);
        assert!(result[0].contains("second@example.com"));
        assert!(result[1].contains("to@example.com"));
    }

    #[test]
    fn test_header_selection_oversigning() {
        let headers = vec![("From", " user@example.com")];
        let signed = vec!["from".to_string(), "from".to_string()];
        let result = select_headers(&headers, &signed, CanonicalizationMethod::Simple);
        assert_eq!(result.len(), 2);
        assert!(result[0].contains("user@example.com"));
        assert_eq!(result[1], "from:\r\n"); // over-signed empty
    }

    // --- b= stripping ---
    #[test]
    fn test_strip_b_tag() {
        let header = "v=1; a=rsa-sha256; b=abc123; bh=xyz789; d=example.com";
        let stripped = strip_b_tag(header);
        assert!(stripped.contains("b=;"));
        assert!(stripped.contains("bh=xyz789"));
    }

    #[test]
    fn test_strip_b_tag_end() {
        let header = "v=1; bh=xyz789; b=abc123";
        let stripped = strip_b_tag(header);
        assert!(stripped.ends_with("b="));
        assert!(stripped.contains("bh=xyz789"));
    }
}
