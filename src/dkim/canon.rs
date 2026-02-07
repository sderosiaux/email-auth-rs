use super::CanonicalizationMethod;

/// Normalize line endings: bare LF → CRLF.
pub fn normalize_line_endings(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\r' && input.get(i + 1) == Some(&b'\n') {
            out.push(b'\r');
            out.push(b'\n');
            i += 2;
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

/// Canonicalize a header field.
pub fn canonicalize_header(name: &str, value: &str, method: CanonicalizationMethod) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            format!("{name}:{value}\r\n")
        }
        CanonicalizationMethod::Relaxed => {
            let lower_name = name.to_ascii_lowercase();
            // Unfold: remove CRLF before whitespace
            let unfolded = unfold(value);
            // Collapse sequential whitespace to single SP
            let collapsed = collapse_whitespace(&unfolded);
            // Trim leading/trailing whitespace
            let trimmed = collapsed.trim();
            format!("{lower_name}:{trimmed}\r\n")
        }
    }
}

/// Canonicalize body.
pub fn canonicalize_body(body: &[u8], method: CanonicalizationMethod) -> Vec<u8> {
    let normalized = normalize_line_endings(body);

    match method {
        CanonicalizationMethod::Simple => {
            simple_body(&normalized)
        }
        CanonicalizationMethod::Relaxed => {
            relaxed_body(&normalized)
        }
    }
}

fn simple_body(body: &[u8]) -> Vec<u8> {
    // Remove trailing empty lines
    let mut result = body.to_vec();
    while result.ends_with(b"\r\n\r\n") {
        result.truncate(result.len() - 2);
    }
    // If body is empty after stripping, treat as single CRLF
    if result.is_empty() {
        result = b"\r\n".to_vec();
    } else if !result.ends_with(b"\r\n") {
        result.extend_from_slice(b"\r\n");
    }
    result
}

fn relaxed_body(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut lines: Vec<String> = Vec::new();

    for line in text.split("\r\n") {
        // Remove trailing whitespace
        let trimmed = line.trim_end_matches(|c: char| c == ' ' || c == '\t');
        // Collapse sequential whitespace within line to single SP
        let collapsed = collapse_whitespace_bytes(trimmed);
        lines.push(collapsed);
    }

    // Remove trailing empty lines
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    // Also pop extra empty caused by split
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }

    if lines.is_empty() {
        return Vec::new(); // relaxed: empty body → empty (NOT CRLF)
    }

    let mut result = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        result.extend_from_slice(line.as_bytes());
        if i < lines.len() - 1 || !line.is_empty() {
            result.extend_from_slice(b"\r\n");
        }
    }
    if !result.ends_with(b"\r\n") && !result.is_empty() {
        result.extend_from_slice(b"\r\n");
    }
    result
}

fn collapse_whitespace_bytes(s: &str) -> String {
    let mut result = String::new();
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

fn unfold(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            chars.next(); // consume \n
            // If next char is SP or HTAB, it's folding — replace with SP
            if let Some(&next) = chars.peek() {
                if next == ' ' || next == '\t' {
                    chars.next();
                    result.push(' ');
                    continue;
                }
            }
            result.push('\r');
            result.push('\n');
        } else {
            result.push(c);
        }
    }
    result
}

fn collapse_whitespace(s: &str) -> String {
    collapse_whitespace_bytes(s)
}

/// Select headers from message for DKIM hash input.
/// Returns canonicalized header lines (name:value\r\n) in order.
/// Headers are selected bottom-up: last unused occurrence first.
pub fn select_headers(
    headers: &[(&str, &str)],
    signed_header_names: &[String],
    method: CanonicalizationMethod,
) -> Vec<String> {
    // Track how many of each header name have been consumed (bottom-up)
    let mut consumed: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    let mut result = Vec::new();

    for h_name in signed_header_names {
        let h_lower = h_name.to_ascii_lowercase();
        let count = consumed.entry(h_lower.clone()).or_insert(0);

        // Find matching headers bottom-up
        let matching: Vec<usize> = headers
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, (name, _))| name.to_ascii_lowercase() == h_lower)
            .map(|(i, _)| i)
            .collect();

        if *count < matching.len() {
            let idx = matching[*count];
            let (name, value) = &headers[idx];
            result.push(canonicalize_header(name, value, method));
            *count += 1;
        } else {
            // Over-signed: header not found, contribute empty value
            result.push(canonicalize_header(h_name, "", method));
        }
    }

    result
}

/// Strip b= tag value from DKIM-Signature header value.
/// Keeps "b=" with empty value. MUST NOT affect "bh=" tag.
pub fn strip_b_tag(header_value: &str) -> String {
    let mut result = String::new();
    let mut remaining = header_value;

    while !remaining.is_empty() {
        // Find next 'b=' that is NOT 'bh='
        if let Some(pos) = remaining.find("b=") {
            // Check it's not "bh="
            if pos > 0 && remaining.as_bytes()[pos - 1] == b'b' {
                // It's "bh=" (or similar), skip
                result.push_str(&remaining[..pos + 2]);
                remaining = &remaining[pos + 2..];
                continue;
            }
            // Also check it's preceded by whitespace, semicolon, or start-of-string
            let is_standalone_b = pos == 0
                || remaining.as_bytes()[pos - 1].is_ascii_whitespace()
                || remaining.as_bytes()[pos - 1] == b';';

            if !is_standalone_b {
                result.push_str(&remaining[..pos + 2]);
                remaining = &remaining[pos + 2..];
                continue;
            }

            // Found standalone b=, strip its value
            result.push_str(&remaining[..pos + 2]); // include "b="
            remaining = &remaining[pos + 2..];

            // Skip value until next ';' or end
            if let Some(semi_pos) = remaining.find(';') {
                remaining = &remaining[semi_pos..];
            } else {
                remaining = "";
            }
        } else {
            result.push_str(remaining);
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_header() {
        let out = canonicalize_header("From", " user@example.com", CanonicalizationMethod::Simple);
        assert_eq!(out, "From: user@example.com\r\n");
    }

    #[test]
    fn test_relaxed_header() {
        let out = canonicalize_header(
            "From",
            "  user@example.com  ",
            CanonicalizationMethod::Relaxed,
        );
        assert_eq!(out, "from:user@example.com\r\n");
    }

    #[test]
    fn test_relaxed_header_collapse_ws() {
        let out = canonicalize_header(
            "Subject",
            "  hello   world  ",
            CanonicalizationMethod::Relaxed,
        );
        assert_eq!(out, "subject:hello world\r\n");
    }

    #[test]
    fn test_simple_body_trailing_empty() {
        let body = b"Hello\r\n\r\n\r\n";
        let out = canonicalize_body(body, CanonicalizationMethod::Simple);
        assert_eq!(out, b"Hello\r\n");
    }

    #[test]
    fn test_simple_body_empty() {
        let out = canonicalize_body(b"", CanonicalizationMethod::Simple);
        assert_eq!(out, b"\r\n");
    }

    #[test]
    fn test_relaxed_body_empty() {
        let out = canonicalize_body(b"", CanonicalizationMethod::Relaxed);
        assert!(out.is_empty());
    }

    #[test]
    fn test_relaxed_body_ws() {
        let body = b"Hello  World \r\n  Foo\t\tBar  \r\n\r\n";
        let out = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        assert_eq!(out, b"Hello World\r\n Foo Bar\r\n");
    }

    #[test]
    fn test_bare_lf_normalization() {
        let out = normalize_line_endings(b"Hello\nWorld\n");
        assert_eq!(out, b"Hello\r\nWorld\r\n");
    }

    #[test]
    fn test_header_selection_bottom_up() {
        let headers = vec![
            ("To", " first@example.com"),
            ("To", " second@example.com"),
            ("From", " user@example.com"),
        ];
        let signed = vec!["to".to_string(), "from".to_string()];
        let result = select_headers(&headers, &signed, CanonicalizationMethod::Simple);
        assert_eq!(result.len(), 2);
        // "to" should select the last (second@example.com) first
        assert!(result[0].contains("second@example.com"));
    }

    #[test]
    fn test_over_signed_headers() {
        let headers = vec![("From", " user@example.com")];
        let signed = vec!["from".to_string(), "from".to_string()];
        let result = select_headers(&headers, &signed, CanonicalizationMethod::Simple);
        assert_eq!(result.len(), 2);
        assert!(result[0].contains("user@example.com"));
        // Second from: over-signed, empty value
        assert_eq!(result[1], "from:\r\n");
    }

    #[test]
    fn test_strip_b_tag() {
        let input = "v=1; a=rsa-sha256; bh=abc123; b=SIGNATURE; d=example.com";
        let stripped = strip_b_tag(input);
        assert!(stripped.contains("bh=abc123"));
        assert!(stripped.contains("b=;"));
        assert!(!stripped.contains("SIGNATURE"));
    }

    #[test]
    fn test_strip_b_tag_at_end() {
        let input = "v=1; bh=abc; b=SIG";
        let stripped = strip_b_tag(input);
        assert_eq!(stripped, "v=1; bh=abc; b=");
    }
}
