use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Line ending normalization
// ---------------------------------------------------------------------------

/// Convert bare LF (not preceded by CR) to CRLF.
/// Existing CRLF sequences are preserved.
pub fn normalize_line_endings(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let len = input.len();
    let mut i = 0;
    while i < len {
        if input[i] == b'\n' && (i == 0 || input[i - 1] != b'\r') {
            out.push(b'\r');
            out.push(b'\n');
        } else {
            out.push(input[i]);
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Header canonicalization
// ---------------------------------------------------------------------------

/// Simple header canonicalization: no modification.
/// Output: `name:value\r\n` (the raw name and value as-is).
pub fn canonicalize_header_simple(name: &str, value: &str) -> String {
    format!("{}:{}\r\n", name, value)
}

/// Relaxed header canonicalization (RFC 6376 Section 3.4.2):
/// - Lowercase the header field name
/// - Unfold header (remove CRLF before WSP)
/// - Collapse runs of WSP to a single SP
/// - Trim trailing WSP from the value
/// - No space around the colon
pub fn canonicalize_header_relaxed(name: &str, value: &str) -> String {
    let lower_name = name.to_ascii_lowercase();

    // Unfold: remove CRLF sequences that precede WSP
    let unfolded = unfold_value(value);

    // Collapse runs of whitespace (SP/TAB) to single SP, then trim trailing
    let collapsed = collapse_wsp(&unfolded);
    let trimmed = collapsed.trim_end();

    format!("{}:{}\r\n", lower_name, trimmed)
}

/// Remove CRLF+WSP (header folding) from a value.
fn unfold_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if i + 2 < len
            && bytes[i] == b'\r'
            && bytes[i + 1] == b'\n'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t')
        {
            // Skip the CRLF, keep the WSP
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Collapse runs of SP/TAB into a single SP.
fn collapse_wsp(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_wsp = false;
    for ch in s.chars() {
        if ch == ' ' || ch == '\t' {
            if !in_wsp {
                out.push(' ');
                in_wsp = true;
            }
        } else {
            out.push(ch);
            in_wsp = false;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Body canonicalization
// ---------------------------------------------------------------------------

/// Simple body canonicalization (RFC 6376 Section 3.4.3):
/// - Remove trailing empty lines (lines that are just CRLF)
/// - If the body is entirely empty after removal, return a single CRLF
/// - Ensure result ends with CRLF
pub fn canonicalize_body_simple(body: &[u8]) -> Vec<u8> {
    let normalized = normalize_line_endings(body);

    // Split into CRLF-terminated lines
    let lines = split_crlf_lines(&normalized);

    // Remove trailing empty lines
    let mut end = lines.len();
    while end > 0 && lines[end - 1].is_empty() {
        end -= 1;
    }

    if end == 0 {
        // Empty body → single CRLF
        return b"\r\n".to_vec();
    }

    // Reconstruct with CRLF terminators
    let mut out = Vec::new();
    for line in &lines[..end] {
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Relaxed body canonicalization (RFC 6376 Section 3.4.4):
/// - Remove trailing WSP on each line
/// - Collapse runs of WSP within each line to a single SP
/// - Remove all trailing empty lines
/// - If the body is empty after these steps, return empty (NOT CRLF)
pub fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    let normalized = normalize_line_endings(body);
    let lines = split_crlf_lines(&normalized);

    // Process each line: collapse WSP, trim trailing WSP
    let processed: Vec<Vec<u8>> = lines
        .iter()
        .map(|line| {
            let mut out = Vec::with_capacity(line.len());
            let mut in_wsp = false;
            for &b in line.iter() {
                if b == b' ' || b == b'\t' {
                    if !in_wsp {
                        out.push(b' ');
                        in_wsp = true;
                    }
                } else {
                    out.push(b);
                    in_wsp = false;
                }
            }
            // Trim trailing WSP
            while out.last() == Some(&b' ') || out.last() == Some(&b'\t') {
                out.pop();
            }
            out
        })
        .collect();

    // Remove trailing empty lines
    let mut end = processed.len();
    while end > 0 && processed[end - 1].is_empty() {
        end -= 1;
    }

    if end == 0 {
        // Empty body → truly empty (differs from simple!)
        return Vec::new();
    }

    // Reconstruct with CRLF terminators
    let mut out = Vec::new();
    for line in &processed[..end] {
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Split a byte slice into lines by CRLF. Each element is the content before
/// the CRLF (not including the CRLF itself). A trailing CRLF produces an
/// empty trailing element.
fn split_crlf_lines(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let len = data.len();
    let mut i = 0;
    while i < len {
        if i + 1 < len && data[i] == b'\r' && data[i + 1] == b'\n' {
            lines.push(&data[start..i]);
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    // If there is trailing content without a CRLF, include it
    if start < len {
        lines.push(&data[start..]);
    }
    lines
}

// ---------------------------------------------------------------------------
// b= tag stripping
// ---------------------------------------------------------------------------

/// Strip the value of the b= tag from a DKIM-Signature header value,
/// keeping the `b=` tag name intact but removing everything between `=` and
/// the next `;` (or end of string).
///
/// Must NOT affect the `bh=` tag. We find `b=` that is NOT preceded by an
/// ASCII letter (to distinguish from `bh=`, `ab=`, etc.).
pub fn strip_b_tag(header_value: &str) -> String {
    let bytes = header_value.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        // Look for 'b' followed by '='
        if bytes[i] == b'b' && i + 1 < len && bytes[i + 1] == b'=' {
            // Check that this is a standalone `b=`, not `bh=`, `ab=`, etc.
            let preceded_by_letter = i > 0 && bytes[i - 1].is_ascii_alphabetic();
            // Check it's not `bh=` (b followed by h before =)
            let is_bh = i + 2 < len && bytes[i + 1] == b'h';

            if !preceded_by_letter && !is_bh {
                // Found standalone b= tag. Keep "b=" but strip the value.
                result.push('b');
                result.push('=');
                i += 2; // skip past "b="
                // Skip value until ';' or end
                while i < len && bytes[i] != b';' {
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

// ---------------------------------------------------------------------------
// Header selection (bottom-up)
// ---------------------------------------------------------------------------

/// Select headers according to the h= list, using bottom-up matching.
///
/// For each name in `h_list`, find the next unused occurrence of that header
/// starting from the bottom of `headers`. If the name appears more times in
/// `h_list` than in `headers`, produce an empty entry for that header name
/// (over-signing protection).
///
/// `headers` is ordered top-to-bottom as they appear in the message.
/// Returns headers in the order they appear in `h_list`.
pub fn select_headers<'a>(
    h_list: &[String],
    headers: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    // Track how many times each header name has been consumed, counting from
    // the bottom. We use a map of name → next index to consume (from bottom).
    let mut consumed_count: HashMap<String, usize> = HashMap::new();
    let mut result = Vec::with_capacity(h_list.len());

    for name in h_list {
        let lower = name.to_ascii_lowercase();
        let count = consumed_count.entry(lower.clone()).or_insert(0);

        // Collect all indices matching this header name, bottom-up
        let matching: Vec<usize> = headers
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, (n, _))| n.eq_ignore_ascii_case(&lower))
            .map(|(idx, _)| idx)
            .collect();

        // matching is already in bottom-up order (rev above)
        if *count < matching.len() {
            let idx = matching[*count];
            result.push(headers[idx]);
            *count += 1;
        } else {
            // Over-signed: more h= entries than actual headers → empty entry
            // Use a leaked static string for the name since we need 'a lifetime
            // Actually, we return ("", "") to signal an empty/missing header
            result.push(("", ""));
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Header canonicalization --

    #[test]
    fn simple_header_unchanged() {
        let result = canonicalize_header_simple("From", " user@example.com");
        assert_eq!(result, "From: user@example.com\r\n");
    }

    #[test]
    fn relaxed_header_transformations() {
        // Lowercase name, collapse WSP, trim trailing WSP
        let result = canonicalize_header_relaxed("Subject", "  Hello   World  ");
        assert_eq!(result, "subject: Hello World\r\n");

        // Tab handling
        let result = canonicalize_header_relaxed("From", "\tuser@example.com\t");
        assert_eq!(result, "from: user@example.com\r\n");

        // Folded header value
        let result = canonicalize_header_relaxed("Subject", " Hello\r\n World");
        assert_eq!(result, "subject: Hello World\r\n");
    }

    // -- Body canonicalization --

    #[test]
    fn simple_body_trailing_blank_removal() {
        let body = b"Hello\r\nWorld\r\n\r\n\r\n";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"Hello\r\nWorld\r\n");
    }

    #[test]
    fn simple_body_empty_becomes_crlf() {
        let result = canonicalize_body_simple(b"");
        assert_eq!(result, b"\r\n");

        // Also test body that is only empty lines
        let result = canonicalize_body_simple(b"\r\n\r\n");
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn relaxed_body_empty_becomes_empty() {
        let result = canonicalize_body_relaxed(b"");
        assert!(result.is_empty());

        let result = canonicalize_body_relaxed(b"\r\n\r\n");
        assert!(result.is_empty());
    }

    #[test]
    fn relaxed_body_whitespace_normalization() {
        let body = b"Hello  \t World  \r\nSecond   line\t\r\n\r\n";
        let result = canonicalize_body_relaxed(body);
        assert_eq!(result, b"Hello World\r\nSecond line\r\n");
    }

    #[test]
    fn bare_lf_to_crlf() {
        let input = b"Hello\nWorld\n";
        let result = normalize_line_endings(input);
        assert_eq!(result, b"Hello\r\nWorld\r\n");

        // Existing CRLF should not be doubled
        let input2 = b"Hello\r\nWorld\r\n";
        let result2 = normalize_line_endings(input2);
        assert_eq!(result2, b"Hello\r\nWorld\r\n");

        // Mixed
        let input3 = b"A\nB\r\nC\n";
        let result3 = normalize_line_endings(input3);
        assert_eq!(result3, b"A\r\nB\r\nC\r\n");
    }

    // -- b= tag stripping --

    #[test]
    fn strip_b_tag_preserves_bh() {
        let header = "v=1; a=rsa-sha256; b=dGVzdA==; bh=aGFzaA==; d=example.com";
        let result = strip_b_tag(header);
        assert_eq!(
            result,
            "v=1; a=rsa-sha256; b=; bh=aGFzaA==; d=example.com"
        );
    }

    #[test]
    fn strip_b_tag_at_end() {
        let header = "v=1; bh=aGFzaA==; b=dGVzdA==";
        let result = strip_b_tag(header);
        assert_eq!(result, "v=1; bh=aGFzaA==; b=");
    }

    #[test]
    fn strip_b_tag_empty_value() {
        let header = "v=1; b=; bh=aGFzaA==";
        let result = strip_b_tag(header);
        assert_eq!(result, "v=1; b=; bh=aGFzaA==");
    }

    // -- Header selection --

    #[test]
    fn bottom_up_header_selection() {
        let headers: Vec<(&str, &str)> = vec![
            ("From", " first@example.com"),
            ("To", " recipient@example.com"),
            ("From", " second@example.com"),
        ];
        let h_list = vec!["from".to_string()];
        let selected = select_headers(&h_list, &headers);
        // Should select the bottom-most From
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1, " second@example.com");
    }

    #[test]
    fn bottom_up_multiple_same_header() {
        let headers: Vec<(&str, &str)> = vec![
            ("From", " first@example.com"),
            ("To", " recipient@example.com"),
            ("From", " second@example.com"),
        ];
        let h_list = vec!["from".to_string(), "from".to_string()];
        let selected = select_headers(&h_list, &headers);
        assert_eq!(selected.len(), 2);
        // First h= entry gets bottom-most, second gets next one up
        assert_eq!(selected[0].1, " second@example.com");
        assert_eq!(selected[1].1, " first@example.com");
    }

    #[test]
    fn over_signed_headers_produce_empty() {
        let headers: Vec<(&str, &str)> = vec![("From", " user@example.com")];
        let h_list = vec!["from".to_string(), "from".to_string()];
        let selected = select_headers(&h_list, &headers);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].1, " user@example.com");
        // Over-signed: no more From headers available
        assert_eq!(selected[1], ("", ""));
    }

    #[test]
    fn header_selection_mixed() {
        let headers: Vec<(&str, &str)> = vec![
            ("From", " sender@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Hello"),
            ("Date", " Mon, 01 Jan 2024"),
        ];
        let h_list = vec![
            "from".to_string(),
            "to".to_string(),
            "subject".to_string(),
        ];
        let selected = select_headers(&h_list, &headers);
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].0, "From");
        assert_eq!(selected[1].0, "To");
        assert_eq!(selected[2].0, "Subject");
    }

    // -- Body with bare LF through canonicalization --

    #[test]
    fn simple_body_bare_lf_normalized() {
        let body = b"Hello\nWorld\n";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"Hello\r\nWorld\r\n");
    }

    #[test]
    fn relaxed_body_bare_lf_normalized() {
        let body = b"Hello  \n";
        let result = canonicalize_body_relaxed(body);
        assert_eq!(result, b"Hello\r\n");
    }

    #[test]
    fn simple_body_preserves_content() {
        let body = b"Line 1\r\nLine 2\r\n";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"Line 1\r\nLine 2\r\n");
    }
}
