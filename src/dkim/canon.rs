//! DKIM canonicalization (RFC 6376 Section 3.4) and header selection (Section 5.4.2).

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Header canonicalization
// ---------------------------------------------------------------------------

/// Simple header canonicalization: no modifications whatsoever.
/// Output: `name:value\r\n`
pub fn canonicalize_header_simple(name: &str, value: &str) -> String {
    format!("{name}:{value}\r\n")
}

/// Relaxed header canonicalization (RFC 6376 Section 3.4.2):
/// - Lowercase the header field name
/// - Unfold header (remove CRLF before WSP)
/// - Collapse runs of WSP to a single SP
/// - Remove trailing WSP from the value
/// - Remove WSP before and after the colon (no space between name and value)
pub fn canonicalize_header_relaxed(name: &str, value: &str) -> String {
    let lower_name = name.to_ascii_lowercase();

    // Unfold: remove CRLF that precede WSP, then collapse WSP runs to single SP.
    let unfolded = unfold_and_collapse(value);

    // Trim trailing whitespace from value.
    let trimmed = unfolded.trim_end();

    // Trim leading whitespace from value (WSP after colon removal).
    let trimmed = trimmed.trim_start();

    format!("{lower_name}:{trimmed}\r\n")
}

/// Unfold CRLF+WSP and collapse all WSP runs to a single SP.
fn unfold_and_collapse(s: &str) -> String {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;
    let mut in_wsp = false;

    while i < len {
        // Detect CRLF followed by WSP (folding) — consume the CRLF and treat
        // the following WSP as part of a whitespace run.
        if i + 2 < len && bytes[i] == b'\r' && bytes[i + 1] == b'\n'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t')
        {
            in_wsp = true;
            i += 2; // skip CR LF; loop will pick up the WSP char next
            continue;
        }

        if bytes[i] == b' ' || bytes[i] == b'\t' {
            in_wsp = true;
            i += 1;
        } else {
            if in_wsp {
                out.push(' ');
                in_wsp = false;
            }
            out.push(bytes[i] as char);
            i += 1;
        }
    }

    // If the string ended while still in a WSP run, emit the single space
    // (will be trimmed later by caller).
    if in_wsp {
        out.push(' ');
    }

    out
}

// ---------------------------------------------------------------------------
// Body canonicalization
// ---------------------------------------------------------------------------

/// Normalize bare LF to CRLF.  Existing CRLF sequences are preserved.
fn normalize_line_endings(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let len = body.len();
    let mut i = 0;
    while i < len {
        if body[i] == b'\r' && i + 1 < len && body[i + 1] == b'\n' {
            out.push(b'\r');
            out.push(b'\n');
            i += 2;
        } else if body[i] == b'\n' {
            // Bare LF -> CRLF
            out.push(b'\r');
            out.push(b'\n');
            i += 1;
        } else if body[i] == b'\r' {
            // Bare CR -> CRLF (defensive)
            out.push(b'\r');
            out.push(b'\n');
            i += 1;
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

/// Simple body canonicalization (RFC 6376 Section 3.4.3):
/// - Normalize line endings to CRLF
/// - Remove all trailing empty lines (lines that are just CRLF)
/// - Ensure body ends with CRLF
/// - Empty body -> single CRLF
pub fn canonicalize_body_simple(body: &[u8]) -> Vec<u8> {
    let normalized = normalize_line_endings(body);

    if normalized.is_empty() {
        return b"\r\n".to_vec();
    }

    // Strip trailing CRLF sequences (empty lines at the end).
    let mut end = normalized.len();
    while end >= 2 && normalized[end - 2] == b'\r' && normalized[end - 1] == b'\n' {
        end -= 2;
    }

    if end == 0 {
        // Body was entirely empty lines.
        return b"\r\n".to_vec();
    }

    // Re-append exactly one CRLF.
    let mut result = normalized[..end].to_vec();
    result.push(b'\r');
    result.push(b'\n');
    result
}

/// Relaxed body canonicalization (RFC 6376 Section 3.4.4):
/// - Normalize line endings to CRLF
/// - Remove trailing WSP on each line (before CRLF)
/// - Collapse runs of WSP within a line to a single SP
/// - Remove all trailing empty lines
/// - Empty body -> empty (no CRLF added)
pub fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    let normalized = normalize_line_endings(body);

    if normalized.is_empty() {
        return Vec::new();
    }

    // Split into lines on CRLF boundaries, process each line.
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut start = 0;
    let len = normalized.len();
    let mut i = 0;
    while i < len {
        if i + 1 < len && normalized[i] == b'\r' && normalized[i + 1] == b'\n' {
            lines.push(process_relaxed_body_line(&normalized[start..i]));
            start = i + 2;
            i = start;
        } else {
            i += 1;
        }
    }
    // Remainder after last CRLF (if any content without trailing CRLF).
    if start < len {
        lines.push(process_relaxed_body_line(&normalized[start..len]));
    }

    // Remove trailing empty lines.
    while let Some(last) = lines.last() {
        if last.is_empty() {
            lines.pop();
        } else {
            break;
        }
    }

    if lines.is_empty() {
        return Vec::new();
    }

    // Reassemble with CRLF.
    let mut result = Vec::new();
    for line in &lines {
        result.extend_from_slice(line);
        result.push(b'\r');
        result.push(b'\n');
    }
    result
}

/// Process a single body line for relaxed canonicalization:
/// collapse WSP runs to single SP, then strip trailing WSP.
fn process_relaxed_body_line(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut in_wsp = false;

    for &b in line {
        if b == b' ' || b == b'\t' {
            in_wsp = true;
        } else {
            if in_wsp {
                out.push(b' ');
                in_wsp = false;
            }
            out.push(b);
        }
    }
    // Trailing WSP is simply dropped (we don't push the pending space).
    out
}

// ---------------------------------------------------------------------------
// Body truncation (l= tag)
// ---------------------------------------------------------------------------

/// Truncate canonicalized body to at most `length_limit` bytes.
/// If `length_limit` is `None`, the full body is returned.
pub fn truncate_body(body: &[u8], length_limit: Option<u64>) -> &[u8] {
    match length_limit {
        Some(limit) => {
            let limit = limit as usize;
            if limit < body.len() {
                &body[..limit]
            } else {
                body
            }
        }
        None => body,
    }
}

// ---------------------------------------------------------------------------
// Header selection (RFC 6376 Section 5.4.2)
// ---------------------------------------------------------------------------

/// Select headers from the message according to the `h=` tag list.
///
/// - Headers are matched case-insensitively.
/// - Multiple occurrences of the same header name are selected bottom-up
///   (last occurrence first).
/// - If `h=` lists a header name more times than it exists in the message,
///   the extra entries produce a sentinel `("header-name", "")` which the
///   caller must canonicalize as an empty header (preventing header injection).
pub fn select_headers<'a>(
    header_list: &[(&'a str, &'a str)],
    signed_headers: &[String],
) -> Vec<(&'a str, &'a str)> {
    // Build a map: lowered header name -> list of indices into header_list,
    // ordered bottom-up (last occurrence at index 0).
    let mut index_map: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, (name, _)) in header_list.iter().enumerate() {
        let lower = name.to_ascii_lowercase();
        index_map.entry(lower).or_default().push(i);
    }
    // Reverse each list so the last occurrence comes first.
    for indices in index_map.values_mut() {
        indices.reverse();
    }

    // Track how many times each header name has been consumed.
    let mut consumed: HashMap<String, usize> = HashMap::new();

    let mut result = Vec::with_capacity(signed_headers.len());

    for h_name in signed_headers {
        let lower = h_name.to_ascii_lowercase();
        let count = consumed.entry(lower.clone()).or_insert(0);

        if let Some(indices) = index_map.get(&lower) {
            if *count < indices.len() {
                let idx = indices[*count];
                result.push(header_list[idx]);
                *count += 1;
            } else {
                // Over-signed: no more occurrences left. Emit sentinel.
                // We leak the name from signed_headers via the static-ish trick below.
                // Actually, we need to return (&'a str, &'a str). For over-signed
                // headers, there is no corresponding entry in header_list.
                // We use "" as sentinel value with an empty-string name placeholder.
                // The caller will use h_name for canonicalization.
                // Since we can't return &'a str from signed_headers (different lifetime),
                // we use a sentinel of ("", "") and document the contract.
                result.push(("", ""));
                *count += 1;
            }
        } else {
            // Header name not present at all in the message. Over-signed.
            result.push(("", ""));
            let count = consumed.entry(lower).or_insert(0);
            *count += 1;
        }
    }

    result
}

// ---------------------------------------------------------------------------
// b= tag stripping
// ---------------------------------------------------------------------------

/// Strip the value of the `b=` tag from a DKIM-Signature header value,
/// leaving `b=` with an empty value.  Must NOT affect the `bh=` tag.
pub fn strip_b_tag_value(dkim_header_value: &str) -> String {
    // We need to find `b=<value>` without matching `bh=`.
    // Strategy: scan for the b= tag specifically. The tag grammar is:
    //   tag = ALPHA *ALNUMD (where ALNUMD = ALPHA / DIGIT / "_")
    // So "b" as a tag is followed by "=" and NOT preceded by an alphanumeric
    // or underscore character (it's at the start or after a `;` + optional WSP).
    //
    // We find the position of "b=" that is a standalone tag, then strip
    // everything between "=" and the next ";" (or end of string), preserving
    // the "b=" prefix.

    let bytes = dkim_header_value.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    // Find the start of the b= tag.
    let b_tag_start;
    loop {
        if i >= len {
            // No b= tag found; return as-is.
            return dkim_header_value.to_string();
        }

        // Look for 'b' or 'B' followed by optional WSP then '='
        if (bytes[i] == b'b' || bytes[i] == b'B') && is_b_tag_at(bytes, i) {
            b_tag_start = i;
            break;
        }
        i += 1;
    }

    // Find the '=' after 'b' (skip optional WSP between tag name and '=').
    let mut eq_pos = b_tag_start + 1;
    while eq_pos < len && (bytes[eq_pos] == b' ' || bytes[eq_pos] == b'\t') {
        eq_pos += 1;
    }
    // eq_pos should now be at '='
    if eq_pos >= len || bytes[eq_pos] != b'=' {
        return dkim_header_value.to_string();
    }

    // Find the end of the b= value: everything up to the next ';' or end.
    let value_start = eq_pos + 1;
    let mut value_end = value_start;
    while value_end < len && bytes[value_end] != b';' {
        value_end += 1;
    }

    // Build result: everything before value_start + everything from value_end onward.
    let mut result = String::with_capacity(len);
    result.push_str(&dkim_header_value[..value_start]);
    result.push_str(&dkim_header_value[value_end..]);
    result
}

/// Check whether position `i` in `bytes` is the start of a standalone `b` tag
/// (not `bh` or any other tag starting with 'b').
fn is_b_tag_at(bytes: &[u8], i: usize) -> bool {
    let len = bytes.len();

    // Character before must be start-of-string, ';', or whitespace.
    if i > 0 {
        let prev = bytes[i - 1];
        if prev != b';' && prev != b' ' && prev != b'\t' && prev != b'\r' && prev != b'\n' {
            return false;
        }
    }

    // Current char is 'b'/'B'. Next non-WSP char must be '=' (not another alnum like 'h').
    let mut j = i + 1;
    while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    if j >= len {
        return false;
    }
    bytes[j] == b'='
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Header canonicalization
    // -----------------------------------------------------------------------

    #[test]
    fn simple_header_preserves_original() {
        let result = canonicalize_header_simple("Subject", " Hello  World ");
        assert_eq!(result, "Subject: Hello  World \r\n");
    }

    #[test]
    fn simple_header_preserves_case() {
        let result = canonicalize_header_simple("X-Custom-Header", "SomeValue");
        assert_eq!(result, "X-Custom-Header:SomeValue\r\n");
    }

    #[test]
    fn relaxed_header_lowercases_name() {
        let result = canonicalize_header_relaxed("Subject", "hello");
        assert_eq!(result, "subject:hello\r\n");
    }

    #[test]
    fn relaxed_header_collapses_internal_wsp() {
        let result = canonicalize_header_relaxed("Subject", "  hello   world  ");
        assert_eq!(result, "subject:hello world\r\n");
    }

    #[test]
    fn relaxed_header_removes_trailing_wsp() {
        let result = canonicalize_header_relaxed("Subject", "hello   ");
        assert_eq!(result, "subject:hello\r\n");
    }

    #[test]
    fn relaxed_header_removes_wsp_around_colon() {
        // The value as passed already excludes the colon; leading/trailing WSP
        // in the value represents space after/before the colon.
        let result = canonicalize_header_relaxed("Subject", "  hello");
        assert_eq!(result, "subject:hello\r\n");
    }

    #[test]
    fn relaxed_header_unfolds_crlf_wsp() {
        let result = canonicalize_header_relaxed("Subject", "hello\r\n world");
        assert_eq!(result, "subject:hello world\r\n");
    }

    #[test]
    fn relaxed_header_unfolds_and_collapses() {
        let result = canonicalize_header_relaxed("Subject", "hello\r\n   world  test");
        assert_eq!(result, "subject:hello world test\r\n");
    }

    #[test]
    fn relaxed_header_tab_handling() {
        let result = canonicalize_header_relaxed("Subject", "\thello\t\tworld\t");
        assert_eq!(result, "subject:hello world\r\n");
    }

    // -----------------------------------------------------------------------
    // Body canonicalization — Simple
    // -----------------------------------------------------------------------

    #[test]
    fn simple_body_removes_trailing_empty_lines() {
        let body = b"hello\r\n\r\n\r\n";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"hello\r\n");
    }

    #[test]
    fn simple_body_empty_becomes_crlf() {
        let result = canonicalize_body_simple(b"");
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn simple_body_preserves_content_trailing_crlf() {
        let body = b"hello\r\nworld\r\n";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"hello\r\nworld\r\n");
    }

    #[test]
    fn simple_body_multiple_trailing_empty_lines() {
        let body = b"test\r\n\r\n\r\n\r\n\r\n";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"test\r\n");
    }

    #[test]
    fn simple_body_only_empty_lines() {
        let body = b"\r\n\r\n\r\n";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"\r\n");
    }

    #[test]
    fn simple_body_bare_lf_normalized() {
        let body = b"hello\nworld\n";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"hello\r\nworld\r\n");
    }

    #[test]
    fn simple_body_no_trailing_crlf_gets_one() {
        let body = b"hello";
        let result = canonicalize_body_simple(body);
        assert_eq!(result, b"hello\r\n");
    }

    // -----------------------------------------------------------------------
    // Body canonicalization — Relaxed
    // -----------------------------------------------------------------------

    #[test]
    fn relaxed_body_removes_trailing_wsp_per_line() {
        let body = b"hello   \r\nworld\t\t\r\n";
        let result = canonicalize_body_relaxed(body);
        assert_eq!(result, b"hello\r\nworld\r\n");
    }

    #[test]
    fn relaxed_body_collapses_wsp() {
        let body = b"hello   world\r\n";
        let result = canonicalize_body_relaxed(body);
        assert_eq!(result, b"hello world\r\n");
    }

    #[test]
    fn relaxed_body_removes_trailing_empty_lines() {
        let body = b"hello\r\n\r\n\r\n";
        let result = canonicalize_body_relaxed(body);
        assert_eq!(result, b"hello\r\n");
    }

    #[test]
    fn relaxed_body_empty_stays_empty() {
        let result = canonicalize_body_relaxed(b"");
        assert!(result.is_empty(), "relaxed empty body must be empty, got {:?}", result);
    }

    #[test]
    fn relaxed_body_only_empty_lines_becomes_empty() {
        let body = b"\r\n\r\n\r\n";
        let result = canonicalize_body_relaxed(body);
        assert!(result.is_empty());
    }

    #[test]
    fn relaxed_body_bare_lf_normalized() {
        let body = b"hello\nworld\n";
        let result = canonicalize_body_relaxed(body);
        assert_eq!(result, b"hello\r\nworld\r\n");
    }

    #[test]
    fn relaxed_body_tabs_collapsed() {
        let body = b"\thello\t\tworld\t\r\n";
        let result = canonicalize_body_relaxed(body);
        assert_eq!(result, b" hello world\r\n");
    }

    #[test]
    fn relaxed_body_only_whitespace_lines() {
        let body = b"   \r\n\t\r\n";
        let result = canonicalize_body_relaxed(body);
        // After removing trailing WSP per line, both lines become empty.
        // Then trailing empty lines removed -> empty.
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Header selection
    // -----------------------------------------------------------------------

    #[test]
    fn select_basic_case_insensitive() {
        let headers = vec![
            ("From", "alice@example.com"),
            ("To", "bob@example.com"),
            ("Subject", "Hello"),
        ];
        let signed = vec!["from".into(), "to".into(), "subject".into()];
        let selected = select_headers(&headers, &signed);
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].0, "From");
        assert_eq!(selected[1].0, "To");
        assert_eq!(selected[2].0, "Subject");
    }

    #[test]
    fn select_bottom_up_last_first() {
        let headers = vec![
            ("Received", "first"),
            ("Received", "second"),
            ("Received", "third"),
        ];
        let signed = vec!["received".into()];
        let selected = select_headers(&headers, &signed);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1, "third");
    }

    #[test]
    fn select_multiple_bottom_up_ordering() {
        let headers = vec![
            ("Received", "first"),
            ("Received", "second"),
            ("Received", "third"),
        ];
        let signed = vec!["received".into(), "received".into(), "received".into()];
        let selected = select_headers(&headers, &signed);
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].1, "third");
        assert_eq!(selected[1].1, "second");
        assert_eq!(selected[2].1, "first");
    }

    #[test]
    fn select_oversigning_produces_sentinel() {
        let headers = vec![("From", "alice@example.com")];
        let signed = vec!["from".into(), "from".into()];
        let selected = select_headers(&headers, &signed);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0, "From");
        assert_eq!(selected[0].1, "alice@example.com");
        // Second entry is over-signed sentinel.
        assert_eq!(selected[1].0, "");
        assert_eq!(selected[1].1, "");
    }

    #[test]
    fn select_missing_header_oversigned() {
        let headers = vec![("From", "alice@example.com")];
        let signed = vec!["from".into(), "x-nonexistent".into()];
        let selected = select_headers(&headers, &signed);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0, "From");
        assert_eq!(selected[1].0, "");
        assert_eq!(selected[1].1, "");
    }

    #[test]
    fn select_mixed_present_and_oversigned() {
        let headers = vec![
            ("From", "alice@example.com"),
            ("To", "bob@example.com"),
            ("Subject", "Hi"),
        ];
        let signed = vec![
            "from".into(),
            "to".into(),
            "from".into(), // over-signed
            "subject".into(),
        ];
        let selected = select_headers(&headers, &signed);
        assert_eq!(selected.len(), 4);
        assert_eq!(selected[0].0, "From");
        assert_eq!(selected[1].0, "To");
        assert_eq!(selected[2], ("", "")); // over-signed sentinel
        assert_eq!(selected[3].0, "Subject");
    }

    // -----------------------------------------------------------------------
    // b= tag stripping
    // -----------------------------------------------------------------------

    #[test]
    fn strip_b_preserves_b_equals() {
        let input = "v=1; b=abc123; bh=xyz";
        let result = strip_b_tag_value(input);
        assert!(result.contains("b="), "must keep b=");
        assert!(result.contains("bh=xyz"), "must keep bh=xyz");
        assert!(!result.contains("abc123"), "must strip b= value");
    }

    #[test]
    fn strip_b_does_not_affect_bh() {
        let input = "v=1; bh=somehash; b=sigvalue; a=rsa-sha256";
        let result = strip_b_tag_value(input);
        assert!(result.contains("bh=somehash"), "bh must be untouched, got: {result}");
        assert!(!result.contains("sigvalue"), "b= value must be stripped");
    }

    #[test]
    fn strip_b_at_start() {
        let input = "b=sigdata; v=1; bh=hash";
        let result = strip_b_tag_value(input);
        assert_eq!(&result[..2], "b=");
        assert!(result.contains("bh=hash"));
        assert!(!result.contains("sigdata"));
    }

    #[test]
    fn strip_b_at_end() {
        let input = "v=1; bh=hash; b=sigdata";
        let result = strip_b_tag_value(input);
        assert!(result.ends_with("b="));
        assert!(result.contains("bh=hash"));
    }

    #[test]
    fn strip_b_with_whitespace_in_value() {
        let input = "v=1; b= abc def\r\n ghi ; bh=hash";
        let result = strip_b_tag_value(input);
        assert!(result.contains("b="), "must keep b=");
        assert!(result.contains("bh=hash"), "must keep bh");
        assert!(!result.contains("abc"), "must strip b= value content");
    }

    #[test]
    fn strip_b_no_b_tag_returns_unchanged() {
        let input = "v=1; bh=hash; a=rsa-sha256";
        let result = strip_b_tag_value(input);
        assert_eq!(result, input);
    }

    // -----------------------------------------------------------------------
    // Body truncation
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_no_limit_full_body() {
        let body = b"hello world";
        assert_eq!(truncate_body(body, None), body.as_slice());
    }

    #[test]
    fn truncate_shorter_than_body() {
        let body = b"hello world";
        assert_eq!(truncate_body(body, Some(5)), b"hello");
    }

    #[test]
    fn truncate_longer_than_body() {
        let body = b"hi";
        assert_eq!(truncate_body(body, Some(100)), b"hi");
    }

    #[test]
    fn truncate_zero_empty() {
        let body = b"hello";
        assert_eq!(truncate_body(body, Some(0)), b"");
    }

    // -----------------------------------------------------------------------
    // Line-ending normalization (internal, tested via body canon)
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_bare_cr() {
        let body = b"hello\rworld\r";
        let normalized = normalize_line_endings(body);
        assert_eq!(normalized, b"hello\r\nworld\r\n");
    }

    #[test]
    fn normalize_mixed_endings() {
        let body = b"a\nb\r\nc\rd";
        let normalized = normalize_line_endings(body);
        assert_eq!(normalized, b"a\r\nb\r\nc\r\nd");
    }
}
