use super::types::CanonicalizationMethod;

// ── Line ending normalization ────────────────────────────────────────

/// Normalize bare LF to CRLF. Leaves existing CRLF intact.
/// Must be applied BEFORE canonicalization (spec §3.3).
pub fn normalize_line_endings(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\r' && i + 1 < input.len() && input[i + 1] == b'\n' {
            out.push(b'\r');
            out.push(b'\n');
            i += 2;
        } else if input[i] == b'\n' {
            // Bare LF → CRLF
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

// ── Header canonicalization ──────────────────────────────────────────

/// Canonicalize a single header for DKIM.
/// `name` is the header field name, `value` is everything after the colon.
pub fn canonicalize_header(
    method: CanonicalizationMethod,
    name: &str,
    value: &str,
) -> String {
    match method {
        CanonicalizationMethod::Simple => {
            // Simple: no changes, output as name:value (exactly as-is)
            format!("{}:{}", name, value)
        }
        CanonicalizationMethod::Relaxed => {
            // Relaxed: lowercase name, unfold, collapse WSP, trim trailing WSP, no space around colon
            let lower_name = name.to_ascii_lowercase();

            // Unfold: remove CRLF before WSP
            let mut unfolded = String::with_capacity(value.len());
            let bytes = value.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if i + 1 < bytes.len() && bytes[i] == b'\r' && bytes[i + 1] == b'\n' {
                    if i + 2 < bytes.len() && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t') {
                        i += 2; // Skip CRLF, keep the WSP
                        continue;
                    }
                }
                unfolded.push(bytes[i] as char);
                i += 1;
            }

            // Collapse sequential WSP to single SP
            let mut collapsed = String::with_capacity(unfolded.len());
            let mut in_wsp = false;
            for ch in unfolded.chars() {
                if ch == ' ' || ch == '\t' {
                    if !in_wsp {
                        collapsed.push(' ');
                        in_wsp = true;
                    }
                } else {
                    collapsed.push(ch);
                    in_wsp = false;
                }
            }

            // Remove trailing WSP
            let trimmed = collapsed.trim_end_matches(|c: char| c == ' ' || c == '\t');

            // Remove leading WSP (space after colon is part of value, collapse handles it)
            let trimmed = trimmed.trim_start_matches(|c: char| c == ' ' || c == '\t');

            format!("{}:{}", lower_name, trimmed)
        }
    }
}

// ── Body canonicalization ────────────────────────────────────────────

/// Canonicalize message body for DKIM.
/// Input should already have line endings normalized (bare LF → CRLF).
pub fn canonicalize_body(method: CanonicalizationMethod, body: &[u8]) -> Vec<u8> {
    match method {
        CanonicalizationMethod::Simple => canonicalize_body_simple(body),
        CanonicalizationMethod::Relaxed => canonicalize_body_relaxed(body),
    }
}

fn canonicalize_body_simple(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        // Empty body → single CRLF
        return b"\r\n".to_vec();
    }

    // Split into lines (preserving CRLF)
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < body.len() {
        if i + 1 < body.len() && body[i] == b'\r' && body[i + 1] == b'\n' {
            lines.push(&body[start..i]); // line content without CRLF
            start = i + 2;
            i += 2;
        } else {
            i += 1;
        }
    }
    // Remaining content after last CRLF (if any)
    if start < body.len() {
        lines.push(&body[start..]);
    }

    // Remove trailing empty lines
    while let Some(last) = lines.last() {
        if last.is_empty() {
            lines.pop();
        } else {
            break;
        }
    }

    if lines.is_empty() {
        // All lines were empty → single CRLF
        return b"\r\n".to_vec();
    }

    // Reconstruct with CRLF endings
    let mut out = Vec::new();
    for line in &lines {
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        // Relaxed empty → empty (NOT CRLF)
        return Vec::new();
    }

    // Split into lines
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < body.len() {
        if i + 1 < body.len() && body[i] == b'\r' && body[i + 1] == b'\n' {
            lines.push(&body[start..i]);
            start = i + 2;
            i += 2;
        } else {
            i += 1;
        }
    }
    if start < body.len() {
        lines.push(&body[start..]);
    }

    // Process each line: remove trailing WSP, collapse sequential WSP to single SP
    let mut processed: Vec<Vec<u8>> = Vec::new();
    for line in &lines {
        let mut out = Vec::new();
        let mut in_wsp = false;
        for &b in *line {
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
        // Remove trailing WSP
        while out.last() == Some(&b' ') {
            out.pop();
        }
        processed.push(out);
    }

    // Remove trailing empty lines
    while let Some(last) = processed.last() {
        if last.is_empty() {
            processed.pop();
        } else {
            break;
        }
    }

    if processed.is_empty() {
        // All lines were empty after processing → empty
        return Vec::new();
    }

    // Reconstruct with CRLF
    let mut out = Vec::new();
    for line in &processed {
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Apply body length limit (l= tag truncation).
pub fn apply_body_length_limit(body: &[u8], limit: Option<u64>) -> &[u8] {
    match limit {
        Some(l) => {
            let l = l as usize;
            if l < body.len() {
                &body[..l]
            } else {
                body
            }
        }
        None => body,
    }
}

// ── Header selection ─────────────────────────────────────────────────

/// Select headers from message for DKIM hash input.
/// `signed_headers`: the h= tag list (may contain duplicates for over-signing).
/// `message_headers`: the message headers as (name, value) pairs, in order (first = top of message).
/// Returns canonicalized header strings ready for hash input (each ending with \r\n).
/// The last entry (DKIM-Signature itself) should be appended separately by the caller.
pub fn select_headers(
    method: CanonicalizationMethod,
    signed_headers: &[String],
    message_headers: &[(&str, &str)],
) -> Vec<String> {
    // Track how many times each header name has been consumed (bottom-up)
    // For each header name, we maintain a counter of consumed instances.
    // consumed[name] = N means the last N occurrences have been consumed.
    let mut consumed: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    let mut result = Vec::new();

    for h_name in signed_headers {
        let lower = h_name.to_ascii_lowercase();
        let count = consumed.entry(lower.clone()).or_insert(0);

        // Collect all occurrences of this header (case-insensitive), in message order
        let occurrences: Vec<usize> = message_headers
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| name.to_ascii_lowercase() == lower)
            .map(|(i, _)| i)
            .collect();

        let total = occurrences.len();
        if *count < total {
            // Bottom-up: select from end. If consumed=0, take last; if consumed=1, take second-to-last, etc.
            let idx = occurrences[total - 1 - *count];
            let (name, value) = message_headers[idx];
            let canon = canonicalize_header(method, name, value);
            result.push(format!("{}\r\n", canon));
            *count += 1;
        } else {
            // Over-signed: no more occurrences → empty header
            result.push(format!("{}:\r\n", lower));
        }
    }

    result
}

// ── b= tag stripping ────────────────────────────────────────────────

/// Strip the value of the b= tag from a DKIM-Signature header value.
/// Keeps `b=` with empty value. Does NOT affect bh= tag.
/// Uses structural parsing to avoid matching bh=.
pub fn strip_b_tag_value(header_value: &str) -> String {
    // Find b= that is NOT preceded by 'h' (to avoid matching bh=)
    // Strategy: parse tag=value pairs structurally
    let mut result = String::with_capacity(header_value.len());
    let bytes = header_value.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Check if we're at a 'b' that could be the b= tag
        if bytes[i] == b'b' && i + 1 < bytes.len() {
            // Check this is NOT bh= (i.e., next char after 'b' should be '=' possibly with whitespace)
            // Also check that previous char (if any) is not 'b' (i.e., this isn't part of another word)
            let is_preceded_by_alpha = i > 0 && bytes[i - 1].is_ascii_alphabetic();

            if !is_preceded_by_alpha {
                // Skip optional whitespace between 'b' and '='
                let mut j = i + 1;
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'=' {
                    // Check it's not bh= — the char after 'b' (before whitespace) must not be 'h'
                    if bytes[i + 1] != b'h' {
                        // Found b= tag! Copy up through '='
                        result.push_str(&header_value[i..=j]);
                        // Skip the value (everything up to next ';' or end)
                        let mut k = j + 1;
                        while k < bytes.len() && bytes[k] != b';' {
                            k += 1;
                        }
                        i = k;
                        continue;
                    }
                }
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

    // ── CHK-338, CHK-339, CHK-340: Simple header canonicalization ────

    // CHK-472: Simple header unchanged
    #[test]
    fn simple_header_unchanged() {
        let canon =
            canonicalize_header(CanonicalizationMethod::Simple, "Subject", " Hello World");
        assert_eq!(canon, "Subject: Hello World");
    }

    // CHK-338: Simple no changes
    #[test]
    fn simple_header_preserves_case_and_whitespace() {
        let canon = canonicalize_header(
            CanonicalizationMethod::Simple,
            "X-Custom-Header",
            "  some  value  ",
        );
        assert_eq!(canon, "X-Custom-Header:  some  value  ");
    }

    // CHK-339: Simple output format
    #[test]
    fn simple_header_output_format() {
        let canon =
            canonicalize_header(CanonicalizationMethod::Simple, "From", " user@example.com");
        assert_eq!(canon, "From: user@example.com");
    }

    // CHK-340: Case-preserved
    #[test]
    fn simple_header_case_preserved() {
        let canon = canonicalize_header(CanonicalizationMethod::Simple, "X-MyHeader", " Value");
        assert!(canon.starts_with("X-MyHeader:"));
    }

    // ── CHK-341..CHK-346: Relaxed header canonicalization ────────────

    // CHK-473: Relaxed header
    #[test]
    fn relaxed_header_full() {
        let canon = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "Subject",
            "  Hello   World  ",
        );
        assert_eq!(canon, "subject:Hello World");
    }

    // CHK-341: Relaxed lowercase
    #[test]
    fn relaxed_header_lowercase_name() {
        let canon = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "X-Custom-HEADER",
            " value",
        );
        assert!(canon.starts_with("x-custom-header:"));
    }

    // CHK-342: Unfold headers
    #[test]
    fn relaxed_header_unfold() {
        let canon = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "Subject",
            " Hello\r\n World",
        );
        assert_eq!(canon, "subject:Hello World");
    }

    // CHK-343: Collapse whitespace
    #[test]
    fn relaxed_header_collapse_whitespace() {
        let canon = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "Subject",
            " Hello   \t  World",
        );
        assert_eq!(canon, "subject:Hello World");
    }

    // CHK-344: Remove trailing WSP
    #[test]
    fn relaxed_header_remove_trailing_wsp() {
        let canon = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "Subject",
            " Hello World   ",
        );
        assert_eq!(canon, "subject:Hello World");
    }

    // CHK-345: No space around colon
    #[test]
    fn relaxed_header_no_space_around_colon() {
        let canon =
            canonicalize_header(CanonicalizationMethod::Relaxed, "From", "  user@test.com ");
        assert_eq!(canon, "from:user@test.com");
    }

    // CHK-346: Relaxed output format
    #[test]
    fn relaxed_header_output_format() {
        let canon = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "Content-Type",
            " text/plain; charset=utf-8",
        );
        assert_eq!(canon, "content-type:text/plain; charset=utf-8");
    }

    // ── CHK-347..CHK-349: Simple body canonicalization ───────────────

    // CHK-474: Simple body
    #[test]
    fn simple_body_removes_trailing_blank_lines() {
        let body = b"Hello World\r\n\r\n\r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Simple, body);
        assert_eq!(canon, b"Hello World\r\n");
    }

    // CHK-347: Simple trailing blank lines
    #[test]
    fn simple_body_trailing_blank_lines() {
        let body = b"line1\r\nline2\r\n\r\n\r\n\r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Simple, body);
        assert_eq!(canon, b"line1\r\nline2\r\n");
    }

    // CHK-348: Simple empty → CRLF
    #[test]
    fn simple_body_empty_to_crlf() {
        let canon = canonicalize_body(CanonicalizationMethod::Simple, b"");
        assert_eq!(canon, b"\r\n");
    }

    // CHK-349: Simple body ends with CRLF
    #[test]
    fn simple_body_ends_with_crlf() {
        let body = b"Hello World";
        let canon = canonicalize_body(CanonicalizationMethod::Simple, body);
        assert!(canon.ends_with(b"\r\n"));
    }

    #[test]
    fn simple_body_all_empty_lines_to_crlf() {
        let body = b"\r\n\r\n\r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Simple, body);
        assert_eq!(canon, b"\r\n");
    }

    // ── CHK-350..CHK-353: Relaxed body canonicalization ──────────────

    // CHK-475: Relaxed body empty
    #[test]
    fn relaxed_body_empty_to_empty() {
        let canon = canonicalize_body(CanonicalizationMethod::Relaxed, b"");
        assert_eq!(canon, b"");
    }

    // CHK-350: Relaxed trailing WSP
    #[test]
    fn relaxed_body_remove_trailing_wsp() {
        let body = b"Hello World   \r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Relaxed, body);
        assert_eq!(canon, b"Hello World\r\n");
    }

    // CHK-351: Relaxed collapse WSP
    #[test]
    fn relaxed_body_collapse_wsp() {
        let body = b"Hello   \t  World\r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Relaxed, body);
        assert_eq!(canon, b"Hello World\r\n");
    }

    // CHK-352: Relaxed trailing blank lines
    #[test]
    fn relaxed_body_trailing_blank_lines() {
        let body = b"Hello\r\n\r\n\r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Relaxed, body);
        assert_eq!(canon, b"Hello\r\n");
    }

    // CHK-353: Relaxed empty body → empty
    #[test]
    fn relaxed_body_only_blank_lines_to_empty() {
        let body = b"\r\n\r\n\r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Relaxed, body);
        assert_eq!(canon, b"");
    }

    #[test]
    fn relaxed_body_only_whitespace_lines_to_empty() {
        let body = b"   \r\n  \t  \r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Relaxed, body);
        assert_eq!(canon, b"");
    }

    // ── CHK-354..CHK-355: Line ending normalization ──────────────────

    // CHK-477: Bare LF → CRLF
    #[test]
    fn normalize_bare_lf_to_crlf() {
        let input = b"Hello\nWorld\n";
        let normalized = normalize_line_endings(input);
        assert_eq!(normalized, b"Hello\r\nWorld\r\n");
    }

    // CHK-354: Bare LF → CRLF
    #[test]
    fn normalize_preserves_existing_crlf() {
        let input = b"Hello\r\nWorld\r\n";
        let normalized = normalize_line_endings(input);
        assert_eq!(normalized, b"Hello\r\nWorld\r\n");
    }

    // CHK-355: Mixed line endings
    #[test]
    fn normalize_mixed_line_endings() {
        let input = b"line1\r\nline2\nline3\r\nline4\n";
        let normalized = normalize_line_endings(input);
        assert_eq!(normalized, b"line1\r\nline2\r\nline3\r\nline4\r\n");
    }

    // CHK-526: Bare LF normalization complete
    #[test]
    fn normalize_no_line_endings() {
        let input = b"Hello World";
        let normalized = normalize_line_endings(input);
        assert_eq!(normalized, b"Hello World");
    }

    // ── CHK-356..CHK-357: Body length limit ──────────────────────────

    // CHK-476: Body length limit
    #[test]
    fn body_length_limit_truncates() {
        let body = b"Hello World\r\n";
        let limited = apply_body_length_limit(body, Some(5));
        assert_eq!(limited, b"Hello");
    }

    // CHK-356: l= truncation
    #[test]
    fn body_length_limit_larger_than_body() {
        let body = b"Hello\r\n";
        let limited = apply_body_length_limit(body, Some(1000));
        assert_eq!(limited, body.as_slice());
    }

    #[test]
    fn body_length_limit_none() {
        let body = b"Hello World\r\n";
        let limited = apply_body_length_limit(body, None);
        assert_eq!(limited, body.as_slice());
    }

    #[test]
    fn body_length_limit_zero() {
        let body = b"Hello World\r\n";
        let limited = apply_body_length_limit(body, Some(0));
        assert_eq!(limited, b"");
    }

    // ── CHK-358..CHK-362: Header selection ───────────────────────────

    // CHK-478: Header selection bottom-up
    #[test]
    fn header_selection_bottom_up() {
        let headers = vec![
            ("From", " first@example.com"),
            ("To", " dest@example.com"),
            ("From", " second@example.com"),
        ];
        let signed = vec!["from".to_string()];
        let selected = select_headers(CanonicalizationMethod::Simple, &signed, &headers);
        assert_eq!(selected.len(), 1);
        // Bottom-up: selects last (second) From
        assert_eq!(selected[0], "From: second@example.com\r\n");
    }

    // CHK-358: Case-insensitive
    #[test]
    fn header_selection_case_insensitive() {
        let headers = vec![("FROM", " user@example.com")];
        let signed = vec!["from".to_string()];
        let selected = select_headers(CanonicalizationMethod::Simple, &signed, &headers);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].starts_with("FROM:"));
    }

    // CHK-359: Bottom-up with multiple same-name
    #[test]
    fn header_selection_multiple_same_name_bottom_up() {
        let headers = vec![
            ("Received", " first"),
            ("Received", " second"),
            ("Received", " third"),
        ];
        let signed = vec!["received".to_string(), "received".to_string()];
        let selected = select_headers(CanonicalizationMethod::Simple, &signed, &headers);
        assert_eq!(selected.len(), 2);
        // First h= "received" takes last (third), second takes second
        assert_eq!(selected[0], "Received: third\r\n");
        assert_eq!(selected[1], "Received: second\r\n");
    }

    // CHK-360: Track consumed
    #[test]
    fn header_selection_tracks_consumed() {
        let headers = vec![
            ("To", " a@example.com"),
            ("To", " b@example.com"),
        ];
        let signed = vec!["to".to_string(), "to".to_string()];
        let selected = select_headers(CanonicalizationMethod::Simple, &signed, &headers);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], "To: b@example.com\r\n"); // last
        assert_eq!(selected[1], "To: a@example.com\r\n"); // second-to-last
    }

    // CHK-479: Over-signed empty
    #[test]
    fn header_selection_over_signed_empty() {
        let headers = vec![("From", " user@example.com")];
        let signed = vec!["from".to_string(), "from".to_string()];
        let selected = select_headers(CanonicalizationMethod::Simple, &signed, &headers);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], "From: user@example.com\r\n");
        assert_eq!(selected[1], "from:\r\n"); // over-signed: empty
    }

    // CHK-361: Over-signing contributes empty
    #[test]
    fn header_selection_over_signed_contributes_empty() {
        let headers = vec![("Subject", " test")];
        // h= lists subject 3 times, message has 1 → 1 real + 2 empty
        let signed = vec![
            "subject".to_string(),
            "subject".to_string(),
            "subject".to_string(),
        ];
        let selected = select_headers(CanonicalizationMethod::Simple, &signed, &headers);
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0], "Subject: test\r\n");
        assert_eq!(selected[1], "subject:\r\n");
        assert_eq!(selected[2], "subject:\r\n");
    }

    // CHK-362: Over-signed NOT skipped
    #[test]
    fn header_selection_over_signed_not_skipped() {
        let headers: Vec<(&str, &str)> = vec![];
        let signed = vec!["x-nonexistent".to_string()];
        let selected = select_headers(CanonicalizationMethod::Simple, &signed, &headers);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], "x-nonexistent:\r\n");
    }

    // CHK-525: Header selection complete
    #[test]
    fn header_selection_relaxed() {
        let headers = vec![("From", "  user@example.com  ")];
        let signed = vec!["from".to_string()];
        let selected = select_headers(CanonicalizationMethod::Relaxed, &signed, &headers);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], "from:user@example.com\r\n");
    }

    // ── CHK-363..CHK-366: b= tag stripping ──────────────────────────

    // CHK-480: b= stripping vs bh=
    #[test]
    fn strip_b_tag_preserves_bh() {
        let header = "v=1; a=rsa-sha256; b=abc123; bh=xyz789; d=example.com";
        let stripped = strip_b_tag_value(header);
        assert!(stripped.contains("bh=xyz789"));
        assert!(stripped.contains("b=;") || stripped.contains("b= ") || stripped.ends_with("b="));
        assert!(!stripped.contains("b=abc123"));
    }

    // CHK-363: Strip b= value
    #[test]
    fn strip_b_tag_value_basic() {
        let header = "v=1; b=SIGDATA; bh=HASH";
        let stripped = strip_b_tag_value(header);
        assert!(!stripped.contains("SIGDATA"));
        assert!(stripped.contains("b="));
        assert!(stripped.contains("bh=HASH"));
    }

    // CHK-364: Not bh=
    #[test]
    fn strip_b_tag_does_not_strip_bh() {
        let header = "bh=bodyhash; b=signature; d=example.com";
        let stripped = strip_b_tag_value(header);
        assert!(stripped.contains("bh=bodyhash"));
        assert!(!stripped.contains("b=signature"));
    }

    // CHK-365: Structural parsing
    #[test]
    fn strip_b_tag_structural_with_semicolons() {
        let header = "a=rsa-sha256; b=AAAA BBBB CCCC; bh=DDDD; d=test.com";
        let stripped = strip_b_tag_value(header);
        assert_eq!(
            stripped,
            "a=rsa-sha256; b=; bh=DDDD; d=test.com"
        );
    }

    // CHK-366: No trailing CRLF (handled by caller)
    #[test]
    fn strip_b_tag_at_end() {
        let header = "a=rsa-sha256; bh=hash; b=signature";
        let stripped = strip_b_tag_value(header);
        assert!(stripped.ends_with("b="));
        assert!(!stripped.contains("signature"));
    }

    // CHK-527: b= stripping complete
    #[test]
    fn strip_b_tag_multiline() {
        let header = "a=rsa-sha256;\r\n b=LONGBASE64DATA;\r\n bh=bodyhash";
        let stripped = strip_b_tag_value(header);
        assert!(!stripped.contains("LONGBASE64DATA"));
        assert!(stripped.contains("bh=bodyhash"));
    }

    // CHK-524: Both canon complete — integration
    #[test]
    fn both_canon_complete_integration() {
        // Simple header + simple body
        let header_s = canonicalize_header(CanonicalizationMethod::Simple, "From", " test@ex.com");
        assert_eq!(header_s, "From: test@ex.com");

        let body_s = canonicalize_body(CanonicalizationMethod::Simple, b"body\r\n\r\n");
        assert_eq!(body_s, b"body\r\n");

        // Relaxed header + relaxed body
        let header_r =
            canonicalize_header(CanonicalizationMethod::Relaxed, "From", "  test@ex.com  ");
        assert_eq!(header_r, "from:test@ex.com");

        let body_r = canonicalize_body(CanonicalizationMethod::Relaxed, b"body  \r\n\r\n");
        assert_eq!(body_r, b"body\r\n");
    }

    // CHK-357: l= security note (documented in types)
    #[test]
    fn body_length_limit_security_note() {
        // l= is a security concern — body truncation attacks
        // Verify it works but note it should be flagged
        let body = b"Safe content\r\nMalicious appendix\r\n";
        let limited = apply_body_length_limit(body, Some(14)); // Just "Safe content\r\n"
        assert_eq!(limited, b"Safe content\r\n");
    }

    // Additional edge cases

    #[test]
    fn simple_body_no_trailing_crlf_gets_one() {
        let body = b"Hello World";
        let canon = canonicalize_body(CanonicalizationMethod::Simple, body);
        assert_eq!(canon, b"Hello World\r\n");
    }

    #[test]
    fn relaxed_body_tabs_and_spaces() {
        let body = b"Hello\t\t  World\t  \r\n";
        let canon = canonicalize_body(CanonicalizationMethod::Relaxed, body);
        assert_eq!(canon, b"Hello World\r\n");
    }

    #[test]
    fn normalize_lone_cr() {
        // Lone CR (not followed by LF) should be preserved
        let input = b"Hello\rWorld";
        let normalized = normalize_line_endings(input);
        assert_eq!(normalized, b"Hello\rWorld");
    }

    #[test]
    fn relaxed_header_tab_handling() {
        let canon = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "Subject",
            "\tHello\t\tWorld\t",
        );
        assert_eq!(canon, "subject:Hello World");
    }

    #[test]
    fn strip_b_tag_b_first_in_header() {
        let header = "b=SIGVAL; a=rsa-sha256; bh=HASH";
        let stripped = strip_b_tag_value(header);
        assert_eq!(stripped, "b=; a=rsa-sha256; bh=HASH");
    }
}
