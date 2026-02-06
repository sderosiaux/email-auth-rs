use super::signature::{CanonicalizationType, DkimSignature};

pub fn canonicalize_body(body: &str, canon_type: CanonicalizationType) -> String {
    match canon_type {
        CanonicalizationType::Simple => simple_body(body),
        CanonicalizationType::Relaxed => relaxed_body(body),
    }
}

pub fn canonicalize_header(name: &str, value: &str, canon_type: CanonicalizationType) -> String {
    match canon_type {
        CanonicalizationType::Simple => format!("{}: {}", name, value),
        CanonicalizationType::Relaxed => relaxed_header(name, value),
    }
}

pub fn canonicalize_headers_for_signing(headers: &str, sig: &DkimSignature) -> String {
    let mut result = Vec::new();
    let header_list = collect_headers(headers);

    // Track how many times each header has been used (for bottom-up selection)
    let mut header_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for signed_name in &sig.signed_headers {
        let lower_name = signed_name.to_lowercase();

        // Find headers matching this name
        let matching: Vec<_> = header_list
            .iter()
            .filter(|(name, _)| name.to_lowercase() == lower_name)
            .collect();

        let count = header_counts.entry(lower_name.clone()).or_insert(0);
        let index_from_bottom = matching.len().saturating_sub(*count + 1);

        if let Some((name, value)) = matching.get(index_from_bottom) {
            let canon = canonicalize_header(name, value, sig.canonicalization.header);
            result.push(canon);
            *count += 1;
        }
    }

    // Add the DKIM-Signature header without the b= value
    let dkim_header = remove_signature_value(&sig.raw_header);
    let (name, value) = split_header(&dkim_header);
    let canon_dkim = canonicalize_header(&name, &value, sig.canonicalization.header);
    result.push(canon_dkim);

    result.join("\r\n")
}

fn simple_body(body: &str) -> String {
    let mut result = body.to_string();

    // Ensure CRLF line endings
    result = result.replace("\r\n", "\n").replace('\n', "\r\n");

    // Remove trailing empty lines, keeping one CRLF
    while result.ends_with("\r\n\r\n") {
        result.truncate(result.len() - 2);
    }

    // If body is completely empty, use single CRLF
    if result.is_empty() {
        result = "\r\n".to_string();
    } else if !result.ends_with("\r\n") {
        result.push_str("\r\n");
    }

    result
}

fn relaxed_body(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut result_lines = Vec::new();

    for line in lines {
        // Replace sequences of whitespace with single space
        let mut processed = String::new();
        let mut prev_was_space = false;

        for c in line.chars() {
            if c == ' ' || c == '\t' {
                if !prev_was_space {
                    processed.push(' ');
                    prev_was_space = true;
                }
            } else {
                processed.push(c);
                prev_was_space = false;
            }
        }

        // Remove trailing whitespace
        let trimmed = processed.trim_end();
        result_lines.push(trimmed.to_string());
    }

    // Remove trailing empty lines
    while result_lines.last().is_some_and(|s| s.is_empty()) {
        result_lines.pop();
    }

    if result_lines.is_empty() {
        return "\r\n".to_string();
    }

    let mut result = result_lines.join("\r\n");
    result.push_str("\r\n");
    result
}

fn relaxed_header(name: &str, value: &str) -> String {
    let lower_name = name.to_lowercase();

    // Unfold and collapse whitespace
    let unfolded = value.replace("\r\n", "").replace('\n', "");
    let mut collapsed = String::new();
    let mut prev_was_space = false;

    for c in unfolded.chars() {
        if c == ' ' || c == '\t' {
            if !prev_was_space && !collapsed.is_empty() {
                collapsed.push(' ');
                prev_was_space = true;
            }
        } else {
            collapsed.push(c);
            prev_was_space = false;
        }
    }

    // Remove leading/trailing whitespace from value
    let collapsed = collapsed.trim();

    // RFC 6376: no space after the colon in relaxed mode
    format!("{}:{}", lower_name, collapsed)
}

fn collect_headers(headers: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut current_name = String::new();
    let mut current_value = String::new();

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation
            current_value.push('\n');
            current_value.push_str(line);
        } else if let Some(pos) = line.find(':') {
            // Save previous header
            if !current_name.is_empty() {
                result.push((current_name, current_value));
            }
            current_name = line[..pos].to_string();
            current_value = line[pos + 1..].to_string();
        }
    }

    // Don't forget last header
    if !current_name.is_empty() {
        result.push((current_name, current_value));
    }

    result
}

fn split_header(header: &str) -> (String, String) {
    if let Some(pos) = header.find(':') {
        (header[..pos].to_string(), header[pos + 1..].to_string())
    } else {
        (header.to_string(), String::new())
    }
}

fn remove_signature_value(header: &str) -> String {
    // Find the b= tag and remove its value, keeping the tag
    let mut result = String::new();
    let mut chars = header.chars().peekable();

    while let Some(c) = chars.next() {
        result.push(c);

        // Check for 'b=' that's not 'bh='
        if c == 'b' {
            // Look ahead to see if this is 'b=' but not 'bh='
            if let Some(&next) = chars.peek() {
                if next == '=' {
                    // Consume the '='
                    chars.next();
                    result.push('=');

                    // Skip until we hit ';' or end
                    for bc in chars.by_ref() {
                        if bc == ';' {
                            result.push(';');
                            break;
                        }
                    }
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_body_empty() {
        assert_eq!(simple_body(""), "\r\n");
    }

    #[test]
    fn test_simple_body_trailing_newlines() {
        assert_eq!(simple_body("hello\r\n\r\n\r\n"), "hello\r\n");
    }

    #[test]
    fn test_relaxed_body_whitespace() {
        assert_eq!(relaxed_body("hello  world\t\t!"), "hello world !\r\n");
    }

    #[test]
    fn test_relaxed_header() {
        // RFC 6376: WSP in value collapsed to single space, leading/trailing trimmed
        assert_eq!(
            relaxed_header("Subject", "  Hello   World  "),
            "subject:Hello World"
        );
    }

    #[test]
    fn test_remove_signature_value() {
        let header = "DKIM-Signature: v=1; bh=abc; b=signature";
        let result = remove_signature_value(header);
        assert!(result.contains("b="));
        assert!(!result.contains("signature"));
        assert!(result.contains("bh=abc"));
    }
}
