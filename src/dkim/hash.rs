use ring::digest;
use super::{Algorithm, CanonicalizationMethod, canon};

/// Compute the body hash for DKIM
pub fn compute_body_hash(canonicalized_body: &[u8], algorithm: &Algorithm) -> Vec<u8> {
    match algorithm {
        Algorithm::RsaSha1 => {
            let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, canonicalized_body);
            digest.as_ref().to_vec()
        }
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            let digest = digest::digest(&digest::SHA256, canonicalized_body);
            digest.as_ref().to_vec()
        }
    }
}

/// Compute the header hash data (the data to be signed/verified)
pub fn compute_header_hash_data(
    headers: &str,
    signed_header_names: &[String],
    dkim_sig_header: &str,
    method: CanonicalizationMethod,
) -> Vec<u8> {
    let mut result = String::new();

    // Build a map of header name -> list of values (in order of appearance, bottom-up for selection)
    let header_map = parse_headers(headers);

    // Track how many times each header has been used
    let mut header_usage: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for header_name in signed_header_names {
        let lower_name = header_name.to_lowercase();
        let usage_count = *header_usage.get(&lower_name).unwrap_or(&0);

        if let Some(values) = header_map.get(&lower_name) {
            // Select from bottom-up: if we've used 0 times, take the last one
            // if we've used 1 time, take the second-to-last, etc.
            let index = values.len().saturating_sub(usage_count + 1);
            if index < values.len() {
                let (name, value) = &values[index];
                let canonicalized = canon::canonicalize_header(name, value, method);
                result.push_str(&canonicalized);
                result.push_str("\r\n");
            }
        }
        // If header not found, it contributes nothing (over-signing case)

        *header_usage.entry(lower_name).or_insert(0) += 1;
    }

    // Append the DKIM-Signature header with b= value removed
    let dkim_sig_cleaned = remove_b_value(dkim_sig_header);
    let (sig_name, sig_value) = split_header(&dkim_sig_cleaned);
    let canonicalized_sig = canon::canonicalize_header(&sig_name, &sig_value, method);
    result.push_str(&canonicalized_sig);
    // Note: NO trailing CRLF for the signature header

    result.into_bytes()
}

fn parse_headers(headers: &str) -> std::collections::HashMap<String, Vec<(String, String)>> {
    let mut result: std::collections::HashMap<String, Vec<(String, String)>> = std::collections::HashMap::new();

    let lines: Vec<&str> = headers.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Skip empty lines
        if line.is_empty() {
            i += 1;
            continue;
        }

        // Skip continuation lines that aren't part of a header
        if line.starts_with(' ') || line.starts_with('\t') {
            i += 1;
            continue;
        }

        // Find the colon
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].to_string();
            let mut value = line[colon_pos + 1..].to_string();

            // Handle folded headers (continuation lines)
            while i + 1 < lines.len() && (lines[i + 1].starts_with(' ') || lines[i + 1].starts_with('\t')) {
                i += 1;
                value.push_str("\r\n");
                value.push_str(lines[i]);
            }

            let lower_name = name.to_lowercase();
            result.entry(lower_name).or_default().push((name, value));
        }

        i += 1;
    }

    result
}

fn split_header(header: &str) -> (String, String) {
    if let Some(colon_pos) = header.find(':') {
        (header[..colon_pos].to_string(), header[colon_pos + 1..].to_string())
    } else {
        (header.to_string(), String::new())
    }
}

/// Remove the b= tag value from a DKIM-Signature header
/// This is tricky because we must not affect the bh= tag
fn remove_b_value(header: &str) -> String {
    let mut result = String::new();
    let mut chars = header.chars().peekable();
    let mut in_b_value = false;
    let mut last_was_semicolon_or_start = true;

    while let Some(c) = chars.next() {
        if last_was_semicolon_or_start && c == 'b' {
            // Check if this is "b=" (not "bh=")
            let next = chars.peek();
            if next == Some(&'=') {
                // This is "b="
                result.push(c);
                result.push(chars.next().unwrap()); // push '='
                in_b_value = true;
                last_was_semicolon_or_start = false;
                continue;
            }
        }

        if in_b_value {
            if c == ';' {
                in_b_value = false;
                result.push(c);
                last_was_semicolon_or_start = true;
            }
            // Skip the value characters
        } else {
            result.push(c);
            last_was_semicolon_or_start = c == ';' || c.is_whitespace();
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_b_value() {
        let header = "DKIM-Signature: v=1; a=rsa-sha256; bh=abc123; b=signature123; d=example.com";
        let result = remove_b_value(header);
        assert!(result.contains("b=;"));
        assert!(result.contains("bh=abc123"));
    }

    #[test]
    fn test_remove_b_value_at_end() {
        let header = "DKIM-Signature: v=1; bh=abc; b=sig";
        let result = remove_b_value(header);
        assert!(result.contains("b="));
        assert!(result.contains("bh=abc"));
        assert!(!result.contains("sig"));
    }

    #[test]
    fn test_parse_headers() {
        let headers = "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test";
        let map = parse_headers(headers);
        assert!(map.contains_key("from"));
        assert!(map.contains_key("to"));
        assert!(map.contains_key("subject"));
    }

    #[test]
    fn test_header_hash_data() {
        let headers = "From: test@example.com\r\nTo: recipient@example.com";
        let sig_header = "DKIM-Signature: v=1; b=sig123";
        let signed = vec!["from".to_string()];

        let data = compute_header_hash_data(headers, &signed, sig_header, CanonicalizationMethod::Relaxed);
        let data_str = String::from_utf8_lossy(&data);
        assert!(data_str.contains("from:"));
        assert!(data_str.contains("dkim-signature:"));
    }
}
