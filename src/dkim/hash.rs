use super::canon::canonicalize_header;
use super::signature::{Algorithm, CanonicalizationMethod};
use ring::digest;

/// Compute body hash
pub fn compute_body_hash(canonicalized_body: &[u8], algorithm: Algorithm) -> Vec<u8> {
    let alg = match algorithm {
        Algorithm::RsaSha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => &digest::SHA256,
    };

    digest::digest(alg, canonicalized_body).as_ref().to_vec()
}

/// Compute header hash data (the data to be signed/verified)
pub fn compute_header_hash_data(
    headers: &str,
    signed_headers: &[String],
    sig_header_name: &str,
    sig_header_value: &str,
    method: CanonicalizationMethod,
) -> Vec<u8> {
    let mut data = Vec::new();

    // Parse headers into list
    let header_list = parse_headers(headers);

    // Track which occurrences of each header we've used
    let mut used_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Process headers in order from h= (bottom-up selection)
    for header_name in signed_headers {
        let header_lower = header_name.to_lowercase();

        // Find matching headers (from bottom to top)
        let matching: Vec<_> = header_list
            .iter()
            .filter(|(name, _)| name.to_lowercase() == header_lower)
            .collect();

        let used = used_counts.entry(header_lower.clone()).or_insert(0);
        let index_from_end = *used;
        *used += 1;

        // Select from bottom-up: index 0 = last, index 1 = second-to-last, etc.
        if index_from_end < matching.len() {
            let (name, value) = matching[matching.len() - 1 - index_from_end];
            let canonicalized = canonicalize_header(name, value, method);
            data.extend_from_slice(canonicalized.as_bytes());
            data.extend_from_slice(b"\r\n");
        }
        // Over-signed headers (not present) contribute nothing
    }

    // Add DKIM-Signature header with b= value removed
    let sig_with_empty_b = remove_b_value(sig_header_value);
    let canonicalized_sig = canonicalize_header(sig_header_name, &sig_with_empty_b, method);

    // Don't add trailing CRLF for the signature header
    data.extend_from_slice(canonicalized_sig.as_bytes());

    data
}

/// Parse headers into (name, value) pairs
fn parse_headers(headers: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut current_name = String::new();
    let mut current_value = String::new();

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line
            if !current_name.is_empty() {
                current_value.push('\n');
                current_value.push_str(line);
            }
        } else {
            // Save previous header
            if !current_name.is_empty() {
                result.push((current_name.clone(), current_value.clone()));
            }

            // Parse new header
            if let Some(colon_pos) = line.find(':') {
                current_name = line[..colon_pos].to_string();
                current_value = line[colon_pos + 1..].to_string();
            } else {
                current_name.clear();
                current_value.clear();
            }
        }
    }

    // Don't forget the last header
    if !current_name.is_empty() {
        result.push((current_name, current_value));
    }

    result
}

/// Remove the b= value from DKIM-Signature header for verification
/// Must be careful not to affect bh= tag
fn remove_b_value(sig_value: &str) -> String {
    // Find b= tag and remove its value
    // Be careful: must match b= but not bh=

    let mut result = String::new();
    let mut chars = sig_value.chars().peekable();
    let mut in_b_value = false;

    while let Some(c) = chars.next() {
        if in_b_value {
            // Skip until we hit ; or end
            if c == ';' {
                in_b_value = false;
                result.push(c);
            }
            // else skip this character
        } else {
            result.push(c);

            // Check if we just wrote 'b='
            if result.ends_with("b=") || result.ends_with("b =") {
                // Check it's not "bh="
                let check_len = if result.ends_with("b =") { 4 } else { 3 };
                if result.len() < check_len
                    || !result[result.len() - check_len..].starts_with("bh")
                {
                    in_b_value = true;
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
    fn test_remove_b_value() {
        let input = "v=1; b=abc123; bh=xyz=";
        let result = remove_b_value(input);
        assert_eq!(result, "v=1; b=; bh=xyz=");
    }

    #[test]
    fn test_remove_b_value_at_end() {
        let input = "v=1; bh=xyz=; b=abc123";
        let result = remove_b_value(input);
        assert_eq!(result, "v=1; bh=xyz=; b=");
    }

    #[test]
    fn test_parse_headers() {
        let headers = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test";
        let parsed = parse_headers(headers);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, "From");
        assert_eq!(parsed[1].0, "To");
        assert_eq!(parsed[2].0, "Subject");
    }

    #[test]
    fn test_parse_folded_header() {
        let headers = "Subject: This is a\r\n very long subject";
        let parsed = parse_headers(headers);
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].1.contains("very long"));
    }
}
