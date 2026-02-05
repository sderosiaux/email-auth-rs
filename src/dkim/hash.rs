use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA256};

use super::canon::canonicalize_header;
use super::signature::{Algorithm, CanonicalizationMethod};

/// Compute the body hash for DKIM
pub fn compute_body_hash(canonicalized_body: &[u8], algorithm: Algorithm) -> Vec<u8> {
    match algorithm {
        Algorithm::RsaSha1 => {
            let digest = ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, canonicalized_body);
            digest.as_ref().to_vec()
        }
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            let digest = ring::digest::digest(&SHA256, canonicalized_body);
            digest.as_ref().to_vec()
        }
    }
}

/// Compute the header hash input for DKIM verification
/// Returns the data to be signed/verified (not the hash itself)
pub fn compute_header_hash_input(
    headers: &str,
    signed_headers: &[String],
    dkim_sig_header: &str,
    canon_method: CanonicalizationMethod,
) -> Vec<u8> {
    let mut hash_input = Vec::new();

    // Build a list of headers from the message
    let header_list = parse_headers(headers);

    // Track which headers have been used (for bottom-up selection)
    let mut used_indices: Vec<bool> = vec![false; header_list.len()];

    // Process each header in h= order (bottom-up selection per RFC 6376)
    for header_name in signed_headers {
        let header_name_lower = header_name.to_lowercase();

        // Find the last unused header with this name
        let mut found_idx = None;
        for (i, (name, _)) in header_list.iter().enumerate().rev() {
            if name.to_lowercase() == header_name_lower && !used_indices[i] {
                found_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = found_idx {
            used_indices[idx] = true;
            let (name, value) = &header_list[idx];
            let canonicalized = canonicalize_header(name, value, canon_method);
            hash_input.extend_from_slice(canonicalized.as_bytes());
            hash_input.extend_from_slice(b"\r\n");
        }
        // If header not found, it contributes nothing (not an error per RFC)
    }

    // Add the DKIM-Signature header itself, with b= value removed
    let sig_without_b = remove_b_value(dkim_sig_header);
    let (sig_name, sig_value) = split_header(&sig_without_b);
    let canonicalized_sig = canonicalize_header(&sig_name, &sig_value, canon_method);
    hash_input.extend_from_slice(canonicalized_sig.as_bytes());
    // Note: No trailing CRLF for the DKIM-Signature header

    hash_input
}

fn parse_headers(headers: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut current_name = String::new();
    let mut current_value = String::new();
    let mut in_header = false;

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line
            if in_header {
                current_value.push_str("\r\n");
                current_value.push_str(line);
            }
        } else if let Some(colon_pos) = line.find(':') {
            // New header
            if in_header {
                result.push((current_name.clone(), current_value.clone()));
            }
            current_name = line[..colon_pos].to_string();
            current_value = line[colon_pos + 1..].to_string();
            in_header = true;
        } else if line.is_empty() {
            // End of headers
            if in_header {
                result.push((current_name.clone(), current_value.clone()));
            }
            break;
        }
    }

    // Don't forget the last header
    if in_header && !current_name.is_empty() {
        result.push((current_name, current_value));
    }

    result
}

fn split_header(header: &str) -> (String, String) {
    if let Some(colon_pos) = header.find(':') {
        let name = header[..colon_pos].to_string();
        let value = header[colon_pos + 1..].to_string();
        (name, value)
    } else {
        (header.to_string(), String::new())
    }
}

/// Remove the b= value from a DKIM-Signature header
/// This is tricky because we need to preserve b= tag but make its value empty
/// while not affecting bh= tag
fn remove_b_value(header: &str) -> String {
    let mut result = String::with_capacity(header.len());
    let mut i = 0;
    let chars: Vec<char> = header.chars().collect();

    while i < chars.len() {
        // Look for b= that's not part of bh=
        if i + 1 < chars.len() && chars[i] == 'b' && chars[i + 1] == '=' {
            // Check if this is bh= by looking back
            if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == 'h') {
                // This might be bh= or another tag ending in b=
                // Check specifically for 'h' before 'b'
                if chars[i - 1] == 'h' {
                    // This is bh=, copy it normally
                    result.push(chars[i]);
                    i += 1;
                    continue;
                }
            }

            // This is b= (not bh=), keep b= but skip the value
            result.push('b');
            result.push('=');
            i += 2;

            // Skip the base64 value (until ; or end)
            while i < chars.len() && chars[i] != ';' {
                i += 1;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_b_value_simple() {
        let header = "DKIM-Signature: v=1; b=abc123; bh=xyz789";
        let result = remove_b_value(header);
        assert!(result.contains("b=;") || result.contains("b= ;") || !result.contains("abc123"));
        assert!(result.contains("bh=xyz789"));
    }

    #[test]
    fn test_remove_b_value_end() {
        let header = "DKIM-Signature: v=1; bh=xyz789; b=abc123";
        let result = remove_b_value(header);
        assert!(!result.contains("abc123"));
        assert!(result.contains("bh=xyz789"));
    }

    #[test]
    fn test_parse_headers() {
        let headers = "From: user@example.com\r\nTo: other@example.com\r\nSubject: Test\r\n";
        let parsed = parse_headers(headers);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, "From");
        assert_eq!(parsed[1].0, "To");
        assert_eq!(parsed[2].0, "Subject");
    }

    #[test]
    fn test_parse_headers_folded() {
        let headers = "Subject: This is a\r\n very long subject\r\nFrom: user@example.com\r\n";
        let parsed = parse_headers(headers);
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].1.contains("very long subject"));
    }
}
