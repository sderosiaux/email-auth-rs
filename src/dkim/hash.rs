//! DKIM hash computation.

use super::canon::{apply_body_limit, canonicalize_body, canonicalize_header};
use super::signature::{Algorithm, CanonicalizationMethod};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};

/// Compute body hash for DKIM.
pub fn compute_body_hash(
    body: &[u8],
    algorithm: &Algorithm,
    method: CanonicalizationMethod,
    length_limit: Option<u64>,
) -> Vec<u8> {
    let canonicalized = canonicalize_body(body, method);
    let limited = apply_body_limit(canonicalized, length_limit);

    let algo = match algorithm {
        Algorithm::RsaSha1 => &SHA1_FOR_LEGACY_USE_ONLY,
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => &SHA256,
    };

    let digest = ring::digest::digest(algo, &limited);
    digest.as_ref().to_vec()
}

/// Compute header hash for DKIM verification.
/// Returns the raw data to be signed/verified (not hashed again by crypto).
pub fn compute_header_hash(
    headers: &str,
    sig_header_name: &str,
    sig_header_value: &str,
    signed_headers: &[String],
    algorithm: &Algorithm,
    method: CanonicalizationMethod,
) -> Vec<u8> {
    let mut data = Vec::new();

    // Build map of headers (bottom-up selection for multiple same-name headers)
    let header_map = parse_headers(headers);

    // Track which instance of each header we've used
    let mut used_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Process headers in order specified by h= tag
    for header_name in signed_headers {
        let name_lower = header_name.to_lowercase();
        let instances = header_map.get(&name_lower);

        let count = used_counts.entry(name_lower.clone()).or_insert(0);

        if let Some(instances) = instances {
            // Bottom-up selection: first occurrence in h= gets last instance in message
            let idx = instances.len().saturating_sub(*count + 1);
            if idx < instances.len() {
                let (name, value) = &instances[idx];
                let canonicalized = canonicalize_header(name, value, method);
                data.extend_from_slice(canonicalized.as_bytes());
                data.extend_from_slice(b"\r\n");
            }
            // If header not present (over-signing), contribute empty value
            *count += 1;
        }
        // Missing headers contribute nothing (not an error)
    }

    // Append the DKIM-Signature header with b= value removed
    let sig_header_without_b = remove_b_value(sig_header_value);
    let canonicalized_sig = canonicalize_header(sig_header_name, &sig_header_without_b, method);
    // Do NOT include trailing CRLF for signature header
    data.extend_from_slice(canonicalized_sig.as_bytes());

    // For ring RSA, we pass the raw message data (ring hashes internally)
    // For verification, we need the data that was signed
    // The caller will hash this according to the algorithm
    match algorithm {
        Algorithm::RsaSha1 => {
            let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
            ctx.update(&data);
            ctx.finish().as_ref().to_vec()
        }
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            let mut ctx = Context::new(&SHA256);
            ctx.update(&data);
            ctx.finish().as_ref().to_vec()
        }
    }
}

fn parse_headers(headers: &str) -> std::collections::HashMap<String, Vec<(String, String)>> {
    let mut map: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();

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
        } else if let Some((name, value)) = line.split_once(':') {
            // New header - save previous
            if in_header {
                let name_lower = current_name.to_lowercase();
                map.entry(name_lower)
                    .or_default()
                    .push((current_name.clone(), current_value.clone()));
            }

            current_name = name.to_string();
            current_value = value.to_string();
            in_header = true;
        }
    }

    // Don't forget the last header
    if in_header {
        let name_lower = current_name.to_lowercase();
        map.entry(name_lower)
            .or_default()
            .push((current_name, current_value));
    }

    map
}

/// Remove b= value from DKIM-Signature header while preserving bh=.
/// This is tricky because we need to not affect the bh= tag.
fn remove_b_value(sig_value: &str) -> String {
    let mut result = String::new();
    let mut i = 0;
    let chars: Vec<char> = sig_value.chars().collect();

    while i < chars.len() {
        // Look for "b=" that's not "bh="
        if i + 1 < chars.len() && chars[i] == 'b' && chars[i + 1] == '=' {
            // Check it's not "bh="
            if i > 0 && chars[i - 1] != ' ' && chars[i - 1] != '\t' && chars[i - 1] != ';' {
                // Part of another tag name, keep it
                result.push(chars[i]);
                i += 1;
                continue;
            }
            // Check for "bh=" (actually starts at i-1 but we're at 'b')
            // We need to look back to see if previous non-whitespace was 'h'
            // Actually, simpler: if next char after '=' area contains 'h', it's bh
            // Let's be more precise: look at the tag name before '='

            // Found "b=" - keep the tag but remove the value
            result.push('b');
            result.push('=');
            i += 2;

            // Skip the value (everything until ; or end)
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
    fn test_remove_b_value() {
        let input = "v=1; bh=abc123; b=signature_here; s=selector";
        let output = remove_b_value(input);
        assert!(output.contains("b=;") || output.contains("b= ;") || output.ends_with("b="));
        assert!(output.contains("bh=abc123"));
    }

    #[test]
    fn test_parse_headers() {
        let headers = "From: user@example.com\r\n\
            To: recipient@example.com\r\n\
            Subject: Test\r\n\
            From: other@example.com";
        let map = parse_headers(headers);
        assert_eq!(map.get("from").unwrap().len(), 2);
    }

    #[test]
    fn test_body_hash() {
        let body = b"Hello World\r\n";
        let hash = compute_body_hash(body, &Algorithm::RsaSha256, CanonicalizationMethod::Simple, None);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
    }
}
