use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};

use super::canon::{canonicalize_body, canonicalize_header};
use super::signature::{Algorithm, CanonicalizationMethod, DkimSignature};

/// Compute body hash for DKIM
pub fn compute_body_hash(
    body: &[u8],
    algorithm: Algorithm,
    canonicalization: CanonicalizationMethod,
    length_limit: Option<u64>,
) -> Vec<u8> {
    // Canonicalize body
    let mut canon_body = canonicalize_body(body, canonicalization);

    // Apply length limit if specified
    if let Some(limit) = length_limit {
        let limit = limit as usize;
        if canon_body.len() > limit {
            canon_body.truncate(limit);
        }
    }

    // Hash
    match algorithm {
        Algorithm::RsaSha1 => {
            let digest = ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, &canon_body);
            digest.as_ref().to_vec()
        }
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            let digest = ring::digest::digest(&SHA256, &canon_body);
            digest.as_ref().to_vec()
        }
    }
}

/// Compute header hash for DKIM verification
pub fn compute_header_hash(
    raw_headers: &str,
    signature: &DkimSignature,
    signature_header_value: &str,
) -> Vec<u8> {
    let method = signature.canonicalization.header;
    let mut ctx = match signature.algorithm {
        Algorithm::RsaSha1 => Context::new(&SHA1_FOR_LEGACY_USE_ONLY),
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => Context::new(&SHA256),
    };

    // Parse headers from raw message
    let headers = parse_headers(raw_headers);

    // Track which header instances have been used
    // RFC 6376: multiple headers with same name selected bottom-up
    let mut header_usage: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Process headers in order specified by h=
    for header_name in &signature.headers {
        let name_lower = header_name.to_lowercase();

        // Find headers with this name (collected in order from message)
        let matching: Vec<_> = headers
            .iter()
            .filter(|(n, _)| n.to_lowercase() == name_lower)
            .collect();

        if matching.is_empty() {
            // Header not present - treat as zero-length (not an error)
            continue;
        }

        // Get usage count for this header name
        let used = *header_usage.get(&name_lower).unwrap_or(&0);

        // Select from bottom-up (last occurrence first)
        let index = matching.len().saturating_sub(used + 1);
        if index < matching.len() {
            let (name, value) = matching[index];
            let canonicalized = canonicalize_header(name, value, method);
            ctx.update(canonicalized.as_bytes());
            ctx.update(b"\r\n");

            // Mark as used
            *header_usage.entry(name_lower).or_insert(0) += 1;
        }
    }

    // Append DKIM-Signature header (with empty b= value)
    // Don't include trailing CRLF for signature header
    let sig_header = remove_signature_value(signature_header_value);
    let canonicalized_sig = canonicalize_header("DKIM-Signature", &sig_header, method);
    ctx.update(canonicalized_sig.as_bytes());
    // Note: NO trailing CRLF for the signature header itself

    ctx.finish().as_ref().to_vec()
}

/// Parse headers from raw message header section
fn parse_headers(raw: &str) -> Vec<(&str, &str)> {
    let mut headers = Vec::new();
    let mut current_name = None;
    let mut current_value_start = 0;
    let mut last_end = 0;

    let lines: Vec<_> = raw.split('\n').collect();

    for (i, line) in lines.iter().enumerate() {
        let line = line.trim_end_matches('\r');

        if line.is_empty() {
            // End of headers
            if let Some(name) = current_name {
                let value = &raw[current_value_start..last_end];
                headers.push((name, value));
            }
            break;
        }

        // Check if this is a continuation line (starts with whitespace)
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header
            last_end = raw[..].find(line).unwrap_or(0) + line.len();
            continue;
        }

        // New header line
        if let Some(name) = current_name {
            // Save previous header
            let value = &raw[current_value_start..last_end];
            headers.push((name, value));
        }

        // Parse new header
        if let Some(colon_pos) = line.find(':') {
            current_name = Some(&line[..colon_pos]);
            // Value starts after colon
            let value_in_line = &line[colon_pos + 1..];
            // Find actual position in raw string
            if let Some(pos) = raw.find(line) {
                current_value_start = pos + colon_pos + 1;
                last_end = pos + line.len();
            }
        } else {
            current_name = None;
        }

        // Handle last header if we're at the end
        if i == lines.len() - 1 {
            if let Some(name) = current_name {
                let value = &raw[current_value_start..last_end];
                headers.push((name, value));
            }
        }
    }

    headers
}

/// Remove the b= signature value from DKIM-Signature header value
fn remove_signature_value(header_value: &str) -> String {
    // Find b= tag and remove its value (but keep the tag)
    let mut result = String::new();
    let mut in_b_tag = false;
    let mut chars = header_value.chars().peekable();

    while let Some(c) = chars.next() {
        if !in_b_tag {
            result.push(c);

            // Check if we're starting the b= tag
            if c == 'b' && chars.peek() == Some(&'=') {
                // Make sure it's not bh=
                if !result.ends_with("bh") {
                    result.push(chars.next().unwrap()); // Add the =
                    in_b_tag = true;
                }
            }
        } else {
            // In b= value, skip until semicolon or end
            if c == ';' {
                result.push(c);
                in_b_tag = false;
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_body_hash_simple() {
        let body = b"Hello World\r\n";
        let hash = compute_body_hash(body, Algorithm::RsaSha256, CanonicalizationMethod::Simple, None);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_compute_body_hash_with_limit() {
        let body = b"Hello World\r\n";
        let hash_full = compute_body_hash(body, Algorithm::RsaSha256, CanonicalizationMethod::Simple, None);
        let hash_limited = compute_body_hash(body, Algorithm::RsaSha256, CanonicalizationMethod::Simple, Some(5));
        assert_ne!(hash_full, hash_limited);
    }

    #[test]
    fn test_remove_signature_value() {
        let header = " v=1; a=rsa-sha256; b=ABCD1234; d=example.com";
        let result = remove_signature_value(header);
        assert_eq!(result, " v=1; a=rsa-sha256; b=; d=example.com");

        // With bh= present (should not be affected)
        let header = " bh=XXXX; b=YYYY";
        let result = remove_signature_value(header);
        assert_eq!(result, " bh=XXXX; b=");
    }

    #[test]
    fn test_parse_headers() {
        let raw = "From: user@example.com\r\nTo: other@example.com\r\n\r\n";
        let headers = parse_headers(raw);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "From");
        assert_eq!(headers[1].0, "To");
    }
}
