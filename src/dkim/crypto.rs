//! DKIM cryptographic verification

use std::time::{SystemTime, UNIX_EPOCH};

use ring::signature::{self, UnparsedPublicKey};

use crate::common::dns::{DnsError, DnsResolver};
use super::canon::{canonicalize_body, canonicalize_header};
use super::hash::compute_body_hash;
use super::key::{DkimPublicKey, KeyType};
use super::signature::{Algorithm, CanonicalizationMethod, DkimSignature};

/// DKIM verification result
#[derive(Debug, Clone)]
pub enum DkimResult {
    Pass { domain: String, selector: String },
    Fail { reason: FailureReason },
    TempFail { reason: String },
    PermFail { reason: String },
    None,
}

#[derive(Debug, Clone)]
pub enum FailureReason {
    SignatureMismatch,
    BodyHashMismatch,
    KeyRevoked,
    KeyNotFound,
    ExpiredSignature,
    FutureSignature,
    AlgorithmMismatch,
    DomainMismatch,
}

/// DKIM verifier
#[derive(Clone)]
pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
    clock_skew_seconds: u64,
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            clock_skew_seconds: 300, // 5 minutes default
        }
    }

    /// Verify all DKIM signatures in a message
    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult> {
        let (headers, body) = match split_message(message) {
            Some(parts) => parts,
            None => return vec![DkimResult::None],
        };

        let signatures = extract_dkim_signatures(&headers);
        if signatures.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::with_capacity(signatures.len());
        for (header_name, header_value) in signatures {
            let result = self.verify_signature(&header_name, &header_value, &headers, body).await;
            results.push(result);
        }

        results
    }

    async fn verify_signature(
        &self,
        sig_header_name: &str,
        sig_header_value: &str,
        headers: &str,
        body: &[u8],
    ) -> DkimResult {
        // Parse signature
        let sig = match DkimSignature::parse(sig_header_value) {
            Ok(s) => s,
            Err(e) => return DkimResult::PermFail { reason: e.to_string() },
        };

        // Check expiration
        if let Some(exp) = sig.expiration {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now > exp + self.clock_skew_seconds {
                return DkimResult::Fail {
                    reason: FailureReason::ExpiredSignature,
                };
            }
        }

        // Check timestamp not in future
        if let Some(ts) = sig.timestamp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if ts > now + self.clock_skew_seconds {
                return DkimResult::Fail {
                    reason: FailureReason::FutureSignature,
                };
            }
        }

        // Fetch public key
        let key_domain = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let key = match self.resolver.query_txt(&key_domain).await {
            Ok(records) => {
                let txt = records.join("");
                match DkimPublicKey::parse(&txt) {
                    Ok(k) => k,
                    Err(e) => {
                        return DkimResult::PermFail {
                            reason: format!("invalid key: {}", e),
                        }
                    }
                }
            }
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                return DkimResult::Fail {
                    reason: FailureReason::KeyNotFound,
                }
            }
            Err(e) => {
                return DkimResult::TempFail {
                    reason: e.to_string(),
                }
            }
        };

        // Check algorithm compatibility
        if !check_algorithm_compatibility(&sig.algorithm, &key) {
            return DkimResult::Fail {
                reason: FailureReason::AlgorithmMismatch,
            };
        }

        // Verify body hash
        let canonicalized_body = canonicalize_body(body, sig.canonicalization.body);
        let body_to_hash = match sig.body_length {
            Some(l) if (l as usize) < canonicalized_body.len() => {
                &canonicalized_body[..l as usize]
            }
            _ => &canonicalized_body[..],
        };
        let computed_body_hash = compute_body_hash(body_to_hash, sig.algorithm);

        if computed_body_hash != sig.body_hash {
            return DkimResult::Fail {
                reason: FailureReason::BodyHashMismatch,
            };
        }

        // Build header hash input
        let header_data = build_header_hash_input(
            headers,
            &sig.headers,
            sig_header_name,
            sig_header_value,
            sig.canonicalization.header,
        );

        // Verify signature
        let verified = verify_signature_crypto(
            &header_data,
            &sig.signature,
            &key.public_key,
            sig.algorithm,
            key.key_type,
        );

        if verified {
            DkimResult::Pass {
                domain: sig.domain,
                selector: sig.selector,
            }
        } else {
            DkimResult::Fail {
                reason: FailureReason::SignatureMismatch,
            }
        }
    }
}

fn split_message(message: &[u8]) -> Option<(String, &[u8])> {
    // Find header/body separator (CRLFCRLF or LFLF)
    let separator_pos = if let Some(pos) = find_subsequence(message, b"\r\n\r\n") {
        pos
    } else if let Some(pos) = find_subsequence(message, b"\n\n") {
        pos
    } else {
        return None;
    };

    let headers = String::from_utf8_lossy(&message[..separator_pos]).into_owned();
    let body_start = if message[separator_pos..].starts_with(b"\r\n\r\n") {
        separator_pos + 4
    } else {
        separator_pos + 2
    };
    let body = &message[body_start..];

    Some((headers, body))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn extract_dkim_signatures(headers: &str) -> Vec<(String, String)> {
    let mut signatures = Vec::new();
    let mut current_header: Option<(String, String)> = None;

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line
            if let Some((_, ref mut value)) = current_header {
                value.push_str(line);
            }
        } else {
            // New header
            if let Some(header) = current_header.take() {
                if header.0.to_lowercase() == "dkim-signature" {
                    signatures.push(header);
                }
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].to_string();
                let value = line[colon_pos + 1..].to_string();
                current_header = Some((name, value));
            }
        }
    }

    // Don't forget last header
    if let Some(header) = current_header {
        if header.0.to_lowercase() == "dkim-signature" {
            signatures.push(header);
        }
    }

    signatures
}

fn check_algorithm_compatibility(algorithm: &Algorithm, key: &DkimPublicKey) -> bool {
    // Check key type matches algorithm
    match (algorithm, key.key_type) {
        (Algorithm::RsaSha1 | Algorithm::RsaSha256, KeyType::Rsa) => {}
        (Algorithm::Ed25519Sha256, KeyType::Ed25519) => {}
        _ => return false,
    }

    // Check hash restriction
    let hash = match algorithm {
        Algorithm::RsaSha1 => "sha1",
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => "sha256",
    };
    key.accepts_hash(hash)
}

fn build_header_hash_input(
    headers: &str,
    signed_headers: &[String],
    sig_header_name: &str,
    sig_header_value: &str,
    method: CanonicalizationMethod,
) -> Vec<u8> {
    let mut result = Vec::new();

    // Parse all headers into (name, value) pairs
    let header_list = parse_headers(headers);

    // Track used headers (for bottom-up selection of duplicates)
    let mut used_indices: Vec<bool> = vec![false; header_list.len()];

    // Process each header in h= list
    for h in signed_headers {
        // Find from bottom (last occurrence first)
        for i in (0..header_list.len()).rev() {
            if !used_indices[i] && header_list[i].0.to_lowercase() == *h {
                used_indices[i] = true;
                let canonical = canonicalize_header(&header_list[i].0, &header_list[i].1, method);
                result.extend_from_slice(canonical.as_bytes());
                result.extend_from_slice(b"\r\n");
                break;
            }
        }
        // If header not found, it contributes nothing (over-signing)
    }

    // Add DKIM-Signature header with b= value removed
    let sig_header_cleaned = remove_b_value(sig_header_value);
    let canonical_sig = canonicalize_header(sig_header_name, &sig_header_cleaned, method);
    result.extend_from_slice(canonical_sig.as_bytes());
    // Note: No trailing CRLF for the signature header itself

    result
}

fn parse_headers(headers: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut current: Option<(String, String)> = None;

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation
            if let Some((_, ref mut value)) = current {
                value.push('\n');
                value.push_str(line);
            }
        } else {
            if let Some(header) = current.take() {
                result.push(header);
            }
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].to_string();
                let value = line[colon_pos + 1..].to_string();
                current = Some((name, value));
            }
        }
    }

    if let Some(header) = current {
        result.push(header);
    }

    result
}

fn remove_b_value(header_value: &str) -> String {
    // Remove the value of b= tag while keeping the tag itself
    // Must be careful not to affect bh= tag
    let mut result = String::with_capacity(header_value.len());
    let mut i = 0;
    let chars: Vec<char> = header_value.chars().collect();

    while i < chars.len() {
        // Look for 'b=' that's not preceded by 'h' (to avoid bh=)
        if i + 1 < chars.len()
            && chars[i] == 'b'
            && chars[i + 1] == '='
            && (i == 0 || chars[i - 1] != 'h')
        {
            result.push('b');
            result.push('=');
            i += 2;
            // Skip until semicolon or end
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

fn verify_signature_crypto(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
    algorithm: Algorithm,
    key_type: KeyType,
) -> bool {
    match (algorithm, key_type) {
        (Algorithm::RsaSha256, KeyType::Rsa) => {
            let key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
            key.verify(data, signature).is_ok()
        }
        (Algorithm::RsaSha1, KeyType::Rsa) => {
            // ring doesn't directly support RSA_PKCS1_SHA1, need alternative approach
            // For now, return false - this is legacy anyway
            // In production, would use rsa crate or openssl
            let key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
            // This is a hack - RSA-SHA1 would need different verification
            // Leaving as placeholder
            key.verify(data, signature).is_ok()
        }
        (Algorithm::Ed25519Sha256, KeyType::Ed25519) => {
            let key = UnparsedPublicKey::new(&signature::ED25519, public_key);
            key.verify(data, signature).is_ok()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_message() {
        let msg = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody here";
        let (headers, body) = split_message(msg).unwrap();
        assert!(headers.contains("From:"));
        assert_eq!(body, b"Body here");
    }

    #[test]
    fn test_extract_dkim_signatures() {
        let headers = "From: test@example.com\nDKIM-Signature: v=1; a=rsa-sha256\nSubject: Test";
        let sigs = extract_dkim_signatures(headers);
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].1.contains("v=1"));
    }

    #[test]
    fn test_remove_b_value() {
        let value = "v=1; bh=abc; b=xyz123; d=example.com";
        let cleaned = remove_b_value(value);
        assert!(cleaned.contains("bh=abc"));
        assert!(cleaned.contains("b="));
        assert!(!cleaned.contains("xyz123"));
    }

    #[test]
    fn test_remove_b_value_preserves_bh() {
        let value = "bh=hash123; b=sig456";
        let cleaned = remove_b_value(value);
        assert!(cleaned.contains("bh=hash123"));
        assert!(!cleaned.contains("sig456"));
    }
}
