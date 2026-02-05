//! DKIM (DomainKeys Identified Mail) implementation per RFC 6376.

mod canon;
mod crypto;
mod hash;
mod key;
mod signature;

pub use crypto::DkimSigner;
pub use signature::{Algorithm, Canonicalization, CanonicalizationMethod, DkimSignature};
pub use key::DkimPublicKey;

use crate::common::dns::{DnsError, DnsResolver};
use thiserror::Error;

const CLOCK_SKEW_SECONDS: u64 = 300; // 5 minutes

/// DKIM verification result.
#[derive(Debug, Clone)]
pub enum DkimResult {
    Pass {
        domain: String,
        selector: String,
    },
    Fail {
        reason: FailureReason,
    },
    TempFail {
        reason: String,
    },
    PermFail {
        reason: String,
    },
    None,
}

impl DkimResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, DkimResult::Pass { .. })
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            DkimResult::Pass { domain, .. } => Some(domain),
            _ => None,
        }
    }
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

#[derive(Debug, Error)]
pub enum DkimError {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("crypto error: {0}")]
    CryptoError(String),
    #[error("DNS error: {0}")]
    DnsError(#[from] DnsError),
}

/// DKIM verifier.
#[derive(Clone)]
pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Verify all DKIM signatures in a message.
    /// Returns a result for each signature found.
    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult> {
        let message_str = String::from_utf8_lossy(message);

        // Split headers and body
        let (headers, body) = match split_message(&message_str) {
            Some(parts) => parts,
            None => return vec![DkimResult::None],
        };

        // Find all DKIM-Signature headers
        let signatures = find_dkim_signatures(&headers);
        if signatures.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::new();

        for (sig_header_name, sig_header_value) in signatures {
            let result = self
                .verify_signature(&sig_header_name, &sig_header_value, &headers, body.as_bytes())
                .await;
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
            Err(e) => {
                return DkimResult::PermFail {
                    reason: format!("invalid signature: {}", e),
                }
            }
        };

        // Check expiration
        if let Some(expiration) = sig.expiration {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now > expiration + CLOCK_SKEW_SECONDS {
                return DkimResult::Fail {
                    reason: FailureReason::ExpiredSignature,
                };
            }
        }

        // Check future timestamp
        if let Some(timestamp) = sig.timestamp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if timestamp > now + CLOCK_SKEW_SECONDS {
                return DkimResult::Fail {
                    reason: FailureReason::FutureSignature,
                };
            }
        }

        // Lookup public key
        let key_domain = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let key = match self.lookup_key(&key_domain).await {
            Ok(Some(k)) => k,
            Ok(None) => {
                return DkimResult::Fail {
                    reason: FailureReason::KeyNotFound,
                }
            }
            Err(DkimError::DnsError(DnsError::ServFail | DnsError::Timeout)) => {
                return DkimResult::TempFail {
                    reason: "DNS error".into(),
                }
            }
            Err(e) => {
                return DkimResult::PermFail {
                    reason: format!("key lookup failed: {}", e),
                }
            }
        };

        // Check if key is revoked
        if key.public_key.is_empty() {
            return DkimResult::Fail {
                reason: FailureReason::KeyRevoked,
            };
        }

        // Check algorithm compatibility with key's h= tag
        if let Some(ref allowed_hashes) = key.acceptable_hashes {
            let sig_hash = match sig.algorithm {
                Algorithm::RsaSha1 => "sha1",
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => "sha256",
            };
            if !allowed_hashes.iter().any(|h| h.eq_ignore_ascii_case(sig_hash)) {
                return DkimResult::Fail {
                    reason: FailureReason::AlgorithmMismatch,
                };
            }
        }

        // Verify body hash
        let body_hash = hash::compute_body_hash(
            body,
            &sig.algorithm,
            sig.canonicalization.body,
            sig.body_length,
        );

        if body_hash != sig.body_hash {
            return DkimResult::Fail {
                reason: FailureReason::BodyHashMismatch,
            };
        }

        // Compute header hash
        let header_data = hash::compute_header_hash(
            headers,
            sig_header_name,
            sig_header_value,
            &sig.signed_headers,
            &sig.algorithm,
            sig.canonicalization.header,
        );

        // Verify signature
        let verify_result = crypto::verify_signature(
            &sig.algorithm,
            &key,
            &header_data,
            &sig.signature,
        );

        match verify_result {
            Ok(()) => DkimResult::Pass {
                domain: sig.domain.clone(),
                selector: sig.selector.clone(),
            },
            Err(_) => DkimResult::Fail {
                reason: FailureReason::SignatureMismatch,
            },
        }
    }

    async fn lookup_key(&self, domain: &str) -> Result<Option<DkimPublicKey>, DkimError> {
        let txt_records = match self.resolver.query_txt(domain).await {
            Ok(r) => r,
            Err(DnsError::NxDomain | DnsError::NoRecords) => return Ok(None),
            Err(e) => return Err(DkimError::DnsError(e)),
        };

        // Concatenate all TXT strings and parse
        let txt = txt_records.join("");
        DkimPublicKey::parse(&txt).map(Some)
    }
}

fn split_message(message: &str) -> Option<(String, String)> {
    // Handle both CRLF and LF line endings
    if let Some(idx) = message.find("\r\n\r\n") {
        Some((message[..idx].to_string(), message[idx + 4..].to_string()))
    } else if let Some(idx) = message.find("\n\n") {
        Some((message[..idx].to_string(), message[idx + 2..].to_string()))
    } else {
        None
    }
}

fn find_dkim_signatures(headers: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let mut current_name = String::new();
    let mut current_value = String::new();
    let mut in_header = false;

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line
            if in_header {
                current_value.push_str(line);
            }
        } else if let Some((name, value)) = line.split_once(':') {
            // New header - save previous if it was DKIM-Signature
            if in_header && current_name.eq_ignore_ascii_case("dkim-signature") {
                results.push((current_name.clone(), current_value.clone()));
            }

            current_name = name.to_string();
            current_value = value.to_string();
            in_header = true;
        }
    }

    // Don't forget the last header
    if in_header && current_name.eq_ignore_ascii_case("dkim-signature") {
        results.push((current_name, current_value));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_message() {
        let msg = "From: test@example.com\r\nSubject: Test\r\n\r\nBody here";
        let (headers, body) = split_message(msg).unwrap();
        assert!(headers.contains("From:"));
        assert_eq!(body, "Body here");
    }

    #[test]
    fn test_find_dkim_signatures() {
        let headers = "From: test@example.com\r\n\
            DKIM-Signature: v=1; a=rsa-sha256; d=example.com;\r\n\
            \ts=selector; b=abc123\r\n\
            Subject: Test";
        let sigs = find_dkim_signatures(headers);
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].1.contains("v=1"));
    }
}
