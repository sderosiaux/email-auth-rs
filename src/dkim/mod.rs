mod signature;
mod key;
mod canon;
mod hash;
mod crypto;

pub use signature::{DkimSignature, Algorithm, Canonicalization, CanonicalizationType};
pub use key::DkimPublicKey;
pub use crypto::{DkimSigner, SigningConfig};

use thiserror::Error;
use crate::common::DnsResolver;

#[derive(Debug, Clone, PartialEq)]
pub enum DkimResult {
    Pass { domain: String, selector: String },
    Fail { domain: String, reason: String },
    Neutral { reason: String },
    TempError { reason: String },
    PermError { reason: String },
    None,
}

#[derive(Debug, Error)]
pub enum DkimError {
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver, clock_skew: 300 }
    }

    pub fn with_clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult> {
        let message_str = match std::str::from_utf8(message) {
            Ok(s) => s,
            Err(_) => return vec![DkimResult::PermError { reason: "Invalid UTF-8".into() }],
        };

        let (headers, body) = match split_message(message_str) {
            Some(parts) => parts,
            None => return vec![DkimResult::PermError { reason: "Invalid message format".into() }],
        };

        let signatures = signature::parse_signatures(&headers);
        if signatures.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::new();
        for sig in signatures {
            let result = self.verify_signature(&sig, &headers, body).await;
            results.push(result);
        }
        results
    }

    async fn verify_signature(&self, sig: &DkimSignature, headers: &str, body: &str) -> DkimResult {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(exp) = sig.expiration {
            if now > exp + self.clock_skew {
                return DkimResult::Fail {
                    domain: sig.domain.clone(),
                    reason: "Signature expired".into(),
                };
            }
        }

        if let Some(ts) = sig.timestamp {
            if ts > now + self.clock_skew {
                return DkimResult::Fail {
                    domain: sig.domain.clone(),
                    reason: "Signature from future".into(),
                };
            }
        }

        let key_record = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let txt_records = match self.resolver.query_txt(&key_record).await {
            Ok(records) => records,
            Err(e) => {
                if e.is_nxdomain() {
                    return DkimResult::PermError {
                        reason: format!("No key found at {}", key_record),
                    };
                }
                return DkimResult::TempError {
                    reason: format!("DNS error: {}", e),
                };
            }
        };

        let key = match key::parse_key_record(&txt_records.join("")) {
            Ok(k) => k,
            Err(e) => {
                return DkimResult::PermError {
                    reason: format!("Invalid key: {}", e),
                };
            }
        };

        let body_canon = canon::canonicalize_body(body, sig.canonicalization.body);
        let body_hash = hash::compute_body_hash(&body_canon, sig.algorithm, sig.body_length);

        if body_hash != sig.body_hash {
            return DkimResult::Fail {
                domain: sig.domain.clone(),
                reason: "Body hash mismatch".into(),
            };
        }

        let header_hash = hash::compute_header_hash(headers, sig);

        match crypto::verify_signature(&header_hash, &sig.signature, &key, sig.algorithm) {
            Ok(true) => DkimResult::Pass {
                domain: sig.domain.clone(),
                selector: sig.selector.clone(),
            },
            Ok(false) => DkimResult::Fail {
                domain: sig.domain.clone(),
                reason: "Signature verification failed".into(),
            },
            Err(e) => DkimResult::PermError {
                reason: format!("Crypto error: {}", e),
            },
        }
    }
}

fn split_message(message: &str) -> Option<(String, &str)> {
    if let Some(pos) = message.find("\r\n\r\n") {
        Some((message[..pos + 2].to_string(), &message[pos + 4..]))
    } else if let Some(pos) = message.find("\n\n") {
        Some((message[..pos + 1].to_string(), &message[pos + 2..]))
    } else {
        None
    }
}
