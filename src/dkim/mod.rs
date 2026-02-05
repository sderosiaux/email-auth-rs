mod canon;
mod crypto;
mod hash;
mod key;
mod signature;

pub use key::DkimPublicKey;
pub use signature::DkimSignature;

use crate::common::DnsResolver;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimResult {
    Pass { domain: String, selector: String },
    Fail { reason: FailureReason },
    TempFail { reason: String },
    PermFail { reason: String },
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureReason::SignatureMismatch => write!(f, "signature mismatch"),
            FailureReason::BodyHashMismatch => write!(f, "body hash mismatch"),
            FailureReason::KeyRevoked => write!(f, "key revoked"),
            FailureReason::KeyNotFound => write!(f, "key not found"),
            FailureReason::ExpiredSignature => write!(f, "signature expired"),
            FailureReason::FutureSignature => write!(f, "signature timestamp in future"),
            FailureReason::AlgorithmMismatch => write!(f, "algorithm mismatch"),
            FailureReason::DomainMismatch => write!(f, "domain mismatch"),
        }
    }
}

#[derive(Debug, Error)]
pub enum DkimError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

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

    pub fn with_clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew_seconds = seconds;
        self
    }

    /// Verify all DKIM signatures in a message
    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult> {
        let message_str = String::from_utf8_lossy(message);

        // Split headers and body
        let (headers, body) = split_message(&message_str);

        // Find all DKIM-Signature headers
        let signatures = extract_dkim_signatures(&headers);

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
                    reason: format!("signature parse error: {}", e),
                }
            }
        };

        // Check timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(t) = sig.timestamp {
            if t > now + self.clock_skew_seconds {
                return DkimResult::Fail {
                    reason: FailureReason::FutureSignature,
                };
            }
        }

        if let Some(x) = sig.expiration {
            if now > x + self.clock_skew_seconds {
                return DkimResult::Fail {
                    reason: FailureReason::ExpiredSignature,
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
                            reason: format!("key parse error: {}", e),
                        }
                    }
                }
            }
            Err(crate::common::DnsError::NxDomain) => {
                return DkimResult::Fail {
                    reason: FailureReason::KeyNotFound,
                }
            }
            Err(e) => {
                return DkimResult::TempFail {
                    reason: format!("DNS error: {}", e),
                }
            }
        };

        // Check for revoked key
        if key.public_key.is_empty() {
            return DkimResult::Fail {
                reason: FailureReason::KeyRevoked,
            };
        }

        // Check algorithm compatibility
        if !key.supports_algorithm(&sig.algorithm) {
            return DkimResult::Fail {
                reason: FailureReason::AlgorithmMismatch,
            };
        }

        // Verify body hash
        let body_to_hash = if let Some(limit) = sig.body_length {
            &body[..std::cmp::min(limit as usize, body.len())]
        } else {
            body
        };

        let canonicalized_body = canon::canonicalize_body(body_to_hash, sig.canonicalization.body);
        let body_hash = hash::compute_body_hash(&canonicalized_body, sig.algorithm);

        if body_hash != sig.body_hash {
            return DkimResult::Fail {
                reason: FailureReason::BodyHashMismatch,
            };
        }

        // Compute header hash
        let header_data = hash::compute_header_hash_data(
            headers,
            &sig.signed_headers,
            sig_header_name,
            sig_header_value,
            sig.canonicalization.header,
        );

        // Verify signature
        match crypto::verify_signature(&sig.algorithm, &key.public_key, &header_data, &sig.signature)
        {
            Ok(true) => DkimResult::Pass {
                domain: sig.domain.clone(),
                selector: sig.selector.clone(),
            },
            Ok(false) => DkimResult::Fail {
                reason: FailureReason::SignatureMismatch,
            },
            Err(e) => DkimResult::PermFail {
                reason: format!("crypto error: {}", e),
            },
        }
    }
}

/// Split message into headers and body
fn split_message(message: &str) -> (String, String) {
    // Handle both CRLF and LF line endings
    if let Some(pos) = message.find("\r\n\r\n") {
        (
            message[..pos].to_string(),
            message[pos + 4..].to_string(),
        )
    } else if let Some(pos) = message.find("\n\n") {
        (
            message[..pos].to_string(),
            message[pos + 2..].to_string(),
        )
    } else {
        (message.to_string(), String::new())
    }
}

/// Extract all DKIM-Signature headers (name, value pairs)
fn extract_dkim_signatures(headers: &str) -> Vec<(String, String)> {
    let mut signatures = Vec::new();
    let mut current_name = String::new();
    let mut current_value = String::new();

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line
            if !current_name.is_empty() {
                current_value.push_str(line);
            }
        } else {
            // New header - save previous if it was DKIM-Signature
            if current_name.eq_ignore_ascii_case("dkim-signature") {
                signatures.push((current_name.clone(), current_value.clone()));
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
    if current_name.eq_ignore_ascii_case("dkim-signature") {
        signatures.push((current_name, current_value));
    }

    signatures
}
