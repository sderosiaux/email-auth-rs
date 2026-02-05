mod signature;
mod key;
mod canon;
mod hash;
mod crypto;

pub use signature::DkimSignature;
pub use key::DkimPublicKey;

use crate::common::dns::{DnsError, DnsResolver};
use thiserror::Error;

/// DKIM verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimResult {
    /// Valid signature
    Pass { domain: String, selector: String },
    /// Invalid signature
    Fail { reason: FailureReason },
    /// Transient error
    TempFail { reason: String },
    /// Permanent error
    PermFail { reason: String },
    /// No signature present
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

/// Reasons for DKIM failure
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

#[derive(Debug, Error)]
pub enum DkimError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("crypto error: {0}")]
    Crypto(String),
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

    pub fn with_clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew_seconds = seconds;
        self
    }

    /// Verify all DKIM signatures in a message
    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult> {
        let message_str = match std::str::from_utf8(message) {
            Ok(s) => s,
            Err(_) => return vec![DkimResult::PermFail { reason: "invalid UTF-8".to_string() }],
        };

        // Split headers and body
        let (headers, body) = Self::split_message(message_str);

        // Find all DKIM-Signature headers
        let signatures = Self::extract_signatures(&headers);

        if signatures.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::new();

        for (sig_header_value, sig_header_full) in signatures {
            let result = self
                .verify_signature(&sig_header_value, &sig_header_full, &headers, body.as_bytes())
                .await;
            results.push(result);
        }

        results
    }

    fn split_message(message: &str) -> (String, String) {
        // Find the blank line separating headers from body
        // Handle both CRLF and LF
        if let Some(pos) = message.find("\r\n\r\n") {
            let headers = message[..pos + 2].to_string(); // Include trailing CRLF
            let body = message[pos + 4..].to_string();
            (headers, body)
        } else if let Some(pos) = message.find("\n\n") {
            let headers = message[..pos + 1].to_string();
            let body = message[pos + 2..].to_string();
            (headers, body)
        } else {
            // No body
            (message.to_string(), String::new())
        }
    }

    fn extract_signatures(headers: &str) -> Vec<(String, String)> {
        let mut signatures = Vec::new();
        let mut current_header = String::new();
        let mut in_dkim_sig = false;

        for line in headers.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation line
                if in_dkim_sig {
                    current_header.push_str(line);
                }
            } else {
                // New header
                if in_dkim_sig && !current_header.is_empty() {
                    // Parse the completed DKIM-Signature
                    if let Some(value) = current_header.strip_prefix("dkim-signature:") {
                        signatures.push((value.trim().to_string(), current_header.clone()));
                    } else if let Some(value) = current_header.strip_prefix("DKIM-Signature:") {
                        signatures.push((value.trim().to_string(), current_header.clone()));
                    }
                }

                current_header = line.to_string();
                in_dkim_sig = line.to_lowercase().starts_with("dkim-signature:");
            }
        }

        // Handle last header
        if in_dkim_sig && !current_header.is_empty() {
            let lower = current_header.to_lowercase();
            if let Some(pos) = lower.find("dkim-signature:") {
                let value_start = pos + "dkim-signature:".len();
                if value_start < current_header.len() {
                    signatures.push((current_header[value_start..].trim().to_string(), current_header.clone()));
                }
            }
        }

        signatures
    }

    async fn verify_signature(
        &self,
        sig_value: &str,
        sig_header_full: &str,
        headers: &str,
        body: &[u8],
    ) -> DkimResult {
        // Parse signature
        let sig = match DkimSignature::parse(sig_value) {
            Ok(s) => s,
            Err(e) => return DkimResult::PermFail { reason: e.to_string() },
        };

        // Validate i= is subdomain of d=
        if let Some(ref auid) = sig.auid {
            if let Some(auid_domain) = auid.rsplit_once('@').map(|(_, d)| d) {
                let d_lower = sig.domain.to_lowercase();
                let auid_lower = auid_domain.to_lowercase();
                if auid_lower != d_lower && !auid_lower.ends_with(&format!(".{}", d_lower)) {
                    return DkimResult::Fail { reason: FailureReason::DomainMismatch };
                }
            }
        }

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(exp) = sig.expiration {
            if now > exp + self.clock_skew_seconds {
                return DkimResult::Fail { reason: FailureReason::ExpiredSignature };
            }
        }

        if let Some(ts) = sig.timestamp {
            if ts > now + self.clock_skew_seconds {
                return DkimResult::Fail { reason: FailureReason::FutureSignature };
            }
        }

        // Lookup public key
        let key = match self.lookup_key(&sig.selector, &sig.domain).await {
            Ok(Some(k)) => k,
            Ok(None) => return DkimResult::Fail { reason: FailureReason::KeyNotFound },
            Err(DkimError::Dns(_)) => return DkimResult::TempFail { reason: "DNS lookup failed".to_string() },
            Err(e) => return DkimResult::PermFail { reason: e.to_string() },
        };

        // Check if key is revoked
        if key.public_key.is_empty() {
            return DkimResult::Fail { reason: FailureReason::KeyRevoked };
        }

        // Check key flags
        if key.flags.contains(&key::KeyFlag::SameDomainOnly) {
            if let Some(ref auid) = sig.auid {
                if let Some(auid_domain) = auid.rsplit_once('@').map(|(_, d)| d) {
                    if auid_domain.to_lowercase() != sig.domain.to_lowercase() {
                        return DkimResult::Fail { reason: FailureReason::DomainMismatch };
                    }
                }
            }
        }

        // Check algorithm compatibility with key's h= tag
        if let Some(ref acceptable_hashes) = key.acceptable_hashes {
            let sig_hash = match sig.algorithm {
                signature::Algorithm::RsaSha1 => "sha1",
                signature::Algorithm::RsaSha256 | signature::Algorithm::Ed25519Sha256 => "sha256",
            };
            if !acceptable_hashes.iter().any(|h| h.to_lowercase() == sig_hash) {
                return DkimResult::Fail { reason: FailureReason::AlgorithmMismatch };
            }
        }

        // Verify body hash
        let canon_body = canon::canonicalize_body(body, sig.canonicalization.body, sig.body_length);
        let body_hash = hash::compute_body_hash(&canon_body, sig.algorithm);

        if body_hash != sig.body_hash {
            return DkimResult::Fail { reason: FailureReason::BodyHashMismatch };
        }

        // Compute header hash
        let header_hash_input = hash::compute_header_hash_input(
            headers,
            &sig.signed_headers,
            sig_header_full,
            sig.canonicalization.header,
        );

        // Verify signature
        match crypto::verify_signature(&header_hash_input, &sig.signature, &key.public_key, sig.algorithm, key.key_type) {
            Ok(true) => DkimResult::Pass {
                domain: sig.domain.clone(),
                selector: sig.selector.clone(),
            },
            Ok(false) => DkimResult::Fail { reason: FailureReason::SignatureMismatch },
            Err(e) => DkimResult::PermFail { reason: e },
        }
    }

    async fn lookup_key(&self, selector: &str, domain: &str) -> Result<Option<DkimPublicKey>, DkimError> {
        let query = format!("{}._domainkey.{}", selector, domain);

        let records = match self.resolver.query_txt(&query).await {
            Ok(r) => r,
            Err(DnsError::NxDomain) => return Ok(None),
            Err(e) => return Err(DkimError::Dns(e.to_string())),
        };

        if records.is_empty() {
            return Ok(None);
        }

        // Concatenate multiple TXT strings
        let txt = records.join("");

        match DkimPublicKey::parse(&txt) {
            Ok(key) => Ok(Some(key)),
            Err(e) => Err(DkimError::Parse(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[tokio::test]
    async fn test_no_signature() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);

        let message = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody";
        let results = verifier.verify(message).await;

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], DkimResult::None));
    }
}
