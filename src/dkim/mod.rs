mod signature;
mod key;
mod canon;
mod hash;
mod crypto;

pub use signature::{DkimSignature, Algorithm, Canonicalization, CanonicalizationMethod};
pub use key::{DkimPublicKey, KeyType, KeyFlag};
pub use crypto::{DkimSigner, SigningConfig};

use std::time::{SystemTime, UNIX_EPOCH};
use crate::common::{DnsResolver, DnsError};

use thiserror::Error;

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

#[derive(Debug, Error)]
pub enum DkimError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("crypto error: {0}")]
    CryptoError(String),
    #[error("DNS error: {0}")]
    DnsError(String),
}

pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            clock_skew: 300, // 5 minutes default
        }
    }

    pub fn with_clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult> {
        let message_str = String::from_utf8_lossy(message);
        let (headers, body) = split_message(&message_str);

        let signatures = extract_dkim_signatures(&headers);

        if signatures.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::new();

        for (sig_header_value, sig_header_full) in signatures {
            let result = self.verify_single(&headers, body.as_bytes(), &sig_header_value, &sig_header_full).await;
            results.push(result);
        }

        results
    }

    async fn verify_single(
        &self,
        headers: &str,
        body: &[u8],
        sig_value: &str,
        sig_header_full: &str,
    ) -> DkimResult {
        // Parse signature
        let sig = match DkimSignature::parse(sig_value) {
            Ok(s) => s,
            Err(e) => return DkimResult::PermFail { reason: e.to_string() },
        };

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(exp) = sig.expiration {
            if now > exp + self.clock_skew {
                return DkimResult::Fail { reason: FailureReason::ExpiredSignature };
            }
        }

        if let Some(ts) = sig.timestamp {
            if ts > now + self.clock_skew {
                return DkimResult::Fail { reason: FailureReason::FutureSignature };
            }
        }

        // Fetch public key
        let key_query = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let key_records = match self.resolver.query_txt(&key_query).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) => {
                return DkimResult::Fail { reason: FailureReason::KeyNotFound };
            }
            Err(e) => {
                return DkimResult::TempFail { reason: format!("DNS error: {:?}", e) };
            }
        };

        let key_record = key_records.join("");
        let public_key = match DkimPublicKey::parse(&key_record) {
            Ok(k) => k,
            Err(e) => return DkimResult::PermFail { reason: e.to_string() },
        };

        // Check if key is revoked
        if public_key.public_key.is_empty() {
            return DkimResult::Fail { reason: FailureReason::KeyRevoked };
        }

        // Check algorithm compatibility
        if !public_key.supports_algorithm(&sig.algorithm) {
            return DkimResult::Fail { reason: FailureReason::AlgorithmMismatch };
        }

        // Verify body hash
        let canonicalized_body = canon::canonicalize_body(body, sig.canonicalization.body, sig.body_length);
        let computed_body_hash = hash::compute_body_hash(&canonicalized_body, &sig.algorithm);

        if computed_body_hash != sig.body_hash {
            return DkimResult::Fail { reason: FailureReason::BodyHashMismatch };
        }

        // Compute header hash
        let header_data = hash::compute_header_hash_data(
            headers,
            &sig.signed_headers,
            sig_header_full,
            sig.canonicalization.header,
        );

        // Verify signature
        match crypto::verify_signature(&sig.algorithm, &public_key.public_key, &header_data, &sig.signature) {
            Ok(true) => DkimResult::Pass {
                domain: sig.domain.clone(),
                selector: sig.selector.clone(),
            },
            Ok(false) => DkimResult::Fail { reason: FailureReason::SignatureMismatch },
            Err(e) => DkimResult::PermFail { reason: e },
        }
    }
}

fn split_message(message: &str) -> (String, String) {
    // Handle both CRLF and LF line endings
    let separator = if message.contains("\r\n\r\n") {
        "\r\n\r\n"
    } else {
        "\n\n"
    };

    if let Some(pos) = message.find(separator) {
        let headers = &message[..pos];
        let body = &message[pos + separator.len()..];
        (headers.to_string(), body.to_string())
    } else {
        (message.to_string(), String::new())
    }
}

fn extract_dkim_signatures(headers: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let lines: Vec<&str> = headers.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        if line.to_lowercase().starts_with("dkim-signature:") {
            let mut full_header = line.to_string();
            let value_start = line.find(':').map(|p| p + 1).unwrap_or(0);
            let mut value = line[value_start..].to_string();

            // Handle folded headers
            while i + 1 < lines.len() && (lines[i + 1].starts_with(' ') || lines[i + 1].starts_with('\t')) {
                i += 1;
                full_header.push_str("\r\n");
                full_header.push_str(lines[i]);
                value.push(' ');
                value.push_str(lines[i].trim());
            }

            results.push((value.trim().to_string(), full_header));
        }
        i += 1;
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_message() {
        let msg = "From: test@example.com\r\nTo: recipient@example.com\r\n\r\nBody text";
        let (headers, body) = split_message(msg);
        assert!(headers.contains("From:"));
        assert_eq!(body, "Body text");
    }

    #[test]
    fn test_extract_dkim_signatures() {
        let headers = "From: test@example.com\r\nDKIM-Signature: v=1; a=rsa-sha256;\r\n\tb=abc123\r\nTo: recipient@example.com";
        let sigs = extract_dkim_signatures(headers);
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].0.contains("v=1"));
    }
}
