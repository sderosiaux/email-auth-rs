mod canon;
mod crypto;
mod hash;
mod key;
mod signature;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::common::dns::{DnsError, DnsResolver};

pub use key::{DkimPublicKey, KeyParseError, KeyType};
pub use signature::{Algorithm, Canonicalization, CanonicalizationMethod, DkimSignature, ParseError};

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

/// DKIM verifier
pub struct DkimVerifier<R: DnsResolver> {
    resolver: Arc<R>,
    clock_skew: u64, // Allowed clock skew in seconds
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            clock_skew: 300, // 5 minutes default
        }
    }

    /// Set allowed clock skew in seconds
    pub fn with_clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    /// Verify all DKIM signatures in message
    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult> {
        // Split message into headers and body
        let (headers, body) = split_message(message);

        // Find DKIM-Signature headers
        let signatures = find_dkim_signatures(&headers);

        if signatures.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::new();

        for (sig_header_value, sig) in signatures {
            let result = self.verify_signature(&headers, body, &sig_header_value, &sig).await;
            results.push(result);
        }

        results
    }

    async fn verify_signature(
        &self,
        headers: &str,
        body: &[u8],
        sig_header_value: &str,
        signature: &DkimSignature,
    ) -> DkimResult {
        // Check expiration
        if let Some(expiration) = signature.expiration {
            let now = current_timestamp();
            if now > expiration + self.clock_skew {
                return DkimResult::PermFail {
                    reason: "signature expired".to_string(),
                };
            }
        }

        // Check timestamp not in future
        if let Some(timestamp) = signature.timestamp {
            let now = current_timestamp();
            if timestamp > now + self.clock_skew {
                return DkimResult::Fail {
                    reason: FailureReason::FutureSignature,
                };
            }
        }

        // Lookup public key
        let key = match self.lookup_key(&signature.domain, &signature.selector).await {
            Ok(k) => k,
            Err(KeyLookupError::NotFound) => {
                return DkimResult::PermFail {
                    reason: "key not found".to_string(),
                };
            }
            Err(KeyLookupError::Revoked) => {
                return DkimResult::Fail {
                    reason: FailureReason::KeyRevoked,
                };
            }
            Err(KeyLookupError::DnsError(e)) => {
                return DkimResult::TempFail {
                    reason: format!("DNS error: {}", e),
                };
            }
            Err(KeyLookupError::ParseError(e)) => {
                return DkimResult::PermFail {
                    reason: format!("key parse error: {}", e),
                };
            }
        };

        // Check hash algorithm restriction
        let hash_alg = match signature.algorithm {
            Algorithm::RsaSha1 => "sha1",
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => "sha256",
        };
        if !key.allows_hash(hash_alg) {
            return DkimResult::Fail {
                reason: FailureReason::AlgorithmMismatch,
            };
        }

        // Verify body hash
        let computed_body_hash = hash::compute_body_hash(
            body,
            signature.algorithm,
            signature.canonicalization.body,
            signature.body_length,
        );

        if computed_body_hash != signature.body_hash {
            return DkimResult::Fail {
                reason: FailureReason::BodyHashMismatch,
            };
        }

        // Compute header hash
        let header_hash = hash::compute_header_hash(headers, signature, sig_header_value);

        // Verify signature
        match crypto::verify_signature(signature.algorithm, &key, &header_hash, &signature.signature) {
            Ok(()) => DkimResult::Pass {
                domain: signature.domain.clone(),
                selector: signature.selector.clone(),
            },
            Err(crypto::CryptoError::AlgorithmMismatch) => DkimResult::Fail {
                reason: FailureReason::AlgorithmMismatch,
            },
            Err(_) => DkimResult::Fail {
                reason: FailureReason::SignatureMismatch,
            },
        }
    }

    async fn lookup_key(&self, domain: &str, selector: &str) -> Result<DkimPublicKey, KeyLookupError> {
        let query = format!("{}._domainkey.{}", selector, domain);

        let records = self.resolver.query_txt(&query).await.map_err(|e| match e {
            DnsError::NxDomain(_) => KeyLookupError::NotFound,
            _ => KeyLookupError::DnsError(e.to_string()),
        })?;

        if records.is_empty() {
            return Err(KeyLookupError::NotFound);
        }

        // Concatenate multiple TXT strings
        let txt = records.join("");

        DkimPublicKey::parse(&txt).map_err(|e| match e {
            KeyParseError::KeyRevoked => KeyLookupError::Revoked,
            _ => KeyLookupError::ParseError(e.to_string()),
        })
    }
}

#[derive(Debug)]
enum KeyLookupError {
    NotFound,
    Revoked,
    DnsError(String),
    ParseError(String),
}

/// DKIM signer configuration
#[derive(Debug, Clone)]
pub struct SigningConfig {
    pub domain: String,
    pub selector: String,
    pub headers: Vec<String>,
    pub algorithm: Algorithm,
    pub canonicalization: Canonicalization,
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            selector: String::new(),
            headers: vec![
                "from".to_string(),
                "to".to_string(),
                "subject".to_string(),
                "date".to_string(),
            ],
            algorithm: Algorithm::RsaSha256,
            canonicalization: Canonicalization::default(),
        }
    }
}

/// DKIM signer (placeholder - implement in M4)
pub struct DkimSigner {
    _config: SigningConfig,
}

impl DkimSigner {
    pub fn sign(&self, _message: &[u8]) -> Result<String, SignError> {
        // TODO: Implement in M4
        Err(SignError::NotImplemented)
    }
}

#[derive(Debug)]
pub enum SignError {
    NotImplemented,
}

/// Split message into headers and body
fn split_message(message: &[u8]) -> (String, &[u8]) {
    // Find blank line separating headers from body
    let mut i = 0;
    while i < message.len() {
        // Look for CRLF CRLF or LF LF
        if i + 3 < message.len()
            && message[i] == b'\r'
            && message[i + 1] == b'\n'
            && message[i + 2] == b'\r'
            && message[i + 3] == b'\n'
        {
            let headers = String::from_utf8_lossy(&message[..i + 2]).into_owned();
            let body = &message[i + 4..];
            return (headers, body);
        }
        if i + 1 < message.len() && message[i] == b'\n' && message[i + 1] == b'\n' {
            let headers = String::from_utf8_lossy(&message[..i + 1]).into_owned();
            let body = &message[i + 2..];
            return (headers, body);
        }
        i += 1;
    }

    // No body
    (String::from_utf8_lossy(message).into_owned(), &[])
}

/// Find all DKIM-Signature headers in message
fn find_dkim_signatures(headers: &str) -> Vec<(String, DkimSignature)> {
    let mut signatures = Vec::new();
    let mut current_header_name = String::new();
    let mut current_header_value = String::new();
    let mut in_dkim_sig = false;

    for line in headers.lines() {
        // Check if continuation line
        if line.starts_with(' ') || line.starts_with('\t') {
            if in_dkim_sig {
                current_header_value.push_str(line);
            }
            continue;
        }

        // End previous header
        if in_dkim_sig && !current_header_value.is_empty() {
            if let Ok(sig) = DkimSignature::parse(&current_header_value) {
                signatures.push((current_header_value.clone(), sig));
            }
        }

        // Check if new header is DKIM-Signature
        if let Some(colon_pos) = line.find(':') {
            current_header_name = line[..colon_pos].to_string();
            current_header_value = line[colon_pos + 1..].to_string();
            in_dkim_sig = current_header_name.eq_ignore_ascii_case("DKIM-Signature");
        } else {
            in_dkim_sig = false;
        }
    }

    // Handle last header
    if in_dkim_sig && !current_header_value.is_empty() {
        if let Ok(sig) = DkimSignature::parse(&current_header_value) {
            signatures.push((current_header_value, sig));
        }
    }

    signatures
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_message() {
        let message = b"From: test@example.com\r\nTo: other@example.com\r\n\r\nBody here";
        let (headers, body) = split_message(message);
        assert!(headers.contains("From:"));
        assert_eq!(body, b"Body here");
    }

    #[test]
    fn test_find_dkim_signatures() {
        // Use proper header format without extra indentation
        let headers = "From: test@example.com\r\n\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=AAAA; b=BBBB\r\n\
To: other@example.com\r\n";

        let sigs = find_dkim_signatures(headers);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].1.domain, "example.com");
    }
}
