use crate::common::dns::{DnsError, DnsResolver};
use super::canon::{canonicalize_body, canonicalize_header, select_headers, strip_b_tag};
use super::key::{DkimPublicKey, KeyType};
use super::signature::DkimSignature;
use super::{Algorithm, DkimResult, FailureKind, PermFailKind};
use ring::signature as ring_sig;
use subtle::ConstantTimeEq;

pub struct DkimVerifier<R: DnsResolver> {
    pub resolver: R,
    pub clock_skew: u64,
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            clock_skew: 300,
        }
    }

    pub fn clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    /// Verify all DKIM-Signature headers in a message.
    pub async fn verify_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<DkimResult> {
        // Find all DKIM-Signature headers
        let dkim_sigs: Vec<(usize, &str, &str)> = headers
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| name.eq_ignore_ascii_case("DKIM-Signature"))
            .map(|(i, (name, value))| (i, *name, *value))
            .collect();

        if dkim_sigs.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::new();
        for (_idx, _name, value) in &dkim_sigs {
            let result = self.verify_single_signature(headers, body, value).await;
            results.push(result);
        }
        results
    }

    async fn verify_single_signature(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        sig_header_value: &str,
    ) -> DkimResult {
        // Parse signature
        let sig = match DkimSignature::parse(sig_header_value) {
            Ok(s) => s,
            Err(e) => {
                return DkimResult::PermFail {
                    kind: PermFailKind::MalformedSignature,
                    detail: e.to_string(),
                }
            }
        };

        // Check expiration before DNS lookup
        if let Some(exp) = sig.expiration {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > exp + self.clock_skew {
                return DkimResult::PermFail {
                    kind: PermFailKind::ExpiredSignature,
                    detail: format!("expired at {exp}, now {now}"),
                };
            }
        }

        // DNS key lookup
        let query_name = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let txt_records = match self.resolver.query_txt(&query_name).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) => {
                return DkimResult::PermFail {
                    kind: PermFailKind::KeyNotFound,
                    detail: format!("NXDOMAIN for {query_name}"),
                }
            }
            Err(DnsError::NoRecords) => {
                return DkimResult::PermFail {
                    kind: PermFailKind::KeyNotFound,
                    detail: format!("no TXT records for {query_name}"),
                }
            }
            Err(DnsError::TempFail) => {
                return DkimResult::TempFail {
                    reason: format!("DNS TempFail for {query_name}"),
                }
            }
        };

        // Concatenate multiple TXT strings
        let txt = txt_records.join("");

        let key = match DkimPublicKey::parse(&txt) {
            Ok(k) => k,
            Err(e) => {
                return DkimResult::PermFail {
                    kind: PermFailKind::KeyNotFound,
                    detail: format!("key parse error: {e}"),
                }
            }
        };

        // Key constraint checks (ordered)
        if key.revoked {
            return DkimResult::PermFail {
                kind: PermFailKind::KeyRevoked,
                detail: "empty p= tag".into(),
            };
        }

        if !key.allows_hash(sig.algorithm) {
            return DkimResult::PermFail {
                kind: PermFailKind::HashNotPermitted,
                detail: "key h= tag rejects this algorithm".into(),
            };
        }

        if !key.allows_email() {
            return DkimResult::PermFail {
                kind: PermFailKind::ServiceTypeMismatch,
                detail: "key s= tag doesn't include email or *".into(),
            };
        }

        if key.is_strict() {
            let i_domain = crate::common::domain::domain_from_email(&sig.auid)
                .unwrap_or(&sig.auid);
            if !crate::common::domain::domains_equal(i_domain, &sig.domain) {
                return DkimResult::PermFail {
                    kind: PermFailKind::StrictModeViolation,
                    detail: format!("t=s but i= domain '{i_domain}' != d= '{}'", sig.domain),
                };
            }
        }

        // Check key type matches algorithm
        let key_type_ok = match sig.algorithm {
            Algorithm::RsaSha1 | Algorithm::RsaSha256 => key.key_type == KeyType::Rsa,
            Algorithm::Ed25519Sha256 => key.key_type == KeyType::Ed25519,
        };
        if !key_type_ok {
            return DkimResult::PermFail {
                kind: PermFailKind::AlgorithmMismatch,
                detail: format!(
                    "algorithm {:?} incompatible with key type {:?}",
                    sig.algorithm, key.key_type
                ),
            };
        }

        // Body hash verification
        let canon_body = canonicalize_body(body, sig.body_canonicalization);
        let hash_body = if let Some(len) = sig.body_length {
            &canon_body[..std::cmp::min(len as usize, canon_body.len())]
        } else {
            &canon_body
        };

        let computed_body_hash = compute_hash(sig.algorithm, hash_body);

        // Constant-time comparison
        if computed_body_hash.ct_eq(&sig.body_hash).unwrap_u8() != 1 {
            return DkimResult::Fail {
                kind: FailureKind::BodyHashMismatch,
                detail: "computed body hash does not match bh= value".into(),
            };
        }

        // Header hash computation
        let header_data = build_header_hash_input(
            headers,
            &sig,
            sig_header_value,
        );

        // Cryptographic verification
        let verify_result = verify_signature(
            sig.algorithm,
            &key.public_key,
            header_data.as_bytes(),
            &sig.signature,
        );

        if let Err(detail) = verify_result {
            return DkimResult::Fail {
                kind: FailureKind::SignatureVerificationFailed,
                detail,
            };
        }

        DkimResult::Pass {
            domain: sig.domain.clone(),
            selector: sig.selector.clone(),
            testing: key.is_testing(),
        }
    }
}

fn compute_hash(algorithm: Algorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            let digest = ring::digest::digest(&ring::digest::SHA256, data);
            digest.as_ref().to_vec()
        }
        Algorithm::RsaSha1 => {
            let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
            digest.as_ref().to_vec()
        }
    }
}

fn build_header_hash_input(
    headers: &[(&str, &str)],
    sig: &DkimSignature,
    sig_header_value: &str,
) -> String {
    // Select and canonicalize signed headers
    let canon_headers = select_headers(
        headers,
        &sig.signed_headers,
        sig.header_canonicalization,
    );

    let mut input = String::new();
    for h in &canon_headers {
        input.push_str(h);
    }

    // Append DKIM-Signature header with b= stripped, WITHOUT trailing CRLF
    let stripped = strip_b_tag(sig_header_value);
    let canon_sig = canonicalize_header("DKIM-Signature", &stripped, sig.header_canonicalization);
    // Remove trailing CRLF (spec: last header has no CRLF)
    let canon_sig = canon_sig.strip_suffix("\r\n").unwrap_or(&canon_sig);
    input.push_str(canon_sig);

    input
}

fn verify_signature(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    match algorithm {
        Algorithm::RsaSha256 => {
            let ring_algo = if public_key.len() < 256 {
                &ring_sig::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
            } else {
                &ring_sig::RSA_PKCS1_2048_8192_SHA256
            };
            let key = ring_sig::UnparsedPublicKey::new(ring_algo, public_key);
            key.verify(message, signature)
                .map_err(|e| format!("RSA-SHA256 verification failed: {e}"))
        }
        Algorithm::RsaSha1 => {
            let ring_algo = if public_key.len() < 256 {
                &ring_sig::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
            } else {
                &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
            };
            let key = ring_sig::UnparsedPublicKey::new(ring_algo, public_key);
            key.verify(message, signature)
                .map_err(|e| format!("RSA-SHA1 verification failed: {e}"))
        }
        Algorithm::Ed25519Sha256 => {
            let key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, public_key);
            key.verify(message, signature)
                .map_err(|e| format!("Ed25519 verification failed: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[tokio::test]
    async fn test_no_dkim_signature() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![("From", " user@example.com")];
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], DkimResult::None);
    }

    #[tokio::test]
    async fn test_key_revoked() {
        let resolver = MockResolver::new().with_txt(
            "sel1._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; p="],
        );
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::KeyRevoked,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_key_not_found() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::KeyNotFound,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_dns_temp_fail() {
        let resolver = MockResolver::new()
            .with_txt_err("sel1._domainkey.example.com", DnsError::TempFail);
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert!(matches!(results[0], DkimResult::TempFail { .. }));
    }

    #[tokio::test]
    async fn test_malformed_signature() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " garbage"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::MalformedSignature,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_hash_not_permitted() {
        let resolver = MockResolver::new().with_txt(
            "sel1._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; h=sha256; p=dGVzdA=="],
        );
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha1; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::HashNotPermitted,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_service_type_mismatch() {
        let resolver = MockResolver::new().with_txt(
            "sel1._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; s=other; p=dGVzdA=="],
        );
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::ServiceTypeMismatch,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_algorithm_key_type_mismatch() {
        let resolver = MockResolver::new().with_txt(
            "sel1._domainkey.example.com",
            vec!["v=DKIM1; k=ed25519; p=dGVzdA=="],
        );
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::AlgorithmMismatch,
                ..
            }
        ));
    }
}
