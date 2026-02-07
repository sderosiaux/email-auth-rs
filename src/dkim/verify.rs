use ring::signature;
use subtle::ConstantTimeEq;

use crate::common::dns::{DnsError, DnsResolver};
use super::canon;
use super::key::DkimPublicKey;
use super::signature::DkimSignature;
use super::{
    Algorithm, DkimResult, FailureKind, HashAlgorithm, KeyFlag,
    KeyType, PermFailKind,
};

/// DKIM signature verifier.
pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
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

    /// Verify all DKIM signatures in a message.
    /// Returns one result per DKIM-Signature header, or single None if no signatures.
    pub async fn verify_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<DkimResult> {
        // Find all DKIM-Signature headers
        let dkim_sigs: Vec<(usize, &str, &str)> = headers
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| name.eq_ignore_ascii_case("dkim-signature"))
            .map(|(i, (name, value))| (i, *name, *value))
            .collect();

        if dkim_sigs.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::new();
        for (_, _, sig_value) in &dkim_sigs {
            let result = self.verify_single(headers, body, sig_value).await;
            results.push(result);
        }
        results
    }

    async fn verify_single(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        sig_value: &str,
    ) -> DkimResult {
        // Parse signature
        let sig = match DkimSignature::parse(sig_value) {
            Ok(s) => s,
            Err(e) => {
                return DkimResult::PermFail {
                    kind: PermFailKind::MalformedSignature,
                    detail: e,
                }
            }
        };

        // Check expiration before DNS lookup
        if let Some(expiration) = sig.expiration {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > expiration + self.clock_skew {
                return DkimResult::PermFail {
                    kind: PermFailKind::ExpiredSignature,
                    detail: format!("signature expired at {}", expiration),
                };
            }
        }

        // i= domain check
        if let Some(i_domain) = crate::common::domain::domain_from_email(&sig.auid) {
            if !crate::common::domain::is_subdomain_of(i_domain, &sig.domain) {
                return DkimResult::PermFail {
                    kind: PermFailKind::DomainMismatch,
                    detail: format!("i= {} not subdomain of d= {}", sig.auid, sig.domain),
                };
            }
        }

        // DNS key lookup
        let key_domain = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let txt_records = match self.resolver.query_txt(&key_domain).await {
            Ok(records) => records,
            Err(DnsError::NxDomain | DnsError::NoRecords) => {
                return DkimResult::PermFail {
                    kind: PermFailKind::KeyNotFound,
                    detail: format!("no key record at {}", key_domain),
                }
            }
            Err(DnsError::TempFail(msg)) => {
                return DkimResult::TempFail {
                    reason: format!("DNS error for {}: {}", key_domain, msg),
                }
            }
        };

        // Concatenate TXT strings
        let txt = txt_records.join("");

        // Parse key record
        let key = match DkimPublicKey::parse(&txt) {
            Ok(k) => k,
            Err(e) => {
                return DkimResult::PermFail {
                    kind: PermFailKind::KeyNotFound,
                    detail: format!("key parse error: {}", e),
                }
            }
        };

        // Key constraint checks (ordered per spec)
        // a. Empty p= -> revoked
        if key.revoked {
            return DkimResult::PermFail {
                kind: PermFailKind::KeyRevoked,
                detail: "key revoked (empty p=)".to_string(),
            };
        }

        // b. Key h= tag constraint
        if let Some(ref hashes) = key.hash_algorithms {
            let sig_hash = match sig.algorithm {
                Algorithm::RsaSha1 => HashAlgorithm::Sha1,
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => HashAlgorithm::Sha256,
            };
            if !hashes.contains(&sig_hash) {
                return DkimResult::PermFail {
                    kind: PermFailKind::HashNotPermitted,
                    detail: format!("key h= does not allow {:?}", sig_hash),
                };
            }
        }

        // c. Key s= tag constraint
        if !key.service_types.iter().any(|s| s == "*" || s == "email") {
            return DkimResult::PermFail {
                kind: PermFailKind::ServiceTypeMismatch,
                detail: "key s= does not include email or *".to_string(),
            };
        }

        // d. Key t=s strict mode
        if key.flags.contains(&KeyFlag::Strict) {
            let i_domain = crate::common::domain::domain_from_email(&sig.auid).unwrap_or("");
            if !crate::common::domain::domains_equal(i_domain, &sig.domain) {
                return DkimResult::PermFail {
                    kind: PermFailKind::StrictModeViolation,
                    detail: format!(
                        "strict mode: i= domain {} must exactly equal d= {}",
                        i_domain, sig.domain
                    ),
                };
            }
        }

        // e. Key type / algorithm compatibility
        if !matches!(
            (sig.algorithm, key.key_type),
            (Algorithm::RsaSha1, KeyType::Rsa)
                | (Algorithm::RsaSha256, KeyType::Rsa)
                | (Algorithm::Ed25519Sha256, KeyType::Ed25519)
        ) {
            return DkimResult::PermFail {
                kind: PermFailKind::AlgorithmMismatch,
                detail: format!(
                    "algorithm {:?} incompatible with key type {:?}",
                    sig.algorithm, key.key_type
                ),
            };
        }

        // Body hash verification
        let canon_body = canon::canonicalize_body(body, sig.body_canonicalization, sig.body_length);
        let computed_body_hash = match sig.algorithm {
            Algorithm::RsaSha1 => {
                ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &canon_body)
                    .as_ref()
                    .to_vec()
            }
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                ring::digest::digest(&ring::digest::SHA256, &canon_body)
                    .as_ref()
                    .to_vec()
            }
        };

        // Constant-time comparison
        if computed_body_hash.ct_eq(&sig.body_hash).unwrap_u8() != 1 {
            return DkimResult::Fail {
                kind: FailureKind::BodyHashMismatch,
                detail: "computed body hash does not match bh=".to_string(),
            };
        }

        // Header hash computation
        let canon_headers =
            canon::select_headers(headers, &sig.signed_headers, sig.header_canonicalization);

        let mut hash_input = Vec::new();
        for h in &canon_headers {
            hash_input.extend_from_slice(h.as_bytes());
        }

        // Append DKIM-Signature header with b= stripped, WITHOUT trailing CRLF
        let stripped = canon::strip_b_tag(&sig.raw_header);
        let dkim_sig_canon = canon::canonicalize_header(
            "dkim-signature",
            &stripped,
            sig.header_canonicalization,
        );
        // Remove trailing CRLF from DKIM-Signature
        let dkim_sig_canon = if dkim_sig_canon.ends_with("\r\n") {
            &dkim_sig_canon[..dkim_sig_canon.len() - 2]
        } else {
            &dkim_sig_canon
        };
        hash_input.extend_from_slice(dkim_sig_canon.as_bytes());

        // Signature verification — pass RAW data to ring (ring hashes internally)
        let verify_result = match sig.algorithm {
            Algorithm::RsaSha256 => {
                let algo = if key.public_key.len() < 256 {
                    &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
                } else {
                    &signature::RSA_PKCS1_2048_8192_SHA256
                };
                let public_key = signature::UnparsedPublicKey::new(algo, &key.public_key);
                public_key.verify(&hash_input, &sig.signature)
            }
            Algorithm::RsaSha1 => {
                let algo = if key.public_key.len() < 256 {
                    &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
                } else {
                    &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
                };
                let public_key = signature::UnparsedPublicKey::new(algo, &key.public_key);
                public_key.verify(&hash_input, &sig.signature)
            }
            Algorithm::Ed25519Sha256 => {
                let public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, &key.public_key);
                public_key.verify(&hash_input, &sig.signature)
            }
        };

        match verify_result {
            Ok(()) => {
                let testing = key.flags.contains(&KeyFlag::Testing);
                DkimResult::Pass {
                    domain: sig.domain,
                    selector: sig.selector,
                    testing,
                }
            }
            Err(_) => DkimResult::Fail {
                kind: FailureKind::SignatureVerificationFailed,
                detail: "cryptographic signature verification failed".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[tokio::test]
    async fn test_no_signatures() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![("From", " user@example.com")];
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], DkimResult::None));
    }

    #[tokio::test]
    async fn test_malformed_signature() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::MalformedSignature,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_key_not_found() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::KeyNotFound,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_key_revoked() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; p=".to_string()],
        );
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0],
            DkimResult::PermFail {
                kind: PermFailKind::KeyRevoked,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_dns_tempfail() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_tempfail("sel1._domainkey.example.com", "timeout");
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from"),
            ("From", " user@example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], DkimResult::TempFail { .. }));
    }
}
