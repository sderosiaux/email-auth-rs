use super::parse::collect_arc_sets;
use super::{ArcResult, ArcSet, ArcValidationResult, ChainValidationStatus};
use crate::common::dns::{DnsError, DnsResolver};
use crate::dkim::canon::{canonicalize_body, canonicalize_header, select_headers, strip_b_tag};
use crate::dkim::key::{DkimPublicKey, KeyType};
use crate::dkim::{Algorithm, CanonicalizationMethod};
use ring::signature as ring_sig;
use subtle::ConstantTimeEq;

pub struct ArcVerifier<R: DnsResolver> {
    pub resolver: R,
}

impl<R: DnsResolver> ArcVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Validate an ARC chain.
    pub async fn validate_chain(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> ArcValidationResult {
        // Step 1: Collect ARC Sets
        let sets = match collect_arc_sets(headers) {
            Ok(s) => s,
            Err(e) => {
                return ArcValidationResult {
                    status: ArcResult::Fail { detail: e },
                    oldest_pass: None,
                }
            }
        };

        if sets.is_empty() {
            return ArcValidationResult {
                status: ArcResult::None,
                oldest_pass: None,
            };
        }

        let n = sets.len();
        if n > 50 {
            return ArcValidationResult {
                status: ArcResult::Fail {
                    detail: "more than 50 ARC sets".into(),
                },
                oldest_pass: None,
            };
        }

        // Step 2: Check latest cv value
        let latest = &sets[n - 1];
        if latest.seal.cv == ChainValidationStatus::Fail {
            return ArcValidationResult {
                status: ArcResult::Fail {
                    detail: format!("AS({n}) cv=fail"),
                },
                oldest_pass: None,
            };
        }

        // Step 3: Validate structure — cv constraints
        if let Err(e) = validate_cv_structure(&sets) {
            return ArcValidationResult {
                status: ArcResult::Fail { detail: e },
                oldest_pass: None,
            };
        }

        // Step 4: Validate most recent AMS
        if let Err(e) = self.validate_ams(headers, body, &sets[n - 1].ams).await {
            return ArcValidationResult {
                status: ArcResult::Fail {
                    detail: format!("AMS({n}) validation failed: {e}"),
                },
                oldest_pass: None,
            };
        }

        // Step 5: Determine oldest-pass (validate older AMS from N-1 down to 1)
        let mut oldest_pass = 0u32; // 0 = all pass
        for i in (0..n - 1).rev() {
            if let Err(_) = self.validate_ams(headers, body, &sets[i].ams).await {
                oldest_pass = sets[i].instance + 1;
                break;
            }
        }

        // Step 6: Validate all AS headers
        for i in (0..n).rev() {
            if let Err(e) = self.validate_seal(&sets, i).await {
                return ArcValidationResult {
                    status: ArcResult::Fail {
                        detail: format!("AS({}) validation failed: {e}", sets[i].instance),
                    },
                    oldest_pass: None,
                };
            }
        }

        // Step 7: Success
        ArcValidationResult {
            status: ArcResult::Pass,
            oldest_pass: Some(oldest_pass),
        }
    }

    /// Validate a single AMS using DKIM verification.
    async fn validate_ams(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        ams: &super::ArcMessageSignature,
    ) -> Result<(), String> {
        // DNS key lookup
        let query_name = format!("{}._domainkey.{}", ams.selector, ams.domain);
        let txt_records = match self.resolver.query_txt(&query_name).await {
            Ok(r) => r,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                return Err(format!("key not found: {query_name}"))
            }
            Err(DnsError::TempFail) => return Err(format!("DNS TempFail: {query_name}")),
        };

        let txt = txt_records.join("");
        let key = DkimPublicKey::parse(&txt).map_err(|e| format!("key parse: {e}"))?;

        if key.revoked {
            return Err("key revoked".into());
        }

        // Check key type matches algorithm
        match ams.algorithm {
            Algorithm::RsaSha1 | Algorithm::RsaSha256 => {
                if key.key_type != KeyType::Rsa {
                    return Err("algorithm/key type mismatch".into());
                }
            }
            Algorithm::Ed25519Sha256 => {
                if key.key_type != KeyType::Ed25519 {
                    return Err("algorithm/key type mismatch".into());
                }
            }
        }

        // Body hash verification
        let canon_body = canonicalize_body(body, ams.body_canonicalization);
        let hash_body = if let Some(len) = ams.body_length {
            &canon_body[..std::cmp::min(len as usize, canon_body.len())]
        } else {
            &canon_body
        };

        let computed_bh = compute_hash(ams.algorithm, hash_body);
        if computed_bh.ct_eq(&ams.body_hash).unwrap_u8() != 1 {
            return Err("body hash mismatch".into());
        }

        // Header hash
        let canon_headers = select_headers(
            headers,
            &ams.signed_headers,
            ams.header_canonicalization,
        );

        let mut hash_input = String::new();
        for h in &canon_headers {
            hash_input.push_str(h);
        }

        // Append AMS header with b= stripped
        let stripped = strip_b_tag(&ams.raw_value);
        let canon_sig =
            canonicalize_header("ARC-Message-Signature", &stripped, ams.header_canonicalization);
        let canon_sig = canon_sig.strip_suffix("\r\n").unwrap_or(&canon_sig);
        hash_input.push_str(canon_sig);

        // Verify signature
        verify_signature(
            ams.algorithm,
            &key.public_key,
            hash_input.as_bytes(),
            &ams.signature,
        )
    }

    /// Validate a single ARC-Seal.
    async fn validate_seal(&self, sets: &[ArcSet], idx: usize) -> Result<(), String> {
        let seal = &sets[idx].seal;

        // DNS key lookup
        let query_name = format!("{}._domainkey.{}", seal.selector, seal.domain);
        let txt_records = match self.resolver.query_txt(&query_name).await {
            Ok(r) => r,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                return Err(format!("key not found: {query_name}"))
            }
            Err(DnsError::TempFail) => return Err(format!("DNS TempFail: {query_name}")),
        };

        let txt = txt_records.join("");
        let key = DkimPublicKey::parse(&txt).map_err(|e| format!("key parse: {e}"))?;

        if key.revoked {
            return Err("key revoked".into());
        }

        // Build seal signature input: all ARC headers from sets 1..=idx+1 in order
        let hash_input = build_seal_hash_input(sets, idx);

        // Verify signature
        verify_signature(
            seal.algorithm,
            &key.public_key,
            hash_input.as_bytes(),
            &seal.signature,
        )
    }
}

/// Build the signature input for an ARC-Seal at the given index.
/// Includes all ARC Sets from 1 to idx+1, in order: AAR, AMS, AS per set.
/// The AS at idx has its b= value stripped.
/// Uses relaxed header canonicalization.
/// Last header has no trailing CRLF.
pub fn build_seal_hash_input(sets: &[ArcSet], idx: usize) -> String {
    let mut input = String::new();
    let method = CanonicalizationMethod::Relaxed;

    for i in 0..=idx {
        let set = &sets[i];

        // AAR
        let aar_canon = canonicalize_header(
            "ARC-Authentication-Results",
            &set.aar.raw_value,
            method,
        );
        input.push_str(&aar_canon);

        // AMS
        let ams_canon = canonicalize_header(
            "ARC-Message-Signature",
            &set.ams.raw_value,
            method,
        );
        input.push_str(&ams_canon);

        // AS
        if i < idx {
            // Previous seals: include as-is
            let as_canon = canonicalize_header("ARC-Seal", &set.seal.raw_value, method);
            input.push_str(&as_canon);
        } else {
            // Current seal: strip b= value, no trailing CRLF
            let stripped = strip_b_tag(&set.seal.raw_value);
            let as_canon = canonicalize_header("ARC-Seal", &stripped, method);
            let as_canon = as_canon.strip_suffix("\r\n").unwrap_or(&as_canon);
            input.push_str(as_canon);
        }
    }

    input
}

fn validate_cv_structure(sets: &[ArcSet]) -> Result<(), String> {
    for (i, set) in sets.iter().enumerate() {
        let expected_instance = (i + 1) as u32;
        if set.instance != expected_instance {
            return Err(format!(
                "instance gap: expected {expected_instance}, got {}",
                set.instance
            ));
        }

        if i == 0 {
            if set.seal.cv != ChainValidationStatus::None {
                return Err(format!(
                    "instance 1 cv must be 'none', got {:?}",
                    set.seal.cv
                ));
            }
        } else {
            if set.seal.cv != ChainValidationStatus::Pass {
                return Err(format!(
                    "instance {} cv must be 'pass', got {:?}",
                    set.instance, set.seal.cv
                ));
            }
        }
    }
    Ok(())
}

fn compute_hash(algorithm: Algorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            ring::digest::digest(&ring::digest::SHA256, data)
                .as_ref()
                .to_vec()
        }
        Algorithm::RsaSha1 => {
            ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
                .as_ref()
                .to_vec()
        }
    }
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
    async fn test_no_arc_sets() {
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&[], b"body").await;
        assert_eq!(result.status, ArcResult::None);
    }

    #[tokio::test]
    async fn test_cv_fail_immediate() {
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Authentication-Results", " i=1; mx.example.com; spf=pass"),
            ("ARC-Message-Signature", " i=1; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from"),
            ("ARC-Seal", " i=1; cv=fail; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
        ];
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    #[tokio::test]
    async fn test_cv_structure_instance1_must_be_none() {
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Authentication-Results", " i=1; mx.example.com; spf=pass"),
            ("ARC-Message-Signature", " i=1; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from"),
            ("ARC-Seal", " i=1; cv=pass; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
        ];
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    #[tokio::test]
    async fn test_instance_gap_fails() {
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Authentication-Results", " i=1; spf=pass"),
            ("ARC-Message-Signature", " i=1; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from"),
            ("ARC-Seal", " i=1; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
            // Gap: missing i=2
            ("ARC-Authentication-Results", " i=3; spf=pass"),
            ("ARC-Message-Signature", " i=3; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from"),
            ("ARC-Seal", " i=3; cv=pass; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
        ];
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }
}
