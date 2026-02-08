use crate::common::dns::{DnsError, DnsResolver};
use crate::dkim::canon::{
    apply_body_length_limit, canonicalize_body, canonicalize_header, normalize_line_endings,
    select_headers, strip_b_tag_value,
};
use crate::dkim::key::DkimPublicKey;
use crate::dkim::types::CanonicalizationMethod;
use crate::dkim::verify::{compute_hash, verify_signature};

use subtle::ConstantTimeEq;

use super::parser::collect_arc_sets;
use super::types::{
    ArcMessageSignature, ArcResult, ArcSeal, ArcSet, ArcValidationResult,
    ChainValidationStatus,
};

/// ARC chain verifier.
pub struct ArcVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> ArcVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Validate the ARC chain in a message.
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
                    status: ArcResult::Fail {
                        reason: e.detail,
                    },
                    oldest_pass: Option::None,
                };
            }
        };

        // No ARC headers → None
        if sets.is_empty() {
            return ArcValidationResult {
                status: ArcResult::None,
                oldest_pass: Option::None,
            };
        }

        let n = sets.len();

        // Step 1b: >50 sets
        if n > 50 {
            return ArcValidationResult {
                status: ArcResult::Fail {
                    reason: format!("too many ARC sets: {}", n),
                },
                oldest_pass: Option::None,
            };
        }

        // Step 2: Check latest cv value
        let latest = &sets[n - 1];
        if latest.seal.cv == ChainValidationStatus::Fail {
            return ArcValidationResult {
                status: ArcResult::Fail {
                    reason: format!("AS({}) has cv=fail", n),
                },
                oldest_pass: Option::None,
            };
        }

        // Step 3: Validate structure
        if let Err(reason) = validate_structure(&sets) {
            return ArcValidationResult {
                status: ArcResult::Fail { reason },
                oldest_pass: Option::None,
            };
        }

        // Step 4: Validate most recent AMS (N)
        if let Err(reason) = self.validate_ams(&sets[n - 1].ams, headers, body).await {
            return ArcValidationResult {
                status: ArcResult::Fail {
                    reason: format!("AMS({}) validation failed: {}", n, reason),
                },
                oldest_pass: Option::None,
            };
        }

        // Step 5: Determine oldest-pass (optional, validate remaining AMS)
        let mut oldest_pass: u32 = 0;
        for i in (0..n - 1).rev() {
            if let Err(_) = self.validate_ams(&sets[i].ams, headers, body).await {
                oldest_pass = (i + 2) as u32; // i is 0-based, instance is 1-based
                break;
            }
        }

        // Step 6: Validate all AS headers
        for i in (0..n).rev() {
            if let Err(reason) = self.validate_seal(&sets[i].seal, &sets, headers).await {
                return ArcValidationResult {
                    status: ArcResult::Fail {
                        reason: format!("AS({}) validation failed: {}", i + 1, reason),
                    },
                    oldest_pass: Option::None,
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
        ams: &ArcMessageSignature,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(), String> {
        // Body hash
        let normalized = normalize_line_endings(body);
        let canonicalized = canonicalize_body(ams.body_canonicalization, &normalized);
        let limited = apply_body_length_limit(&canonicalized, ams.body_length);
        let computed_body_hash = compute_hash(ams.algorithm, limited);

        if !bool::from(computed_body_hash.ct_eq(&ams.body_hash)) {
            return Err("body hash mismatch".to_string());
        }

        // Header hash: select headers per h=, then append AMS header with b= stripped
        // Filter out ALL ARC headers and the current AMS header from header selection
        let non_arc_headers: Vec<(&str, &str)> = headers
            .iter()
            .filter(|(name, _)| {
                let lower = name.to_ascii_lowercase();
                lower != "arc-authentication-results"
                    && lower != "arc-message-signature"
                    && lower != "arc-seal"
            })
            .copied()
            .collect();

        let selected = select_headers(
            ams.header_canonicalization,
            &ams.signed_headers,
            &non_arc_headers,
        );

        let mut hash_input = Vec::new();
        for header_line in &selected {
            hash_input.extend_from_slice(header_line.as_bytes());
        }

        // Append canonicalized AMS header with b= stripped, NO trailing CRLF
        let stripped = strip_b_tag_value(&ams.raw_header);
        let canon_ams = canonicalize_header(
            ams.header_canonicalization,
            "arc-message-signature",
            &stripped,
        );
        hash_input.extend_from_slice(canon_ams.as_bytes());

        // DNS key lookup
        let key = self.lookup_key(&ams.selector, &ams.domain).await?;

        // Crypto verification
        verify_signature(&ams.algorithm, &key, &hash_input, &ams.signature)
    }

    /// Validate a single ARC-Seal.
    async fn validate_seal(
        &self,
        seal: &ArcSeal,
        sets: &[ArcSet],
        _headers: &[(&str, &str)],
    ) -> Result<(), String> {
        let instance = seal.instance as usize;

        // Build signature input: all ARC Sets from 1 to instance
        let mut hash_input = Vec::new();

        for set_idx in 0..instance {
            let set = &sets[set_idx];

            // AAR
            let aar_canon = canonicalize_header(
                CanonicalizationMethod::Relaxed,
                "arc-authentication-results",
                &set.aar.raw_header,
            );
            hash_input.extend_from_slice(aar_canon.as_bytes());

            // AMS
            let ams_canon = canonicalize_header(
                CanonicalizationMethod::Relaxed,
                "arc-message-signature",
                &set.ams.raw_header,
            );
            hash_input.extend_from_slice(ams_canon.as_bytes());

            // AS — strip b= from the AS being validated (last one), keep b= for others
            if set_idx == instance - 1 {
                // This is the AS being validated — strip b= and NO trailing CRLF
                let stripped = strip_b_tag_value(&set.seal.raw_header);
                let canon_seal = canonicalize_header(
                    CanonicalizationMethod::Relaxed,
                    "arc-seal",
                    &stripped,
                );
                // Remove trailing CRLF from the last header
                let seal_bytes = canon_seal.as_bytes();
                if seal_bytes.ends_with(b"\r\n") {
                    hash_input.extend_from_slice(&seal_bytes[..seal_bytes.len() - 2]);
                } else {
                    hash_input.extend_from_slice(seal_bytes);
                }
            } else {
                let seal_canon = canonicalize_header(
                    CanonicalizationMethod::Relaxed,
                    "arc-seal",
                    &set.seal.raw_header,
                );
                hash_input.extend_from_slice(seal_canon.as_bytes());
            }
        }

        // DNS key lookup
        let key = self.lookup_key(&seal.selector, &seal.domain).await?;

        // Crypto verification
        verify_signature(&seal.algorithm, &key, &hash_input, &seal.signature)
    }

    /// DNS key lookup for ARC (same as DKIM).
    async fn lookup_key(&self, selector: &str, domain: &str) -> Result<DkimPublicKey, String> {
        let query = format!("{}._domainkey.{}", selector, domain);
        let txt_records = match self.resolver.query_txt(&query).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                return Err(format!("no DNS key record at {}", query));
            }
            Err(DnsError::TempFail) => {
                return Err(format!("DNS temp failure for {}", query));
            }
        };

        let concatenated = txt_records.join("");
        DkimPublicKey::parse(&concatenated).map_err(|e| e.detail)
    }
}

/// Validate structural integrity of ARC Sets.
fn validate_structure(sets: &[ArcSet]) -> Result<(), String> {
    for (idx, set) in sets.iter().enumerate() {
        let expected_instance = (idx + 1) as u32;
        if set.instance != expected_instance {
            return Err(format!(
                "expected instance {}, got {}",
                expected_instance, set.instance
            ));
        }

        // Instance 1: cv=none
        if set.instance == 1 && set.seal.cv != ChainValidationStatus::None {
            return Err(format!(
                "instance 1 must have cv=none, got {:?}",
                set.seal.cv
            ));
        }

        // Instance >1: cv=pass
        if set.instance > 1 && set.seal.cv != ChainValidationStatus::Pass {
            return Err(format!(
                "instance {} must have cv=pass, got {:?}",
                set.instance, set.seal.cv
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arc::types::ArcAuthenticationResults;
    use crate::common::dns::mock::MockResolver;
    use crate::dkim::types::Algorithm;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn gen_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), public_key)
    }

    fn ed25519_sign(pkcs8: &[u8], data: &[u8]) -> Vec<u8> {
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8).unwrap();
        key_pair.sign(data).as_ref().to_vec()
    }

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    fn make_dns_key_record(public_key: &[u8]) -> String {
        format!("v=DKIM1; k=ed25519; p={}", b64(public_key))
    }

    /// Build a complete single-hop ARC set with real signatures.
    /// Returns (headers, resolver) ready for validation.
    fn build_single_arc_set(
    ) -> (Vec<(String, String)>, MockResolver, Vec<u8>, Vec<u8>) {
        let (pkcs8, pub_key) = gen_ed25519_keypair();

        let body = b"Hello, world!\r\n";
        let message_headers = vec![
            ("From".to_string(), "sender@example.com".to_string()),
            ("To".to_string(), "recipient@example.com".to_string()),
            ("Subject".to_string(), "test".to_string()),
        ];

        // Compute body hash (relaxed canonicalization)
        let normalized = normalize_line_endings(body);
        let canonicalized = canonicalize_body(CanonicalizationMethod::Relaxed, &normalized);
        let body_hash = compute_hash(Algorithm::Ed25519Sha256, &canonicalized);

        // Build AMS header (without b= value first)
        let ams_raw_no_b = format!(
            "i=1; a=ed25519-sha256; d=sealer.com; s=arc; c=relaxed/relaxed; h=from:to:subject; bh={}; b=",
            b64(&body_hash)
        );

        // Compute AMS signature
        let non_arc_headers: Vec<(&str, &str)> = message_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();

        let selected = select_headers(
            CanonicalizationMethod::Relaxed,
            &["from".to_string(), "to".to_string(), "subject".to_string()],
            &non_arc_headers,
        );
        let mut ams_hash_input = Vec::new();
        for h in &selected {
            ams_hash_input.extend_from_slice(h.as_bytes());
        }
        let canon_ams = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "arc-message-signature",
            &ams_raw_no_b,
        );
        ams_hash_input.extend_from_slice(canon_ams.as_bytes());

        let ams_sig = ed25519_sign(&pkcs8, &ams_hash_input);
        let ams_raw = format!(
            "i=1; a=ed25519-sha256; d=sealer.com; s=arc; c=relaxed/relaxed; h=from:to:subject; bh={}; b={}",
            b64(&body_hash),
            b64(&ams_sig),
        );

        // Build AAR
        let aar_raw = "i=1; spf=pass smtp.mailfrom=example.com".to_string();

        // Build AS (seal)
        let seal_raw_no_b =
            "i=1; cv=none; a=ed25519-sha256; d=sealer.com; s=arc; b=".to_string();

        // AS signature input: AAR → AMS → AS(b= stripped, no trailing CRLF)
        let mut seal_hash_input = Vec::new();
        let canon_aar = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "arc-authentication-results",
            &aar_raw,
        );
        seal_hash_input.extend_from_slice(canon_aar.as_bytes());
        let canon_ams_full = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "arc-message-signature",
            &ams_raw,
        );
        seal_hash_input.extend_from_slice(canon_ams_full.as_bytes());
        let canon_seal = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "arc-seal",
            &seal_raw_no_b,
        );
        // Remove trailing CRLF
        let seal_bytes = canon_seal.as_bytes();
        if seal_bytes.ends_with(b"\r\n") {
            seal_hash_input.extend_from_slice(&seal_bytes[..seal_bytes.len() - 2]);
        } else {
            seal_hash_input.extend_from_slice(seal_bytes);
        }

        let seal_sig = ed25519_sign(&pkcs8, &seal_hash_input);
        let seal_raw = format!(
            "i=1; cv=none; a=ed25519-sha256; d=sealer.com; s=arc; b={}",
            b64(&seal_sig),
        );

        // Build complete headers (ARC headers + message headers)
        let mut all_headers = vec![
            ("ARC-Seal".to_string(), seal_raw),
            ("ARC-Message-Signature".to_string(), ams_raw),
            ("ARC-Authentication-Results".to_string(), aar_raw),
        ];
        all_headers.extend(message_headers);

        // Set up DNS
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "arc._domainkey.sealer.com",
            vec![make_dns_key_record(&pub_key)],
        );

        (all_headers, resolver, body.to_vec(), pkcs8)
    }

    // ─── CHK-825: No ARC headers → None ──────────────────────────────

    #[tokio::test]
    async fn no_arc_headers_none() {
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let headers = vec![("From", "test@example.com")];
        let result = verifier.validate_chain(&headers, b"body").await;
        assert_eq!(result.status, ArcResult::None);
    }

    // ─── CHK-828: Highest cv=fail → Fail immediately ─────────────────

    #[tokio::test]
    async fn latest_cv_fail_immediately() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=fail; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-831: Instance 1 must have cv=none ───────────────────────

    #[tokio::test]
    async fn instance_1_cv_pass_fails() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=pass; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-832: Instance >1 must have cv=pass ──────────────────────

    #[tokio::test]
    async fn instance_2_cv_none_fails() {
        // This will fail at structure validation because instance 2 has cv=none
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
            ("ARC-Authentication-Results", "i=2; dkim=pass"),
            (
                "ARC-Message-Signature",
                "i=2; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=2; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-882: Single ARC Set → Pass (with real crypto) ───────────

    #[tokio::test]
    async fn single_arc_set_pass() {
        let (headers_owned, resolver, body, _) = build_single_arc_set();
        let headers: Vec<(&str, &str)> = headers_owned
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, &body).await;
        assert_eq!(result.status, ArcResult::Pass);
        assert_eq!(result.oldest_pass, Some(0));
    }

    // ─── CHK-884: Gap in instances → Fail ────────────────────────────

    #[tokio::test]
    async fn gap_in_instances_fails() {
        // Create headers with gap (1, 3)
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
            ("ARC-Authentication-Results", "i=3; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=3; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=3; cv=pass; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-885: Duplicate instances → Fail ─────────────────────────

    #[tokio::test]
    async fn duplicate_instances_fails() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            ("ARC-Authentication-Results", "i=1; dkim=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-886: Instance 1 with cv=pass → Fail ─────────────────────

    #[tokio::test]
    async fn instance_1_cv_pass_structure_fail() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=pass; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-890: Most recent AMS body hash fails → Fail ─────────────

    #[tokio::test]
    async fn ams_body_hash_mismatch_fails() {
        let (headers_owned, resolver, _, _) = build_single_arc_set();
        let headers: Vec<(&str, &str)> = headers_owned
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let verifier = ArcVerifier::new(resolver);
        // Different body → body hash mismatch
        let result = verifier.validate_chain(&headers, b"tampered body\r\n").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-891: AS crypto fail → Fail ──────────────────────────────

    #[tokio::test]
    async fn seal_tampered_fails() {
        let (mut headers_owned, resolver, body, _) = build_single_arc_set();
        // Tamper the AAR payload to break the AS signature
        if let Some(aar) = headers_owned
            .iter_mut()
            .find(|(n, _)| n == "ARC-Authentication-Results")
        {
            aar.1 = "i=1; spf=fail smtp.mailfrom=evil.com".to_string();
        }
        let headers: Vec<(&str, &str)> = headers_owned
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, &body).await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-889: >50 sets → Fail ───────────────────────────────────

    #[tokio::test]
    async fn too_many_sets_fails() {
        // Just check the instance=51 parse failure
        let headers = vec![
            ("ARC-Authentication-Results", "i=51; spf=pass"),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-883: Three sets → Pass (multi-hop) ─────────────────────

    #[tokio::test]
    async fn three_sets_pass() {
        // Build 3-hop ARC chain with real signatures
        let (pkcs8, pub_key) = gen_ed25519_keypair();
        let body = b"test body\r\n";

        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "arc._domainkey.sealer.com",
            vec![make_dns_key_record(&pub_key)],
        );

        let message_headers: Vec<(String, String)> = vec![
            ("From".to_string(), "s@example.com".to_string()),
            ("Subject".to_string(), "test".to_string()),
        ];

        // Build chain iteratively
        // ordered_sets stores (aar_raw, ams_raw, seal_raw) in instance order for seal construction
        let mut ordered_sets: Vec<(String, String, String)> = Vec::new();

        for hop in 1..=3u32 {
            let cv = if hop == 1 { "none" } else { "pass" };

            // AMS
            let normalized = normalize_line_endings(body);
            let canonicalized =
                canonicalize_body(CanonicalizationMethod::Relaxed, &normalized);
            let body_hash = compute_hash(Algorithm::Ed25519Sha256, &canonicalized);

            let ams_raw_no_b = format!(
                "i={}; a=ed25519-sha256; d=sealer.com; s=arc; c=relaxed/relaxed; h=from:subject; bh={}; b=",
                hop,
                b64(&body_hash),
            );

            let non_arc: Vec<(&str, &str)> = message_headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();

            let selected = select_headers(
                CanonicalizationMethod::Relaxed,
                &["from".to_string(), "subject".to_string()],
                &non_arc,
            );
            let mut ams_input = Vec::new();
            for h in &selected {
                ams_input.extend_from_slice(h.as_bytes());
            }
            let canon_ams =
                canonicalize_header(CanonicalizationMethod::Relaxed, "arc-message-signature", &ams_raw_no_b);
            ams_input.extend_from_slice(canon_ams.as_bytes());
            let ams_sig = ed25519_sign(&pkcs8, &ams_input);
            let ams_raw = format!(
                "i={}; a=ed25519-sha256; d=sealer.com; s=arc; c=relaxed/relaxed; h=from:subject; bh={}; b={}",
                hop, b64(&body_hash), b64(&ams_sig),
            );

            let aar_raw = format!("i={}; spf=pass", hop);

            let seal_raw_no_b = format!(
                "i={}; cv={}; a=ed25519-sha256; d=sealer.com; s=arc; b=",
                hop, cv,
            );

            // AS signature input: all ARC sets 1..hop
            let mut seal_input = Vec::new();
            // Previous sets (from ordered_sets, stable indices)
            for prev in &ordered_sets {
                let c = canonicalize_header(
                    CanonicalizationMethod::Relaxed,
                    "arc-authentication-results",
                    &prev.0,
                );
                seal_input.extend_from_slice(c.as_bytes());
                let c = canonicalize_header(
                    CanonicalizationMethod::Relaxed,
                    "arc-message-signature",
                    &prev.1,
                );
                seal_input.extend_from_slice(c.as_bytes());
                let c = canonicalize_header(
                    CanonicalizationMethod::Relaxed,
                    "arc-seal",
                    &prev.2,
                );
                seal_input.extend_from_slice(c.as_bytes());
            }
            // Current set: AAR, AMS, AS(b= stripped, no trailing CRLF)
            let c = canonicalize_header(
                CanonicalizationMethod::Relaxed,
                "arc-authentication-results",
                &aar_raw,
            );
            seal_input.extend_from_slice(c.as_bytes());
            let c = canonicalize_header(
                CanonicalizationMethod::Relaxed,
                "arc-message-signature",
                &ams_raw,
            );
            seal_input.extend_from_slice(c.as_bytes());
            let c = canonicalize_header(
                CanonicalizationMethod::Relaxed,
                "arc-seal",
                &seal_raw_no_b,
            );
            let seal_bytes = c.as_bytes();
            if seal_bytes.ends_with(b"\r\n") {
                seal_input.extend_from_slice(&seal_bytes[..seal_bytes.len() - 2]);
            } else {
                seal_input.extend_from_slice(seal_bytes);
            }

            let seal_sig = ed25519_sign(&pkcs8, &seal_input);
            let seal_raw = format!(
                "i={}; cv={}; a=ed25519-sha256; d=sealer.com; s=arc; b={}",
                hop, cv, b64(&seal_sig),
            );

            // Store in instance order for seal construction
            ordered_sets.push((aar_raw.clone(), ams_raw.clone(), seal_raw.clone()));
        }

        // Build headers in email order (newest first)
        let mut arc_headers: Vec<(String, String)> = Vec::new();
        for (aar, ams, seal) in ordered_sets.iter().rev() {
            arc_headers.push(("ARC-Seal".to_string(), seal.clone()));
            arc_headers.push(("ARC-Message-Signature".to_string(), ams.clone()));
            arc_headers.push(("ARC-Authentication-Results".to_string(), aar.clone()));
        }

        // Combine headers
        let mut all_headers: Vec<(String, String)> = arc_headers;
        all_headers.extend(message_headers);

        let headers: Vec<(&str, &str)> = all_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, body).await;
        assert_eq!(result.status, ArcResult::Pass);
        assert_eq!(result.oldest_pass, Some(0));
    }

    // ─── CHK-887: Instance 2 cv=none → Fail ─────────────────────────

    #[tokio::test]
    async fn instance_2_cv_none_structure_fail() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
            ("ARC-Authentication-Results", "i=2; dkim=pass"),
            (
                "ARC-Message-Signature",
                "i=2; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=2; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-888: Highest cv=fail → immediate Fail ───────────────────

    #[tokio::test]
    async fn highest_cv_fail_fast() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=fail; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, b"body").await;
        assert!(matches!(result.status, ArcResult::Fail { .. }));
    }

    // ─── CHK-901: Body modification → oldest_pass > 0 ─────────────

    #[tokio::test]
    async fn oldest_pass_after_body_modification() {
        // Construct 2-hop chain where AMS(1) was signed over original body
        // and AMS(2) over modified body. Both AS signatures valid.
        // Validator should return Pass with oldest_pass = 2.
        let (pkcs8, pub_key) = gen_ed25519_keypair();

        let original_body = b"original body\r\n";
        let modified_body = b"modified body\r\n";
        let message_headers: Vec<(String, String)> = vec![
            ("From".to_string(), "s@example.com".to_string()),
            ("Subject".to_string(), "test".to_string()),
        ];

        // ─── Hop 1: AMS signed over original body ───
        let normalized_orig = normalize_line_endings(original_body);
        let canon_orig = canonicalize_body(CanonicalizationMethod::Relaxed, &normalized_orig);
        let bh_orig = compute_hash(Algorithm::Ed25519Sha256, &canon_orig);

        let ams1_raw_no_b = format!(
            "i=1; a=ed25519-sha256; d=sealer.com; s=arc; c=relaxed/relaxed; h=from:subject; bh={}; b=",
            b64(&bh_orig),
        );

        let non_arc: Vec<(&str, &str)> = message_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let selected = select_headers(
            CanonicalizationMethod::Relaxed,
            &["from".to_string(), "subject".to_string()],
            &non_arc,
        );
        let mut ams1_input = Vec::new();
        for h in &selected {
            ams1_input.extend_from_slice(h.as_bytes());
        }
        let canon_ams1 = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "arc-message-signature",
            &ams1_raw_no_b,
        );
        ams1_input.extend_from_slice(canon_ams1.as_bytes());
        let ams1_sig = ed25519_sign(&pkcs8, &ams1_input);
        let ams1_raw = format!(
            "i=1; a=ed25519-sha256; d=sealer.com; s=arc; c=relaxed/relaxed; h=from:subject; bh={}; b={}",
            b64(&bh_orig), b64(&ams1_sig),
        );

        let aar1_raw = "i=1; spf=pass".to_string();

        // AS(1): cv=none
        let seal1_raw_no_b = "i=1; cv=none; a=ed25519-sha256; d=sealer.com; s=arc; b=".to_string();
        let mut seal1_input = Vec::new();
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-authentication-results", &aar1_raw);
        seal1_input.extend_from_slice(c.as_bytes());
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-message-signature", &ams1_raw);
        seal1_input.extend_from_slice(c.as_bytes());
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-seal", &seal1_raw_no_b);
        let sb = c.as_bytes();
        if sb.ends_with(b"\r\n") {
            seal1_input.extend_from_slice(&sb[..sb.len() - 2]);
        } else {
            seal1_input.extend_from_slice(sb);
        }
        let seal1_sig = ed25519_sign(&pkcs8, &seal1_input);
        let seal1_raw = format!(
            "i=1; cv=none; a=ed25519-sha256; d=sealer.com; s=arc; b={}",
            b64(&seal1_sig),
        );

        // ─── Hop 2: AMS signed over modified body ───
        let normalized_mod = normalize_line_endings(modified_body);
        let canon_mod = canonicalize_body(CanonicalizationMethod::Relaxed, &normalized_mod);
        let bh_mod = compute_hash(Algorithm::Ed25519Sha256, &canon_mod);

        let ams2_raw_no_b = format!(
            "i=2; a=ed25519-sha256; d=sealer.com; s=arc; c=relaxed/relaxed; h=from:subject; bh={}; b=",
            b64(&bh_mod),
        );
        let mut ams2_input = Vec::new();
        for h in &selected {
            ams2_input.extend_from_slice(h.as_bytes());
        }
        let canon_ams2 = canonicalize_header(
            CanonicalizationMethod::Relaxed,
            "arc-message-signature",
            &ams2_raw_no_b,
        );
        ams2_input.extend_from_slice(canon_ams2.as_bytes());
        let ams2_sig = ed25519_sign(&pkcs8, &ams2_input);
        let ams2_raw = format!(
            "i=2; a=ed25519-sha256; d=sealer.com; s=arc; c=relaxed/relaxed; h=from:subject; bh={}; b={}",
            b64(&bh_mod), b64(&ams2_sig),
        );

        let aar2_raw = "i=2; arc=pass".to_string();

        // AS(2): cv=pass, covers sets 1..2
        let seal2_raw_no_b = "i=2; cv=pass; a=ed25519-sha256; d=sealer.com; s=arc; b=".to_string();
        let mut seal2_input = Vec::new();
        // Set 1
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-authentication-results", &aar1_raw);
        seal2_input.extend_from_slice(c.as_bytes());
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-message-signature", &ams1_raw);
        seal2_input.extend_from_slice(c.as_bytes());
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-seal", &seal1_raw);
        seal2_input.extend_from_slice(c.as_bytes());
        // Set 2
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-authentication-results", &aar2_raw);
        seal2_input.extend_from_slice(c.as_bytes());
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-message-signature", &ams2_raw);
        seal2_input.extend_from_slice(c.as_bytes());
        let c = canonicalize_header(CanonicalizationMethod::Relaxed, "arc-seal", &seal2_raw_no_b);
        let sb = c.as_bytes();
        if sb.ends_with(b"\r\n") {
            seal2_input.extend_from_slice(&sb[..sb.len() - 2]);
        } else {
            seal2_input.extend_from_slice(sb);
        }
        let seal2_sig = ed25519_sign(&pkcs8, &seal2_input);
        let seal2_raw = format!(
            "i=2; cv=pass; a=ed25519-sha256; d=sealer.com; s=arc; b={}",
            b64(&seal2_sig),
        );

        // Build headers: newest first
        let mut all_headers: Vec<(String, String)> = vec![
            ("ARC-Seal".to_string(), seal2_raw),
            ("ARC-Message-Signature".to_string(), ams2_raw),
            ("ARC-Authentication-Results".to_string(), aar2_raw),
            ("ARC-Seal".to_string(), seal1_raw),
            ("ARC-Message-Signature".to_string(), ams1_raw),
            ("ARC-Authentication-Results".to_string(), aar1_raw),
        ];
        all_headers.extend(message_headers);

        let headers: Vec<(&str, &str)> = all_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();

        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "arc._domainkey.sealer.com",
            vec![make_dns_key_record(&pub_key)],
        );
        let verifier = ArcVerifier::new(resolver);

        // Validate with modified body: AMS(2) passes, AMS(1) body hash fails
        let result = verifier.validate_chain(&headers, modified_body).await;
        assert_eq!(result.status, ArcResult::Pass);
        // oldest_pass should be 2 (AMS(1) at index 0 failed, so oldest passing is instance 2)
        assert_eq!(result.oldest_pass, Some(2));
    }

    // ─── Structure validation unit test ──────────────────────────────

    #[test]
    fn validate_structure_valid() {
        let sets = vec![
            ArcSet {
                instance: 1,
                aar: ArcAuthenticationResults {
                    instance: 1,
                    payload: "".to_string(),
                    raw_header: "".to_string(),
                },
                ams: ArcMessageSignature {
                    instance: 1,
                    algorithm: Algorithm::RsaSha256,
                    signature: vec![],
                    body_hash: vec![],
                    domain: "".to_string(),
                    selector: "".to_string(),
                    signed_headers: vec![],
                    header_canonicalization: CanonicalizationMethod::Relaxed,
                    body_canonicalization: CanonicalizationMethod::Relaxed,
                    timestamp: Option::None,
                    body_length: Option::None,
                    raw_header: "".to_string(),
                },
                seal: ArcSeal {
                    instance: 1,
                    cv: ChainValidationStatus::None,
                    algorithm: Algorithm::RsaSha256,
                    signature: vec![],
                    domain: "".to_string(),
                    selector: "".to_string(),
                    timestamp: Option::None,
                    raw_header: "".to_string(),
                },
            },
        ];
        assert!(validate_structure(&sets).is_ok());
    }
}
