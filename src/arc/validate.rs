// ---------------------------------------------------------------------------
// ARC chain validation (RFC 8617 Section 5.2)
// ---------------------------------------------------------------------------

use ring::digest;
use subtle::ConstantTimeEq;

use crate::arc::parse::{
    collect_arc_sets, ArcMessageSignature, ArcSet, ChainValidationStatus,
};
use crate::common::dns::{DnsError, DnsResolver};
use crate::dkim::canon::{
    canonicalize_body_relaxed, canonicalize_body_simple, canonicalize_header_relaxed,
    canonicalize_header_simple, select_headers, strip_b_tag,
};
use crate::dkim::key::{DkimPublicKey, KeyType};
use crate::dkim::signature::{Algorithm, CanonicalizationMethod};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcResult {
    /// No ARC sets present in the message.
    None,
    /// All ARC sets validated successfully.
    Pass,
    /// Chain validation failed.
    Fail(String),
}

#[derive(Debug, Clone)]
pub struct ArcValidationResult {
    pub status: ArcResult,
    /// Lowest AMS instance that validated. 0 means all passed.
    /// `None` when status is not Pass.
    pub oldest_pass: Option<u32>,
}

// ---------------------------------------------------------------------------
// ArcVerifier
// ---------------------------------------------------------------------------

pub struct ArcVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> ArcVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Validate the ARC chain on a message per RFC 8617 Section 5.2.
    pub async fn validate_chain(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> ArcValidationResult {
        // 1. Collect ARC sets
        let sets = match collect_arc_sets(headers) {
            Ok(s) => s,
            Err(e) => {
                return ArcValidationResult {
                    status: ArcResult::Fail(format!("parse error: {}", e)),
                    oldest_pass: None,
                };
            }
        };

        if sets.is_empty() {
            return ArcValidationResult {
                status: ArcResult::None,
                oldest_pass: None,
            };
        }

        // 2. N = highest instance
        let n = sets.last().unwrap().instance;

        // 3. Instance limit
        if n > 50 {
            return ArcValidationResult {
                status: ArcResult::Fail(format!("too many ARC sets: {}", n)),
                oldest_pass: None,
            };
        }

        // 4. If most recent seal has cv=fail -> immediate fail
        let newest = &sets[(n - 1) as usize];
        if newest.seal.cv == ChainValidationStatus::Fail {
            return ArcValidationResult {
                status: ArcResult::Fail("most recent ARC-Seal cv=fail".to_string()),
                oldest_pass: None,
            };
        }

        // 5. Validate cv structure
        for set in &sets {
            if set.instance == 1 {
                if set.seal.cv != ChainValidationStatus::None {
                    return ArcValidationResult {
                        status: ArcResult::Fail(format!(
                            "instance 1 cv must be none, got {}",
                            set.seal.cv
                        )),
                        oldest_pass: None,
                    };
                }
            } else if set.seal.cv != ChainValidationStatus::Pass {
                return ArcValidationResult {
                    status: ArcResult::Fail(format!(
                        "instance {} cv must be pass, got {}",
                        set.instance, set.seal.cv
                    )),
                    oldest_pass: None,
                };
            }
        }

        // 6. Validate most recent AMS
        if let Err(reason) = self.validate_ams(&sets[(n - 1) as usize].ams, headers, body).await {
            return ArcValidationResult {
                status: ArcResult::Fail(format!("AMS {} validation failed: {}", n, reason)),
                oldest_pass: None,
            };
        }

        // 7. Determine oldest-pass (optional enrichment)
        let mut oldest_pass: u32 = 0;
        for i in (0..((n - 1) as usize)).rev() {
            if let Err(_) = self.validate_ams(&sets[i].ams, headers, body).await {
                oldest_pass = sets[i].instance + 1;
                break;
            }
        }

        // 8. Validate all AS headers from N down to 1
        for i in (0..n as usize).rev() {
            let target = sets[i].instance;
            if let Err(reason) = self.validate_seal(&sets, target).await {
                return ArcValidationResult {
                    status: ArcResult::Fail(format!(
                        "ARC-Seal {} validation failed: {}",
                        target, reason
                    )),
                    oldest_pass: None,
                };
            }
        }

        // 9. All pass
        ArcValidationResult {
            status: ArcResult::Pass,
            oldest_pass: Some(oldest_pass),
        }
    }

    /// Validate an ARC-Message-Signature (analogous to DKIM verification).
    async fn validate_ams(
        &self,
        ams: &ArcMessageSignature,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(), String> {
        // DNS lookup
        let dns_name = format!("{}._domainkey.{}", ams.selector, ams.domain);
        let txt_records = match self.resolver.query_txt(&dns_name).await {
            Ok(records) => records,
            Err(DnsError::NxDomain | DnsError::NoRecords) => {
                return Err(format!("no key record at {}", dns_name));
            }
            Err(DnsError::TempFail) => {
                return Err(format!("DNS temp failure for {}", dns_name));
            }
        };
        let concatenated = txt_records.join("");

        // Parse key
        let key = DkimPublicKey::parse(&concatenated)
            .map_err(|e| format!("key parse error: {:?}", e))?;

        if key.revoked {
            return Err("key revoked".to_string());
        }

        // Verify key type matches algorithm
        let expected_key_type = match ams.algorithm {
            Algorithm::RsaSha1 | Algorithm::RsaSha256 => KeyType::Rsa,
            Algorithm::Ed25519Sha256 => KeyType::Ed25519,
        };
        if key.key_type != expected_key_type {
            return Err(format!(
                "algorithm {:?} incompatible with key type {:?}",
                ams.algorithm, key.key_type
            ));
        }

        // Body hash verification
        let canon_body = match ams.body_canonicalization {
            CanonicalizationMethod::Simple => canonicalize_body_simple(body),
            CanonicalizationMethod::Relaxed => canonicalize_body_relaxed(body),
        };
        let canon_body = match ams.body_length {
            Some(len) => {
                let len = len as usize;
                if len < canon_body.len() {
                    canon_body[..len].to_vec()
                } else {
                    canon_body
                }
            }
            None => canon_body,
        };
        let digest_algo = match ams.algorithm {
            Algorithm::RsaSha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => &digest::SHA256,
        };
        let computed_bh = digest::digest(digest_algo, &canon_body);
        let bh_match: bool = computed_bh.as_ref().ct_eq(&ams.body_hash).into();
        if !bh_match {
            return Err("body hash mismatch".to_string());
        }

        // Header hash computation
        let selected = select_headers(&ams.signed_headers, headers);
        let mut data_to_verify = Vec::new();

        let canonicalize_fn = match ams.header_canonicalization {
            CanonicalizationMethod::Simple => canonicalize_header_simple,
            CanonicalizationMethod::Relaxed => canonicalize_header_relaxed,
        };

        for (i, &(name, value)) in selected.iter().enumerate() {
            if name.is_empty() && value.is_empty() {
                let h_name = &ams.signed_headers[i];
                let canon = canonicalize_fn(h_name, "");
                data_to_verify.extend_from_slice(canon.as_bytes());
            } else {
                let canon = canonicalize_fn(name, value);
                data_to_verify.extend_from_slice(canon.as_bytes());
            }
        }

        // Append AMS header with b= stripped, no trailing CRLF
        let stripped = strip_b_tag(&ams.raw_header);
        let ams_canon = canonicalize_fn("ARC-Message-Signature", &stripped);
        let ams_bytes = ams_canon.as_bytes();
        if ams_bytes.ends_with(b"\r\n") {
            data_to_verify.extend_from_slice(&ams_bytes[..ams_bytes.len() - 2]);
        } else {
            data_to_verify.extend_from_slice(ams_bytes);
        }

        // Crypto verify
        verify_signature(&ams.algorithm, &key, &data_to_verify, &ams.signature)
    }

    /// Validate an ARC-Seal at the given instance.
    async fn validate_seal(
        &self,
        sets: &[ArcSet],
        target_instance: u32,
    ) -> Result<(), String> {
        let target_set = &sets[(target_instance - 1) as usize];
        let seal = &target_set.seal;

        // DNS lookup
        let dns_name = format!("{}._domainkey.{}", seal.selector, seal.domain);
        let txt_records = match self.resolver.query_txt(&dns_name).await {
            Ok(records) => records,
            Err(DnsError::NxDomain | DnsError::NoRecords) => {
                return Err(format!("no key record at {}", dns_name));
            }
            Err(DnsError::TempFail) => {
                return Err(format!("DNS temp failure for {}", dns_name));
            }
        };
        let concatenated = txt_records.join("");

        // Parse key
        let key = DkimPublicKey::parse(&concatenated)
            .map_err(|e| format!("key parse error: {:?}", e))?;

        if key.revoked {
            return Err("key revoked".to_string());
        }

        let expected_key_type = match seal.algorithm {
            Algorithm::RsaSha1 | Algorithm::RsaSha256 => KeyType::Rsa,
            Algorithm::Ed25519Sha256 => KeyType::Ed25519,
        };
        if key.key_type != expected_key_type {
            return Err(format!(
                "algorithm {:?} incompatible with key type {:?}",
                seal.algorithm, key.key_type
            ));
        }

        // Build seal signature input
        let data = build_seal_input(sets, target_instance);

        // Crypto verify
        verify_signature(&seal.algorithm, &key, &data, &seal.signature)
    }
}

// ---------------------------------------------------------------------------
// Seal signature input construction
// ---------------------------------------------------------------------------

/// Build the data buffer that an ARC-Seal at `target_instance` signs over.
///
/// For each ARC set from 1 through target_instance (ascending):
///   - Canonicalize AAR (relaxed)
///   - Canonicalize AMS (relaxed)
///   - Canonicalize AS (relaxed); for the target instance, strip b= first
/// The last header omits trailing CRLF.
fn build_seal_input(sets: &[ArcSet], target_instance: u32) -> Vec<u8> {
    let mut data = Vec::new();
    let relevant: Vec<&ArcSet> = sets
        .iter()
        .filter(|s| s.instance <= target_instance)
        .collect();

    for set in &relevant {
        // AAR: reconstruct header value as "i=N; <payload>"
        let aar_value = format!("i={}; {}", set.aar.instance, set.aar.payload);
        let aar_canon =
            canonicalize_header_relaxed("ARC-Authentication-Results", &aar_value);
        data.extend_from_slice(aar_canon.as_bytes());

        // AMS
        let ams_canon =
            canonicalize_header_relaxed("ARC-Message-Signature", &set.ams.raw_header);
        data.extend_from_slice(ams_canon.as_bytes());

        // AS
        if set.instance == target_instance {
            // Strip b= from the seal being validated
            let stripped = strip_b_tag(&set.seal.raw_header);
            let seal_canon = canonicalize_header_relaxed("ARC-Seal", &stripped);
            let seal_bytes = seal_canon.as_bytes();
            // Last header: remove trailing CRLF
            if seal_bytes.ends_with(b"\r\n") {
                data.extend_from_slice(&seal_bytes[..seal_bytes.len() - 2]);
            } else {
                data.extend_from_slice(seal_bytes);
            }
        } else {
            let seal_canon =
                canonicalize_header_relaxed("ARC-Seal", &set.seal.raw_header);
            data.extend_from_slice(seal_canon.as_bytes());
        }
    }
    data
}

// ---------------------------------------------------------------------------
// Crypto verification
// ---------------------------------------------------------------------------

/// Verify a signature using ring, matching the algorithm to the key type.
fn verify_signature(
    algorithm: &Algorithm,
    key: &DkimPublicKey,
    data: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let result = match algorithm {
        Algorithm::RsaSha1 | Algorithm::RsaSha256 => {
            let pkcs1_bytes = crate::dkim::key::strip_spki_wrapper(&key.public_key);
            let algo: &dyn ring::signature::VerificationAlgorithm = match algorithm {
                Algorithm::RsaSha256 => {
                    if pkcs1_bytes.len() >= 256 {
                        &ring::signature::RSA_PKCS1_2048_8192_SHA256
                    } else {
                        &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
                    }
                }
                Algorithm::RsaSha1 => {
                    if pkcs1_bytes.len() >= 256 {
                        &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
                    } else {
                        &ring::signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
                    }
                }
                _ => unreachable!(),
            };
            let public_key =
                ring::signature::UnparsedPublicKey::new(algo, &pkcs1_bytes);
            public_key.verify(data, signature)
        }
        Algorithm::Ed25519Sha256 => {
            let public_key = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                &key.public_key,
            );
            public_key.verify(data, signature)
        }
    };

    result.map_err(|_| "cryptographic signature verification failed".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ring::digest;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use crate::common::dns::mock::MockResolver;
    use crate::dkim::canon::{canonicalize_body_relaxed, canonicalize_header_relaxed};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Generate Ed25519 keypair, return (keypair, public_key_bytes).
    fn gen_ed25519() -> (Ed25519KeyPair, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_bytes = kp.public_key().as_ref().to_vec();
        (kp, pub_bytes)
    }

    fn test_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("From", " sender@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test message"),
        ]
    }

    fn test_body() -> &'static [u8] {
        b"Hello, world!\r\n"
    }

    fn setup_dns_ed25519(resolver: &MockResolver, domain: &str, selector: &str, pub_key: &[u8]) {
        let dns_name = format!("{}._domainkey.{}", selector, domain);
        let key_b64 = STANDARD.encode(pub_key);
        resolver.add_txt(
            &dns_name,
            vec![format!("v=DKIM1; k=ed25519; p={}", key_b64)],
        );
    }

    /// Build a signed ARC set at the given instance.
    ///
    /// Returns (ArcSet headers, keypair, public key bytes).
    /// The headers are returned as (name, value) pairs suitable for appending
    /// to a message header list.
    ///
    /// `prior_sets`: previously constructed ArcSet objects (for seal chaining).
    /// `msg_headers`: the original message headers (for AMS signing).
    /// `body`: the message body (for AMS body hash).
    fn build_signed_arc_set(
        instance: u32,
        prior_sets: &[ArcSet],
        msg_headers: &[(&str, &str)],
        body: &[u8],
        domain: &str,
        selector: &str,
    ) -> (Vec<(String, String)>, Ed25519KeyPair, Vec<u8>) {
        let (kp, pub_bytes) = gen_ed25519();

        // --- AAR ---
        let aar_payload = "dkim=pass header.d=example.com";
        let aar_value = format!(" i={}; {}", instance, aar_payload);

        // --- AMS ---
        // Compute body hash (relaxed/relaxed)
        let canon_body = canonicalize_body_relaxed(body);
        let bh = digest::digest(&digest::SHA256, &canon_body);
        let bh_b64 = STANDARD.encode(bh.as_ref());

        // Build h= list from msg_headers
        let h_list: Vec<&str> = msg_headers.iter().map(|(n, _)| *n).collect();
        let h_tag = h_list.join(":");

        // AMS header value with empty b=
        let ams_template = format!(
            " i={}; a=ed25519-sha256; c=relaxed/relaxed; d={}; s={}; h={}; bh={}; b=",
            instance, domain, selector, h_tag, bh_b64,
        );

        // Build AMS signing input: canonicalized selected headers + AMS header (b= stripped)
        let mut ams_data = Vec::new();
        for &(name, value) in msg_headers {
            let canon = canonicalize_header_relaxed(name, value);
            ams_data.extend_from_slice(canon.as_bytes());
        }
        let ams_canon =
            canonicalize_header_relaxed("ARC-Message-Signature", &ams_template);
        let ams_bytes = ams_canon.as_bytes();
        if ams_bytes.ends_with(b"\r\n") {
            ams_data.extend_from_slice(&ams_bytes[..ams_bytes.len() - 2]);
        } else {
            ams_data.extend_from_slice(ams_bytes);
        }

        let ams_sig = kp.sign(&ams_data);
        let ams_sig_b64 = STANDARD.encode(ams_sig.as_ref());
        let ams_value = format!("{}{}", ams_template, ams_sig_b64);

        // --- AS ---
        let cv = if instance == 1 { "none" } else { "pass" };
        let seal_template = format!(
            " i={}; cv={}; a=ed25519-sha256; d={}; s={}; b=",
            instance, cv, domain, selector,
        );

        // Build seal signing input from all prior sets + this set's AAR/AMS + this seal template
        // Construct a temporary ArcSet for building the seal input
        let temp_aar = crate::arc::parse::ArcAuthenticationResults {
            instance,
            payload: aar_payload.to_string(),
        };
        let temp_ams = crate::arc::parse::ArcMessageSignature {
            instance,
            algorithm: Algorithm::Ed25519Sha256,
            domain: domain.to_string(),
            selector: selector.to_string(),
            signed_headers: h_list.iter().map(|s| s.to_string()).collect(),
            header_canonicalization: CanonicalizationMethod::Relaxed,
            body_canonicalization: CanonicalizationMethod::Relaxed,
            body_hash: bh.as_ref().to_vec(),
            signature: ams_sig.as_ref().to_vec(),
            body_length: None,
            timestamp: None,
            raw_header: ams_value.clone(),
        };
        let temp_seal = crate::arc::parse::ArcSeal {
            instance,
            cv: if instance == 1 {
                ChainValidationStatus::None
            } else {
                ChainValidationStatus::Pass
            },
            algorithm: Algorithm::Ed25519Sha256,
            domain: domain.to_string(),
            selector: selector.to_string(),
            signature: Vec::new(), // placeholder, will be computed
            timestamp: None,
            raw_header: seal_template.clone(),
        };
        let temp_set = ArcSet {
            instance,
            aar: temp_aar,
            ams: temp_ams,
            seal: temp_seal,
        };

        let mut all_sets: Vec<ArcSet> = prior_sets.to_vec();
        all_sets.push(temp_set);

        let seal_data = build_seal_input(&all_sets, instance);
        let seal_sig = kp.sign(&seal_data);
        let seal_sig_b64 = STANDARD.encode(seal_sig.as_ref());
        let seal_value = format!("{}{}", seal_template, seal_sig_b64);

        let headers = vec![
            (
                "ARC-Authentication-Results".to_string(),
                aar_value.clone(),
            ),
            ("ARC-Message-Signature".to_string(), ams_value),
            ("ARC-Seal".to_string(), seal_value),
        ];

        (headers, kp, pub_bytes)
    }

    /// Build headers from message headers + ARC header tuples.
    fn assemble_headers<'a>(
        msg: &[(&'a str, &'a str)],
        arc_headers: &'a [(String, String)],
    ) -> Vec<(&'a str, &'a str)> {
        let mut all: Vec<(&str, &str)> = msg.to_vec();
        for (name, value) in arc_headers {
            all.push((name.as_str(), value.as_str()));
        }
        all
    }

    // -----------------------------------------------------------------------
    // Test 1: no_arc_sets_returns_none
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_arc_sets_returns_none() {
        let resolver = MockResolver::new();
        let verifier = ArcVerifier::new(resolver);
        let headers = test_headers();
        let result = verifier.validate_chain(&headers, test_body()).await;
        assert_eq!(result.status, ArcResult::None);
        assert!(result.oldest_pass.is_none());
    }

    // -----------------------------------------------------------------------
    // Test 2: single_valid_set
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn single_valid_set() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        let (arc_hdrs, _kp, pub_bytes) =
            build_signed_arc_set(1, &[], &msg_headers, body, "example.com", "sel1");
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let all = assemble_headers(&msg_headers, &arc_hdrs);
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&all, body).await;

        assert_eq!(result.status, ArcResult::Pass);
        assert_eq!(result.oldest_pass, Some(0));
    }

    // -----------------------------------------------------------------------
    // Test 3: three_valid_sets
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn three_valid_sets() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        // Set 1
        let (arc_hdrs1, _kp1, pub1) =
            build_signed_arc_set(1, &[], &msg_headers, body, "hop1.example", "s1");
        setup_dns_ed25519(&resolver, "hop1.example", "s1", &pub1);

        // We need the ArcSet objects for chaining
        let set1_headers = assemble_headers(&msg_headers, &arc_hdrs1);
        let sets1 = collect_arc_sets(&set1_headers).unwrap();

        // Set 2
        let (arc_hdrs2, _kp2, pub2) =
            build_signed_arc_set(2, &sets1, &msg_headers, body, "hop2.example", "s2");
        setup_dns_ed25519(&resolver, "hop2.example", "s2", &pub2);

        let mut all_arc_hdrs: Vec<(String, String)> = arc_hdrs1.clone();
        all_arc_hdrs.extend(arc_hdrs2.clone());
        let set2_headers = assemble_headers(&msg_headers, &all_arc_hdrs);
        let sets2 = collect_arc_sets(&set2_headers).unwrap();

        // Set 3
        let (arc_hdrs3, _kp3, pub3) =
            build_signed_arc_set(3, &sets2, &msg_headers, body, "hop3.example", "s3");
        setup_dns_ed25519(&resolver, "hop3.example", "s3", &pub3);

        all_arc_hdrs.extend(arc_hdrs3);
        let all = assemble_headers(&msg_headers, &all_arc_hdrs);
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&all, body).await;

        assert_eq!(result.status, ArcResult::Pass);
        assert_eq!(result.oldest_pass, Some(0));
    }

    // -----------------------------------------------------------------------
    // Test 4: cv_fail_immediate_fail
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cv_fail_immediate_fail() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        // Build a valid set 1
        let (mut arc_hdrs, _kp, pub_bytes) =
            build_signed_arc_set(1, &[], &msg_headers, body, "example.com", "sel1");
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        // Tamper: replace the ARC-Seal cv=none with cv=fail in the header value
        for (name, value) in &mut arc_hdrs {
            if name == "ARC-Seal" {
                *value = value.replace("cv=none", "cv=fail");
            }
        }

        let all = assemble_headers(&msg_headers, &arc_hdrs);
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&all, body).await;

        match &result.status {
            ArcResult::Fail(reason) => {
                assert!(
                    reason.contains("cv=fail"),
                    "expected cv=fail reason, got: {}",
                    reason
                );
            }
            other => panic!("expected Fail, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: instance_1_cv_not_none
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn instance_1_cv_not_none() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        let (mut arc_hdrs, _kp, pub_bytes) =
            build_signed_arc_set(1, &[], &msg_headers, body, "example.com", "sel1");
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        // Tamper: change cv=none to cv=pass for instance 1
        for (name, value) in &mut arc_hdrs {
            if name == "ARC-Seal" {
                *value = value.replace("cv=none", "cv=pass");
            }
        }

        let all = assemble_headers(&msg_headers, &arc_hdrs);
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&all, body).await;

        match &result.status {
            ArcResult::Fail(reason) => {
                assert!(
                    reason.contains("instance 1") && reason.contains("none"),
                    "expected instance 1 cv error, got: {}",
                    reason
                );
            }
            other => panic!("expected Fail, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: instance_2_cv_not_pass
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn instance_2_cv_not_pass() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        // Set 1
        let (arc_hdrs1, _kp1, pub1) =
            build_signed_arc_set(1, &[], &msg_headers, body, "hop1.example", "s1");
        setup_dns_ed25519(&resolver, "hop1.example", "s1", &pub1);

        let set1_headers = assemble_headers(&msg_headers, &arc_hdrs1);
        let sets1 = collect_arc_sets(&set1_headers).unwrap();

        // Set 2
        let (mut arc_hdrs2, _kp2, pub2) =
            build_signed_arc_set(2, &sets1, &msg_headers, body, "hop2.example", "s2");
        setup_dns_ed25519(&resolver, "hop2.example", "s2", &pub2);

        // Tamper: change cv=pass to cv=none for instance 2
        for (name, value) in &mut arc_hdrs2 {
            if name == "ARC-Seal" {
                *value = value.replace("cv=pass", "cv=none");
            }
        }

        let mut all_arc = arc_hdrs1;
        all_arc.extend(arc_hdrs2);
        let all = assemble_headers(&msg_headers, &all_arc);
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&all, body).await;

        match &result.status {
            ArcResult::Fail(reason) => {
                assert!(
                    reason.contains("instance 2") && reason.contains("pass"),
                    "expected instance 2 cv error, got: {}",
                    reason
                );
            }
            other => panic!("expected Fail, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: ams_body_hash_mismatch
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ams_body_hash_mismatch() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        let (arc_hdrs, _kp, pub_bytes) =
            build_signed_arc_set(1, &[], &msg_headers, body, "example.com", "sel1");
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let all = assemble_headers(&msg_headers, &arc_hdrs);
        let verifier = ArcVerifier::new(resolver);

        // Pass a different body to trigger body hash mismatch
        let tampered_body = b"Tampered body!\r\n";
        let result = verifier.validate_chain(&all, tampered_body).await;

        match &result.status {
            ArcResult::Fail(reason) => {
                assert!(
                    reason.contains("body hash"),
                    "expected body hash mismatch, got: {}",
                    reason
                );
            }
            other => panic!("expected Fail, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: seal_signature_invalid
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn seal_signature_invalid() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        let (mut arc_hdrs, _kp, pub_bytes) =
            build_signed_arc_set(1, &[], &msg_headers, body, "example.com", "sel1");
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        // Tamper with the seal signature: decode b=, flip a byte, re-encode
        for (name, value) in &mut arc_hdrs {
            if name == "ARC-Seal" {
                // Find b= tag value and replace with corrupted signature
                if let Some(b_pos) = value.find("; b=") {
                    let sig_start = b_pos + 4; // after "; b="
                    let sig_b64 = &value[sig_start..];
                    if let Ok(mut sig_bytes) = STANDARD.decode(sig_b64.trim()) {
                        if !sig_bytes.is_empty() {
                            sig_bytes[0] ^= 0xFF; // flip first byte
                        }
                        let new_b64 = STANDARD.encode(&sig_bytes);
                        *value = format!("{}{}", &value[..sig_start], new_b64);
                    }
                }
            }
        }

        let all = assemble_headers(&msg_headers, &arc_hdrs);
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&all, body).await;

        match &result.status {
            ArcResult::Fail(reason) => {
                assert!(
                    reason.contains("Seal") && reason.contains("failed"),
                    "expected seal verification failure, got: {}",
                    reason
                );
            }
            other => panic!("expected Fail, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: key_not_found
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn key_not_found() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        // Build a set but do NOT register DNS
        let (arc_hdrs, _kp, _pub_bytes) =
            build_signed_arc_set(1, &[], &msg_headers, body, "example.com", "sel1");

        let all = assemble_headers(&msg_headers, &arc_hdrs);
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&all, body).await;

        match &result.status {
            ArcResult::Fail(reason) => {
                assert!(
                    reason.contains("no key record"),
                    "expected key not found, got: {}",
                    reason
                );
            }
            other => panic!("expected Fail, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: dns_tempfail
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dns_tempfail() {
        let resolver = MockResolver::new();
        let msg_headers = test_headers();
        let body = test_body();

        let (arc_hdrs, _kp, _pub_bytes) =
            build_signed_arc_set(1, &[], &msg_headers, body, "example.com", "sel1");

        // Register a TempFail for the DNS lookup
        resolver.add_txt_err("sel1._domainkey.example.com", DnsError::TempFail);

        let all = assemble_headers(&msg_headers, &arc_hdrs);
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&all, body).await;

        match &result.status {
            ArcResult::Fail(reason) => {
                assert!(
                    reason.contains("DNS temp"),
                    "expected DNS temp failure, got: {}",
                    reason
                );
            }
            other => panic!("expected Fail, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: parse_error_fails
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn parse_error_fails() {
        let resolver = MockResolver::new();
        // Malformed ARC headers: only AAR, no AMS or AS
        let headers: Vec<(&str, &str)> = vec![
            ("From", " sender@example.com"),
            ("ARC-Authentication-Results", " i=1; dkim=pass"),
        ];
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&headers, test_body()).await;

        match &result.status {
            ArcResult::Fail(reason) => {
                assert!(
                    reason.contains("parse error"),
                    "expected parse error, got: {}",
                    reason
                );
            }
            other => panic!("expected Fail, got {:?}", other),
        }
    }
}
