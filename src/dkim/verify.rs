use std::time::SystemTime;

use ring::digest;
use subtle::ConstantTimeEq;

use crate::common::dns::{DnsError, DnsResolver};
use crate::dkim::canon::{
    canonicalize_body_relaxed, canonicalize_body_simple, canonicalize_header_relaxed,
    canonicalize_header_simple, select_headers, strip_b_tag,
};
use crate::dkim::key::{DkimPublicKey, HashAlgorithm, KeyFlag, KeyType};
use crate::dkim::signature::{
    Algorithm, CanonicalizationMethod, DkimResult, DkimSignature, FailureKind, PermFailKind,
};

// ---------------------------------------------------------------------------
// DkimVerifier
// ---------------------------------------------------------------------------

pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
    current_time: Option<u64>,
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            clock_skew: 300,
            current_time: None,
        }
    }

    pub fn clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    pub fn current_time(mut self, timestamp: u64) -> Self {
        self.current_time = Some(timestamp);
        self
    }

    fn get_current_time(&self) -> u64 {
        self.current_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        })
    }

    pub async fn verify_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<DkimResult> {
        // Collect all DKIM-Signature headers
        let dkim_headers: Vec<(&str, &str)> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("DKIM-Signature"))
            .copied()
            .collect();

        if dkim_headers.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::with_capacity(dkim_headers.len());
        for &(_name, value) in &dkim_headers {
            results.push(self.verify_one(value, headers, body).await);
        }
        results
    }

    async fn verify_one(
        &self,
        sig_value: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> DkimResult {
        // (a) Parse signature
        let sig = match DkimSignature::parse(sig_value) {
            Ok(s) => s,
            Err(e) => return e,
        };

        // (b) Expiration check
        if let Some(expiration) = sig.expiration {
            let now = self.get_current_time();
            if now > expiration + self.clock_skew {
                return DkimResult::PermFail {
                    kind: PermFailKind::ExpiredSignature,
                    detail: format!(
                        "signature expired at {}, now {} (skew {})",
                        expiration, now, self.clock_skew
                    ),
                };
            }
        }

        // (c) DNS lookup
        let dns_name = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let txt_records = match self.resolver.query_txt(&dns_name).await {
            Ok(records) => records,
            Err(DnsError::NxDomain | DnsError::NoRecords) => {
                return DkimResult::PermFail {
                    kind: PermFailKind::KeyNotFound,
                    detail: format!("no key record at {}", dns_name),
                };
            }
            Err(DnsError::TempFail) => {
                return DkimResult::TempFail {
                    reason: format!("DNS temp failure for {}", dns_name),
                };
            }
        };
        let concatenated = txt_records.join("");

        // (d) Parse key record
        let key = match DkimPublicKey::parse(&concatenated) {
            Ok(k) => k,
            Err(e) => return e,
        };

        // (e) Key constraint checks (order matters)

        // e1. Revoked
        if key.revoked {
            return DkimResult::PermFail {
                kind: PermFailKind::KeyRevoked,
                detail: "key has been revoked (empty p=)".to_string(),
            };
        }

        // e2. Hash algorithm permitted
        let required_hash = match sig.algorithm {
            Algorithm::RsaSha1 => HashAlgorithm::Sha1,
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => HashAlgorithm::Sha256,
        };
        if let Some(ref permitted) = key.hash_algorithms {
            if !permitted.contains(&required_hash) {
                return DkimResult::PermFail {
                    kind: PermFailKind::HashNotPermitted,
                    detail: format!("key does not permit {:?}", required_hash),
                };
            }
        }

        // e3. Service type
        if let Some(ref services) = key.service_types {
            if !services.iter().any(|s| s == "email" || s == "*") {
                return DkimResult::PermFail {
                    kind: PermFailKind::ServiceTypeMismatch,
                    detail: "key service type does not include 'email' or '*'".to_string(),
                };
            }
        }

        // e4. Strict mode (t=s flag)
        if key.flags.contains(&KeyFlag::Strict) {
            let auid_domain = sig
                .auid
                .rsplit_once('@')
                .map(|(_, d)| d.to_ascii_lowercase())
                .unwrap_or_default();
            let sig_domain = sig.domain.to_ascii_lowercase();
            if auid_domain != sig_domain {
                return DkimResult::PermFail {
                    kind: PermFailKind::StrictModeViolation,
                    detail: format!(
                        "strict mode: i= domain '{}' != d= '{}'",
                        auid_domain, sig_domain
                    ),
                };
            }
        }

        // e5. Algorithm / key type match
        let expected_key_type = match sig.algorithm {
            Algorithm::RsaSha1 | Algorithm::RsaSha256 => KeyType::Rsa,
            Algorithm::Ed25519Sha256 => KeyType::Ed25519,
        };
        if key.key_type != expected_key_type {
            return DkimResult::PermFail {
                kind: PermFailKind::AlgorithmMismatch,
                detail: format!(
                    "signature algorithm {:?} incompatible with key type {:?}",
                    sig.algorithm, key.key_type
                ),
            };
        }

        // (f) Body hash verification
        let canon_body = match sig.body_canonicalization {
            CanonicalizationMethod::Simple => canonicalize_body_simple(body),
            CanonicalizationMethod::Relaxed => canonicalize_body_relaxed(body),
        };
        let canon_body = match sig.body_length {
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
        let digest_algo = match sig.algorithm {
            Algorithm::RsaSha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => &digest::SHA256,
        };
        let computed_bh = digest::digest(digest_algo, &canon_body);
        let bh_match: bool = computed_bh.as_ref().ct_eq(&sig.body_hash).into();
        if !bh_match {
            return DkimResult::Fail {
                kind: FailureKind::BodyHashMismatch,
                detail: "computed body hash does not match bh= tag".to_string(),
            };
        }

        // (g) Header hash computation
        let selected = select_headers(&sig.signed_headers, headers);
        let mut data_to_verify = Vec::new();

        let canonicalize_fn = match sig.header_canonicalization {
            CanonicalizationMethod::Simple => canonicalize_header_simple,
            CanonicalizationMethod::Relaxed => canonicalize_header_relaxed,
        };

        for (i, &(name, value)) in selected.iter().enumerate() {
            if name.is_empty() && value.is_empty() {
                // Over-signed: use the h= list name with empty value
                let h_name = &sig.signed_headers[i];
                let canon = canonicalize_fn(h_name, "");
                data_to_verify.extend_from_slice(canon.as_bytes());
            } else {
                let canon = canonicalize_fn(name, value);
                data_to_verify.extend_from_slice(canon.as_bytes());
            }
        }

        // Append the DKIM-Signature header itself with b= stripped
        let stripped = strip_b_tag(&sig.raw_header);
        let dkim_canon = canonicalize_fn("DKIM-Signature", &stripped);
        // Remove trailing \r\n (last header has no trailing CRLF)
        let dkim_bytes = dkim_canon.as_bytes();
        let dkim_bytes = if dkim_bytes.ends_with(b"\r\n") {
            &dkim_bytes[..dkim_bytes.len() - 2]
        } else {
            dkim_bytes
        };
        data_to_verify.extend_from_slice(dkim_bytes);

        // (h) Cryptographic verification — pass raw data, ring hashes internally
        let verify_result = match sig.algorithm {
            Algorithm::RsaSha1 | Algorithm::RsaSha256 => {
                let pkcs1_bytes = crate::dkim::key::strip_spki_wrapper(&key.public_key);
                let algo: &dyn ring::signature::VerificationAlgorithm = match sig.algorithm {
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
                public_key.verify(&data_to_verify, &sig.signature)
            }
            Algorithm::Ed25519Sha256 => {
                let public_key = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ED25519,
                    &key.public_key,
                );
                public_key.verify(&data_to_verify, &sig.signature)
            }
        };

        match verify_result {
            Ok(()) => {
                // (i) Pass
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use crate::common::dns::mock::MockResolver;
    use crate::dkim::canon::{canonicalize_body_relaxed, canonicalize_body_simple};

    /// Helper: generate Ed25519 keypair, return (keypair, public_key_bytes).
    fn gen_ed25519() -> (Ed25519KeyPair, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_bytes = kp.public_key().as_ref().to_vec();
        (kp, pub_bytes)
    }

    /// Standard test headers.
    fn test_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("From", " sender@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test message"),
            ("Date", " Mon, 01 Jan 2024 00:00:00 +0000"),
        ]
    }

    fn test_body() -> &'static [u8] {
        b"Hello, world!\r\n"
    }

    /// Build a DKIM-Signature header value, sign it with the given Ed25519 keypair,
    /// and return (dkim_sig_value, headers_with_dkim_sig).
    ///
    /// This manually constructs and signs, bypassing any signer module.
    fn sign_ed25519(
        kp: &Ed25519KeyPair,
        headers: &[(&str, &str)],
        body: &[u8],
        domain: &str,
        selector: &str,
        header_canon: CanonicalizationMethod,
        body_canon: CanonicalizationMethod,
        extra_tags: &str, // additional tags like "x=12345; "
    ) -> String {
        let canon_str = match (header_canon, body_canon) {
            (CanonicalizationMethod::Relaxed, CanonicalizationMethod::Relaxed) => "relaxed/relaxed",
            (CanonicalizationMethod::Relaxed, CanonicalizationMethod::Simple) => "relaxed/simple",
            (CanonicalizationMethod::Simple, CanonicalizationMethod::Relaxed) => "simple/relaxed",
            (CanonicalizationMethod::Simple, CanonicalizationMethod::Simple) => "simple/simple",
        };

        // Build h= list from headers
        let h_list: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
        let h_tag = h_list.join(":");

        // Compute body hash
        let canon_body = match body_canon {
            CanonicalizationMethod::Simple => canonicalize_body_simple(body),
            CanonicalizationMethod::Relaxed => canonicalize_body_relaxed(body),
        };
        let bh = digest::digest(&digest::SHA256, &canon_body);
        let bh_b64 = STANDARD.encode(bh.as_ref());

        // Build signature header value with empty b=
        let sig_value = format!(
            " v=1; a=ed25519-sha256; c={}; d={}; s={}; {}h={}; bh={}; b=",
            canon_str, domain, selector, extra_tags, h_tag, bh_b64,
        );

        // Canonicalize headers for signing
        let canonicalize_fn = match header_canon {
            CanonicalizationMethod::Simple => canonicalize_header_simple,
            CanonicalizationMethod::Relaxed => canonicalize_header_relaxed,
        };

        let mut data = Vec::new();
        for &(name, value) in headers {
            let canon = canonicalize_fn(name, value);
            data.extend_from_slice(canon.as_bytes());
        }

        // Append DKIM-Signature header (with b= stripped — already empty here)
        let dkim_canon = canonicalize_fn("DKIM-Signature", &sig_value);
        let dkim_bytes = dkim_canon.as_bytes();
        // Remove trailing CRLF
        let dkim_bytes = if dkim_bytes.ends_with(b"\r\n") {
            &dkim_bytes[..dkim_bytes.len() - 2]
        } else {
            dkim_bytes
        };
        data.extend_from_slice(dkim_bytes);

        // Sign
        let signature = kp.sign(&data);
        let sig_b64 = STANDARD.encode(signature.as_ref());

        // Reconstruct complete signature value with b= filled in
        format!("{}{}", sig_value, sig_b64)
    }

    fn setup_dns_ed25519(resolver: &MockResolver, domain: &str, selector: &str, pub_key: &[u8]) {
        let dns_name = format!("{}._domainkey.{}", selector, domain);
        let key_b64 = STANDARD.encode(pub_key);
        resolver.add_txt(&dns_name, vec![format!("v=DKIM1; k=ed25519; p={}", key_b64)]);
    }

    // -----------------------------------------------------------------------
    // Test 1: Ed25519 sign-then-verify roundtrip (relaxed/relaxed)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ed25519_roundtrip_relaxed() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass {
                domain, selector, ..
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(selector, "sel1");
            }
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: Ed25519 sign-then-verify roundtrip (simple/simple)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ed25519_roundtrip_simple() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Simple,
            CanonicalizationMethod::Simple,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass {
                domain, selector, ..
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(selector, "sel1");
            }
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: Tampered body -> Fail(BodyHashMismatch)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tampered_body_fails() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let tampered_body = b"Tampered body!\r\n";
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, tampered_body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Fail { kind, .. } => {
                assert_eq!(*kind, FailureKind::BodyHashMismatch);
            }
            other => panic!("expected Fail(BodyHashMismatch), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Tampered header -> Fail(SignatureVerificationFailed)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tampered_header_fails() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        // Tamper with a signed header
        let tampered_headers: Vec<(&str, &str)> = vec![
            ("From", " attacker@evil.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test message"),
            ("Date", " Mon, 01 Jan 2024 00:00:00 +0000"),
            ("DKIM-Signature", &sig_value),
        ];

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&tampered_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Fail { kind, .. } => {
                assert_eq!(*kind, FailureKind::SignatureVerificationFailed);
            }
            other => panic!(
                "expected Fail(SignatureVerificationFailed), got {:?}",
                other
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: Ground-truth Ed25519 (manually constructed, no signer)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ground_truth_ed25519() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "test.example", "ground", &pub_bytes);

        let msg_headers: Vec<(&str, &str)> = vec![
            ("From", " alice@test.example"),
            ("To", " bob@test.example"),
            ("Subject", " Ground truth test"),
        ];
        let body = b"This is the body.\r\n";

        // Manually compute body hash (relaxed)
        let canon_body = canonicalize_body_relaxed(body);
        let bh = digest::digest(&digest::SHA256, &canon_body);
        let bh_b64 = STANDARD.encode(bh.as_ref());

        // Build DKIM-Signature header value with empty b=
        let sig_template = format!(
            " v=1; a=ed25519-sha256; c=relaxed/relaxed; d=test.example; s=ground; h=From:To:Subject; bh={}; b=",
            bh_b64
        );

        // Manually canonicalize headers
        let mut data = Vec::new();
        for &(name, value) in &msg_headers {
            let canon = canonicalize_header_relaxed(name, value);
            data.extend_from_slice(canon.as_bytes());
        }

        // Canonicalize the DKIM-Signature header (with b= empty, which is
        // the same as strip_b_tag since b= is already empty)
        let dkim_canon = canonicalize_header_relaxed("DKIM-Signature", &sig_template);
        let dkim_bytes = dkim_canon.as_bytes();
        let dkim_bytes = if dkim_bytes.ends_with(b"\r\n") {
            &dkim_bytes[..dkim_bytes.len() - 2]
        } else {
            dkim_bytes
        };
        data.extend_from_slice(dkim_bytes);

        // Sign with Ed25519
        let signature = kp.sign(&data);
        let sig_b64 = STANDARD.encode(signature.as_ref());

        // Complete the signature value
        let complete_sig = format!("{}{}", sig_template, sig_b64);

        // Assemble full message headers
        let mut full_headers = msg_headers.clone();
        full_headers.push(("DKIM-Signature", &complete_sig));

        // Verify
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass {
                domain,
                selector,
                testing,
            } => {
                assert_eq!(domain, "test.example");
                assert_eq!(selector, "ground");
                assert!(!testing);
            }
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: Expired signature -> PermFail(ExpiredSignature)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn expired_signature() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let headers = test_headers();
        let body = test_body();

        // Sign with x=1000 (expired long ago)
        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "x=1000; ",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        // Set current time well past expiration + clock_skew
        let verifier = DkimVerifier::new(resolver).current_time(2000);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::ExpiredSignature);
            }
            other => panic!("expected PermFail(ExpiredSignature), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 6b: Signature within clock skew window should still pass
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn within_clock_skew_passes() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let headers = test_headers();
        let body = test_body();

        // Sign with x=1000
        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "x=1000; ",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        // Set current time within clock_skew (1000 + 300 = 1300, we use 1200)
        let verifier = DkimVerifier::new(resolver).current_time(1200);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass (within clock skew), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: Key not found -> PermFail(KeyNotFound)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn key_not_found() {
        let (kp, _pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        // Deliberately do NOT add any DNS record

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::KeyNotFound);
            }
            other => panic!("expected PermFail(KeyNotFound), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: Key revoked -> PermFail(KeyRevoked)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn key_revoked() {
        let (kp, _) = gen_ed25519();
        let resolver = MockResolver::new();
        // Add DNS record with empty p= (revoked)
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec!["v=DKIM1; k=ed25519; p=".to_string()],
        );

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::KeyRevoked);
            }
            other => panic!("expected PermFail(KeyRevoked), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: DNS temp fail -> TempFail
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dns_temp_fail() {
        let (kp, _) = gen_ed25519();
        let resolver = MockResolver::new();
        resolver.add_txt_err("sel1._domainkey.example.com", DnsError::TempFail);

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::TempFail { .. } => {}
            other => panic!("expected TempFail, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: Hash not permitted -> PermFail(HashNotPermitted)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn hash_not_permitted() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        // Key only permits sha1, but ed25519-sha256 needs sha256
        let key_b64 = STANDARD.encode(&pub_bytes);
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec![format!("v=DKIM1; k=ed25519; h=sha1; p={}", key_b64)],
        );

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::HashNotPermitted);
            }
            other => panic!("expected PermFail(HashNotPermitted), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Service type mismatch -> PermFail(ServiceTypeMismatch)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn service_type_mismatch() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        let key_b64 = STANDARD.encode(&pub_bytes);
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec![format!("v=DKIM1; k=ed25519; s=other; p={}", key_b64)],
        );

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::ServiceTypeMismatch);
            }
            other => panic!("expected PermFail(ServiceTypeMismatch), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 12: Strict mode violation -> PermFail(StrictModeViolation)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn strict_mode_violation() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        let key_b64 = STANDARD.encode(&pub_bytes);
        // Key has t=s (strict), but i= will be @sub.example.com (subdomain, not exact)
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec![format!("v=DKIM1; k=ed25519; t=s; p={}", key_b64)],
        );

        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@sub.example.com"),
            ("To", " recipient@example.com"),
        ];
        let body = test_body();

        // We need a signature with i=user@sub.example.com and d=example.com
        // Since our sign helper defaults i= to @d=, we need to construct the
        // signature manually with an explicit i= tag.

        let canon_body = canonicalize_body_relaxed(body);
        let bh = digest::digest(&digest::SHA256, &canon_body);
        let bh_b64 = STANDARD.encode(bh.as_ref());

        let sig_template = format!(
            " v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=sel1; i=user@sub.example.com; h=From:To; bh={}; b=",
            bh_b64
        );

        let mut data = Vec::new();
        for &(name, value) in &headers {
            let canon = canonicalize_header_relaxed(name, value);
            data.extend_from_slice(canon.as_bytes());
        }
        let dkim_canon = canonicalize_header_relaxed("DKIM-Signature", &sig_template);
        let dkim_bytes = dkim_canon.as_bytes();
        let dkim_bytes = if dkim_bytes.ends_with(b"\r\n") {
            &dkim_bytes[..dkim_bytes.len() - 2]
        } else {
            dkim_bytes
        };
        data.extend_from_slice(dkim_bytes);

        let signature = kp.sign(&data);
        let complete_sig = format!("{}{}", sig_template, STANDARD.encode(signature.as_ref()));

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &complete_sig));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::StrictModeViolation);
            }
            other => panic!("expected PermFail(StrictModeViolation), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: Algorithm mismatch -> PermFail(AlgorithmMismatch)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn algorithm_mismatch() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        let key_b64 = STANDARD.encode(&pub_bytes);
        // Key says k=rsa, but signature says ed25519-sha256
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec![format!("v=DKIM1; k=rsa; p={}", key_b64)],
        );

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::AlgorithmMismatch);
            }
            other => panic!("expected PermFail(AlgorithmMismatch), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: No DKIM-Signature -> vec![DkimResult::None]
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_dkim_signature() {
        let resolver = MockResolver::new();
        let headers: Vec<(&str, &str)> = vec![
            ("From", " sender@example.com"),
            ("To", " recipient@example.com"),
        ];
        let body = test_body();

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&headers, body).await;

        assert_eq!(results, vec![DkimResult::None]);
    }

    // -----------------------------------------------------------------------
    // Test 15: Simple/simple canonicalization end-to-end
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn simple_simple_end_to_end() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        // Headers with mixed case and spacing that simple canon preserves
        let headers: Vec<(&str, &str)> = vec![
            ("From", "  Sender@Example.COM  "),
            ("To", " Recipient@Example.COM"),
            ("Subject", " Hello  World"),
        ];
        let body = b"Body content\r\nwith lines\r\n";

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Simple,
            CanonicalizationMethod::Simple,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 16: Relaxed/relaxed canonicalization end-to-end
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn relaxed_relaxed_end_to_end() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        // Headers with extra whitespace that relaxed canon normalizes
        let headers: Vec<(&str, &str)> = vec![
            ("From", "  sender@example.com  "),
            ("To", "\trecipient@example.com\t"),
            ("Subject", "  Hello   World  "),
        ];
        let body = b"Body  content  \r\nwith   spaces  \r\n\r\n\r\n";

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 17: Testing flag propagated in result
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn testing_flag_propagated() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        let key_b64 = STANDARD.encode(&pub_bytes);
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec![format!("v=DKIM1; k=ed25519; t=y; p={}", key_b64)],
        );

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass { testing, .. } => {
                assert!(*testing, "testing flag should be true");
            }
            other => panic!("expected Pass with testing=true, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 18: Multiple DKIM-Signature headers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn multiple_signatures() {
        let (kp1, pub1) = gen_ed25519();
        let (kp2, pub2) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub1);
        setup_dns_ed25519(&resolver, "example.com", "sel2", &pub2);

        let headers = test_headers();
        let body = test_body();

        let sig1 = sign_ed25519(
            &kp1,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );
        let sig2 = sign_ed25519(
            &kp2,
            &headers,
            body,
            "example.com",
            "sel2",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig1));
        full_headers.push(("DKIM-Signature", &sig2));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 2);
        for result in &results {
            match result {
                DkimResult::Pass { domain, .. } => {
                    assert_eq!(domain, "example.com");
                }
                other => panic!("expected Pass, got {:?}", other),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 19: DNS returns multiple TXT strings (concatenated)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dns_multiple_txt_strings_concatenated() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        let key_b64 = STANDARD.encode(&pub_bytes);
        // Split the key record across two TXT strings
        let part1 = format!("v=DKIM1; k=ed25519; p={}", &key_b64[..20]);
        let part2 = key_b64[20..].to_string();
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec![part1, part2],
        );

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 20: Malformed signature -> PermFail(MalformedSignature)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn malformed_signature() {
        let resolver = MockResolver::new();
        let headers: Vec<(&str, &str)> = vec![
            ("From", " sender@example.com"),
            ("DKIM-Signature", " garbage; not=valid"),
        ];
        let body = test_body();

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::MalformedSignature);
            }
            other => panic!("expected PermFail(MalformedSignature), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 21: Body length truncation (l= tag)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn body_length_truncation() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let headers = test_headers();
        let body = b"Hello, world!\r\n";

        // Sign with l=5 (only first 5 bytes of canonicalized body)
        // We need to manually construct this since our helper doesn't support l=
        let canon_body = canonicalize_body_relaxed(body);
        let truncated = &canon_body[..5];
        let bh = digest::digest(&digest::SHA256, truncated);
        let bh_b64 = STANDARD.encode(bh.as_ref());

        let h_list = headers.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(":");
        let sig_template = format!(
            " v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=sel1; h={}; l=5; bh={}; b=",
            h_list, bh_b64
        );

        let mut data = Vec::new();
        for &(name, value) in &headers {
            let canon = canonicalize_header_relaxed(name, value);
            data.extend_from_slice(canon.as_bytes());
        }
        let dkim_canon = canonicalize_header_relaxed("DKIM-Signature", &sig_template);
        let dkim_bytes = dkim_canon.as_bytes();
        let dkim_bytes = if dkim_bytes.ends_with(b"\r\n") {
            &dkim_bytes[..dkim_bytes.len() - 2]
        } else {
            dkim_bytes
        };
        data.extend_from_slice(dkim_bytes);

        let signature = kp.sign(&data);
        let complete_sig = format!("{}{}", sig_template, STANDARD.encode(signature.as_ref()));

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &complete_sig));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass with l= truncation, got {:?}", other),
        }

        // Also verify that appending to body still passes (l= protects prefix only)
        let extended_body = b"Hello, world!\r\nExtra content appended\r\n";
        let results2 = verifier.verify_message(&full_headers, extended_body).await;
        assert_eq!(results2.len(), 1);
        match &results2[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass with extended body + l= tag, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 22: Strict mode passes when i= domain matches d= exactly
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn strict_mode_exact_match_passes() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        let key_b64 = STANDARD.encode(&pub_bytes);
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec![format!("v=DKIM1; k=ed25519; t=s; p={}", key_b64)],
        );

        let headers = test_headers();
        let body = test_body();

        // Default i= is @example.com which matches d=example.com exactly
        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass (strict mode, exact match), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 23: Clock skew builder
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn custom_clock_skew() {
        let (kp, pub_bytes) = gen_ed25519();
        let resolver = MockResolver::new();
        setup_dns_ed25519(&resolver, "example.com", "sel1", &pub_bytes);

        let headers = test_headers();
        let body = test_body();

        let sig_value = sign_ed25519(
            &kp,
            &headers,
            body,
            "example.com",
            "sel1",
            CanonicalizationMethod::Relaxed,
            CanonicalizationMethod::Relaxed,
            "x=1000; ",
        );

        let mut full_headers = headers.clone();
        full_headers.push(("DKIM-Signature", &sig_value));

        // With clock_skew=0 and time=1001, should expire
        let verifier = DkimVerifier::new(resolver).clock_skew(0).current_time(1001);
        let results = verifier.verify_message(&full_headers, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::ExpiredSignature);
            }
            other => panic!("expected PermFail(ExpiredSignature), got {:?}", other),
        }
    }
}
