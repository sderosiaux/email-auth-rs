//! DKIM signature verification (RFC 6376 Section 6).

use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use ring::signature::{self, UnparsedPublicKey};

use crate::common::dns::{DnsError, DnsResolver};
use crate::dkim::canon::{
    canonicalize_body_relaxed, canonicalize_body_simple, canonicalize_header_relaxed,
    canonicalize_header_simple, select_headers, strip_b_tag_value, truncate_body,
};
use crate::dkim::key::{DkimPublicKey, HashAlgorithm, KeyFlag, KeyType};
use crate::dkim::signature::{Algorithm, CanonicalizationMethod, DkimSignature};
use crate::dkim::DkimResult;

// ---------------------------------------------------------------------------
// DkimVerifier
// ---------------------------------------------------------------------------

/// DKIM message verifier. Holds a DNS resolver and configuration.
pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
}

impl<R: DnsResolver> DkimVerifier<R> {
    /// Create a new verifier with the given DNS resolver.
    /// Default clock skew allowance: 300 seconds.
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            clock_skew: 300,
        }
    }

    /// Override the clock skew allowance (in seconds).
    pub fn clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    /// Verify all DKIM signatures in a message.
    ///
    /// `headers` is an ordered list of (name, value) pairs representing the
    /// message headers. `body` is the raw message body bytes.
    ///
    /// Returns one `DkimResult` per DKIM-Signature header found, or a single
    /// `DkimResult::None` if no signatures are present.
    pub async fn verify_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<DkimResult> {
        // Collect all DKIM-Signature headers (case-insensitive).
        let dkim_headers: Vec<(&str, &str)> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("dkim-signature"))
            .copied()
            .collect();

        if dkim_headers.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::with_capacity(dkim_headers.len());
        for (_name, value) in &dkim_headers {
            let result = self.verify_single_signature(value, headers, body).await;
            results.push(result);
        }
        results
    }

    /// Verify a single DKIM-Signature header value.
    async fn verify_single_signature(
        &self,
        sig_value: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> DkimResult {
        // 1. Parse signature
        let sig = match DkimSignature::parse(sig_value) {
            Ok(s) => s,
            Err(e) => {
                return DkimResult::PermFail {
                    reason: format!("malformed signature: {e}"),
                }
            }
        };

        // 2. Check expiration
        if let Some(expiration) = sig.expiration {
            let now = current_timestamp();
            if now > expiration + self.clock_skew {
                return DkimResult::PermFail {
                    reason: format!(
                        "signature expired at {expiration}, now {now} (skew {}s)",
                        self.clock_skew
                    ),
                };
            }
        }

        // 3. DNS lookup for key record
        let dns_name = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let txt_records = match self.resolver.query_txt(&dns_name).await {
            Ok(records) => records,
            Err(DnsError::TempFail(msg)) => {
                return DkimResult::TempFail {
                    reason: format!("DNS temp failure for {dns_name}: {msg}"),
                }
            }
            Err(e) => {
                return DkimResult::PermFail {
                    reason: format!("DNS lookup failed for {dns_name}: {e}"),
                }
            }
        };

        // Concatenate TXT record strings (multi-string TXT records).
        let txt_data = txt_records.join("");

        // 4. Parse key record
        let key = match DkimPublicKey::parse(&txt_data) {
            Ok(k) => k,
            Err(e) => {
                return DkimResult::PermFail {
                    reason: format!("key parse error: {e}"),
                }
            }
        };

        // 5. Enforce key constraints

        // 5a. Revoked key (empty p=)
        if key.revoked {
            return DkimResult::PermFail {
                reason: "key has been revoked (empty p=)".into(),
            };
        }

        // 5b. Key h= tag: signature's hash algorithm must be in the list
        if let Some(ref permitted) = key.hash_algorithms {
            let sig_hash = match sig.algorithm {
                Algorithm::RsaSha1 => HashAlgorithm::Sha1,
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => HashAlgorithm::Sha256,
            };
            if !permitted.contains(&sig_hash) {
                return DkimResult::PermFail {
                    reason: format!(
                        "hash algorithm {sig_hash} not permitted by key (allowed: {permitted:?})"
                    ),
                };
            }
        }

        // 5c. Key s= tag: must include "email" or "*"
        if !key.accepts_email() {
            return DkimResult::PermFail {
                reason: format!(
                    "key service type {:?} does not include email or *",
                    key.service_types
                ),
            };
        }

        // 5d. Key t=s flag: i= domain must exactly equal d=
        if key.flags.contains(&KeyFlag::Strict) {
            let i_domain = sig
                .auid
                .rsplit_once('@')
                .map(|(_, d)| d)
                .unwrap_or(&sig.auid);
            if !crate::common::domain::domains_equal(i_domain, &sig.domain) {
                return DkimResult::PermFail {
                    reason: format!(
                        "strict mode: i= domain \"{i_domain}\" does not exactly match d= \"{}\"",
                        sig.domain
                    ),
                };
            }
        }

        // 5e. Verify key type matches algorithm
        match (&sig.algorithm, &key.key_type) {
            (Algorithm::RsaSha1 | Algorithm::RsaSha256, KeyType::Rsa) => {}
            (Algorithm::Ed25519Sha256, KeyType::Ed25519) => {}
            _ => {
                return DkimResult::PermFail {
                    reason: format!(
                        "algorithm {} incompatible with key type {}",
                        sig.algorithm, key.key_type
                    ),
                }
            }
        }

        let testing = key.is_testing();

        // 6. Body hash verification
        let canon_body = match sig.body_canonicalization {
            CanonicalizationMethod::Simple => canonicalize_body_simple(body),
            CanonicalizationMethod::Relaxed => canonicalize_body_relaxed(body),
        };
        let truncated = truncate_body(&canon_body, sig.body_length);

        let body_hash = match sig.algorithm {
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => digest(&SHA256, truncated),
            Algorithm::RsaSha1 => digest(&SHA1_FOR_LEGACY_USE_ONLY, truncated),
        };

        // Constant-time body hash comparison
        #[allow(deprecated)]
        if ring::constant_time::verify_slices_are_equal(body_hash.as_ref(), &sig.body_hash)
            .is_err()
        {
            return DkimResult::Fail {
                reason: "body hash mismatch".into(),
            };
        }

        // 7. Header hash + signature verification

        // Select headers from message per h= list.
        let selected = select_headers(headers, &sig.signed_headers);

        // Canonicalize selected headers.
        let mut header_data = String::new();
        for (i, (name, value)) in selected.iter().enumerate() {
            if name.is_empty() && value.is_empty() {
                // Over-signed sentinel: canonicalize as empty header using h= name.
                let h_name = &sig.signed_headers[i];
                let canon = match sig.header_canonicalization {
                    CanonicalizationMethod::Simple => {
                        canonicalize_header_simple(h_name, "")
                    }
                    CanonicalizationMethod::Relaxed => {
                        canonicalize_header_relaxed(h_name, "")
                    }
                };
                header_data.push_str(&canon);
            } else {
                let canon = match sig.header_canonicalization {
                    CanonicalizationMethod::Simple => {
                        canonicalize_header_simple(name, value)
                    }
                    CanonicalizationMethod::Relaxed => {
                        canonicalize_header_relaxed(name, value)
                    }
                };
                header_data.push_str(&canon);
            }
        }

        // Append canonicalized DKIM-Signature with b= value stripped.
        // No trailing CRLF on the final header.
        let stripped_value = strip_b_tag_value(&sig.raw_header);
        let dkim_sig_canon = match sig.header_canonicalization {
            CanonicalizationMethod::Simple => {
                canonicalize_header_simple("DKIM-Signature", &stripped_value)
            }
            CanonicalizationMethod::Relaxed => {
                canonicalize_header_relaxed("DKIM-Signature", &stripped_value)
            }
        };
        // Remove trailing CRLF from the DKIM-Signature line (spec requirement).
        let dkim_sig_canon = dkim_sig_canon.strip_suffix("\r\n").unwrap_or(&dkim_sig_canon);
        header_data.push_str(dkim_sig_canon);

        // 8. Cryptographic signature verification — pass RAW header data to ring.
        let header_bytes = header_data.as_bytes();

        let verify_result = match sig.algorithm {
            Algorithm::RsaSha256 => {
                let alg: &dyn signature::VerificationAlgorithm = if key.public_key.len() < 200 {
                    &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
                } else {
                    &signature::RSA_PKCS1_2048_8192_SHA256
                };
                let pk = UnparsedPublicKey::new(alg, &key.public_key);
                pk.verify(header_bytes, &sig.signature)
            }
            Algorithm::RsaSha1 => {
                let alg: &dyn signature::VerificationAlgorithm = if key.public_key.len() < 200 {
                    &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
                } else {
                    &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
                };
                let pk = UnparsedPublicKey::new(alg, &key.public_key);
                pk.verify(header_bytes, &sig.signature)
            }
            Algorithm::Ed25519Sha256 => {
                let pk = UnparsedPublicKey::new(&signature::ED25519, &key.public_key);
                pk.verify(header_bytes, &sig.signature)
            }
        };

        match verify_result {
            Ok(()) => DkimResult::Pass {
                domain: sig.domain,
                selector: sig.selector,
                testing,
            },
            Err(_) => DkimResult::Fail {
                reason: "signature verification failed".into(),
            },
        }
    }
}

/// Get current UNIX timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::{MockDnsResponse, MockResolver};
    use base64::Engine;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    /// Generate an Ed25519 key pair, returning (pkcs8_bytes, public_key_bytes).
    fn gen_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_key = kp.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), pub_key)
    }

    /// Sign header data with an Ed25519 key pair. Returns signature bytes.
    fn ed25519_sign(pkcs8: &[u8], data: &[u8]) -> Vec<u8> {
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8).unwrap();
        kp.sign(data).as_ref().to_vec()
    }

    /// Construct a mock DNS key record TXT value for Ed25519.
    fn ed25519_dns_record(pub_key: &[u8]) -> String {
        format!("v=DKIM1; k=ed25519; p={}", b64(pub_key))
    }

    /// Build mock resolver with a single DKIM key record.
    fn resolver_with_key(selector: &str, domain: &str, txt_record: &str) -> MockResolver {
        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            format!("{selector}._domainkey.{domain}"),
            MockDnsResponse::Records(vec![txt_record.to_string()]),
        );
        resolver
    }

    /// Compute the body hash for a body using the given canonicalization + SHA-256.
    fn compute_body_hash_sha256(body: &[u8], method: CanonicalizationMethod) -> Vec<u8> {
        let canon = match method {
            CanonicalizationMethod::Simple => canonicalize_body_simple(body),
            CanonicalizationMethod::Relaxed => canonicalize_body_relaxed(body),
        };
        digest(&SHA256, &canon).as_ref().to_vec()
    }

    /// Build the header data bytes that ring will verify for Ed25519.
    /// This replicates the verifier's logic so we can sign them in tests.
    fn build_header_data_for_signing(
        headers: &[(&str, &str)],
        signed_header_names: &[&str],
        sig_value_without_b: &str,
        canon: CanonicalizationMethod,
    ) -> Vec<u8> {
        let signed: Vec<String> = signed_header_names.iter().map(|s| s.to_string()).collect();
        let selected = select_headers(headers, &signed);

        let mut header_data = String::new();
        for (i, (name, value)) in selected.iter().enumerate() {
            if name.is_empty() && value.is_empty() {
                let h_name = &signed[i];
                let c = match canon {
                    CanonicalizationMethod::Simple => canonicalize_header_simple(h_name, ""),
                    CanonicalizationMethod::Relaxed => canonicalize_header_relaxed(h_name, ""),
                };
                header_data.push_str(&c);
            } else {
                let c = match canon {
                    CanonicalizationMethod::Simple => canonicalize_header_simple(name, value),
                    CanonicalizationMethod::Relaxed => canonicalize_header_relaxed(name, value),
                };
                header_data.push_str(&c);
            }
        }

        // Append DKIM-Signature with b= stripped, no trailing CRLF.
        let dkim_canon = match canon {
            CanonicalizationMethod::Simple => {
                canonicalize_header_simple("DKIM-Signature", sig_value_without_b)
            }
            CanonicalizationMethod::Relaxed => {
                canonicalize_header_relaxed("DKIM-Signature", sig_value_without_b)
            }
        };
        let dkim_canon = dkim_canon
            .strip_suffix("\r\n")
            .unwrap_or(&dkim_canon);
        header_data.push_str(dkim_canon);

        header_data.into_bytes()
    }

    // -----------------------------------------------------------------------
    // Helper: end-to-end Ed25519 test builder
    // -----------------------------------------------------------------------

    struct Ed25519TestSetup {
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        resolver: MockResolver,
    }

    /// Create a fully-signed Ed25519 DKIM message.
    fn setup_ed25519_message(
        domain: &str,
        selector: &str,
        canon: &str,
        extra_key_tags: &str,
        extra_sig_tags: &str,
    ) -> Ed25519TestSetup {
        let (pkcs8, pub_key) = gen_ed25519_keypair();

        // Parse header/body canonicalization from canon string (e.g. "relaxed/relaxed")
        let (header_canon_method, body_canon_method) = if let Some((h, b)) = canon.split_once('/') {
            (
                if h == "relaxed" { CanonicalizationMethod::Relaxed } else { CanonicalizationMethod::Simple },
                if b == "relaxed" { CanonicalizationMethod::Relaxed } else { CanonicalizationMethod::Simple },
            )
        } else {
            let hm = if canon == "relaxed" { CanonicalizationMethod::Relaxed } else { CanonicalizationMethod::Simple };
            (hm, CanonicalizationMethod::Simple)
        };

        let body = b"Hello, world!\r\n";
        let body_hash = compute_body_hash_sha256(body, body_canon_method);
        let bh_b64 = b64(&body_hash);

        let msg_headers = vec![
            ("From".to_string(), " sender@".to_string() + domain),
            ("To".to_string(), " recipient@example.org".to_string()),
            ("Subject".to_string(), " Test message".to_string()),
        ];

        let signed_header_names = ["from", "to", "subject"];

        // Build partial sig value with empty b= for signing.
        // Include leading space to match what the parser will store in raw_header
        // (the header value includes the space after the colon).
        let mut sig_core = format!(
            "v=1; a=ed25519-sha256; d={domain}; s={selector}; h=from:to:subject; bh={bh_b64}; b=; c={canon}"
        );
        if !extra_sig_tags.is_empty() {
            sig_core.push_str("; ");
            sig_core.push_str(extra_sig_tags);
        }
        let sig_template = format!(" {sig_core}");

        // Build header data to sign (with b= stripped = empty)
        let headers_ref: Vec<(&str, &str)> = msg_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();

        let canon_method = header_canon_method;

        let header_data = build_header_data_for_signing(
            &headers_ref,
            &signed_header_names,
            &sig_template,
            canon_method,
        );

        // Sign
        let signature = ed25519_sign(&pkcs8, &header_data);
        let sig_b64 = b64(&signature);

        // Build the real sig value with actual b= filled in (with leading space)
        let mut real_core = format!(
            "v=1; a=ed25519-sha256; d={domain}; s={selector}; h=from:to:subject; bh={bh_b64}; b={sig_b64}; c={canon}"
        );
        if !extra_sig_tags.is_empty() {
            real_core.push_str("; ");
            real_core.push_str(extra_sig_tags);
        }
        let real_sig_value = format!(" {real_core}");

        // Build complete headers including DKIM-Signature
        let mut all_headers = vec![(
            "DKIM-Signature".to_string(),
            real_sig_value,
        )];
        all_headers.extend(msg_headers);

        // DNS key record
        let mut key_record = ed25519_dns_record(&pub_key);
        if !extra_key_tags.is_empty() {
            key_record.push_str("; ");
            key_record.push_str(extra_key_tags);
        }

        let resolver = resolver_with_key(selector, domain, &key_record);

        Ed25519TestSetup {
            headers: all_headers,
            body: body.to_vec(),
            resolver,
        }
    }

    fn headers_as_ref(h: &[(String, String)]) -> Vec<(&str, &str)> {
        h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
    }

    // -----------------------------------------------------------------------
    // Test 1: Pass - Ed25519-SHA256
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pass_ed25519_sha256() {
        let setup = setup_ed25519_message(
            "example.com",
            "sel",
            "relaxed/relaxed",
            "",
            "",
        );
        let verifier = DkimVerifier::new(setup.resolver);
        let h = headers_as_ref(&setup.headers);
        let results = verifier.verify_message(&h, &setup.body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass {
                domain,
                selector,
                testing,
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(selector, "sel");
                assert!(!testing);
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: Pass - Ed25519 with testing flag
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pass_ed25519_testing_flag() {
        let setup = setup_ed25519_message(
            "example.com",
            "sel",
            "relaxed/relaxed",
            "t=y",
            "",
        );
        let verifier = DkimVerifier::new(setup.resolver);
        let h = headers_as_ref(&setup.headers);
        let results = verifier.verify_message(&h, &setup.body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Pass { testing, .. } => {
                assert!(*testing, "should be marked as testing");
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: Fail - body hash mismatch
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fail_body_hash_mismatch() {
        let setup = setup_ed25519_message(
            "example.com",
            "sel",
            "relaxed/relaxed",
            "",
            "",
        );
        let verifier = DkimVerifier::new(setup.resolver);
        let h = headers_as_ref(&setup.headers);
        // Pass different body than what was signed
        let wrong_body = b"This is not the original body\r\n";
        let results = verifier.verify_message(&h, wrong_body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Fail { reason } => {
                assert!(reason.contains("body hash"), "reason: {reason}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Fail - signature mismatch (correct body hash, wrong signature)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fail_signature_mismatch() {
        let (_, pub_key) = gen_ed25519_keypair();
        let body = b"Hello, world!\r\n";
        let body_hash = compute_body_hash_sha256(body, CanonicalizationMethod::Relaxed);
        let bh_b64 = b64(&body_hash);

        // Use random bytes as signature (wrong)
        let fake_sig = vec![0u8; 64];
        let sig_b64 = b64(&fake_sig);

        let sig_value = format!(
            "v=1; a=ed25519-sha256; d=example.com; s=sel; h=from; bh={bh_b64}; b={sig_b64}; c=relaxed/relaxed"
        );

        let headers = vec![
            ("DKIM-Signature".to_string(), format!(" {sig_value}")),
            ("From".to_string(), " sender@example.com".to_string()),
        ];

        let key_record = ed25519_dns_record(&pub_key);
        let resolver = resolver_with_key("sel", "example.com", &key_record);
        let verifier = DkimVerifier::new(resolver);
        let h = headers_as_ref(&headers);
        let results = verifier.verify_message(&h, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::Fail { reason } => {
                assert!(
                    reason.contains("signature verification failed"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: PermFail - key revoked (empty p=)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn permfail_key_revoked() {
        let body = b"test\r\n";
        let body_hash = compute_body_hash_sha256(body, CanonicalizationMethod::Relaxed);
        let bh_b64 = b64(&body_hash);
        let sig_b64 = b64(&[0u8; 64]);

        let sig_value = format!(
            "v=1; a=ed25519-sha256; d=example.com; s=sel; h=from; bh={bh_b64}; b={sig_b64}; c=relaxed/relaxed"
        );

        let headers = vec![
            ("DKIM-Signature".to_string(), format!(" {sig_value}")),
            ("From".to_string(), " a@example.com".to_string()),
        ];

        let resolver = resolver_with_key("sel", "example.com", "v=DKIM1; k=ed25519; p=");
        let verifier = DkimVerifier::new(resolver);
        let h = headers_as_ref(&headers);
        let results = verifier.verify_message(&h, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { reason } => {
                assert!(reason.contains("revoked"), "reason: {reason}");
            }
            other => panic!("expected PermFail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: PermFail - hash algorithm not permitted by key
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn permfail_hash_not_permitted() {
        // Key allows only sha1, signature uses ed25519-sha256 (sha256)
        let (_, pub_key) = gen_ed25519_keypair();
        let body = b"test\r\n";
        let body_hash = compute_body_hash_sha256(body, CanonicalizationMethod::Relaxed);
        let bh_b64 = b64(&body_hash);
        let sig_b64 = b64(&[0u8; 64]);

        let sig_value = format!(
            "v=1; a=ed25519-sha256; d=example.com; s=sel; h=from; bh={bh_b64}; b={sig_b64}; c=relaxed/relaxed"
        );

        let headers = vec![
            ("DKIM-Signature".to_string(), format!(" {sig_value}")),
            ("From".to_string(), " a@example.com".to_string()),
        ];

        let key_record = format!("v=DKIM1; k=ed25519; p={}; h=sha1", b64(&pub_key));
        let resolver = resolver_with_key("sel", "example.com", &key_record);
        let verifier = DkimVerifier::new(resolver);
        let h = headers_as_ref(&headers);
        let results = verifier.verify_message(&h, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { reason } => {
                assert!(reason.contains("not permitted"), "reason: {reason}");
            }
            other => panic!("expected PermFail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: PermFail - service type mismatch
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn permfail_service_type_mismatch() {
        let (_, pub_key) = gen_ed25519_keypair();
        let body = b"test\r\n";
        let body_hash = compute_body_hash_sha256(body, CanonicalizationMethod::Relaxed);
        let bh_b64 = b64(&body_hash);
        let sig_b64 = b64(&[0u8; 64]);

        let sig_value = format!(
            "v=1; a=ed25519-sha256; d=example.com; s=sel; h=from; bh={bh_b64}; b={sig_b64}; c=relaxed/relaxed"
        );

        let headers = vec![
            ("DKIM-Signature".to_string(), format!(" {sig_value}")),
            ("From".to_string(), " a@example.com".to_string()),
        ];

        let key_record = format!("v=DKIM1; k=ed25519; p={}; s=other", b64(&pub_key));
        let resolver = resolver_with_key("sel", "example.com", &key_record);
        let verifier = DkimVerifier::new(resolver);
        let h = headers_as_ref(&headers);
        let results = verifier.verify_message(&h, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { reason } => {
                assert!(
                    reason.contains("email") || reason.contains("service"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected PermFail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: PermFail - strict mode domain mismatch (t=s, i= is subdomain)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn permfail_strict_mode_domain_mismatch() {
        let (_, pub_key) = gen_ed25519_keypair();
        let body = b"test\r\n";
        let body_hash = compute_body_hash_sha256(body, CanonicalizationMethod::Relaxed);
        let bh_b64 = b64(&body_hash);
        let sig_b64 = b64(&[0u8; 64]);

        // i= is a subdomain of d= but key has t=s (strict), so must be exact match
        let sig_value = format!(
            "v=1; a=ed25519-sha256; d=example.com; s=sel; h=from; bh={bh_b64}; b={sig_b64}; c=relaxed/relaxed; i=user@sub.example.com"
        );

        let headers = vec![
            ("DKIM-Signature".to_string(), format!(" {sig_value}")),
            ("From".to_string(), " a@example.com".to_string()),
        ];

        let key_record = format!("v=DKIM1; k=ed25519; p={}; t=s", b64(&pub_key));
        let resolver = resolver_with_key("sel", "example.com", &key_record);
        let verifier = DkimVerifier::new(resolver);
        let h = headers_as_ref(&headers);
        let results = verifier.verify_message(&h, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { reason } => {
                assert!(reason.contains("strict"), "reason: {reason}");
            }
            other => panic!("expected PermFail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: PermFail - expired signature
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn permfail_expired_signature() {
        let (_, pub_key) = gen_ed25519_keypair();
        let body = b"test\r\n";
        let body_hash = compute_body_hash_sha256(body, CanonicalizationMethod::Relaxed);
        let bh_b64 = b64(&body_hash);
        let sig_b64 = b64(&[0u8; 64]);

        // Expired 1 hour ago
        let past = current_timestamp() - 3600;
        let sig_value = format!(
            "v=1; a=ed25519-sha256; d=example.com; s=sel; h=from; bh={bh_b64}; b={sig_b64}; c=relaxed/relaxed; t=1000; x={past}"
        );

        let headers = vec![
            ("DKIM-Signature".to_string(), format!(" {sig_value}")),
            ("From".to_string(), " a@example.com".to_string()),
        ];

        let key_record = format!("v=DKIM1; k=ed25519; p={}", b64(&pub_key));
        let resolver = resolver_with_key("sel", "example.com", &key_record);
        let verifier = DkimVerifier::new(resolver);
        let h = headers_as_ref(&headers);
        let results = verifier.verify_message(&h, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { reason } => {
                assert!(reason.contains("expired"), "reason: {reason}");
            }
            other => panic!("expected PermFail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: TempFail - DNS error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tempfail_dns_error() {
        let body = b"test\r\n";
        let body_hash = compute_body_hash_sha256(body, CanonicalizationMethod::Relaxed);
        let bh_b64 = b64(&body_hash);
        let sig_b64 = b64(&[0u8; 64]);

        let sig_value = format!(
            "v=1; a=ed25519-sha256; d=example.com; s=sel; h=from; bh={bh_b64}; b={sig_b64}; c=relaxed/relaxed"
        );

        let headers = vec![
            ("DKIM-Signature".to_string(), format!(" {sig_value}")),
            ("From".to_string(), " a@example.com".to_string()),
        ];

        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "sel._domainkey.example.com".into(),
            MockDnsResponse::TempFail("timeout".into()),
        );

        let verifier = DkimVerifier::new(resolver);
        let h = headers_as_ref(&headers);
        let results = verifier.verify_message(&h, body).await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::TempFail { reason } => {
                assert!(reason.contains("timeout"), "reason: {reason}");
            }
            other => panic!("expected TempFail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: None - no DKIM-Signature headers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn none_no_dkim_signature() {
        let headers = vec![
            ("From", " a@example.com"),
            ("To", " b@example.com"),
            ("Subject", " Hi"),
        ];

        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&headers, b"body").await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], DkimResult::None);
    }

    // -----------------------------------------------------------------------
    // Test 12: PermFail - malformed signature
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn permfail_malformed_signature() {
        let headers = vec![
            ("DKIM-Signature", " this is not valid"),
            ("From", " a@example.com"),
        ];

        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&headers, b"body").await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { reason } => {
                assert!(reason.contains("malformed"), "reason: {reason}");
            }
            other => panic!("expected PermFail, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: Multiple signatures - all checked, results collected
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn multiple_signatures() {
        // First: valid Ed25519 signature
        let setup = setup_ed25519_message(
            "example.com",
            "sel",
            "relaxed/relaxed",
            "",
            "",
        );

        // Second: malformed signature
        let mut all_headers = setup.headers.clone();
        all_headers.insert(0, ("DKIM-Signature".to_string(), " garbage".to_string()));

        let verifier = DkimVerifier::new(setup.resolver);
        let h = headers_as_ref(&all_headers);
        let results = verifier.verify_message(&h, &setup.body).await;

        assert_eq!(results.len(), 2, "should have 2 results: {results:?}");
        // First result (garbage) should be PermFail
        assert!(
            matches!(&results[0], DkimResult::PermFail { .. }),
            "first: {:?}",
            results[0]
        );
        // Second result (valid) should be Pass
        assert!(
            matches!(&results[1], DkimResult::Pass { .. }),
            "second: {:?}",
            results[1]
        );
    }

    // -----------------------------------------------------------------------
    // Test 14: Pass - simple/simple canonicalization
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pass_ed25519_simple_simple() {
        let setup = setup_ed25519_message(
            "example.com",
            "sel",
            "simple/simple",
            "",
            "",
        );
        let verifier = DkimVerifier::new(setup.resolver);
        let h = headers_as_ref(&setup.headers);
        let results = verifier.verify_message(&h, &setup.body).await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], DkimResult::Pass { .. }),
            "expected Pass, got {:?}",
            results[0]
        );
    }

    // -----------------------------------------------------------------------
    // Test 15: Strict mode with exact domain match passes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pass_strict_mode_exact_domain() {
        // i= defaults to @domain, which matches d= exactly -- should pass strict
        let setup = setup_ed25519_message(
            "example.com",
            "sel",
            "relaxed/relaxed",
            "t=s",
            "",
        );
        let verifier = DkimVerifier::new(setup.resolver);
        let h = headers_as_ref(&setup.headers);
        let results = verifier.verify_message(&h, &setup.body).await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], DkimResult::Pass { .. }),
            "expected Pass, got {:?}",
            results[0]
        );
    }
}
