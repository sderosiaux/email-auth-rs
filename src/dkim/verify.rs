use std::time::{SystemTime, UNIX_EPOCH};

use ring::signature as ring_sig;
use subtle::ConstantTimeEq;

use crate::common::dns::{DnsError, DnsResolver};

use super::canon::{
    apply_body_length_limit, canonicalize_body, canonicalize_header, normalize_line_endings,
    select_headers, strip_b_tag_value,
};
use super::key::DkimPublicKey;
use super::types::{
    Algorithm, CanonicalizationMethod, DkimResult, DkimSignature, FailureKind, HashAlgorithm,
    KeyType, PermFailKind,
};

/// DKIM signature verifier.
pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
    clock_skew: u64, // default 300s
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
    /// `headers`: message headers as (name, value) pairs, in order (first = top of message).
    /// `body`: raw message body bytes.
    /// Returns one DkimResult per DKIM-Signature, or `[DkimResult::None]` if none found.
    pub async fn verify_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<DkimResult> {
        // Find all DKIM-Signature headers
        let dkim_indices: Vec<usize> = headers
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| name.eq_ignore_ascii_case("dkim-signature"))
            .map(|(i, _)| i)
            .collect();

        if dkim_indices.is_empty() {
            return vec![DkimResult::None];
        }

        let mut results = Vec::new();
        for idx in dkim_indices {
            let (_, value) = headers[idx];
            let result = self.verify_single(headers, body, value, idx).await;
            results.push(result);
        }
        results
    }

    async fn verify_single(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        sig_value: &str,
        sig_idx: usize,
    ) -> DkimResult {
        // Parse signature
        let sig = match DkimSignature::parse(sig_value) {
            Ok(s) => s,
            Err(e) => {
                return DkimResult::PermFail {
                    kind: e.kind,
                    detail: e.detail,
                }
            }
        };

        // Expiration check (BEFORE DNS lookup)
        if let Some(expiration) = sig.expiration {
            let now = current_timestamp();
            if now > expiration + self.clock_skew {
                return DkimResult::PermFail {
                    kind: PermFailKind::ExpiredSignature,
                    detail: format!("signature expired at {}, now {}", expiration, now),
                };
            }
        }

        // DNS key lookup
        let query = format!("{}._domainkey.{}", sig.selector, sig.domain);
        let key = match self.lookup_key(&query).await {
            Ok(k) => k,
            Err(result) => return result,
        };

        // Key constraint enforcement (ordered per spec §4.3)
        if let Some(result) = enforce_key_constraints(&sig, &key) {
            return result;
        }

        // Body hash verification
        if let Some(result) =
            verify_body_hash(&sig, body)
        {
            return result;
        }

        // Header hash computation + crypto verification
        let header_data = compute_header_hash_input(&sig, headers, sig_idx);

        // Crypto verification
        match verify_signature(&sig.algorithm, &key, &header_data, &sig.signature) {
            Ok(()) => DkimResult::Pass {
                domain: sig.domain,
                selector: sig.selector,
                testing: key.is_testing(),
            },
            Err(detail) => DkimResult::Fail {
                kind: FailureKind::SignatureVerificationFailed,
                detail,
            },
        }
    }

    async fn lookup_key(&self, query: &str) -> Result<DkimPublicKey, DkimResult> {
        let txt_records = match self.resolver.query_txt(query).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                return Err(DkimResult::PermFail {
                    kind: PermFailKind::KeyNotFound,
                    detail: format!("no DNS key record at {}", query),
                })
            }
            Err(DnsError::TempFail) => {
                return Err(DkimResult::TempFail {
                    reason: format!("DNS temp failure for {}", query),
                })
            }
        };

        // Concatenate multiple TXT strings
        let concatenated = txt_records.join("");

        DkimPublicKey::parse(&concatenated).map_err(|e| DkimResult::PermFail {
            kind: e.kind,
            detail: e.detail,
        })
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Enforce key constraints per spec §4.3 (ordered).
pub(crate) fn enforce_key_constraints(sig: &DkimSignature, key: &DkimPublicKey) -> Option<DkimResult> {
    // a. Empty p= → KeyRevoked
    if key.revoked {
        return Some(DkimResult::PermFail {
            kind: PermFailKind::KeyRevoked,
            detail: "key revoked (empty p= tag)".into(),
        });
    }

    // b. Key h= tag: signature's hash must be in list
    if let Some(ref hash_algs) = key.hash_algorithms {
        let sig_hash = sig.algorithm.hash_algorithm();
        if !hash_algs.contains(&sig_hash) {
            return Some(DkimResult::PermFail {
                kind: PermFailKind::HashNotPermitted,
                detail: format!("key h= tag does not permit {:?}", sig_hash),
            });
        }
    }

    // c. Key s= tag: must include "email" or "*"
    if let Some(ref service_types) = key.service_types {
        if !service_types.iter().any(|s| s == "email" || s == "*") {
            return Some(DkimResult::PermFail {
                kind: PermFailKind::ServiceTypeMismatch,
                detail: "key s= tag does not include 'email' or '*'".into(),
            });
        }
    }

    // d. Key t=s strict: i= domain must exactly equal d=
    if key.is_strict() {
        let i_domain = sig
            .auid
            .rfind('@')
            .map(|pos| &sig.auid[pos + 1..])
            .unwrap_or(&sig.auid);
        if !i_domain.eq_ignore_ascii_case(&sig.domain) {
            return Some(DkimResult::PermFail {
                kind: PermFailKind::StrictModeViolation,
                detail: format!(
                    "key t=s strict mode: i= domain '{}' must exactly equal d= '{}'",
                    i_domain, sig.domain
                ),
            });
        }
    }

    // e. Key type must match algorithm
    let expected_key_type = match sig.algorithm {
        Algorithm::RsaSha1 | Algorithm::RsaSha256 => KeyType::Rsa,
        Algorithm::Ed25519Sha256 => KeyType::Ed25519,
    };
    if key.key_type != expected_key_type {
        return Some(DkimResult::PermFail {
            kind: PermFailKind::AlgorithmMismatch,
            detail: format!(
                "key type {:?} incompatible with algorithm {:?}",
                key.key_type, sig.algorithm
            ),
        });
    }

    None
}

/// Verify body hash: canonicalize → hash → constant-time compare with bh=.
pub(crate) fn verify_body_hash(sig: &DkimSignature, body: &[u8]) -> Option<DkimResult> {
    let normalized = normalize_line_endings(body);
    let canonicalized = canonicalize_body(sig.body_canonicalization, &normalized);
    let limited = apply_body_length_limit(&canonicalized, sig.body_length);

    let computed_hash = compute_hash(sig.algorithm, limited);

    // Constant-time comparison
    if computed_hash.ct_eq(&sig.body_hash).into() {
        None // match — continue verification
    } else {
        Some(DkimResult::Fail {
            kind: FailureKind::BodyHashMismatch,
            detail: "computed body hash does not match bh= value".into(),
        })
    }
}

/// Compute hash using the algorithm's hash function.
pub(crate) fn compute_hash(algorithm: Algorithm, data: &[u8]) -> Vec<u8> {
    match algorithm.hash_algorithm() {
        HashAlgorithm::Sha256 => {
            let digest = ring::digest::digest(&ring::digest::SHA256, data);
            digest.as_ref().to_vec()
        }
        HashAlgorithm::Sha1 => {
            let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
            digest.as_ref().to_vec()
        }
    }
}

/// Build the header hash input for DKIM verification.
fn compute_header_hash_input(
    sig: &DkimSignature,
    headers: &[(&str, &str)],
    sig_idx: usize,
) -> Vec<u8> {
    // Exclude the DKIM-Signature header being verified from the message headers
    let filtered_headers: Vec<(&str, &str)> = headers
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != sig_idx)
        .map(|(_, h)| *h)
        .collect();

    // Select and canonicalize headers per h= tag
    let selected = select_headers(
        sig.header_canonicalization,
        &sig.signed_headers,
        &filtered_headers,
    );

    let mut hash_input = Vec::new();
    for header_line in &selected {
        hash_input.extend_from_slice(header_line.as_bytes());
    }

    // Append DKIM-Signature header with b= stripped, canonicalized, NO trailing CRLF
    let stripped = strip_b_tag_value(&sig.raw_header);
    let canon_sig = if sig.header_canonicalization == CanonicalizationMethod::Simple {
        // Simple: preserve original header name casing
        format!("DKIM-Signature:{}", stripped)
    } else {
        canonicalize_header(
            sig.header_canonicalization,
            "dkim-signature",
            &stripped,
        )
    };

    hash_input.extend_from_slice(canon_sig.as_bytes());
    // Note: NO trailing CRLF on the DKIM-Signature header

    hash_input
}

/// Strip SPKI wrapper from RSA public key to get PKCS#1 format.
/// DKIM p= stores SPKI DER. ring expects PKCS#1 for RSA.
/// If already PKCS#1, returns as-is.
pub(crate) fn strip_spki_wrapper(spki_der: &[u8]) -> &[u8] {
    // SPKI structure: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { RSAPublicKey } }
    // Check for SPKI prefix: starts with 0x30 (SEQUENCE), contains RSA OID
    // OID 1.2.840.113549.1.1.1 = 06 09 2a 86 48 86 f7 0d 01 01 01
    let rsa_oid: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    if spki_der.len() < 24 || spki_der[0] != 0x30 {
        return spki_der; // Not SPKI, assume PKCS#1
    }

    // Search for the RSA OID
    if let Some(oid_pos) = spki_der
        .windows(rsa_oid.len())
        .position(|w| w == rsa_oid)
    {
        // After OID + NULL, find the BIT STRING
        let after_oid = oid_pos + rsa_oid.len();
        // Skip NULL (05 00)
        let mut pos = after_oid;
        if pos + 1 < spki_der.len() && spki_der[pos] == 0x05 && spki_der[pos + 1] == 0x00 {
            pos += 2;
        }
        // BIT STRING tag (03)
        if pos < spki_der.len() && spki_der[pos] == 0x03 {
            pos += 1;
            // Parse length
            let (len, len_bytes) = parse_asn1_length(&spki_der[pos..]);
            pos += len_bytes;
            if len > 0 && pos < spki_der.len() {
                // Skip unused-bits byte (should be 0)
                pos += 1;
                // Remaining bytes are the PKCS#1 RSAPublicKey
                if pos < spki_der.len() {
                    return &spki_der[pos..];
                }
            }
        }
    }

    spki_der // Fallback: return as-is
}

/// Parse ASN.1 DER length encoding. Returns (length, bytes_consumed).
fn parse_asn1_length(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return (0, 1);
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        (len, 1 + num_bytes)
    }
}

/// Verify the cryptographic signature using ring.
pub(crate) fn verify_signature(
    algorithm: &Algorithm,
    key: &DkimPublicKey,
    data: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let ring_algorithm: &dyn ring_sig::VerificationAlgorithm = match algorithm {
        Algorithm::RsaSha256 => {
            if key.public_key.len() >= 256 {
                &ring_sig::RSA_PKCS1_2048_8192_SHA256
            } else {
                &ring_sig::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
            }
        }
        Algorithm::RsaSha1 => {
            if key.public_key.len() >= 256 {
                &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
            } else {
                &ring_sig::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
            }
        }
        Algorithm::Ed25519Sha256 => &ring_sig::ED25519,
    };

    // For RSA keys, strip SPKI wrapper to get PKCS#1
    let key_bytes = match key.key_type {
        KeyType::Rsa => strip_spki_wrapper(&key.public_key),
        KeyType::Ed25519 => &key.public_key,
    };

    let public_key = ring_sig::UnparsedPublicKey::new(ring_algorithm, key_bytes);
    public_key
        .verify(data, signature)
        .map_err(|_| "cryptographic signature verification failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// Helper: generate Ed25519 key pair using ring, return (pkcs8, public_key_32_bytes).
    fn gen_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), public_key)
    }

    /// Helper: sign data with Ed25519 key pair.
    fn ed25519_sign(pkcs8: &[u8], data: &[u8]) -> Vec<u8> {
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8).unwrap();
        key_pair.sign(data).as_ref().to_vec()
    }

    /// Helper: compute body hash for a given body, algorithm, and canonicalization.
    fn compute_body_hash(
        body: &[u8],
        algorithm: Algorithm,
        body_canon: CanonicalizationMethod,
    ) -> String {
        let normalized = normalize_line_endings(body);
        let canonicalized = canonicalize_body(body_canon, &normalized);
        let hash = compute_hash(algorithm, &canonicalized);
        base64::engine::general_purpose::STANDARD.encode(&hash)
    }

    /// Helper: compute the header hash input manually (ground-truth).
    fn compute_header_input_manual(
        headers: &[(&str, &str)],
        signed_header_names: &[&str],
        sig_header_value_stripped: &str,
        header_canon: CanonicalizationMethod,
    ) -> Vec<u8> {
        let signed: Vec<String> = signed_header_names.iter().map(|s| s.to_string()).collect();
        let selected = select_headers(header_canon, &signed, headers);

        let mut input = Vec::new();
        for h in &selected {
            input.extend_from_slice(h.as_bytes());
        }

        // Append DKIM-Signature header (canonicalized, no trailing CRLF)
        let canon_sig =
            canonicalize_header(header_canon, "dkim-signature", sig_header_value_stripped);
        let canon_sig = if header_canon == CanonicalizationMethod::Simple {
            format!("DKIM-Signature:{}", sig_header_value_stripped)
        } else {
            canon_sig
        };
        input.extend_from_slice(canon_sig.as_bytes());
        input
    }

    fn setup_mock_key(resolver: &mut MockResolver, selector: &str, domain: &str, key_record: &str) {
        let query = format!("{}._domainkey.{}", selector, domain);
        resolver.add_txt(&query, vec![key_record.to_string()]);
    }

    // ─── CHK-367..CHK-370: Signature extraction ─────────────────────

    // CHK-494: No DKIM-Signature → None
    #[tokio::test]
    async fn no_dkim_signature_returns_none() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("Subject", " test"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], DkimResult::None);
    }

    // CHK-367: Find DKIM-Signature headers
    // CHK-370: One result per signature
    #[tokio::test]
    async fn multiple_signatures_return_multiple_results() {
        let resolver = MockResolver::new();
        // Both signatures will fail DNS lookup
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=a.com; h=from; s=s1"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=b.com; h=from; s=s1"),
        ];
        // Leave DNS unconfigured → NxDomain → KeyNotFound
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 2);
    }

    // CHK-368, CHK-369: Parse each, malformed → PermFail
    #[tokio::test]
    async fn malformed_signature_returns_permfail() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " not-a-valid-signature"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        assert_eq!(results.len(), 1);
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::MalformedSignature);
            }
            _ => panic!("expected PermFail"),
        }
    }

    // ─── CHK-371..CHK-376: DNS key lookup ───────────────────────────

    // CHK-487: Key not found
    #[tokio::test]
    async fn key_not_found_nxdomain() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        match &results[0] {
            DkimResult::PermFail { kind, .. } => assert_eq!(*kind, PermFailKind::KeyNotFound),
            _ => panic!("expected PermFail KeyNotFound"),
        }
    }

    // CHK-493: DNS temp failure
    #[tokio::test]
    async fn dns_temp_failure() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_err("sel1._domainkey.example.com", DnsError::TempFail);
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        match &results[0] {
            DkimResult::TempFail { .. } => {}
            _ => panic!("expected TempFail"),
        }
    }

    // CHK-488: Key revoked
    #[tokio::test]
    async fn key_revoked_empty_p() {
        let mut resolver = MockResolver::new();
        setup_mock_key(&mut resolver, "sel1", "example.com", "v=DKIM1; p=");
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        match &results[0] {
            DkimResult::PermFail { kind, .. } => assert_eq!(*kind, PermFailKind::KeyRevoked),
            _ => panic!("expected PermFail KeyRevoked"),
        }
    }

    // ─── CHK-377..CHK-381: Key constraints ──────────────────────────

    // CHK-489: h= rejects algo
    #[tokio::test]
    async fn key_h_rejects_algorithm() {
        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(vec![0x30u8; 162]);
        setup_mock_key(
            &mut resolver,
            "sel1",
            "example.com",
            &format!("v=DKIM1; h=sha1; k=rsa; p={}", p),
        );
        let verifier = DkimVerifier::new(resolver);
        // Signature uses rsa-sha256 but key only allows sha1
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        match &results[0] {
            DkimResult::PermFail { kind, .. } => assert_eq!(*kind, PermFailKind::HashNotPermitted),
            _ => panic!("expected PermFail HashNotPermitted"),
        }
    }

    // CHK-490: s= rejects email
    #[tokio::test]
    async fn key_s_rejects_email() {
        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(vec![0x30u8; 162]);
        setup_mock_key(
            &mut resolver,
            "sel1",
            "example.com",
            &format!("v=DKIM1; s=other; k=rsa; p={}", p),
        );
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::ServiceTypeMismatch)
            }
            _ => panic!("expected PermFail ServiceTypeMismatch"),
        }
    }

    // CHK-491: t=s strict
    #[tokio::test]
    async fn key_strict_mode_violation() {
        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(vec![0x30u8; 162]);
        setup_mock_key(
            &mut resolver,
            "sel1",
            "example.com",
            &format!("v=DKIM1; t=s; k=rsa; p={}", p),
        );
        let verifier = DkimVerifier::new(resolver);
        // i= defaults to @example.com, but let's use a subdomain
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@sub.example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1; i=user@sub.example.com"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::StrictModeViolation)
            }
            _ => panic!("expected PermFail StrictModeViolation"),
        }
    }

    // CHK-492: Algorithm/key mismatch
    #[tokio::test]
    async fn algorithm_key_type_mismatch() {
        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(vec![0xABu8; 32]);
        // Key is ed25519 but signature says rsa-sha256
        setup_mock_key(
            &mut resolver,
            "sel1",
            "example.com",
            &format!("v=DKIM1; k=ed25519; p={}", p),
        );
        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::AlgorithmMismatch)
            }
            _ => panic!("expected PermFail AlgorithmMismatch"),
        }
    }

    // ─── CHK-382..CHK-384: Expiration ───────────────────────────────

    // CHK-486: Expired signature
    #[tokio::test]
    async fn expired_signature() {
        let resolver = MockResolver::new();
        let verifier = DkimVerifier::new(resolver);
        // x=1000000 is well in the past
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", " v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1; x=1000000"),
        ];
        let results = verifier.verify_message(&headers, b"body").await;
        match &results[0] {
            DkimResult::PermFail { kind, .. } => {
                assert_eq!(*kind, PermFailKind::ExpiredSignature)
            }
            _ => panic!("expected PermFail ExpiredSignature"),
        }
    }

    // ─── CHK-481: Ed25519 → Pass (ground truth) ─────────────────────

    #[tokio::test]
    async fn ed25519_pass_ground_truth() {
        let (pkcs8, public_key) = gen_ed25519_keypair();
        let body = b"Hello DKIM\r\n";
        let domain = "example.com";
        let selector = "ed";

        // Compute body hash (relaxed/relaxed)
        let bh = compute_body_hash(body, Algorithm::Ed25519Sha256, CanonicalizationMethod::Relaxed);

        // Build signature header template (without real signature)
        let sig_header_template = format!(
            " v=1; a=ed25519-sha256; b=; bh={}; c=relaxed/relaxed; d={}; h=from; s={}",
            bh, domain, selector
        );

        // Compute header hash input
        let header_input = compute_header_input_manual(
            &[("From", " user@example.com")],
            &["from"],
            &sig_header_template,
            CanonicalizationMethod::Relaxed,
        );

        // Sign with Ed25519
        let signature = ed25519_sign(&pkcs8, &header_input);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        // Build final signature header
        let final_sig_header = format!(
            " v=1; a=ed25519-sha256; b={}; bh={}; c=relaxed/relaxed; d={}; h=from; s={}",
            sig_b64, bh, domain, selector
        );

        // Setup DNS
        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(&public_key);
        setup_mock_key(&mut resolver, selector, domain, &format!("k=ed25519; p={}", p));

        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", &final_sig_header),
        ];

        let results = verifier.verify_message(&headers, body).await;
        match &results[0] {
            DkimResult::Pass { domain: d, selector: s, testing } => {
                assert_eq!(d, domain);
                assert_eq!(s, selector);
                assert!(!testing);
            }
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // ─── CHK-484: Tampered body ─────────────────────────────────────

    #[tokio::test]
    async fn ed25519_tampered_body() {
        let (pkcs8, public_key) = gen_ed25519_keypair();
        let body = b"Hello DKIM\r\n";
        let domain = "example.com";
        let selector = "ed";

        let bh = compute_body_hash(body, Algorithm::Ed25519Sha256, CanonicalizationMethod::Relaxed);
        let sig_header_template = format!(
            " v=1; a=ed25519-sha256; b=; bh={}; c=relaxed/relaxed; d={}; h=from; s={}",
            bh, domain, selector
        );

        let header_input = compute_header_input_manual(
            &[("From", " user@example.com")],
            &["from"],
            &sig_header_template,
            CanonicalizationMethod::Relaxed,
        );

        let signature = ed25519_sign(&pkcs8, &header_input);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        let final_sig_header = format!(
            " v=1; a=ed25519-sha256; b={}; bh={}; c=relaxed/relaxed; d={}; h=from; s={}",
            sig_b64, bh, domain, selector
        );

        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(&public_key);
        setup_mock_key(&mut resolver, selector, domain, &format!("k=ed25519; p={}", p));

        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", &final_sig_header),
        ];

        // Tampered body
        let results = verifier.verify_message(&headers, b"TAMPERED BODY\r\n").await;
        match &results[0] {
            DkimResult::Fail { kind, .. } => assert_eq!(*kind, FailureKind::BodyHashMismatch),
            other => panic!("expected Fail BodyHashMismatch, got {:?}", other),
        }
    }

    // ─── CHK-485: Tampered header ───────────────────────────────────

    #[tokio::test]
    async fn ed25519_tampered_header() {
        let (pkcs8, public_key) = gen_ed25519_keypair();
        let body = b"Hello DKIM\r\n";
        let domain = "example.com";
        let selector = "ed";

        let bh = compute_body_hash(body, Algorithm::Ed25519Sha256, CanonicalizationMethod::Relaxed);
        let sig_header_template = format!(
            " v=1; a=ed25519-sha256; b=; bh={}; c=relaxed/relaxed; d={}; h=from:subject; s={}",
            bh, domain, selector
        );

        let header_input = compute_header_input_manual(
            &[("From", " user@example.com"), ("Subject", " original")],
            &["from", "subject"],
            &sig_header_template,
            CanonicalizationMethod::Relaxed,
        );

        let signature = ed25519_sign(&pkcs8, &header_input);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        let final_sig_header = format!(
            " v=1; a=ed25519-sha256; b={}; bh={}; c=relaxed/relaxed; d={}; h=from:subject; s={}",
            sig_b64, bh, domain, selector
        );

        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(&public_key);
        setup_mock_key(&mut resolver, selector, domain, &format!("k=ed25519; p={}", p));

        let verifier = DkimVerifier::new(resolver);
        // Subject is different from what was signed
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("Subject", " TAMPERED"),
            ("DKIM-Signature", &final_sig_header),
        ];

        let results = verifier.verify_message(&headers, body).await;
        match &results[0] {
            DkimResult::Fail { kind, .. } => {
                assert_eq!(*kind, FailureKind::SignatureVerificationFailed)
            }
            other => panic!("expected Fail SigVerificationFailed, got {:?}", other),
        }
    }

    // ─── CHK-495: simple/simple e2e ─────────────────────────────────

    #[tokio::test]
    async fn ed25519_simple_simple_e2e() {
        let (pkcs8, public_key) = gen_ed25519_keypair();
        let body = b"Simple body content\r\n";
        let domain = "example.com";
        let selector = "ed";

        let bh = compute_body_hash(body, Algorithm::Ed25519Sha256, CanonicalizationMethod::Simple);
        let sig_header_template = format!(
            " v=1; a=ed25519-sha256; b=; bh={}; c=simple/simple; d={}; h=from; s={}",
            bh, domain, selector
        );

        let header_input = compute_header_input_manual(
            &[("From", " user@example.com")],
            &["from"],
            &sig_header_template,
            CanonicalizationMethod::Simple,
        );

        let signature = ed25519_sign(&pkcs8, &header_input);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        let final_sig_header = format!(
            " v=1; a=ed25519-sha256; b={}; bh={}; c=simple/simple; d={}; h=from; s={}",
            sig_b64, bh, domain, selector
        );

        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(&public_key);
        setup_mock_key(&mut resolver, selector, domain, &format!("k=ed25519; p={}", p));

        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", &final_sig_header),
        ];

        let results = verifier.verify_message(&headers, body).await;
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // ─── CHK-496: relaxed/relaxed e2e ───────────────────────────────

    #[tokio::test]
    async fn ed25519_relaxed_relaxed_e2e() {
        let (pkcs8, public_key) = gen_ed25519_keypair();
        let body = b"Relaxed body  content  \r\n";
        let domain = "example.com";
        let selector = "ed";

        let bh = compute_body_hash(body, Algorithm::Ed25519Sha256, CanonicalizationMethod::Relaxed);
        let sig_header_template = format!(
            " v=1; a=ed25519-sha256; b=; bh={}; c=relaxed/relaxed; d={}; h=from; s={}",
            bh, domain, selector
        );

        let header_input = compute_header_input_manual(
            &[("From", " user@example.com")],
            &["from"],
            &sig_header_template,
            CanonicalizationMethod::Relaxed,
        );

        let signature = ed25519_sign(&pkcs8, &header_input);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        let final_sig_header = format!(
            " v=1; a=ed25519-sha256; b={}; bh={}; c=relaxed/relaxed; d={}; h=from; s={}",
            sig_b64, bh, domain, selector
        );

        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(&public_key);
        setup_mock_key(&mut resolver, selector, domain, &format!("k=ed25519; p={}", p));

        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", &final_sig_header),
        ];

        let results = verifier.verify_message(&headers, body).await;
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // ─── CHK-497: Over-signed verify ────────────────────────────────

    #[tokio::test]
    async fn ed25519_over_signed_verify() {
        let (pkcs8, public_key) = gen_ed25519_keypair();
        let body = b"body\r\n";
        let domain = "example.com";
        let selector = "ed";

        let bh = compute_body_hash(body, Algorithm::Ed25519Sha256, CanonicalizationMethod::Relaxed);
        // h= lists "from" twice (over-sign)
        let sig_header_template = format!(
            " v=1; a=ed25519-sha256; b=; bh={}; c=relaxed/relaxed; d={}; h=from:from; s={}",
            bh, domain, selector
        );

        let header_input = compute_header_input_manual(
            &[("From", " user@example.com")],
            &["from", "from"],
            &sig_header_template,
            CanonicalizationMethod::Relaxed,
        );

        let signature = ed25519_sign(&pkcs8, &header_input);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        let final_sig_header = format!(
            " v=1; a=ed25519-sha256; b={}; bh={}; c=relaxed/relaxed; d={}; h=from:from; s={}",
            sig_b64, bh, domain, selector
        );

        let mut resolver = MockResolver::new();
        let p = base64::engine::general_purpose::STANDARD.encode(&public_key);
        setup_mock_key(&mut resolver, selector, domain, &format!("k=ed25519; p={}", p));

        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("DKIM-Signature", &final_sig_header),
        ];

        let results = verifier.verify_message(&headers, body).await;
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass with over-signing, got {:?}", other),
        }
    }

    // ─── CHK-498..CHK-501: Ground-truth tests ───────────────────────

    // CHK-498: Manual ring primitives (ground-truth)
    // CHK-499: Full DkimVerifier pipeline
    // CHK-500: Catch self-consistent bugs
    #[tokio::test]
    async fn ground_truth_ed25519_manual_ring_primitives() {
        // This test constructs a DKIM signature MANUALLY using ring primitives,
        // bypassing any DkimSigner, then verifies through DkimVerifier.
        let (pkcs8, public_key) = gen_ed25519_keypair();
        let body = b"Ground truth test body\r\n";
        let domain = "gt.example.com";
        let selector = "gtsel";

        // Step 1: Compute body hash manually
        let normalized_body = normalize_line_endings(body);
        let canon_body = canonicalize_body(CanonicalizationMethod::Relaxed, &normalized_body);
        let body_hash = ring::digest::digest(&ring::digest::SHA256, &canon_body);
        let bh_b64 = base64::engine::general_purpose::STANDARD.encode(body_hash.as_ref());

        // Step 2: Build sig header template (b= empty)
        let sig_template = format!(
            " v=1; a=ed25519-sha256; b=; bh={}; c=relaxed/relaxed; d={}; h=from:to; s={}",
            bh_b64, domain, selector
        );

        // Step 3: Compute header hash input manually
        let msg_headers = vec![
            ("From", " sender@gt.example.com"),
            ("To", " receiver@gt.example.com"),
        ];
        let header_input = compute_header_input_manual(
            &msg_headers,
            &["from", "to"],
            &sig_template,
            CanonicalizationMethod::Relaxed,
        );

        // Step 4: Sign with ring Ed25519
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let sig_bytes = key_pair.sign(&header_input);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes.as_ref());

        // Step 5: Build final header
        let final_sig = format!(
            " v=1; a=ed25519-sha256; b={}; bh={}; c=relaxed/relaxed; d={}; h=from:to; s={}",
            sig_b64, bh_b64, domain, selector
        );

        // Step 6: Setup DNS and verify
        let mut resolver = MockResolver::new();
        let p_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key);
        setup_mock_key(&mut resolver, selector, domain, &format!("k=ed25519; p={}", p_b64));

        let verifier = DkimVerifier::new(resolver);
        let full_headers: Vec<(&str, &str)> = vec![
            ("From", " sender@gt.example.com"),
            ("To", " receiver@gt.example.com"),
            ("DKIM-Signature", &final_sig),
        ];

        let results = verifier.verify_message(&full_headers, body).await;
        match &results[0] {
            DkimResult::Pass { domain: d, .. } => assert_eq!(d, domain),
            other => panic!("Ground-truth test failed: {:?}", other),
        }
    }

    // CHK-501: Ed25519 ground-truth + tampered body
    #[tokio::test]
    async fn ground_truth_ed25519_tampered() {
        let (pkcs8, public_key) = gen_ed25519_keypair();
        let body = b"Original body\r\n";
        let domain = "gt.example.com";
        let selector = "gtsel";

        let normalized_body = normalize_line_endings(body);
        let canon_body = canonicalize_body(CanonicalizationMethod::Relaxed, &normalized_body);
        let body_hash = ring::digest::digest(&ring::digest::SHA256, &canon_body);
        let bh_b64 = base64::engine::general_purpose::STANDARD.encode(body_hash.as_ref());

        let sig_template = format!(
            " v=1; a=ed25519-sha256; b=; bh={}; c=relaxed/relaxed; d={}; h=from; s={}",
            bh_b64, domain, selector
        );

        let header_input = compute_header_input_manual(
            &[("From", " sender@gt.example.com")],
            &["from"],
            &sig_template,
            CanonicalizationMethod::Relaxed,
        );

        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let sig_bytes = key_pair.sign(&header_input);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes.as_ref());

        let final_sig = format!(
            " v=1; a=ed25519-sha256; b={}; bh={}; c=relaxed/relaxed; d={}; h=from; s={}",
            sig_b64, bh_b64, domain, selector
        );

        let mut resolver = MockResolver::new();
        let p_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key);
        setup_mock_key(&mut resolver, selector, domain, &format!("k=ed25519; p={}", p_b64));

        let verifier = DkimVerifier::new(resolver);
        let full_headers: Vec<(&str, &str)> = vec![
            ("From", " sender@gt.example.com"),
            ("DKIM-Signature", &final_sig),
        ];

        // Tampered body
        let results = verifier
            .verify_message(&full_headers, b"Tampered body\r\n")
            .await;
        match &results[0] {
            DkimResult::Fail { kind, .. } => assert_eq!(*kind, FailureKind::BodyHashMismatch),
            other => panic!("expected BodyHashMismatch, got {:?}", other),
        }
    }

    // ─── CHK-531: Ground-truth complete ─────────────────────────────
    // (covered by the ground_truth_ed25519_manual_ring_primitives and _tampered tests above)

    // ─── CHK-510..CHK-517: Security ─────────────────────────────────
    // (Most security properties are verified by the constraint/verification tests above)

    // ─── CHK-482: RSA-SHA256 pre-computed fixture ─────────────────
    // Generated with OpenSSL RSA-2048 key. This is a TRUE pre-computed fixture:
    // signing was done externally (openssl dgst -sha256 -sign), not by this library.
    // The SPKI public key exercises strip_spki_wrapper with real ASN.1 data.

    const RSA_FIXTURE_SPKI_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0zzOtswuqB21FtQ+W5cgh7DiaJ+4TMQBmSm3V6gKYSq/WPbg0vaSdlru6PBbdocwBrn4di2bNpdy5Co1ujLtogyg6+f4A9K36CygLWqOhygt6A/Rl94daXwew1S/7oSksuAGnSg2+XMuU2An+IHSYnx/qAiGnnzkhGgsTnUnJxZ2mitvKemPjTDIB2dz1hJAmnJS0ffUADnSXgS55f8aXAdRRDQwYlTwBRLrdpcQzVRKU+L/hm4EzePVkvXUgeuBKqhIosNHl28fuN1nac3zuosWorJQ7Ox2MKKdVB5FkT85mZp/i7L0+/JMVXJeNHnlFe3OqFUEKmYpgL37oTGCdQIDAQAB";

    #[tokio::test]
    async fn rsa_sha256_precomputed_fixture_pass() {
        let body = b"Test body for RSA verification\r\n";
        let sig_value = concat!(
            " v=1; a=rsa-sha256; b=zm5IJ/e9WakQhZ+pmKQafoSc2iZE2xGfYA7sbWF+O8vhES09D7HyUo",
            "sQVnG4fm6mHOc6pHLtTaQDe/4r0tOjjI7peVO8BCi3KSQtKZIORJ8wrs3PQLpZtZdK/zlfIZywW0",
            "n5DMxbHU+uqjkR4y191xYg/fWZaC14d/4V5RvzKb8ZV7qYzpi5EWDlXTCbJTryuJydjRVYIa1F+6",
            "cI3ROJn8U9GcyGcJJQo5HrrWYKAiPGhR3sXjKbBEOah7CH5XQv22j4Q3q2LhNjtTnXrS77rvw8lu",
            "b+H0e8vEB4Ps4Y9y81QPGqs9Xse2MakBVER44/1M4XvlpS+5bD4bUZfYG5cQ==; bh=A82pV6ef4",
            "eO/+6HFHShh58CZ7NYOh4gNm0JUpCe9AJU=; c=relaxed/relaxed; d=example.com; h=fro",
            "m:to:subject; s=rsa2048",
        );

        let mut resolver = MockResolver::new();
        setup_mock_key(
            &mut resolver,
            "rsa2048",
            "example.com",
            &format!("v=DKIM1; k=rsa; p={}", RSA_FIXTURE_SPKI_B64),
        );

        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " RSA test"),
            ("DKIM-Signature", sig_value),
        ];

        let results = verifier.verify_message(&headers, body).await;
        match &results[0] {
            DkimResult::Pass { domain, selector, .. } => {
                assert_eq!(domain, "example.com");
                assert_eq!(selector, "rsa2048");
            }
            other => panic!("RSA-SHA256 fixture: expected Pass, got {:?}", other),
        }
    }

    // ─── CHK-483: RSA-SHA1 pre-computed fixture ─────────────────────
    // ring 0.17 cannot sign SHA-1. This fixture was signed externally with openssl dgst -sha1 -sign.

    #[tokio::test]
    async fn rsa_sha1_precomputed_fixture_pass() {
        let body = b"Test body for RSA verification\r\n";
        let sig_value = concat!(
            " v=1; a=rsa-sha1; b=Y9CjLLQ3d8kw7z7FnjDF7YDbD5jV8F4nmNN2IP7HcIIJFMmEdvE2+mMH",
            "OulTI26Kp7x+r0aubcmOAvOUh1eFX2t7359bnVL9n1MEKIcxdZO3fIU5LhXBAfrkILe/caA5hQgU",
            "94HdPiOyGUNIQdGIG4ECZ6zdcW1K4TVYQmGawJzwKyKo1m4MqT99bJot5MUEmK/7jX9aROrDtwok",
            "qtFAysXpmqWj3lOg+IJSmiKzD0DvbvU1G/LE4T95zjnot+rBtC0/jJ/ooq0ZBBOvC5KHQ0pwDxCC",
            "ENR18UkcyZG/6FRLFGGzReJPQViJ4XqBNpDOovEXj3v4q9tdBmNt5zNKzQ==; bh=wIO7ahU/Pub",
            "98XWknH1rIcruxRc=; c=relaxed/relaxed; d=example.com; h=from:to:subject; s=rs",
            "a2048",
        );

        let mut resolver = MockResolver::new();
        setup_mock_key(
            &mut resolver,
            "rsa2048",
            "example.com",
            &format!("v=DKIM1; k=rsa; p={}", RSA_FIXTURE_SPKI_B64),
        );

        let verifier = DkimVerifier::new(resolver);
        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " RSA test"),
            ("DKIM-Signature", sig_value),
        ];

        let results = verifier.verify_message(&headers, body).await;
        match &results[0] {
            DkimResult::Pass { domain, selector, .. } => {
                assert_eq!(domain, "example.com");
                assert_eq!(selector, "rsa2048");
            }
            other => panic!("RSA-SHA1 fixture: expected Pass, got {:?}", other),
        }
    }

    // ─── CHK-529: All three algorithms verified ─────────────────────
    // Ed25519: ed25519_pass_ground_truth
    // RSA-SHA256: rsa_sha256_precomputed_fixture_pass
    // RSA-SHA1: rsa_sha1_precomputed_fixture_pass

    // ─── SPKI stripping unit tests ──────────────────────────────────

    #[test]
    fn strip_spki_passthrough_pkcs1() {
        // Non-SPKI data returned as-is
        let data = vec![0x30, 0x82, 0x00]; // looks like ASN.1 but no RSA OID
        assert_eq!(strip_spki_wrapper(&data), data.as_slice());
    }

    #[test]
    fn strip_spki_too_short() {
        let data = vec![0x30; 10];
        assert_eq!(strip_spki_wrapper(&data), data.as_slice());
    }

    #[test]
    fn strip_spki_real_rsa_2048_key() {
        // Test SPKI stripping with the real RSA-2048 SPKI key used in fixtures
        let spki_der = base64::engine::general_purpose::STANDARD
            .decode(RSA_FIXTURE_SPKI_B64)
            .unwrap();
        assert_eq!(spki_der.len(), 294); // 2048-bit RSA SPKI

        let pkcs1 = strip_spki_wrapper(&spki_der);
        // PKCS#1 should be shorter (SPKI header stripped)
        assert!(pkcs1.len() < spki_der.len());
        // PKCS#1 RSAPublicKey starts with SEQUENCE tag 0x30
        assert_eq!(pkcs1[0], 0x30);
        // The stripped key should be usable by ring (verified by the RSA fixture tests above)
        assert!(pkcs1.len() > 250); // 2048-bit modulus is ~256 bytes
    }
}
