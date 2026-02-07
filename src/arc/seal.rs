// ---------------------------------------------------------------------------
// ARC chain sealing (RFC 8617 Section 5.1)
// ---------------------------------------------------------------------------

use base64::{engine::general_purpose::STANDARD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};
use std::time::SystemTime;

use crate::arc::parse::{collect_arc_sets, ArcSet, ChainValidationStatus};
use crate::dkim::canon::{
    canonicalize_body_relaxed, canonicalize_header_relaxed, select_headers, strip_b_tag,
};
use crate::dkim::signature::Algorithm;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    ChainFailed,
    InstanceOverflow,
    ParseError(String),
    SigningError(String),
}

#[derive(Debug)]
pub struct SealOutput {
    pub aar: String,
    pub ams: String,
    pub seal: String,
}

enum PrivateKey {
    Rsa(RsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

const DEFAULT_HEADERS: &[&str] = &[
    "from",
    "to",
    "subject",
    "date",
    "message-id",
    "dkim-signature",
];

// ---------------------------------------------------------------------------
// PEM helper
// ---------------------------------------------------------------------------

fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(pem).map_err(|e| format!("PEM is not UTF-8: {}", e))?;
    let b64: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    STANDARD
        .decode(&b64)
        .map_err(|e| format!("PEM base64 decode failed: {}", e))
}

// ---------------------------------------------------------------------------
// ArcSealer
// ---------------------------------------------------------------------------

pub struct ArcSealer {
    private_key: PrivateKey,
    domain: String,
    selector: String,
    algorithm: Algorithm,
    headers_to_sign: Vec<String>,
}

impl ArcSealer {
    /// Create an ARC sealer using Ed25519-SHA256 from PKCS#8 DER bytes.
    pub fn ed25519(domain: &str, selector: &str, pkcs8_der: &[u8]) -> Result<Self, String> {
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_der)
            .map_err(|e| format!("Ed25519 key parse failed: {}", e))?;
        Ok(Self {
            private_key: PrivateKey::Ed25519(key_pair),
            domain: domain.to_string(),
            selector: selector.to_string(),
            algorithm: Algorithm::Ed25519Sha256,
            headers_to_sign: DEFAULT_HEADERS.iter().map(|s| s.to_string()).collect(),
        })
    }

    /// Create an ARC sealer using RSA-SHA256 from a PEM-encoded PKCS#8 private key.
    pub fn rsa_sha256(domain: &str, selector: &str, pem_pkcs8: &[u8]) -> Result<Self, String> {
        let der = pem_to_der(pem_pkcs8)?;
        let key_pair =
            RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("RSA key parse failed: {}", e))?;
        Ok(Self {
            private_key: PrivateKey::Rsa(key_pair),
            domain: domain.to_string(),
            selector: selector.to_string(),
            algorithm: Algorithm::RsaSha256,
            headers_to_sign: DEFAULT_HEADERS.iter().map(|s| s.to_string()).collect(),
        })
    }

    /// Override the set of headers signed by AMS.
    /// ARC-* and Authentication-Results headers are automatically excluded.
    pub fn headers(mut self, headers: Vec<String>) -> Self {
        self.headers_to_sign = headers
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| !is_arc_or_ar_header(s))
            .collect();
        self
    }

    // -----------------------------------------------------------------------
    // Sealing
    // -----------------------------------------------------------------------

    /// Seal a message by adding a new ARC set (AAR + AMS + AS).
    ///
    /// `headers` — message headers as (name, value) pairs.
    /// `body` — raw message body bytes.
    /// `authres_payload` — authentication results content, e.g. "dkim=pass; spf=pass".
    /// `incoming_cv` — chain validation status determined by the caller (from ArcVerifier).
    pub fn seal_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        authres_payload: &str,
        incoming_cv: ChainValidationStatus,
    ) -> Result<SealOutput, SealError> {
        // 1. Collect existing ARC sets
        let existing_sets = collect_arc_sets(headers)
            .map_err(|e| SealError::ParseError(e.to_string()))?;

        let existing_count = existing_sets.len() as u32;

        // 2. If last seal has cv=fail, reject
        if existing_count > 0 {
            if existing_sets.last().unwrap().seal.cv == ChainValidationStatus::Fail {
                return Err(SealError::ChainFailed);
            }
        }

        // 3. New instance
        let new_instance = existing_count + 1;
        if new_instance > 50 {
            return Err(SealError::InstanceOverflow);
        }

        // 4. Determine cv
        let cv = if existing_count == 0 {
            ChainValidationStatus::None
        } else {
            incoming_cv
        };

        // 5. Algorithm string
        let algo_str = algo_tag_value(&self.algorithm);

        // 6. Generate AAR
        let aar_value = format!(" i={}; {}", new_instance, authres_payload);

        // 7. Generate AMS
        let ams_value = self.build_ams(headers, body, new_instance, algo_str)?;

        // 8. Generate AS
        let seal_value =
            self.build_seal(&existing_sets, &aar_value, &ams_value, new_instance, &cv, algo_str)?;

        Ok(SealOutput {
            aar: aar_value,
            ams: ams_value,
            seal: seal_value,
        })
    }

    // -----------------------------------------------------------------------
    // AMS construction
    // -----------------------------------------------------------------------

    fn build_ams(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        instance: u32,
        algo_str: &str,
    ) -> Result<String, SealError> {
        // Body hash: relaxed/relaxed canonicalization, SHA-256
        let canon_body = canonicalize_body_relaxed(body);
        let body_hash = {
            let digest = ring::digest::digest(&ring::digest::SHA256, &canon_body);
            STANDARD.encode(digest.as_ref())
        };

        // Filter headers_to_sign to those actually present (case-insensitive)
        let present: Vec<String> = headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect();

        let h_list: Vec<String> = self
            .headers_to_sign
            .iter()
            .filter(|h| present.iter().any(|p| p == *h))
            .cloned()
            .collect();

        let h_tag = h_list.join(":");

        // Build AMS template with empty b=
        let ams_template = format!(
            " i={}; a={}; c=relaxed/relaxed; d={}; s={}; h={}; bh={}; b=",
            instance, algo_str, self.domain, self.selector, h_tag, body_hash,
        );

        // Canonicalize selected message headers
        let selected = select_headers(&h_list, headers);
        let mut sign_input = Vec::new();
        for (name, value) in &selected {
            if name.is_empty() {
                continue;
            }
            let canon = canonicalize_header_relaxed(name, value);
            sign_input.extend_from_slice(canon.as_bytes());
        }

        // Add AMS header itself (with b= stripped, no trailing CRLF)
        let ams_stripped = strip_b_tag(&ams_template);
        let ams_canon = canonicalize_header_relaxed("ARC-Message-Signature", &ams_stripped);
        let ams_trimmed = ams_canon.strip_suffix("\r\n").unwrap_or(&ams_canon);
        sign_input.extend_from_slice(ams_trimmed.as_bytes());

        // Sign
        let sig_bytes = self.sign_data(&sign_input)?;
        let sig_b64 = STANDARD.encode(&sig_bytes);

        // Fill b=
        let ams_value = format!("{}{}", ams_template, sig_b64);
        Ok(ams_value)
    }

    // -----------------------------------------------------------------------
    // AS construction
    // -----------------------------------------------------------------------

    fn build_seal(
        &self,
        existing_sets: &[ArcSet],
        new_aar_value: &str,
        new_ams_value: &str,
        instance: u32,
        cv: &ChainValidationStatus,
        algo_str: &str,
    ) -> Result<String, SealError> {
        // Timestamp
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| SealError::SigningError(format!("system time error: {}", e)))?
            .as_secs();

        // Build seal template with empty b=
        let seal_template = format!(
            " i={}; cv={}; a={}; d={}; s={}; t={}; b=",
            instance, cv, algo_str, self.domain, self.selector, timestamp,
        );

        // Build signature input:
        // 1. All existing ARC sets in ascending instance order
        let mut sign_input = Vec::new();
        for set in existing_sets {
            // AAR: reconstruct from instance + payload
            let aar_header_value = format!("i={}; {}", set.aar.instance, set.aar.payload);
            let aar_canon =
                canonicalize_header_relaxed("ARC-Authentication-Results", &aar_header_value);
            sign_input.extend_from_slice(aar_canon.as_bytes());

            // AMS: use raw_header
            let ams_canon =
                canonicalize_header_relaxed("ARC-Message-Signature", &set.ams.raw_header);
            sign_input.extend_from_slice(ams_canon.as_bytes());

            // AS: use raw_header
            let as_canon = canonicalize_header_relaxed("ARC-Seal", &set.seal.raw_header);
            sign_input.extend_from_slice(as_canon.as_bytes());
        }

        // 2. New AAR
        let new_aar_canon =
            canonicalize_header_relaxed("ARC-Authentication-Results", new_aar_value);
        sign_input.extend_from_slice(new_aar_canon.as_bytes());

        // 3. New AMS
        let new_ams_canon =
            canonicalize_header_relaxed("ARC-Message-Signature", new_ams_value);
        sign_input.extend_from_slice(new_ams_canon.as_bytes());

        // 4. New AS template (b= stripped, no trailing CRLF)
        let seal_stripped = strip_b_tag(&seal_template);
        let seal_canon = canonicalize_header_relaxed("ARC-Seal", &seal_stripped);
        let seal_trimmed = seal_canon.strip_suffix("\r\n").unwrap_or(&seal_canon);
        sign_input.extend_from_slice(seal_trimmed.as_bytes());

        // Sign
        let sig_bytes = self.sign_data(&sign_input)?;
        let sig_b64 = STANDARD.encode(&sig_bytes);

        let seal_value = format!("{}{}", seal_template, sig_b64);
        Ok(seal_value)
    }

    // -----------------------------------------------------------------------
    // Cryptographic signing
    // -----------------------------------------------------------------------

    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SealError> {
        match &self.private_key {
            PrivateKey::Rsa(kp) => {
                let mut sig = vec![0u8; kp.public().modulus_len()];
                kp.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), data, &mut sig)
                    .map_err(|e| SealError::SigningError(format!("RSA sign error: {}", e)))?;
                Ok(sig)
            }
            PrivateKey::Ed25519(kp) => Ok(kp.sign(data).as_ref().to_vec()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn algo_tag_value(algo: &Algorithm) -> &'static str {
    match algo {
        Algorithm::RsaSha256 => "rsa-sha256",
        Algorithm::Ed25519Sha256 => "ed25519-sha256",
        Algorithm::RsaSha1 => "rsa-sha1",
    }
}

/// Returns true if the header name (lowercased) is an ARC header or
/// Authentication-Results, which MUST NOT appear in AMS h= tag.
fn is_arc_or_ar_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("arc-") || lower == "authentication-results"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{self as ring_sig, Ed25519KeyPair, KeyPair};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Generate an Ed25519 key pair; returns (pkcs8_der, public_key_bytes).
    fn gen_ed25519_key() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pkcs8_bytes = pkcs8.as_ref().to_vec();
        let kp = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).unwrap();
        let pub_bytes = kp.public_key().as_ref().to_vec();
        (pkcs8_bytes, pub_bytes)
    }

    fn sample_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("From", " sender@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test message"),
            ("Date", " Sat, 01 Jan 2022 00:00:00 +0000"),
            ("Message-ID", " <test@example.com>"),
            ("DKIM-Signature", " v=1; a=ed25519-sha256; d=example.com; s=sel; h=from:to; bh=abc; b=xyz"),
        ]
    }

    fn sample_body() -> &'static [u8] {
        b"Hello, this is a test email body.\r\n"
    }

    /// Extract a tag value from a header value string.
    fn extract_tag(header: &str, tag: &str) -> Option<String> {
        for part in header.split(';') {
            let part = part.trim();
            if let Some((t, v)) = part.split_once('=') {
                if t.trim() == tag {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }

    /// Build headers that contain one existing ARC set (instance=1, cv=none).
    fn headers_with_one_arc_set(pkcs8: &[u8]) -> Vec<(String, String)> {
        let sealer = ArcSealer::ed25519("relay.example.com", "arc1", pkcs8).unwrap();
        let base_headers = sample_headers();
        let output = sealer
            .seal_message(&base_headers, sample_body(), "dkim=pass", ChainValidationStatus::None)
            .unwrap();
        // Return owned strings so we can build references
        vec![
            ("ARC-Authentication-Results".to_string(), output.aar),
            ("ARC-Message-Signature".to_string(), output.ams),
            ("ARC-Seal".to_string(), output.seal),
        ]
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn seal_no_existing_chain() {
        let (pkcs8, _pub_key) = gen_ed25519_key();
        let sealer = ArcSealer::ed25519("example.com", "arc1", &pkcs8).unwrap();

        let output = sealer
            .seal_message(&sample_headers(), sample_body(), "dkim=pass; spf=pass", ChainValidationStatus::None)
            .unwrap();

        // AAR should have i=1
        assert!(output.aar.contains("i=1"));
        assert!(output.aar.contains("dkim=pass; spf=pass"));

        // AMS should have i=1
        let ams_instance = extract_tag(&output.ams, "i").unwrap();
        assert_eq!(ams_instance, "1");

        // AS should have i=1, cv=none
        let seal_instance = extract_tag(&output.seal, "i").unwrap();
        assert_eq!(seal_instance, "1");
        let seal_cv = extract_tag(&output.seal, "cv").unwrap();
        assert_eq!(seal_cv, "none");
    }

    #[test]
    fn seal_with_existing_chain() {
        let (pkcs8, _pub_key) = gen_ed25519_key();

        // First, create one ARC set
        let arc_owned = headers_with_one_arc_set(&pkcs8);
        let arc_refs: Vec<(&str, &str)> = arc_owned
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();

        // Combine original headers with ARC headers
        let mut all_headers: Vec<(&str, &str)> = sample_headers();
        all_headers.extend_from_slice(&arc_refs);

        // Now seal again as instance 2
        let sealer = ArcSealer::ed25519("relay2.example.com", "arc2", &pkcs8).unwrap();
        let output = sealer
            .seal_message(&all_headers, sample_body(), "dkim=pass", ChainValidationStatus::Pass)
            .unwrap();

        let seal_instance = extract_tag(&output.seal, "i").unwrap();
        assert_eq!(seal_instance, "2");

        let seal_cv = extract_tag(&output.seal, "cv").unwrap();
        assert_eq!(seal_cv, "pass");

        let ams_instance = extract_tag(&output.ams, "i").unwrap();
        assert_eq!(ams_instance, "2");
    }

    #[test]
    fn seal_instance_overflow() {
        let (pkcs8, _pub_key) = gen_ed25519_key();
        let sealer = ArcSealer::ed25519("example.com", "arc1", &pkcs8).unwrap();

        // Build 50 fake ARC sets in headers
        let mut headers: Vec<(String, String)> = Vec::new();
        for i in 1..=50u32 {
            let cv = if i == 1 { "none" } else { "pass" };
            let fake_b = STANDARD.encode(b"fakesig");
            let fake_bh = STANDARD.encode(b"fakehash");
            headers.push((
                "ARC-Authentication-Results".to_string(),
                format!(" i={}; dkim=pass", i),
            ));
            headers.push((
                "ARC-Message-Signature".to_string(),
                format!(
                    " i={}; a=ed25519-sha256; c=relaxed/relaxed; d=x.com; s=s; h=from; bh={}; b={}",
                    i, fake_bh, fake_b
                ),
            ));
            headers.push((
                "ARC-Seal".to_string(),
                format!(
                    " i={}; cv={}; a=ed25519-sha256; d=x.com; s=s; t=1000; b={}",
                    i, cv, fake_b
                ),
            ));
        }

        // Add base message headers
        let mut all: Vec<(&str, &str)> = sample_headers();
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        all.extend_from_slice(&refs);

        let result = sealer.seal_message(&all, sample_body(), "dkim=pass", ChainValidationStatus::Pass);
        assert_eq!(result.unwrap_err(), SealError::InstanceOverflow);
    }

    #[test]
    fn seal_incoming_cv_fail() {
        let (pkcs8, _pub_key) = gen_ed25519_key();

        // Build a single ARC set where the seal has cv=fail
        let fake_b = STANDARD.encode(b"fakesig");
        let fake_bh = STANDARD.encode(b"fakehash");
        let arc_headers: Vec<(String, String)> = vec![
            (
                "ARC-Authentication-Results".to_string(),
                " i=1; dkim=fail".to_string(),
            ),
            (
                "ARC-Message-Signature".to_string(),
                format!(
                    " i=1; a=ed25519-sha256; c=relaxed/relaxed; d=x.com; s=s; h=from; bh={}; b={}",
                    fake_bh, fake_b
                ),
            ),
            (
                "ARC-Seal".to_string(),
                format!(
                    " i=1; cv=fail; a=ed25519-sha256; d=x.com; s=s; t=1000; b={}",
                    fake_b
                ),
            ),
        ];

        let mut all: Vec<(&str, &str)> = sample_headers();
        let refs: Vec<(&str, &str)> = arc_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        all.extend_from_slice(&refs);

        let sealer = ArcSealer::ed25519("example.com", "arc1", &pkcs8).unwrap();
        let result = sealer.seal_message(&all, sample_body(), "dkim=pass", ChainValidationStatus::Fail);
        assert_eq!(result.unwrap_err(), SealError::ChainFailed);
    }

    #[test]
    fn seal_ams_contains_body_hash() {
        let (pkcs8, _pub_key) = gen_ed25519_key();
        let sealer = ArcSealer::ed25519("example.com", "arc1", &pkcs8).unwrap();

        let output = sealer
            .seal_message(&sample_headers(), sample_body(), "dkim=pass", ChainValidationStatus::None)
            .unwrap();

        let bh = extract_tag(&output.ams, "bh");
        assert!(bh.is_some(), "AMS must contain bh= tag");

        // Verify the body hash value is valid base64 and matches expected
        let bh_val = bh.unwrap();
        let decoded = STANDARD.decode(&bh_val);
        assert!(decoded.is_ok(), "bh= value must be valid base64");

        // Compute expected body hash
        let canon_body = canonicalize_body_relaxed(sample_body());
        let expected = {
            let digest = ring::digest::digest(&ring::digest::SHA256, &canon_body);
            STANDARD.encode(digest.as_ref())
        };
        assert_eq!(bh_val, expected);
    }

    #[test]
    fn seal_ams_h_tag_present() {
        let (pkcs8, _pub_key) = gen_ed25519_key();
        let sealer = ArcSealer::ed25519("example.com", "arc1", &pkcs8).unwrap();

        let output = sealer
            .seal_message(&sample_headers(), sample_body(), "dkim=pass", ChainValidationStatus::None)
            .unwrap();

        let h_tag = extract_tag(&output.ams, "h").unwrap();
        let h_names: Vec<&str> = h_tag.split(':').map(|s| s.trim()).collect();

        // All default headers present in sample_headers should appear
        assert!(h_names.iter().any(|n| n.eq_ignore_ascii_case("from")));
        assert!(h_names.iter().any(|n| n.eq_ignore_ascii_case("to")));
        assert!(h_names.iter().any(|n| n.eq_ignore_ascii_case("subject")));
        assert!(h_names.iter().any(|n| n.eq_ignore_ascii_case("date")));
        assert!(h_names.iter().any(|n| n.eq_ignore_ascii_case("message-id")));
        assert!(h_names.iter().any(|n| n.eq_ignore_ascii_case("dkim-signature")));

        // ARC-* headers must NOT be in h=
        assert!(!h_names.iter().any(|n| n.to_ascii_lowercase().starts_with("arc-")));
    }

    #[test]
    fn seal_as_cv_none_first_instance() {
        let (pkcs8, _pub_key) = gen_ed25519_key();
        let sealer = ArcSealer::ed25519("example.com", "arc1", &pkcs8).unwrap();

        let output = sealer
            .seal_message(&sample_headers(), sample_body(), "dkim=pass", ChainValidationStatus::None)
            .unwrap();

        let cv = extract_tag(&output.seal, "cv").unwrap();
        assert_eq!(cv, "none", "First instance must have cv=none");

        let instance = extract_tag(&output.seal, "i").unwrap();
        assert_eq!(instance, "1");
    }

    #[test]
    fn seal_as_cv_pass_subsequent() {
        let (pkcs8, _pub_key) = gen_ed25519_key();

        // Create first ARC set
        let arc_owned = headers_with_one_arc_set(&pkcs8);
        let arc_refs: Vec<(&str, &str)> = arc_owned
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();

        let mut all_headers: Vec<(&str, &str)> = sample_headers();
        all_headers.extend_from_slice(&arc_refs);

        let sealer = ArcSealer::ed25519("relay2.example.com", "arc2", &pkcs8).unwrap();
        let output = sealer
            .seal_message(&all_headers, sample_body(), "dkim=pass", ChainValidationStatus::Pass)
            .unwrap();

        let cv = extract_tag(&output.seal, "cv").unwrap();
        assert_eq!(cv, "pass", "Subsequent instance must use incoming cv");

        let instance = extract_tag(&output.seal, "i").unwrap();
        assert_eq!(instance, "2");
    }

    #[test]
    fn seal_roundtrip() {
        let (pkcs8, pub_key) = gen_ed25519_key();
        let sealer = ArcSealer::ed25519("example.com", "arc1", &pkcs8).unwrap();

        let headers = sample_headers();
        let body = sample_body();
        let output = sealer
            .seal_message(&headers, body, "dkim=pass", ChainValidationStatus::None)
            .unwrap();

        // ---- Verify AMS signature ----
        let ams_b64 = extract_tag(&output.ams, "b").unwrap();
        let ams_sig_bytes = STANDARD.decode(&ams_b64).unwrap();

        // Reconstruct AMS signing input
        let h_tag = extract_tag(&output.ams, "h").unwrap();
        let h_list: Vec<String> = h_tag.split(':').map(|s| s.trim().to_string()).collect();
        let selected = select_headers(&h_list, &headers);

        let mut ams_sign_input = Vec::new();
        for (name, value) in &selected {
            if name.is_empty() {
                continue;
            }
            let canon = canonicalize_header_relaxed(name, value);
            ams_sign_input.extend_from_slice(canon.as_bytes());
        }

        // AMS template with b= stripped
        let ams_template = output.ams.split("b=").next().unwrap().to_string() + "b=";
        let ams_stripped = strip_b_tag(&ams_template);
        let ams_canon = canonicalize_header_relaxed("ARC-Message-Signature", &ams_stripped);
        let ams_trimmed = ams_canon.strip_suffix("\r\n").unwrap_or(&ams_canon);
        ams_sign_input.extend_from_slice(ams_trimmed.as_bytes());

        let peer_pk = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, &pub_key);
        peer_pk
            .verify(&ams_sign_input, &ams_sig_bytes)
            .expect("AMS Ed25519 signature verification should pass");

        // ---- Verify AS signature ----
        let as_b64 = extract_tag(&output.seal, "b").unwrap();
        let as_sig_bytes = STANDARD.decode(&as_b64).unwrap();

        // Reconstruct AS signing input: new AAR + new AMS + new AS template (no existing sets)
        let mut as_sign_input = Vec::new();

        // New AAR
        let aar_canon =
            canonicalize_header_relaxed("ARC-Authentication-Results", &output.aar);
        as_sign_input.extend_from_slice(aar_canon.as_bytes());

        // New AMS (full value including b=)
        let ams_canon_full =
            canonicalize_header_relaxed("ARC-Message-Signature", &output.ams);
        as_sign_input.extend_from_slice(ams_canon_full.as_bytes());

        // New AS template with b= stripped, no trailing CRLF
        let seal_template = output.seal.split("b=").next().unwrap().to_string() + "b=";
        let seal_stripped = strip_b_tag(&seal_template);
        let seal_canon = canonicalize_header_relaxed("ARC-Seal", &seal_stripped);
        let seal_trimmed = seal_canon.strip_suffix("\r\n").unwrap_or(&seal_canon);
        as_sign_input.extend_from_slice(seal_trimmed.as_bytes());

        peer_pk
            .verify(&as_sign_input, &as_sig_bytes)
            .expect("AS Ed25519 signature verification should pass");
    }

    #[test]
    fn seal_filters_missing_headers() {
        let (pkcs8, _pub_key) = gen_ed25519_key();
        let sealer = ArcSealer::ed25519("example.com", "arc1", &pkcs8).unwrap();

        // Only provide From and To — other default headers should be omitted from h=
        let headers: Vec<(&str, &str)> = vec![
            ("From", " sender@example.com"),
            ("To", " recipient@example.com"),
        ];

        let output = sealer
            .seal_message(&headers, sample_body(), "dkim=pass", ChainValidationStatus::None)
            .unwrap();

        let h_tag = extract_tag(&output.ams, "h").unwrap();
        let h_names: Vec<&str> = h_tag.split(':').map(|s| s.trim()).collect();

        assert!(
            h_names.iter().any(|n| n.eq_ignore_ascii_case("from")),
            "from should be in h="
        );
        assert!(
            h_names.iter().any(|n| n.eq_ignore_ascii_case("to")),
            "to should be in h="
        );
        assert!(
            !h_names.iter().any(|n| n.eq_ignore_ascii_case("subject")),
            "subject should NOT be in h= when absent from message"
        );
        assert!(
            !h_names.iter().any(|n| n.eq_ignore_ascii_case("date")),
            "date should NOT be in h= when absent from message"
        );
        assert!(
            !h_names.iter().any(|n| n.eq_ignore_ascii_case("message-id")),
            "message-id should NOT be in h= when absent from message"
        );
    }
}
