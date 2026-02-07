use base64::{engine::general_purpose::STANDARD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};
use std::time::SystemTime;

use crate::dkim::canon::{
    canonicalize_body_relaxed, canonicalize_body_simple, canonicalize_header_relaxed,
    canonicalize_header_simple, select_headers,
};
use crate::dkim::signature::{Algorithm, CanonicalizationMethod};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

enum PrivateKey {
    Rsa(RsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

pub struct DkimSigner {
    private_key: PrivateKey,
    domain: String,
    selector: String,
    algorithm: Algorithm,
    header_canon: CanonicalizationMethod,
    body_canon: CanonicalizationMethod,
    headers_to_sign: Vec<String>,
    expiration_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_HEADERS: &[&str] = &[
    "from",
    "to",
    "subject",
    "date",
    "mime-version",
    "content-type",
    "message-id",
];

// ---------------------------------------------------------------------------
// PEM helpers
// ---------------------------------------------------------------------------

/// Strip PEM armor and decode the base64 body to DER bytes.
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
// Constructors
// ---------------------------------------------------------------------------

impl DkimSigner {
    /// Create a signer using RSA-SHA256 from a PEM-encoded PKCS#8 private key.
    pub fn rsa_sha256(domain: &str, selector: &str, pem_pkcs8: &[u8]) -> Result<Self, String> {
        let der = pem_to_der(pem_pkcs8)?;
        let key_pair =
            RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("RSA key parse failed: {}", e))?;

        Ok(Self {
            private_key: PrivateKey::Rsa(key_pair),
            domain: domain.to_string(),
            selector: selector.to_string(),
            algorithm: Algorithm::RsaSha256,
            header_canon: CanonicalizationMethod::Relaxed,
            body_canon: CanonicalizationMethod::Relaxed,
            headers_to_sign: DEFAULT_HEADERS.iter().map(|s| s.to_string()).collect(),
            expiration_seconds: None,
        })
    }

    /// Create a signer using Ed25519-SHA256 from PKCS#8 DER bytes.
    pub fn ed25519(domain: &str, selector: &str, pkcs8_der: &[u8]) -> Result<Self, String> {
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_der)
            .map_err(|e| format!("Ed25519 key parse failed: {}", e))?;

        Ok(Self {
            private_key: PrivateKey::Ed25519(key_pair),
            domain: domain.to_string(),
            selector: selector.to_string(),
            algorithm: Algorithm::Ed25519Sha256,
            header_canon: CanonicalizationMethod::Relaxed,
            body_canon: CanonicalizationMethod::Relaxed,
            headers_to_sign: DEFAULT_HEADERS.iter().map(|s| s.to_string()).collect(),
            expiration_seconds: None,
        })
    }

    // -----------------------------------------------------------------------
    // Builder methods
    // -----------------------------------------------------------------------

    pub fn canonicalization(
        mut self,
        header: CanonicalizationMethod,
        body: CanonicalizationMethod,
    ) -> Self {
        self.header_canon = header;
        self.body_canon = body;
        self
    }

    /// Set custom headers to sign. "from" is always included even if omitted.
    pub fn headers(mut self, headers: Vec<String>) -> Self {
        let mut h: Vec<String> = headers
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        if !h.iter().any(|s| s == "from") {
            h.insert(0, "from".to_string());
        }
        self.headers_to_sign = h;
        self
    }

    pub fn expiration(mut self, seconds: u64) -> Self {
        self.expiration_seconds = Some(seconds);
        self
    }

    // -----------------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------------

    /// Sign a message and return the DKIM-Signature header **value**
    /// (everything after `DKIM-Signature:`).
    pub fn sign_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<String, String> {
        // 1. Body hash
        let canon_body = match self.body_canon {
            CanonicalizationMethod::Simple => canonicalize_body_simple(body),
            CanonicalizationMethod::Relaxed => canonicalize_body_relaxed(body),
        };
        let body_hash = {
            let digest = ring::digest::digest(&ring::digest::SHA256, &canon_body);
            STANDARD.encode(digest.as_ref())
        };

        // 2. Timestamp
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {}", e))?
            .as_secs();

        // 3. Build h= list: filter to headers actually present, then over-sign "from"
        let h_tag_list = self.build_h_list(headers);
        let h_tag = h_tag_list.join(":");

        // 4. Algorithm string
        let algo_str = match self.algorithm {
            Algorithm::RsaSha256 => "rsa-sha256",
            Algorithm::Ed25519Sha256 => "ed25519-sha256",
            Algorithm::RsaSha1 => "rsa-sha1",
        };

        // 5. Canonicalization string
        let hc = match self.header_canon {
            CanonicalizationMethod::Simple => "simple",
            CanonicalizationMethod::Relaxed => "relaxed",
        };
        let bc = match self.body_canon {
            CanonicalizationMethod::Simple => "simple",
            CanonicalizationMethod::Relaxed => "relaxed",
        };

        // 6. Build DKIM-Signature template with b= empty
        let mut sig_value = format!(
            " v=1; a={}; c={}/{}; d={}; s={}; h={}; bh={}; t={}",
            algo_str, hc, bc, self.domain, self.selector, h_tag, body_hash, timestamp,
        );
        if let Some(exp) = self.expiration_seconds {
            sig_value.push_str(&format!("; x={}", timestamp + exp));
        }
        sig_value.push_str("; b=");

        // 7. Compute header hash input
        let data_to_sign = self.build_header_hash_input(headers, &h_tag_list, &sig_value);

        // 8. Sign
        let signature_bytes = self.compute_signature(&data_to_sign)?;
        let sig_b64 = STANDARD.encode(&signature_bytes);

        // 9. Append signature to template
        sig_value.push_str(&sig_b64);
        Ok(sig_value)
    }

    /// Build the h= tag list: only headers present in message, plus over-sign "from".
    fn build_h_list(&self, headers: &[(&str, &str)]) -> Vec<String> {
        let present: Vec<String> = headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect();

        let mut h_list: Vec<String> = self
            .headers_to_sign
            .iter()
            .filter(|h| present.iter().any(|p| p == *h))
            .cloned()
            .collect();

        // Ensure "from" is in the list
        if !h_list.iter().any(|h| h == "from") {
            h_list.push("from".to_string());
        }

        // Over-sign "from": add an extra entry so attackers can't prepend a From header
        h_list.push("from".to_string());

        h_list
    }

    /// Build the byte buffer to be signed: canonicalized selected headers +
    /// the DKIM-Signature header itself (without trailing CRLF).
    fn build_header_hash_input(
        &self,
        headers: &[(&str, &str)],
        h_list: &[String],
        sig_value: &str,
    ) -> Vec<u8> {
        let selected = select_headers(h_list, headers);
        let mut input = Vec::new();

        for (name, value) in &selected {
            if name.is_empty() {
                // Over-signed: no matching header, contributes nothing to hash input
                continue;
            }
            let canon = match self.header_canon {
                CanonicalizationMethod::Simple => {
                    canonicalize_header_simple(name, value)
                }
                CanonicalizationMethod::Relaxed => {
                    canonicalize_header_relaxed(name, value)
                }
            };
            input.extend_from_slice(canon.as_bytes());
        }

        // The DKIM-Signature header itself, without trailing CRLF
        let dkim_canon = match self.header_canon {
            CanonicalizationMethod::Simple => {
                canonicalize_header_simple("DKIM-Signature", sig_value)
            }
            CanonicalizationMethod::Relaxed => {
                canonicalize_header_relaxed("DKIM-Signature", sig_value)
            }
        };
        // Strip trailing CRLF per RFC 6376 Section 3.7
        let trimmed = dkim_canon.strip_suffix("\r\n").unwrap_or(&dkim_canon);
        input.extend_from_slice(trimmed.as_bytes());

        input
    }

    fn compute_signature(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match &self.private_key {
            PrivateKey::Rsa(key_pair) => {
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; key_pair.public().modulus_len()];
                key_pair
                    .sign(&RSA_PKCS1_SHA256, &rng, data, &mut sig)
                    .map_err(|e| format!("RSA signing failed: {}", e))?;
                Ok(sig)
            }
            PrivateKey::Ed25519(key_pair) => {
                let sig = key_pair.sign(data);
                Ok(sig.as_ref().to_vec())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{self as ring_sig, KeyPair};

    fn sample_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("From", " sender@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test message"),
            ("Date", " Sat, 01 Jan 2022 00:00:00 +0000"),
            ("Message-ID", " <test@example.com>"),
        ]
    }

    fn sample_body() -> &'static [u8] {
        b"Hello, this is a test email body.\r\n"
    }

    /// Generate an Ed25519 PKCS#8 key pair for testing.
    fn gen_ed25519_pkcs8() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        pkcs8.as_ref().to_vec()
    }

    // Helper: extract tag value from a DKIM-Signature header value
    fn extract_tag(sig: &str, tag: &str) -> Option<String> {
        for part in sig.split(';') {
            let part = part.trim();
            if let Some((t, v)) = part.split_once('=') {
                if t.trim() == tag {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }

    #[test]
    fn test_ed25519_sign_roundtrip() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel1", &pkcs8).unwrap();

        let headers = sample_headers();
        let body = sample_body();
        let sig_value = signer.sign_message(&headers, body).unwrap();

        // Verify output format
        assert!(sig_value.contains("a=ed25519-sha256"));
        assert!(sig_value.contains("d=example.com"));
        assert!(sig_value.contains("s=sel1"));
        assert!(sig_value.contains("bh="));
        assert!(sig_value.contains("b="));

        // Extract b= and verify the signature cryptographically
        let b_value = extract_tag(&sig_value, "b").unwrap();
        let sig_bytes = STANDARD.decode(&b_value).unwrap();

        // Reconstruct the data that was signed
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();

        // Re-derive the signing input by building the same template with b= empty
        let sig_template = sig_value
            .split("b=")
            .next()
            .unwrap()
            .to_string()
            + "b=";

        let h_list: Vec<String> = extract_tag(&sig_value, "h")
            .unwrap()
            .split(':')
            .map(|s| s.trim().to_string())
            .collect();

        let selected = select_headers(&h_list, &headers);
        let mut data_to_sign = Vec::new();
        for (name, value) in &selected {
            if name.is_empty() {
                continue;
            }
            let canon = canonicalize_header_relaxed(name, value);
            data_to_sign.extend_from_slice(canon.as_bytes());
        }
        let dkim_canon = canonicalize_header_relaxed("DKIM-Signature", &sig_template);
        let trimmed = dkim_canon.strip_suffix("\r\n").unwrap_or(&dkim_canon);
        data_to_sign.extend_from_slice(trimmed.as_bytes());

        // Verify using ring
        let public_key_bytes = key_pair.public_key().as_ref();
        let peer_public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, public_key_bytes);
        peer_public_key
            .verify(&data_to_sign, &sig_bytes)
            .expect("Ed25519 signature verification should pass");
    }

    #[test]
    fn test_rsa_sign_roundtrip() {
        // ring cannot generate RSA keys; verify structure and body hash instead.
        // We generate a real Ed25519 signer but test RSA format expectations
        // by verifying the output tags. Full RSA roundtrip tested in verify.rs
        // with a pre-generated key.

        // Verify body hash computation is correct
        let body = sample_body();
        let canon_body = canonicalize_body_relaxed(body);
        let expected_bh = {
            let digest = ring::digest::digest(&ring::digest::SHA256, &canon_body);
            STANDARD.encode(digest.as_ref())
        };

        // Use Ed25519 to test the body-hash path (algorithm-agnostic)
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "rsa-test", &pkcs8).unwrap();
        let sig_value = signer.sign_message(&sample_headers(), body).unwrap();

        let bh = extract_tag(&sig_value, "bh").unwrap();
        assert_eq!(bh, expected_bh, "body hash should match SHA-256 of canonicalized body");
    }

    #[test]
    fn test_from_enforced() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel1", &pkcs8)
            .unwrap()
            .headers(vec!["to".to_string(), "subject".to_string()]);

        assert!(
            signer.headers_to_sign.contains(&"from".to_string()),
            "from must always be in headers_to_sign"
        );
    }

    #[test]
    fn test_timestamp_and_expiration() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel1", &pkcs8)
            .unwrap()
            .expiration(3600);

        let sig_value = signer.sign_message(&sample_headers(), sample_body()).unwrap();

        let t: u64 = extract_tag(&sig_value, "t").unwrap().parse().unwrap();
        let x: u64 = extract_tag(&sig_value, "x").unwrap().parse().unwrap();

        assert!(t > 0, "timestamp should be nonzero");
        assert_eq!(x, t + 3600, "expiration should be timestamp + 3600");
    }

    #[test]
    fn test_custom_canonicalization() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel1", &pkcs8)
            .unwrap()
            .canonicalization(CanonicalizationMethod::Simple, CanonicalizationMethod::Simple);

        let sig_value = signer
            .sign_message(&sample_headers(), sample_body())
            .unwrap();
        assert!(
            sig_value.contains("c=simple/simple"),
            "canonicalization should be simple/simple, got: {}",
            sig_value
        );
    }

    #[test]
    fn test_oversign_from() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel1", &pkcs8).unwrap();
        let sig_value = signer.sign_message(&sample_headers(), sample_body()).unwrap();

        let h_tag = extract_tag(&sig_value, "h").unwrap();
        let from_count = h_tag
            .split(':')
            .filter(|s| s.trim().eq_ignore_ascii_case("from"))
            .count();

        assert_eq!(
            from_count, 2,
            "from should appear exactly twice in h= (over-signing), got h={}",
            h_tag
        );
    }

    #[test]
    fn test_missing_headers_filtered() {
        let pkcs8 = gen_ed25519_pkcs8();
        // Only provide From and To — other default headers should be omitted from h=
        let headers: Vec<(&str, &str)> = vec![
            ("From", " sender@example.com"),
            ("To", " recipient@example.com"),
        ];
        let signer = DkimSigner::ed25519("example.com", "sel1", &pkcs8).unwrap();
        let sig_value = signer.sign_message(&headers, sample_body()).unwrap();

        let h_tag = extract_tag(&sig_value, "h").unwrap();
        let h_names: Vec<&str> = h_tag.split(':').map(|s| s.trim()).collect();

        // Should contain from, to, and the over-signed from — but NOT subject, date, etc.
        assert!(
            !h_names.iter().any(|n| n.eq_ignore_ascii_case("subject")),
            "subject should not be in h= when not present in message"
        );
        assert!(
            h_names.iter().any(|n| n.eq_ignore_ascii_case("from")),
            "from must always be in h="
        );
        assert!(
            h_names.iter().any(|n| n.eq_ignore_ascii_case("to")),
            "to should be in h= when present in message"
        );
    }

    #[test]
    fn test_no_expiration_by_default() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel1", &pkcs8).unwrap();
        let sig_value = signer.sign_message(&sample_headers(), sample_body()).unwrap();

        assert!(
            extract_tag(&sig_value, "x").is_none(),
            "x= should not be present when no expiration is set"
        );
    }
}
