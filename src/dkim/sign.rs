use super::canon::{canonicalize_body, canonicalize_header, select_headers, strip_b_tag};
use super::{Algorithm, CanonicalizationMethod};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature as ring_sig;

pub struct DkimSigner {
    pub domain: String,
    pub selector: String,
    pub private_key_pem: Vec<u8>,
    pub algorithm: Algorithm,
    pub header_canon: CanonicalizationMethod,
    pub body_canon: CanonicalizationMethod,
    pub signed_headers: Vec<String>,
    pub body_length: Option<u64>,
}

impl DkimSigner {
    pub fn new(
        domain: impl Into<String>,
        selector: impl Into<String>,
        private_key_pem: &[u8],
        algorithm: Algorithm,
    ) -> Self {
        Self {
            domain: domain.into(),
            selector: selector.into(),
            private_key_pem: private_key_pem.to_vec(),
            algorithm,
            header_canon: CanonicalizationMethod::Relaxed,
            body_canon: CanonicalizationMethod::Relaxed,
            signed_headers: vec![
                "from".into(),
                "to".into(),
                "subject".into(),
                "date".into(),
            ],
            body_length: None,
        }
    }

    pub fn canonicalization(mut self, header: CanonicalizationMethod, body: CanonicalizationMethod) -> Self {
        self.header_canon = header;
        self.body_canon = body;
        self
    }

    pub fn signed_headers(mut self, headers: Vec<String>) -> Self {
        self.signed_headers = headers;
        self
    }

    pub fn body_length(mut self, len: Option<u64>) -> Self {
        self.body_length = len;
        self
    }

    /// Sign a message. Returns the DKIM-Signature header value (without header name prefix).
    pub fn sign(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<String, String> {
        // Body hash
        let canon_body = canonicalize_body(body, self.body_canon);
        let hash_body = if let Some(len) = self.body_length {
            &canon_body[..std::cmp::min(len as usize, canon_body.len())]
        } else {
            &canon_body
        };

        let body_hash = compute_hash(self.algorithm, hash_body);
        let b64_bh = base64::engine::general_purpose::STANDARD.encode(&body_hash);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let canon_str = format!(
            "{}/{}",
            canon_name(self.header_canon),
            canon_name(self.body_canon),
        );

        let h_str = self.signed_headers.join(":");

        // Build signature header template with empty b=
        let mut sig_value = format!(
            " v=1; a={}; c={}; d={}; s={};\r\n\th={};\r\n\tbh={};\r\n\tt={}; b=",
            alg_name(self.algorithm),
            canon_str,
            self.domain,
            self.selector,
            h_str,
            b64_bh,
            timestamp,
        );

        if let Some(len) = self.body_length {
            sig_value = format!(
                " v=1; a={}; c={}; d={}; s={};\r\n\th={};\r\n\tbh={};\r\n\tl={}; t={}; b=",
                alg_name(self.algorithm),
                canon_str,
                self.domain,
                self.selector,
                h_str,
                b64_bh,
                len,
                timestamp,
            );
        }

        // Compute header hash
        let canon_headers = select_headers(headers, &self.signed_headers, self.header_canon);
        let mut hash_input = String::new();
        for h in &canon_headers {
            hash_input.push_str(h);
        }

        // Append DKIM-Signature with empty b= (no trailing CRLF)
        let stripped = strip_b_tag(&sig_value);
        let canon_sig = canonicalize_header("DKIM-Signature", &stripped, self.header_canon);
        let canon_sig = canon_sig.strip_suffix("\r\n").unwrap_or(&canon_sig);
        hash_input.push_str(canon_sig);

        // Sign
        let signature_bytes = self.sign_data(hash_input.as_bytes())?;
        let b64_sig = base64::engine::general_purpose::STANDARD.encode(&signature_bytes);

        // Fold the b= value for readability
        sig_value.push_str(&b64_sig);

        Ok(sig_value)
    }

    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let key_der = pem_to_der(&self.private_key_pem)?;

        match self.algorithm {
            Algorithm::RsaSha256 => {
                let key_pair = ring_sig::RsaKeyPair::from_pkcs8(&key_der)
                    .map_err(|e| format!("invalid RSA key: {e}"))?;
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; key_pair.public().modulus_len()];
                key_pair
                    .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, data, &mut sig)
                    .map_err(|e| format!("RSA signing failed: {e}"))?;
                Ok(sig)
            }
            Algorithm::RsaSha1 => {
                // ring 0.17 doesn't expose a SHA1 signing padding scheme.
                // SHA1 signing is discouraged; use RSA_PKCS1_SHA256 instead for new signatures.
                // For legacy compatibility, we still try SHA256 padding (callers should use RsaSha256).
                return Err("RSA-SHA1 signing not supported by ring 0.17 — use rsa-sha256".into());
            }
            Algorithm::Ed25519Sha256 => {
                let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8(&key_der)
                    .map_err(|e| format!("invalid Ed25519 key: {e}"))?;
                let sig = key_pair.sign(data);
                Ok(sig.as_ref().to_vec())
            }
        }
    }
}

fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, String> {
    let pem_str = std::str::from_utf8(pem).map_err(|e| format!("invalid PEM: {e}"))?;

    // Extract base64 between BEGIN and END lines
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem_str.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if trimmed.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(trimmed);
        }
    }

    if b64.is_empty() {
        return Err("no PEM data found".into());
    }

    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("PEM base64 decode error: {e}"))
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

fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::RsaSha256 => "rsa-sha256",
        Algorithm::RsaSha1 => "rsa-sha1",
        Algorithm::Ed25519Sha256 => "ed25519-sha256",
    }
}

fn canon_name(m: CanonicalizationMethod) -> &'static str {
    match m {
        CanonicalizationMethod::Simple => "simple",
        CanonicalizationMethod::Relaxed => "relaxed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;
    use crate::dkim::DkimVerifier;

    const RSA_2048_PEM: &str = include_str!("../../specs/ground-truth/rsa2048.pem");
    const RSA_2048_PUB_B64: &str = include_str!("../../specs/ground-truth/rsa2048.pub.b64");
    const ED25519_PEM: &str = include_str!("../../specs/ground-truth/ed25519.pem");
    const ED25519_PUB_B64: &str = include_str!("../../specs/ground-truth/ed25519.pub.b64");
    const RSA_1024_PEM: &str = include_str!("../../specs/ground-truth/rsa1024.pem");
    #[allow(dead_code)]
    const RSA_1024_PUB_B64: &str = include_str!("../../specs/ground-truth/rsa1024.pub.b64");

    fn test_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("From", " user@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test Message"),
            ("Date", " Mon, 01 Jan 2024 00:00:00 +0000"),
        ]
    }

    fn make_resolver_with_key(selector: &str, key_type: &str, pub_b64: &str) -> MockResolver {
        let record = format!("v=DKIM1; k={key_type}; p={}", pub_b64.trim());
        MockResolver::new().with_txt(
            &format!("{selector}._domainkey.example.com"),
            vec![Box::leak(record.into_boxed_str()) as &str],
        )
    }

    #[tokio::test]
    async fn test_sign_verify_rsa2048() {
        let signer = DkimSigner::new(
            "example.com",
            "sel1",
            RSA_2048_PEM.as_bytes(),
            Algorithm::RsaSha256,
        );

        let headers = test_headers();
        let body = b"Hello, World!\r\n";

        let sig_value = signer.sign(&headers, body).unwrap();

        // Build message headers with DKIM-Signature prepended
        let mut full_headers: Vec<(&str, &str)> = Vec::new();
        full_headers.push(("DKIM-Signature", Box::leak(sig_value.into_boxed_str())));
        full_headers.extend_from_slice(&headers);

        let resolver = make_resolver_with_key("sel1", "rsa", RSA_2048_PUB_B64);
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert!(results[0].is_pass(), "expected Pass, got: {:?}", results[0]);
    }

    #[tokio::test]
    async fn test_sign_verify_ed25519() {
        let signer = DkimSigner::new(
            "example.com",
            "sel-ed",
            ED25519_PEM.as_bytes(),
            Algorithm::Ed25519Sha256,
        );

        let headers = test_headers();
        let body = b"Hello, Ed25519!\r\n";

        let sig_value = signer.sign(&headers, body).unwrap();

        let mut full_headers: Vec<(&str, &str)> = Vec::new();
        full_headers.push(("DKIM-Signature", Box::leak(sig_value.into_boxed_str())));
        full_headers.extend_from_slice(&headers);

        let resolver = make_resolver_with_key("sel-ed", "ed25519", ED25519_PUB_B64);
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert!(results[0].is_pass(), "expected Pass, got: {:?}", results[0]);
    }

    #[test]
    fn test_sign_rsa1024_rejected() {
        // ring 0.17 rejects 1024-bit RSA for signing (security policy).
        // 1024-bit keys are verify-only.
        let signer = DkimSigner::new(
            "example.com",
            "sel-1024",
            RSA_1024_PEM.as_bytes(),
            Algorithm::RsaSha256,
        );
        let headers = test_headers();
        assert!(signer.sign(&headers, b"test\r\n").is_err());
    }

    #[tokio::test]
    async fn test_tampered_body_fails() {
        let signer = DkimSigner::new(
            "example.com",
            "sel1",
            RSA_2048_PEM.as_bytes(),
            Algorithm::RsaSha256,
        );

        let headers = test_headers();
        let body = b"Original body\r\n";

        let sig_value = signer.sign(&headers, body).unwrap();

        let mut full_headers: Vec<(&str, &str)> = Vec::new();
        full_headers.push(("DKIM-Signature", Box::leak(sig_value.into_boxed_str())));
        full_headers.extend_from_slice(&headers);

        let resolver = make_resolver_with_key("sel1", "rsa", RSA_2048_PUB_B64);
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, b"Tampered body\r\n").await;

        assert!(
            matches!(
                results[0],
                crate::dkim::DkimResult::Fail {
                    kind: crate::dkim::FailureKind::BodyHashMismatch,
                    ..
                }
            ),
            "expected body hash mismatch, got: {:?}",
            results[0]
        );
    }

    #[tokio::test]
    async fn test_simple_canon_roundtrip() {
        let signer = DkimSigner::new(
            "example.com",
            "sel1",
            RSA_2048_PEM.as_bytes(),
            Algorithm::RsaSha256,
        )
        .canonicalization(CanonicalizationMethod::Simple, CanonicalizationMethod::Simple);

        let headers = test_headers();
        let body = b"Simple canon test\r\n";

        let sig_value = signer.sign(&headers, body).unwrap();

        let mut full_headers: Vec<(&str, &str)> = Vec::new();
        full_headers.push(("DKIM-Signature", Box::leak(sig_value.into_boxed_str())));
        full_headers.extend_from_slice(&headers);

        let resolver = make_resolver_with_key("sel1", "rsa", RSA_2048_PUB_B64);
        let verifier = DkimVerifier::new(resolver);
        let results = verifier.verify_message(&full_headers, body).await;

        assert!(results[0].is_pass(), "expected Pass, got: {:?}", results[0]);
    }
}
