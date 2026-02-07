use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, RsaKeyPair};

use super::canon;
use super::{Algorithm, CanonicalizationMethod};

/// DKIM message signer.
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

enum PrivateKey {
    Rsa(RsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

impl DkimSigner {
    /// Create a signer with RSA-SHA256 using PEM-encoded PKCS8 private key.
    pub fn rsa_sha256(
        domain: &str,
        selector: &str,
        pem_pkcs8: &[u8],
    ) -> Result<Self, String> {
        let der = pem_to_der(pem_pkcs8)?;
        let key_pair = RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| format!("invalid RSA key: {}", e))?;
        Ok(Self {
            private_key: PrivateKey::Rsa(key_pair),
            domain: domain.to_string(),
            selector: selector.to_string(),
            algorithm: Algorithm::RsaSha256,
            header_canon: CanonicalizationMethod::Relaxed,
            body_canon: CanonicalizationMethod::Relaxed,
            headers_to_sign: vec![
                "from".to_string(),
                "to".to_string(),
                "subject".to_string(),
                "date".to_string(),
                "mime-version".to_string(),
                "content-type".to_string(),
                "message-id".to_string(),
            ],
            expiration_seconds: None,
        })
    }

    /// Create a signer with Ed25519-SHA256 using PKCS8 private key bytes (PEM or DER).
    pub fn ed25519(
        domain: &str,
        selector: &str,
        pkcs8: &[u8],
    ) -> Result<Self, String> {
        let der = if pkcs8.starts_with(b"-----") {
            pem_to_der(pkcs8)?
        } else {
            pkcs8.to_vec()
        };
        let key_pair = Ed25519KeyPair::from_pkcs8(&der)
            .map_err(|e| format!("invalid Ed25519 key: {}", e))?;
        Ok(Self {
            private_key: PrivateKey::Ed25519(key_pair),
            domain: domain.to_string(),
            selector: selector.to_string(),
            algorithm: Algorithm::Ed25519Sha256,
            header_canon: CanonicalizationMethod::Relaxed,
            body_canon: CanonicalizationMethod::Relaxed,
            headers_to_sign: vec![
                "from".to_string(),
                "to".to_string(),
                "subject".to_string(),
                "date".to_string(),
                "mime-version".to_string(),
                "content-type".to_string(),
                "message-id".to_string(),
            ],
            expiration_seconds: None,
        })
    }

    pub fn header_canonicalization(mut self, method: CanonicalizationMethod) -> Self {
        self.header_canon = method;
        self
    }

    pub fn body_canonicalization(mut self, method: CanonicalizationMethod) -> Self {
        self.body_canon = method;
        self
    }

    pub fn headers_to_sign(mut self, headers: Vec<String>) -> Self {
        self.headers_to_sign = headers;
        self
    }

    pub fn expiration(mut self, seconds: u64) -> Self {
        self.expiration_seconds = Some(seconds);
        self
    }

    /// Sign a message. `headers` is the raw header text (including line endings).
    /// `body` is the raw message body.
    /// Returns the DKIM-Signature header value (without the "DKIM-Signature: " prefix).
    pub fn sign_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<String, String> {
        // Ensure From is in the sign list
        if !self
            .headers_to_sign
            .iter()
            .any(|h| h.eq_ignore_ascii_case("from"))
        {
            return Err("headers_to_sign must include From".to_string());
        }

        // 1. Canonicalize body and compute body hash
        let canon_body = canon::canonicalize_body(body, self.body_canon, None);
        let body_hash = ring::digest::digest(&ring::digest::SHA256, &canon_body);
        let bh = base64::engine::general_purpose::STANDARD.encode(body_hash.as_ref());

        // 2. Build DKIM-Signature header template
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let canon_str = format!(
            "{}/{}",
            canon_method_str(self.header_canon),
            canon_method_str(self.body_canon)
        );

        let h_value = self.headers_to_sign.join(":");

        let mut sig_header = format!(
            "v=1; a={}; c={}; d={}; s={}; h={}; bh={}; t={}",
            self.algorithm.as_str(),
            canon_str,
            self.domain,
            self.selector,
            h_value,
            bh,
            timestamp,
        );

        if let Some(exp_secs) = self.expiration_seconds {
            sig_header.push_str(&format!("; x={}", timestamp + exp_secs));
        }

        sig_header.push_str("; b=");

        // 3. Canonicalize signed headers
        let canon_headers =
            canon::select_headers(headers, &self.headers_to_sign, self.header_canon);

        let mut hash_input = Vec::new();
        for h in &canon_headers {
            hash_input.extend_from_slice(h.as_bytes());
        }

        // Append the incomplete DKIM-Signature (with b= empty) WITHOUT trailing CRLF
        let dkim_canon = canon::canonicalize_header(
            "dkim-signature",
            &format!(" {}", sig_header),
            self.header_canon,
        );
        let dkim_canon = if dkim_canon.ends_with("\r\n") {
            &dkim_canon[..dkim_canon.len() - 2]
        } else {
            &dkim_canon
        };
        hash_input.extend_from_slice(dkim_canon.as_bytes());

        // 4. Sign
        let sig_bytes = match &self.private_key {
            PrivateKey::Rsa(key_pair) => {
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; key_pair.public().modulus_len()];
                key_pair
                    .sign(
                        &ring::signature::RSA_PKCS1_SHA256,
                        &rng,
                        &hash_input,
                        &mut sig,
                    )
                    .map_err(|e| format!("RSA signing failed: {}", e))?;
                sig
            }
            PrivateKey::Ed25519(key_pair) => key_pair.sign(&hash_input).as_ref().to_vec(),
        };

        // 5. Encode and build final header
        let b_value = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
        sig_header.push_str(&b_value);

        Ok(sig_header)
    }
}

fn canon_method_str(method: CanonicalizationMethod) -> &'static str {
    match method {
        CanonicalizationMethod::Simple => "simple",
        CanonicalizationMethod::Relaxed => "relaxed",
    }
}

/// Convert PEM to DER by stripping headers and base64-decoding.
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, String> {
    let pem_str = std::str::from_utf8(pem).map_err(|_| "invalid PEM encoding")?;
    let mut b64 = String::new();
    let mut in_body = false;
    for line in pem_str.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_body {
            b64.push_str(line);
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("PEM base64 decode error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkim::{DkimResult, FailureKind};
    use crate::dkim::verify::DkimVerifier;
    use crate::common::dns::MockResolver;
    use ring::signature::KeyPair;

    #[test]
    fn test_pem_to_der() {
        let pem = b"-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----\n";
        let der = pem_to_der(pem).unwrap();
        assert_eq!(der, b"test");
    }

    fn load_ed25519_key() -> Vec<u8> {
        include_bytes!("../../specs/ground-truth/ed25519.pem").to_vec()
    }

    fn load_rsa2048_key() -> Vec<u8> {
        include_bytes!("../../specs/ground-truth/rsa2048.pem").to_vec()
    }

    #[tokio::test]
    async fn test_sign_verify_ed25519_roundtrip() {
        let key_pem = load_ed25519_key();
        let signer = DkimSigner::ed25519("example.com", "sel-ed", &key_pem)
            .unwrap()
            .headers_to_sign(vec!["from".to_string(), "to".to_string(), "subject".to_string()]);

        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test message"),
        ];
        let body = b"Hello, world!\r\n";

        let sig_value = signer.sign_message(&headers, body).unwrap();

        // Set up mock DNS with Ed25519 public key
        let mut resolver = MockResolver::new();
        // Extract raw 32-byte public key from PKCS8 Ed25519 key pair
        let der = pem_to_der(&key_pem).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&der).unwrap();
        let pub_key_bytes = key_pair.public_key().as_ref();
        let pub_key_b64 = base64::engine::general_purpose::STANDARD.encode(pub_key_bytes);
        resolver.add_txt(
            "sel-ed._domainkey.example.com",
            vec![format!("v=DKIM1; k=ed25519; p={}", pub_key_b64)],
        );

        // Verify
        let verifier = DkimVerifier::new(resolver);
        let mut all_headers: Vec<(&str, &str)> = vec![("DKIM-Signature", "")];
        // We need to provide the sig value as the header value
        let sig_with_space = format!(" {}", sig_value);
        all_headers[0] = ("DKIM-Signature", &sig_with_space);
        all_headers.extend_from_slice(&headers);

        let results = verifier.verify_message(&all_headers, body).await;
        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], DkimResult::Pass { domain, .. } if domain == "example.com"),
            "Expected Pass, got {:?}",
            results[0]
        );
    }

    #[tokio::test]
    async fn test_sign_verify_rsa_roundtrip() {
        let key_pem = load_rsa2048_key();
        let signer = DkimSigner::rsa_sha256("example.com", "sel1", &key_pem)
            .unwrap()
            .headers_to_sign(vec!["from".to_string(), "to".to_string(), "subject".to_string()]);

        let headers: Vec<(&str, &str)> = vec![
            ("From", " user@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test message"),
        ];
        let body = b"Hello, world!\r\n";

        let sig_value = signer.sign_message(&headers, body).unwrap();

        // Set up mock DNS with RSA public key (SPKI format, as in real DKIM records)
        let mut resolver = MockResolver::new();
        let pub_key_b64 = include_str!("../../specs/ground-truth/rsa2048.pub.b64").trim();
        resolver.add_txt(
            "sel1._domainkey.example.com",
            vec![format!("v=DKIM1; k=rsa; p={}", pub_key_b64)],
        );

        let verifier = DkimVerifier::new(resolver);
        let sig_with_space = format!(" {}", sig_value);
        let mut all_headers: Vec<(&str, &str)> = vec![("DKIM-Signature", &sig_with_space)];
        all_headers.extend_from_slice(&headers);

        let results = verifier.verify_message(&all_headers, body).await;
        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], DkimResult::Pass { domain, .. } if domain == "example.com"),
            "Expected Pass, got {:?}",
            results[0]
        );
    }

    #[tokio::test]
    async fn test_sign_verify_tampered_body() {
        let key_pem = load_ed25519_key();
        let signer = DkimSigner::ed25519("example.com", "sel-ed", &key_pem)
            .unwrap()
            .headers_to_sign(vec!["from".to_string()]);

        let headers: Vec<(&str, &str)> = vec![("From", " user@example.com")];
        let body = b"Original body\r\n";
        let sig_value = signer.sign_message(&headers, body).unwrap();

        let mut resolver = MockResolver::new();
        let der = pem_to_der(&key_pem).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&der).unwrap();
        let pub_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref());
        resolver.add_txt(
            "sel-ed._domainkey.example.com",
            vec![format!("v=DKIM1; k=ed25519; p={}", pub_key_b64)],
        );

        let verifier = DkimVerifier::new(resolver);
        let sig_with_space = format!(" {}", sig_value);
        let all_headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", &sig_with_space),
            ("From", " user@example.com"),
        ];

        let results = verifier
            .verify_message(&all_headers, b"Tampered body\r\n")
            .await;
        assert!(matches!(
            &results[0],
            DkimResult::Fail {
                kind: FailureKind::BodyHashMismatch,
                ..
            }
        ));
    }
}
