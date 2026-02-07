//! DKIM message signing (RFC 6376 Section 5).

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, RsaKeyPair};
#[cfg(test)]
use ring::signature::KeyPair;

use crate::dkim::canon::{
    canonicalize_body_relaxed, canonicalize_body_simple, canonicalize_header_relaxed,
    canonicalize_header_simple, select_headers, truncate_body,
};
use crate::dkim::signature::{Algorithm, CanonicalizationMethod};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors during DKIM signing.
#[derive(Debug, Clone)]
pub enum SignError {
    /// The `from` header is required in headers_to_sign but not present.
    MissingFromHeader,
    /// Private key could not be parsed.
    KeyError(String),
    /// Cryptographic signing failed.
    SigningError(String),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFromHeader => write!(f, "From header is required in headers_to_sign"),
            Self::KeyError(msg) => write!(f, "key error: {msg}"),
            Self::SigningError(msg) => write!(f, "signing error: {msg}"),
        }
    }
}

impl std::error::Error for SignError {}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

enum PrivateKey {
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

// ---------------------------------------------------------------------------
// PEM parsing
// ---------------------------------------------------------------------------

/// Strip PEM armor and decode the inner base64 to DER bytes.
/// Handles PRIVATE KEY, RSA PRIVATE KEY, ED25519 PRIVATE KEY labels.
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, SignError> {
    let text = std::str::from_utf8(pem).map_err(|e| SignError::KeyError(format!("invalid UTF-8 in PEM: {e}")))?;

    let mut in_base64 = false;
    let mut b64_data = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN ") && trimmed.ends_with("-----") {
            in_base64 = true;
            continue;
        }
        if trimmed.starts_with("-----END ") && trimmed.ends_with("-----") {
            break;
        }
        if in_base64 {
            b64_data.push_str(trimmed);
        }
    }

    if b64_data.is_empty() {
        return Err(SignError::KeyError("no base64 data found in PEM".into()));
    }

    base64::engine::general_purpose::STANDARD
        .decode(&b64_data)
        .map_err(|e| SignError::KeyError(format!("invalid base64 in PEM: {e}")))
}

/// Detect whether input is PEM (starts with -----BEGIN) or raw DER.
fn parse_pkcs8(input: &[u8]) -> Result<Vec<u8>, SignError> {
    if input.starts_with(b"-----BEGIN ") {
        pem_to_der(input)
    } else {
        Ok(input.to_vec())
    }
}

// ---------------------------------------------------------------------------
// DkimSigner
// ---------------------------------------------------------------------------

/// DKIM message signer. Construct via [`DkimSigner::ed25519`] or
/// [`DkimSigner::rsa_sha256`], then call [`DkimSigner::sign_message`].
pub struct DkimSigner {
    domain: String,
    selector: String,
    algorithm: Algorithm,
    header_canon: CanonicalizationMethod,
    body_canon: CanonicalizationMethod,
    headers_to_sign: Vec<String>,
    body_length: Option<u64>,
    expiration_secs: Option<u64>,
    private_key: PrivateKey,
}

impl DkimSigner {
    /// Create an Ed25519-SHA256 signer from PKCS#8 key material (PEM or DER).
    pub fn ed25519(
        domain: impl Into<String>,
        selector: impl Into<String>,
        pkcs8: &[u8],
    ) -> Result<Self, SignError> {
        let der = parse_pkcs8(pkcs8)?;
        let key_pair = Ed25519KeyPair::from_pkcs8(&der)
            .or_else(|_| Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der))
            .map_err(|e| SignError::KeyError(format!("Ed25519 PKCS#8 parse: {e}")))?;

        Ok(Self {
            domain: domain.into(),
            selector: selector.into(),
            algorithm: Algorithm::Ed25519Sha256,
            header_canon: CanonicalizationMethod::Relaxed,
            body_canon: CanonicalizationMethod::Relaxed,
            headers_to_sign: default_headers(),
            body_length: None,
            expiration_secs: None,
            private_key: PrivateKey::Ed25519(key_pair),
        })
    }

    /// Create an RSA-SHA256 signer from PKCS#8 key material (PEM or DER).
    pub fn rsa_sha256(
        domain: impl Into<String>,
        selector: impl Into<String>,
        pkcs8: &[u8],
    ) -> Result<Self, SignError> {
        let der = parse_pkcs8(pkcs8)?;
        let key_pair = RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| SignError::KeyError(format!("RSA PKCS#8 parse: {e}")))?;

        Ok(Self {
            domain: domain.into(),
            selector: selector.into(),
            algorithm: Algorithm::RsaSha256,
            header_canon: CanonicalizationMethod::Relaxed,
            body_canon: CanonicalizationMethod::Relaxed,
            headers_to_sign: default_headers(),
            body_length: None,
            expiration_secs: None,
            private_key: PrivateKey::Rsa(key_pair),
        })
    }

    /// Override which headers to sign (lowercased). Must include `from`.
    pub fn headers(mut self, headers: &[&str]) -> Self {
        self.headers_to_sign = headers.iter().map(|h| h.to_ascii_lowercase()).collect();
        self
    }

    /// Set header and body canonicalization methods.
    pub fn canonicalization(
        mut self,
        header: CanonicalizationMethod,
        body: CanonicalizationMethod,
    ) -> Self {
        self.header_canon = header;
        self.body_canon = body;
        self
    }

    /// Set body length limit (l= tag).
    pub fn body_length(mut self, len: u64) -> Self {
        self.body_length = Some(len);
        self
    }

    /// Set expiration as seconds from signing time (x= t + secs).
    pub fn expiration(mut self, secs: u64) -> Self {
        self.expiration_secs = Some(secs);
        self
    }

    /// Sign a message and return the complete DKIM-Signature header value.
    ///
    /// The returned string is the value part only (after `DKIM-Signature:`).
    /// Prepend it as `DKIM-Signature: <value>` to the message headers.
    ///
    /// `headers` is the ordered list of (name, value) pairs from the message.
    /// `body` is the raw message body bytes.
    pub fn sign_message(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<String, SignError> {
        // Validate: "from" must be in headers_to_sign.
        if !self.headers_to_sign.iter().any(|h| h == "from") {
            return Err(SignError::MissingFromHeader);
        }

        // Validate: message must contain a From header if "from" is signed.
        let has_from = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("from"));
        if !has_from {
            return Err(SignError::MissingFromHeader);
        }

        // 1. Body hash
        let canon_body = match self.body_canon {
            CanonicalizationMethod::Simple => canonicalize_body_simple(body),
            CanonicalizationMethod::Relaxed => canonicalize_body_relaxed(body),
        };
        let truncated = truncate_body(&canon_body, self.body_length);
        let body_hash = digest(&SHA256, truncated);
        let bh_b64 = base64::engine::general_purpose::STANDARD.encode(body_hash.as_ref());

        // 2. Timestamp
        let now = current_timestamp();

        // 3. Build the DKIM-Signature header value with b= empty.
        //    The value includes a leading space (convention matching parser storage).
        let h_list = self.headers_to_sign.join(":");
        let c_tag = format!("{}/{}", self.header_canon, self.body_canon);

        let mut sig_value = format!(
            " v=1; a={}; d={}; s={}; c={}; h={}; bh={}; t={}; b=",
            self.algorithm, self.domain, self.selector, c_tag, h_list, bh_b64, now,
        );

        // Optional tags before b= is finalized
        if let Some(len) = self.body_length {
            // Insert l= before b=. Rebuild to maintain tag ordering.
            sig_value = format!(
                " v=1; a={}; d={}; s={}; c={}; h={}; bh={}; t={}; l={}; b=",
                self.algorithm, self.domain, self.selector, c_tag, h_list, bh_b64, now, len,
            );
        }

        if let Some(exp_secs) = self.expiration_secs {
            let x = now + exp_secs;
            // Append x= before b= by rebuilding
            let base = sig_value.trim_end_matches("b=");
            sig_value = format!("{base}x={x}; b=");
        }

        // 4. Build header data to sign (same logic as verifier)
        let selected = select_headers(headers, &self.headers_to_sign);

        let mut header_data = String::new();
        for (i, (name, value)) in selected.iter().enumerate() {
            if name.is_empty() && value.is_empty() {
                // Over-signed sentinel
                let h_name = &self.headers_to_sign[i];
                let canon = match self.header_canon {
                    CanonicalizationMethod::Simple => canonicalize_header_simple(h_name, ""),
                    CanonicalizationMethod::Relaxed => canonicalize_header_relaxed(h_name, ""),
                };
                header_data.push_str(&canon);
            } else {
                let canon = match self.header_canon {
                    CanonicalizationMethod::Simple => canonicalize_header_simple(name, value),
                    CanonicalizationMethod::Relaxed => canonicalize_header_relaxed(name, value),
                };
                header_data.push_str(&canon);
            }
        }

        // Append canonicalized DKIM-Signature (with b= empty), no trailing CRLF.
        let dkim_sig_canon = match self.header_canon {
            CanonicalizationMethod::Simple => {
                canonicalize_header_simple("DKIM-Signature", &sig_value)
            }
            CanonicalizationMethod::Relaxed => {
                canonicalize_header_relaxed("DKIM-Signature", &sig_value)
            }
        };
        let dkim_sig_canon = dkim_sig_canon
            .strip_suffix("\r\n")
            .unwrap_or(&dkim_sig_canon);
        header_data.push_str(dkim_sig_canon);

        // 5. Sign
        let header_bytes = header_data.as_bytes();
        let sig_bytes = match &self.private_key {
            PrivateKey::Ed25519(kp) => kp.sign(header_bytes).as_ref().to_vec(),
            PrivateKey::Rsa(kp) => {
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; kp.public().modulus_len()];
                kp.sign(&signature::RSA_PKCS1_SHA256, &rng, header_bytes, &mut sig)
                    .map_err(|e| SignError::SigningError(format!("RSA signing failed: {e}")))?;
                sig
            }
        };

        let b_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        // 6. Build final header value with b= filled in.
        let final_value = format!("{sig_value}{b_b64}");

        Ok(final_value)
    }

    /// Return the public key bytes (SubjectPublicKeyInfo DER for RSA, raw for Ed25519).
    /// Useful for constructing DNS records in tests.
    #[cfg(test)]
    fn public_key_bytes(&self) -> Vec<u8> {
        match &self.private_key {
            PrivateKey::Ed25519(kp) => kp.public_key().as_ref().to_vec(),
            PrivateKey::Rsa(kp) => kp.public().as_ref().to_vec(),
        }
    }
}

fn default_headers() -> Vec<String> {
    ["from", "to", "subject", "date", "mime-version", "content-type", "message-id"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

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
    use crate::dkim::verify::DkimVerifier;
    use crate::dkim::DkimResult;

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    /// Generate an Ed25519 PKCS#8 key pair for testing.
    fn gen_ed25519_pkcs8() -> Vec<u8> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        pkcs8.as_ref().to_vec()
    }

    /// Build a MockResolver with the signer's public key registered as a DNS record.
    fn resolver_for_signer(signer: &DkimSigner, domain: &str, selector: &str) -> MockResolver {
        let pub_bytes = signer.public_key_bytes();
        let key_type = match signer.algorithm {
            Algorithm::Ed25519Sha256 => "ed25519",
            Algorithm::RsaSha256 => "rsa",
            _ => "rsa",
        };
        let txt = format!("v=DKIM1; k={key_type}; p={}", b64(&pub_bytes));
        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            format!("{selector}._domainkey.{domain}"),
            MockDnsResponse::Records(vec![txt]),
        );
        resolver
    }

    /// Sign a message, prepend the DKIM-Signature header, then verify with DkimVerifier.
    async fn sign_and_verify(
        signer: &DkimSigner,
        msg_headers: &[(&str, &str)],
        body: &[u8],
        domain: &str,
        selector: &str,
    ) -> Vec<DkimResult> {
        let sig_value = signer.sign_message(msg_headers, body).unwrap();

        // Prepend DKIM-Signature to headers
        let mut all_headers: Vec<(String, String)> = vec![(
            "DKIM-Signature".to_string(),
            sig_value.clone(),
        )];
        for (n, v) in msg_headers {
            all_headers.push((n.to_string(), v.to_string()));
        }

        let headers_ref: Vec<(&str, &str)> = all_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();

        let resolver = resolver_for_signer(signer, domain, selector);
        let verifier = DkimVerifier::new(resolver);
        verifier.verify_message(&headers_ref, body).await
    }

    fn assert_pass(results: &[DkimResult]) {
        assert_eq!(results.len(), 1, "expected 1 result, got {results:?}");
        match &results[0] {
            DkimResult::Pass { .. } => {}
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: Ed25519 sign and verify round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ed25519_roundtrip() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to", "subject"]);

        let headers = vec![
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " Test message"),
        ];
        let body = b"Hello, world!\r\n";

        let results = sign_and_verify(&signer, &headers, body, "example.com", "sel").await;
        assert_pass(&results);
    }

    // -----------------------------------------------------------------------
    // Test 2: RSA sign and verify round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rsa_roundtrip() {
        let pem = std::fs::read("/private/tmp/email-auth/specs/ground-truth/rsa2048.pem").unwrap();
        let signer = DkimSigner::rsa_sha256("example.com", "rsa-sel", &pem)
            .unwrap()
            .headers(&["from", "to", "subject"]);

        let headers = vec![
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " RSA test"),
        ];
        let body = b"RSA signed body\r\n";

        let results = sign_and_verify(&signer, &headers, body, "example.com", "rsa-sel").await;
        assert_pass(&results);
    }

    // -----------------------------------------------------------------------
    // Test 3: SignError on missing From header
    // -----------------------------------------------------------------------

    #[test]
    fn error_missing_from_in_message() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to"]);

        // Message has no From header
        let headers = vec![("To", " bob@example.org")];
        let result = signer.sign_message(&headers, b"body");
        assert!(matches!(result, Err(SignError::MissingFromHeader)));
    }

    #[test]
    fn error_from_not_in_headers_to_sign() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["to", "subject"]); // No "from"

        let headers = vec![
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
        ];
        let result = signer.sign_message(&headers, b"body");
        assert!(matches!(result, Err(SignError::MissingFromHeader)));
    }

    // -----------------------------------------------------------------------
    // Test 4: Relaxed/relaxed round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn relaxed_relaxed_roundtrip() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to", "subject"])
            .canonicalization(CanonicalizationMethod::Relaxed, CanonicalizationMethod::Relaxed);

        let headers = vec![
            ("From", "  alice@example.com  "),
            ("To", "\tbob@example.org"),
            ("Subject", " Hello  World "),
        ];
        let body = b"Body  with   extra   spaces  \r\n\r\n";

        let results = sign_and_verify(&signer, &headers, body, "example.com", "sel").await;
        assert_pass(&results);
    }

    // -----------------------------------------------------------------------
    // Test 5: Simple/simple round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn simple_simple_roundtrip() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to", "subject"])
            .canonicalization(CanonicalizationMethod::Simple, CanonicalizationMethod::Simple);

        let headers = vec![
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " Test"),
        ];
        let body = b"Simple body\r\n";

        let results = sign_and_verify(&signer, &headers, body, "example.com", "sel").await;
        assert_pass(&results);
    }

    // -----------------------------------------------------------------------
    // Test 6: Body length limit round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn body_length_limit_roundtrip() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to", "subject"])
            .body_length(5);

        let headers = vec![
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " Length test"),
        ];
        let body = b"Hello, this body is longer than 5 bytes\r\n";

        let results = sign_and_verify(&signer, &headers, body, "example.com", "sel").await;
        assert_pass(&results);
    }

    // -----------------------------------------------------------------------
    // Test 7: Custom header set
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn custom_headers_roundtrip() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "subject", "x-custom"]);

        let headers = vec![
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " Custom header test"),
            ("X-Custom", " my-value"),
        ];
        let body = b"Custom headers\r\n";

        let results = sign_and_verify(&signer, &headers, body, "example.com", "sel").await;
        assert_pass(&results);
    }

    // -----------------------------------------------------------------------
    // Test 8: Expiration tag
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn expiration_roundtrip() {
        let pkcs8 = gen_ed25519_pkcs8();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to"])
            .expiration(3600); // 1 hour from now

        let headers = vec![
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
        ];
        let body = b"Expiring signature\r\n";

        let results = sign_and_verify(&signer, &headers, body, "example.com", "sel").await;
        assert_pass(&results);
    }

    // -----------------------------------------------------------------------
    // Test 9: PEM key loading
    // -----------------------------------------------------------------------

    #[test]
    fn rsa_pem_loading() {
        let pem = std::fs::read("/private/tmp/email-auth/specs/ground-truth/rsa2048.pem").unwrap();
        let signer = DkimSigner::rsa_sha256("example.com", "sel", &pem);
        assert!(signer.is_ok(), "should load RSA PEM key: {:?}", signer.err());
    }

    // -----------------------------------------------------------------------
    // Test 10: RSA simple/simple round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rsa_simple_simple_roundtrip() {
        let pem = std::fs::read("/private/tmp/email-auth/specs/ground-truth/rsa2048.pem").unwrap();
        let signer = DkimSigner::rsa_sha256("example.com", "rsa-sel", &pem)
            .unwrap()
            .headers(&["from", "to", "subject"])
            .canonicalization(CanonicalizationMethod::Simple, CanonicalizationMethod::Simple);

        let headers = vec![
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " RSA simple test"),
        ];
        let body = b"RSA simple body\r\n";

        let results = sign_and_verify(&signer, &headers, body, "example.com", "rsa-sel").await;
        assert_pass(&results);
    }
}
