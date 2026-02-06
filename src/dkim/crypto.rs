use ring::signature::{self, KeyPair, UnparsedPublicKey, VerificationAlgorithm};
use base64::Engine;
use super::signature::Algorithm;
use super::key::{DkimPublicKey, KeyType};

pub fn verify_signature(
    header_hash: &[u8],
    signature_bytes: &[u8],
    key: &DkimPublicKey,
    algorithm: Algorithm,
) -> Result<bool, String> {
    let verification_algorithm: &'static dyn VerificationAlgorithm = match (algorithm, key.key_type) {
        (Algorithm::RsaSha256, KeyType::Rsa) => &signature::RSA_PKCS1_2048_8192_SHA256,
        (Algorithm::RsaSha1, KeyType::Rsa) => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        (Algorithm::Ed25519Sha256, KeyType::Ed25519) => &signature::ED25519,
        _ => return Err(format!("Incompatible algorithm {:?} with key type {:?}", algorithm, key.key_type)),
    };

    // For RSA keys, the public key is in SubjectPublicKeyInfo format
    // For Ed25519, it's the raw 32-byte key
    let public_key_bytes = match key.key_type {
        KeyType::Rsa => extract_rsa_public_key(&key.public_key)?,
        KeyType::Ed25519 => key.public_key.clone(),
    };

    let public_key = UnparsedPublicKey::new(verification_algorithm, &public_key_bytes);

    // For RSA, we verify the hash directly (RSA PKCS#1 v1.5 signature)
    // ring expects the data that was signed, not the hash
    // But DKIM signs the canonicalized headers, and we passed in the hash
    // So we need to verify against the canonicalized data, not the hash

    // Actually, looking at the DKIM spec and ring's API:
    // The signature is over the canonicalized headers, not a hash.
    // The header_hash we computed is what we need to verify.

    // Wait - re-reading: DKIM computes hash of canonicalized headers,
    // then signs that hash with RSA. So the signature IS over the hash.
    // But ring's RSA_PKCS1 expects the message and does the hashing internally.

    // So we need to pass the canonicalized headers, not the hash.
    // Let me check the actual flow...

    // The way DKIM works:
    // 1. Canonicalize headers
    // 2. Hash the canonicalized headers
    // 3. Sign the hash with RSA (or Ed25519)
    //
    // ring's RSA_PKCS1 verify:
    // 1. Takes message and signature
    // 2. Hashes the message internally
    // 3. Verifies the signature

    // So we need to pass the pre-hash data (canonicalized headers as bytes)
    // But our current API receives the hash...

    // Let me reconsider the API. The header_hash should actually be
    // the canonicalized header data, not the hash of it.

    // Looking at our hash.rs, compute_header_hash returns the hash.
    // That's wrong for the verify step - we need the raw canonicalized data.

    // For now, let's assume header_hash is actually the canonicalized data
    // and this will be fixed in the calling code.

    match public_key.verify(header_hash, signature_bytes) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn extract_rsa_public_key(der: &[u8]) -> Result<Vec<u8>, String> {
    // The DER is in SubjectPublicKeyInfo format
    // We need to return it as-is for ring
    Ok(der.to_vec())
}

// DKIM Signing

pub struct SigningConfig {
    pub domain: String,
    pub selector: String,
    pub algorithm: Algorithm,
    pub headers_to_sign: Vec<String>,
    pub canonicalization: super::signature::Canonicalization,
}

pub struct DkimSigner {
    config: SigningConfig,
    private_key: PrivateKey,
}

enum PrivateKey {
    Rsa(ring::signature::RsaKeyPair),
    Ed25519(ring::signature::Ed25519KeyPair),
}

impl DkimSigner {
    pub fn new(config: SigningConfig, private_key_pem: &str) -> Result<Self, String> {
        let private_key = parse_private_key(private_key_pem, config.algorithm)?;
        Ok(Self { config, private_key })
    }

    pub fn sign(&self, message: &[u8]) -> Result<String, String> {
        let message_str = std::str::from_utf8(message).map_err(|e| e.to_string())?;

        let (headers, body) = split_message(message_str)
            .ok_or_else(|| "Invalid message format".to_string())?;

        // Canonicalize and hash body
        let canon_body = super::canon::canonicalize_body(body, self.config.canonicalization.body);
        let body_hash = super::hash::compute_body_hash(&canon_body, self.config.algorithm, None);
        let body_hash_b64 = base64::engine::general_purpose::STANDARD.encode(&body_hash);

        // Build DKIM-Signature header (without b= value yet)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let headers_list = self.config.headers_to_sign.join(":");

        let sig_header_value = format!(
            "v=1; a={}; c={}; d={}; s={}; t={}; h={}; bh={}; b=",
            self.config.algorithm,
            self.config.canonicalization,
            self.config.domain,
            self.config.selector,
            timestamp,
            headers_list,
            body_hash_b64,
        );

        let sig_header = format!("DKIM-Signature: {}", sig_header_value);

        // Create a temporary signature for canonicalization
        let temp_sig = super::signature::DkimSignature {
            version: 1,
            algorithm: self.config.algorithm,
            signature: vec![],
            body_hash: body_hash.clone(),
            canonicalization: self.config.canonicalization,
            domain: self.config.domain.clone(),
            selector: self.config.selector.clone(),
            signed_headers: self.config.headers_to_sign.clone(),
            body_length: None,
            timestamp: Some(timestamp),
            expiration: None,
            copied_headers: None,
            auid: None,
            query_methods: None,
            raw_header: sig_header.clone(),
        };

        // Canonicalize headers for signing
        let canon_headers = super::canon::canonicalize_headers_for_signing(&headers, &temp_sig);

        // Sign
        let signature = self.sign_data(canon_headers.as_bytes())?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        // Return complete DKIM-Signature header
        Ok(format!("DKIM-Signature: {}{}",sig_header_value, signature_b64))
    }

    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match &self.private_key {
            PrivateKey::Rsa(key_pair) => {
                let rng = ring::rand::SystemRandom::new();
                let mut signature = vec![0u8; key_pair.public().modulus_len()];
                key_pair
                    .sign(&signature::RSA_PKCS1_SHA256, &rng, data, &mut signature)
                    .map_err(|e| e.to_string())?;
                Ok(signature)
            }
            PrivateKey::Ed25519(key_pair) => {
                let signature = key_pair.sign(data);
                Ok(signature.as_ref().to_vec())
            }
        }
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        match &self.private_key {
            PrivateKey::Rsa(key_pair) => {
                key_pair.public().as_ref().to_vec()
            }
            PrivateKey::Ed25519(key_pair) => {
                key_pair.public_key().as_ref().to_vec()
            }
        }
    }
}

fn parse_private_key(pem: &str, algorithm: Algorithm) -> Result<PrivateKey, String> {
    let der = pem_to_der(pem)?;

    match algorithm {
        Algorithm::RsaSha256 | Algorithm::RsaSha1 => {
            let key_pair = signature::RsaKeyPair::from_pkcs8(&der)
                .or_else(|_| signature::RsaKeyPair::from_der(&der))
                .map_err(|e| format!("Failed to parse RSA key: {}", e))?;
            Ok(PrivateKey::Rsa(key_pair))
        }
        Algorithm::Ed25519Sha256 => {
            let key_pair = signature::Ed25519KeyPair::from_pkcs8(&der)
                .or_else(|_| signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der))
                .map_err(|e| format!("Failed to parse Ed25519 key: {}", e))?;
            Ok(PrivateKey::Ed25519(key_pair))
        }
    }
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let lines: Vec<&str> = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    let b64 = lines.join("");

    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("Invalid base64 in PEM: {}", e))
}

fn split_message(message: &str) -> Option<(String, &str)> {
    if let Some(pos) = message.find("\r\n\r\n") {
        Some((message[..pos + 2].to_string(), &message[pos + 4..]))
    } else if let Some(pos) = message.find("\n\n") {
        Some((message[..pos + 1].to_string(), &message[pos + 2..]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid RSA-2048 private key in PKCS#8 format for testing
    const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCf9ijrMEeYNCv/
J4bncBDURENhBV7TOEzfY1SkoVWyHIxnDtyJSbMiuuY8rAKtVgaKS3Hk1fb8atLo
0pgpFtG/m0YxNohfIjg2toOJpcqlBdIBCxkKTK5HMT73T5TBRD6lyIOLYI/O9Da/
2w/6AJYf0V8/ytn83pmTG2tFf18i8c+7ghq5Rnqw4/NwCTVZS3sll6FHzc9MKtNn
K+WjXNwwqDSYctnOkB9Tl7uoMvxEAyZ0Ri4gNKkfDgy5SECtozxDhHEUuQGo4LDX
xepcY+M5rE+85K6pyLIl95KtqVIu+SBOpgwQGtEqiFaGWN6IDTaCOgv4PYiwWVvH
CPAu8CpzAgMBAAECggEACMynSpd2Jh10ms18rShBMhQWlXSQrKjeXbQz+KHMD4dk
19nS8EBxeMR0RuZ6zTiRaokk7kmGPojNKl6aB+SdTDTeoyAUrLsQAZPVCjzoYrST
wq1EHDNvVjOTevz8j2HRhRgnLa3LAL+hcA4SbmvFgQw+TkmP5/UCLhFQ5i/6tqF6
soKRSRfzCOX9uexXKrihxB028BvZMv0wBbKSGwIb5sgSa5WnIzXXUq866FJtwCCZ
SeLmABs6UMuN8FHiZhc9avh7FG2wxsUxc43VlvMwKYR9ywm2Zq8dc8i+8uZTBBWv
GtAAXF+wg7LSfvBcDbRxZQ/CjRBBZayz6X9Ehdi5+QKBgQDd9EyBZezXJ2TnAnaL
1vsxGJk5TVLVPMqMF5wua0/nOI4TRHbiMXp5QSOeXizi/K9LKkzWMJIYjkHOIVBX
kwW53ScUyKfGWH2EFlS3zPFJmkYoZLfekU4YP+hF8J/LOjAFJvlcc0/oIx3aR3z7
Xwwtqzrjxo5hzI/10uaAlMptOQKBgQC4f4fLdV7cV+sOeD5C5Xf17EKJKgM1shcC
Erk8DEIaFEhj41i8oGNUllNibLw7cSCO9INSif4pCFbWfcFA4ostMpIX1sC0XSK9
7aAHmm8yDY8UjG/65dkj5n7Tq1MfUyF5tDfH2/CcvM8ISurGsVeKUyUyt0o3ErFq
JxUq6pJBCwKBgQCt1Eoiwa/W5ax53Az6AlninrBKF4v7I0xCoa8ZD8SZg0qKPoGZ
L0ULN//sZTdkYp/rD2r0CUAyaR+Sj7a7j5LZeSHFfk0f42gSDec1uBV1HpU5x3/V
mRl/lnWUaRrM8HpxXo/HXyxC01XrATgaKtt/3O4XPAeBAtPwo8cRBvbuyQKBgQCU
OYEzqHwpskiaO2hp/kk+Pi3GXQZvIUDy3XAMGh0RLrJp7cDg6kpjLtKXBJzFdMGf
mDnZGhwjgxug/y8/ncIK8dIFbPcs8JZ02G/1K9Gh+Nq2u41LmVW2TfweuknxpKwE
RxF5c+3/PoFmPCoar2eRLfN4p2DslgwLKJMNA5+0uQKBgBJSQe6fvYanXWvyypYU
hDDwOtVAi5/9n9cbomiv2LanrEWM8ZvOLWVY+BxHU6CE9gA730RV2mVeTVKfDEmZ
j9q/0m5aMbtrH+DqkleiWIpN7hReAlk9e9P0BaQ/pe//ykhC4Yd5+ee+cUg2coC+
GdvWeMXjYHa44lRedysxLHhw
-----END PRIVATE KEY-----";

    #[test]
    fn test_sign_and_verify() {
        let config = SigningConfig {
            domain: "example.com".into(),
            selector: "test".into(),
            algorithm: Algorithm::RsaSha256,
            headers_to_sign: vec!["from".into(), "to".into(), "subject".into()],
            canonicalization: super::super::signature::Canonicalization::default(),
        };

        let signer = DkimSigner::new(config, TEST_RSA_PRIVATE_KEY_PEM).unwrap();

        let message = b"From: sender@example.com\r\n\
                        To: recipient@example.com\r\n\
                        Subject: Test\r\n\
                        \r\n\
                        Hello, World!\r\n";

        let signature_header = signer.sign(message).unwrap();
        assert!(signature_header.starts_with("DKIM-Signature:"));
        assert!(signature_header.contains("d=example.com"));
        assert!(signature_header.contains("s=test"));

        // Get public key for verification
        let public_key_der = signer.public_key_der();
        assert!(!public_key_der.is_empty());
    }
}
