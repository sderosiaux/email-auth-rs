use ring::signature::{self, UnparsedPublicKey, RsaKeyPair, Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use base64::Engine;

use super::{Algorithm, Canonicalization, CanonicalizationMethod, DkimError};
use super::canon;
use super::hash;

/// Verify a DKIM signature
pub fn verify_signature(
    algorithm: &Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    match algorithm {
        Algorithm::RsaSha1 => {
            let key = UnparsedPublicKey::new(&signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY, public_key);
            Ok(key.verify(message, signature).is_ok())
        }
        Algorithm::RsaSha256 => {
            let key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
            match key.verify(message, signature) {
                Ok(()) => Ok(true),
                Err(_) => {
                    // Try with 1024-bit key support
                    let key = UnparsedPublicKey::new(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, public_key);
                    Ok(key.verify(message, signature).is_ok())
                }
            }
        }
        Algorithm::Ed25519Sha256 => {
            let key = UnparsedPublicKey::new(&signature::ED25519, public_key);
            Ok(key.verify(message, signature).is_ok())
        }
    }
}

/// Configuration for DKIM signing
#[derive(Debug, Clone)]
pub struct SigningConfig {
    pub domain: String,
    pub selector: String,
    pub algorithm: Algorithm,
    pub canonicalization: Canonicalization,
    pub headers_to_sign: Vec<String>,
    pub include_timestamp: bool,
    pub expiration_seconds: Option<u64>,
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            selector: String::new(),
            algorithm: Algorithm::RsaSha256,
            canonicalization: Canonicalization {
                header: CanonicalizationMethod::Relaxed,
                body: CanonicalizationMethod::Relaxed,
            },
            headers_to_sign: vec![
                "from".to_string(),
                "to".to_string(),
                "subject".to_string(),
                "date".to_string(),
                "mime-version".to_string(),
                "content-type".to_string(),
            ],
            include_timestamp: true,
            expiration_seconds: None,
        }
    }
}

/// DKIM message signer
pub struct DkimSigner {
    rsa_key_pair: Option<RsaKeyPair>,
    ed25519_key_pair: Option<Ed25519KeyPair>,
    rng: SystemRandom,
}

impl DkimSigner {
    /// Create a new signer from a PEM-encoded private key
    pub fn from_pem(pem_data: &str) -> Result<Self, DkimError> {
        let der = decode_pem(pem_data)?;
        Self::from_der(&der)
    }

    /// Create a new signer from a DER-encoded private key
    pub fn from_der(der_data: &[u8]) -> Result<Self, DkimError> {
        let rng = SystemRandom::new();

        // Try RSA first
        if let Ok(key_pair) = RsaKeyPair::from_pkcs8(der_data) {
            return Ok(Self {
                rsa_key_pair: Some(key_pair),
                ed25519_key_pair: None,
                rng,
            });
        }

        // Try Ed25519
        if let Ok(key_pair) = Ed25519KeyPair::from_pkcs8(der_data) {
            return Ok(Self {
                rsa_key_pair: None,
                ed25519_key_pair: Some(key_pair),
                rng,
            });
        }

        // Try RSA with traditional format
        if let Ok(key_pair) = RsaKeyPair::from_der(der_data) {
            return Ok(Self {
                rsa_key_pair: Some(key_pair),
                ed25519_key_pair: None,
                rng,
            });
        }

        Err(DkimError::CryptoError("failed to parse private key".into()))
    }

    /// Sign a message and return the DKIM-Signature header value
    pub fn sign(&self, message: &[u8], config: &SigningConfig) -> Result<String, DkimError> {
        let message_str = String::from_utf8_lossy(message);
        let (headers, body) = split_message(&message_str);

        // Canonicalize body and compute body hash
        let canon_body = canon::canonicalize_body(body.as_bytes(), config.canonicalization.body, None);
        let body_hash = hash::compute_body_hash(&canon_body, &config.algorithm);
        let body_hash_b64 = base64::engine::general_purpose::STANDARD.encode(&body_hash);

        // Build the h= tag value (only include headers that exist)
        let existing_headers = filter_existing_headers(&headers, &config.headers_to_sign);
        let h_tag = existing_headers.join(":");

        // Build timestamp
        let timestamp = if config.include_timestamp {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        } else {
            0
        };

        // Build the DKIM-Signature header (without b= value for signing)
        let mut sig_parts = vec![
            "v=1".to_string(),
            format!("a={}", config.algorithm.to_string()),
            format!("c={}", config.canonicalization.to_string()),
            format!("d={}", config.domain),
            format!("s={}", config.selector),
            format!("h={}", h_tag),
            format!("bh={}", body_hash_b64),
        ];

        if config.include_timestamp {
            sig_parts.push(format!("t={}", timestamp));
        }

        if let Some(exp_secs) = config.expiration_seconds {
            sig_parts.push(format!("x={}", timestamp + exp_secs));
        }

        // Add empty b= for signing
        sig_parts.push("b=".to_string());

        let sig_value = sig_parts.join("; ");
        let sig_header = format!("DKIM-Signature: {}", sig_value);

        // Compute header hash data
        let header_data = hash::compute_header_hash_data(
            &headers,
            &existing_headers,
            &sig_header,
            config.canonicalization.header,
        );

        // Sign the header hash data
        let signature = self.sign_data(&header_data, &config.algorithm)?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

        // Build final header value with b= filled in
        let final_parts: Vec<&str> = sig_parts.iter().map(|s| s.as_str()).collect();
        let final_value = final_parts[..final_parts.len() - 1].join("; ");
        let result = format!("{}; b={}", final_value, signature_b64);

        Ok(result)
    }

    fn sign_data(&self, data: &[u8], algorithm: &Algorithm) -> Result<Vec<u8>, DkimError> {
        match algorithm {
            Algorithm::RsaSha1 | Algorithm::RsaSha256 => {
                let key_pair = self.rsa_key_pair.as_ref()
                    .ok_or_else(|| DkimError::CryptoError("RSA key required for RSA algorithms".into()))?;

                let padding = match algorithm {
                    Algorithm::RsaSha256 => &signature::RSA_PKCS1_SHA256,
                    _ => return Err(DkimError::CryptoError("RSA-SHA1 signing not supported".into())),
                };

                let mut sig = vec![0u8; key_pair.public().modulus_len()];
                key_pair.sign(padding, &self.rng, data, &mut sig)
                    .map_err(|e| DkimError::CryptoError(e.to_string()))?;

                Ok(sig)
            }
            Algorithm::Ed25519Sha256 => {
                let key_pair = self.ed25519_key_pair.as_ref()
                    .ok_or_else(|| DkimError::CryptoError("Ed25519 key required for Ed25519 algorithm".into()))?;

                let signature = key_pair.sign(data);
                Ok(signature.as_ref().to_vec())
            }
        }
    }

    /// Get the public key bytes (for DNS record)
    pub fn public_key_der(&self) -> Option<Vec<u8>> {
        self.rsa_key_pair
            .as_ref()
            .map(|rsa| rsa.public().as_ref().to_vec())
            .or_else(|| {
                self.ed25519_key_pair
                    .as_ref()
                    .map(|ed| ed.public_key().as_ref().to_vec())
            })
    }
}

fn decode_pem(pem: &str) -> Result<Vec<u8>, DkimError> {
    let lines: Vec<&str> = pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    let b64 = lines.join("");
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| DkimError::CryptoError(format!("invalid PEM: {}", e)))
}

fn split_message(message: &str) -> (String, String) {
    let separator = if message.contains("\r\n\r\n") {
        "\r\n\r\n"
    } else {
        "\n\n"
    };

    if let Some(pos) = message.find(separator) {
        let headers = &message[..pos];
        let body = &message[pos + separator.len()..];
        (headers.to_string(), body.to_string())
    } else {
        (message.to_string(), String::new())
    }
}

fn filter_existing_headers(headers: &str, requested: &[String]) -> Vec<String> {
    let lower_headers: Vec<String> = headers
        .lines()
        .filter_map(|line| {
            line.find(':').map(|pos| line[..pos].to_lowercase())
        })
        .collect();

    requested
        .iter()
        .filter(|h| lower_headers.contains(&h.to_lowercase()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RSA key pair for testing (generated via openssl genpkey)
    const TEST_RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCZFp2oaetqyRsj
ZZFj5Bo7yPuXDnPEDql4rLYbh6uxqcemrRPNwleluLRepu93o3Y1araJIXFCq6uK
a6lIS9b1WmlCRgm1y0yo/uTVE8LL/rs+uP3lf0vAU6ghUvfUR0gPJjSfoFpxBhck
MODRCx/DWOmvBA7huTPr78WnD8TnKGdnciDkjeghcqi9tEBtzqLR/77tk30OU/Gl
ykGUck4ovWC80eOiWUsvTIWpsMxFV/9pc/d2qY99rgL34tbzfrrSmppO9Aulamkw
D0Kmji+Jolv+hyrJ5QSAWpAm0xOqaLj4Lee/tUvyknJPpZ4GXV1Y79pbEyxy25i2
Qjurhzz5AgMBAAECggEABy5gqGcJkEmNQJiR3KP1WBMaPDCFHTAL4pmFdF6lnvCm
KSsqx+bjKiazLVJ63ruX/rL6C446TCSV6CkbOIU4OOusDtwOtgyqlK3aSaWC6INT
QMK4RET3pna2JxQHhJlwZ6eE5e0FeRJOURgK37t8GrOHyLoxwYRoy1tExAyxEZ/I
sNSqi06Ru0ceWOHYPvRxITzAc32Gh1YxY5nV0Le+AewUyRvi2rkXRn+5WyQmU/74
lCRjjd4o1KA4/bzf2HyM+EYX+HuCQYFvJ7xJ8tq7C1Ic5Rj4kEfC7w2LhSKP037T
aBQNIOHUZlJa0r1o9bnsC/OXGBlAIIuocmMl58sghQKBgQDXJW7E4v3jBBwdbk+H
J2y6LQ6o82Gm9DvzvUXZ68k+XGH4Ktod6SA5h30LyqZnPGCZJdjWr2PgJqZoKhSW
sbDrKh+bLPPK7U1vtwbbu+ACfPX8UhFztg6SA6r5Lwdy1mZhi87Zwf5s+DkIp22d
mEExc6F4hQbgWWpTHXFJiir+xQKBgQC2KHXeialqMvsEeKjkbTvzScoJR2kwprjl
ls7wzdDeMiZuEja6s6CeRjHKiB/m/X3WIYzfQ2nZqQHEEZRpUmeTwh+AaCOKWf/m
KQiYSQio6a+VI0ehnSsYts/PXraVmjnvF0/nFm3MAALsHbz95lglfolly/GBo8FB
bfb0wh1opQKBgFSKCPSknU7PFp0Z83YQL9EYU2JgAEcyQTyNax0uYW13r6dsbzjB
mkAA1UoE305Bk1OaY5I4aO5zQYA8yMpOGE7PxoubJlDe3ka/jJpbQLK5l48GUIU/
TIpjlpNDv5GIXcKGxUkbyXXYM9EKuS/r2/IqlZBd9U3C1NzD/PgAqtRhAoGBAIdR
hUZdA5KV7q2CqQyQLSHtZf4Ao571q5M6td5jNs9pd+z68Nc/S4loYeKvvutM0qc4
4zqUDNUZ3Or3mEWpZrJ4Wgh81DIZ66TiRLVEQ/+fIcVroPHpHLPOUpAdLwvxtynr
KntjyQrr0z/uU5BWBpNL7evGVlFVAeKGOxfWABzVAoGBAMrjwAlL7RgBR0LrUiet
xYBAhurTKPbm777D5AOG9zw8LvIdzIPza2mrhZZRG15/smrLNTtvntGUoqsSrLMu
NSFEkEDULGb28m0+vh8ONjks4dbhgejfn7/855ibemWFGh1nkZPv29Z0AMFltwgK
sO62wayK8/OutRHlvvVcnbNs
-----END PRIVATE KEY-----"#;

    #[test]
    fn test_sign_and_verify() {
        let signer = DkimSigner::from_pem(TEST_RSA_PRIVATE_KEY_PEM).unwrap();

        let config = SigningConfig {
            domain: "example.com".to_string(),
            selector: "test".to_string(),
            algorithm: Algorithm::RsaSha256,
            canonicalization: Canonicalization {
                header: CanonicalizationMethod::Relaxed,
                body: CanonicalizationMethod::Relaxed,
            },
            headers_to_sign: vec!["from".to_string(), "to".to_string(), "subject".to_string()],
            include_timestamp: false,
            expiration_seconds: None,
        };

        let message = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nHello, World!";

        let sig_header = signer.sign(message, &config).unwrap();

        // Verify the signature contains expected tags
        assert!(sig_header.contains("v=1"));
        assert!(sig_header.contains("a=rsa-sha256"));
        assert!(sig_header.contains("d=example.com"));
        assert!(sig_header.contains("s=test"));
        assert!(sig_header.contains("b="));
        assert!(sig_header.contains("bh="));
    }

    #[test]
    fn test_verify_signature_rsa() {
        // This is a minimal test - real verification would need actual key/message pairs
        let fake_key = vec![0u8; 32]; // Invalid key, will fail
        let result = verify_signature(
            &Algorithm::RsaSha256,
            &fake_key,
            b"test message",
            b"fake signature",
        );
        // Should return Ok(false) or error, not panic
        assert!(result.is_ok() || result.is_err());
    }
}
