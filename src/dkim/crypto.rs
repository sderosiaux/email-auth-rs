use ring::signature::{self, UnparsedPublicKey};

use super::key::KeyType;
use super::signature::Algorithm;

/// Verify a DKIM signature
pub fn verify_signature(
    message: &[u8],
    signature_bytes: &[u8],
    public_key: &[u8],
    algorithm: Algorithm,
    key_type: KeyType,
) -> Result<bool, String> {
    match (algorithm, key_type) {
        (Algorithm::RsaSha256, KeyType::Rsa) => {
            verify_rsa_sha256(message, signature_bytes, public_key)
        }
        (Algorithm::RsaSha1, KeyType::Rsa) => {
            // Note: ring doesn't directly support RSA-SHA1 verification
            // For now, we'll return an error. In production, you'd use a different crate.
            Err("RSA-SHA1 not supported".to_string())
        }
        (Algorithm::Ed25519Sha256, KeyType::Ed25519) => {
            verify_ed25519(message, signature_bytes, public_key)
        }
        _ => Err(format!(
            "algorithm {:?} not compatible with key type {:?}",
            algorithm, key_type
        )),
    }
}

fn verify_rsa_sha256(message: &[u8], signature: &[u8], public_key_der: &[u8]) -> Result<bool, String> {
    // ring expects the public key in SubjectPublicKeyInfo DER format
    let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key_der);

    match public_key.verify(message, signature) {
        Ok(()) => Ok(true),
        Err(_) => {
            // Try with smaller key sizes (1024-bit keys are still common in the wild)
            let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, public_key_der);
            match public_key.verify(message, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }
}

fn verify_ed25519(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String> {
    // Ed25519 public keys are raw 32 bytes
    if public_key.len() != 32 {
        return Err(format!("Ed25519 key must be 32 bytes, got {}", public_key.len()));
    }

    let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key);

    match public_key.verify(message, signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    // Note: Proper crypto tests require real test keys
    // These are placeholder tests

    #[test]
    fn test_algorithm_key_mismatch() {
        use super::*;

        let result = verify_signature(
            b"test",
            b"sig",
            b"key",
            Algorithm::Ed25519Sha256,
            KeyType::Rsa,
        );

        assert!(result.is_err());
    }
}
