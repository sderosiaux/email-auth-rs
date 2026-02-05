use ring::signature::{self, UnparsedPublicKey, ED25519};
use thiserror::Error;

use super::key::{DkimPublicKey, KeyType};
use super::signature::Algorithm;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("algorithm mismatch")]
    AlgorithmMismatch,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
}

/// Verify DKIM signature
pub fn verify_signature(
    algorithm: Algorithm,
    public_key: &DkimPublicKey,
    hash: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    // Check algorithm compatibility
    match (algorithm, public_key.key_type) {
        (Algorithm::RsaSha1, KeyType::Rsa) => verify_rsa_sha1(&public_key.public_key, hash, signature),
        (Algorithm::RsaSha256, KeyType::Rsa) => verify_rsa_sha256(&public_key.public_key, hash, signature),
        (Algorithm::Ed25519Sha256, KeyType::Ed25519) => verify_ed25519(&public_key.public_key, hash, signature),
        _ => Err(CryptoError::AlgorithmMismatch),
    }
}

fn verify_rsa_sha1(public_key_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let public_key = UnparsedPublicKey::new(
        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        public_key_der,
    );

    public_key
        .verify(message, signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

fn verify_rsa_sha256(public_key_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let public_key = UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        public_key_der,
    );

    public_key
        .verify(message, signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

fn verify_ed25519(public_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);

    public_key
        .verify(message, signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Real crypto tests require actual key pairs
    // These tests just verify the API works

    #[test]
    fn test_algorithm_mismatch() {
        let key = DkimPublicKey {
            version: None,
            hash_algorithms: None,
            key_type: KeyType::Rsa,
            notes: None,
            public_key: vec![0u8; 32], // Dummy
            service_types: vec!["*".to_string()],
            flags: vec![],
        };

        // Ed25519 algorithm with RSA key should fail
        let result = verify_signature(
            Algorithm::Ed25519Sha256,
            &key,
            b"hash",
            b"signature",
        );

        assert!(matches!(result, Err(CryptoError::AlgorithmMismatch)));
    }
}
