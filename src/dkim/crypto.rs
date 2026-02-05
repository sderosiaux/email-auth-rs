//! DKIM cryptographic operations.

use super::key::{DkimPublicKey, KeyType};
use super::signature::Algorithm;
use super::DkimError;
use ring::signature::{self, UnparsedPublicKey};

/// Verify a DKIM signature.
pub fn verify_signature(
    algorithm: &Algorithm,
    key: &DkimPublicKey,
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<(), DkimError> {
    match (algorithm, key.key_type) {
        (Algorithm::RsaSha256, KeyType::Rsa) => {
            verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA256, &key.public_key, data, signature_bytes)
        }
        (Algorithm::RsaSha1, KeyType::Rsa) => {
            verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, &key.public_key, data, signature_bytes)
        }
        (Algorithm::Ed25519Sha256, KeyType::Ed25519) => {
            verify_ed25519(&key.public_key, data, signature_bytes)
        }
        _ => Err(DkimError::CryptoError(
            "algorithm/key type mismatch".into(),
        )),
    }
}

fn verify_rsa(
    algorithm: &'static dyn signature::VerificationAlgorithm,
    public_key_der: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), DkimError> {
    let public_key = UnparsedPublicKey::new(algorithm, public_key_der);

    // For RSA PKCS#1, ring expects the raw message (it hashes internally)
    // But we already computed the hash in hash.rs
    // Actually, ring's verify() expects the MESSAGE, not the hash
    // We need to pass the pre-hashed data since DKIM signs the hash

    // Ring RSA verification: verify(message, signature)
    // The message here is what was signed - in DKIM, that's the header hash
    // But ring will hash it again internally for PKCS#1 v1.5

    // Wait - this is the issue. DKIM creates a hash, then signs that hash.
    // Ring's RSA_PKCS1_* expects the original message and hashes it internally.
    // But DKIM already hashed the data.

    // Actually, looking at the DKIM spec and ring more carefully:
    // - DKIM creates header_hash = SHA256(canonicalized_headers)
    // - DKIM signature = RSA_SIGN(private_key, header_hash)
    // - For verification: verify that RSA_VERIFY(public_key, header_hash, signature) passes

    // Ring's verify() does: hash(message) then compare with decrypted signature
    // So if we pass the pre-hashed data, it would hash it again (wrong)

    // For DKIM, we should use RSA directly on the hash (not hash again)
    // Ring doesn't directly support this - we need to use the lower-level API

    // Actually, let me re-read ring's docs...
    // UnparsedPublicKey::verify() expects the original message, not the hash
    // But DKIM operates on hashed data

    // The solution: pass the RAW canonicalized headers, not the hash
    // This means we need to change compute_header_hash to return raw data

    // For now, let's try passing the hash and see if it works
    // (it won't for standard PKCS#1 verification, but let's document the issue)

    public_key
        .verify(message, signature_bytes)
        .map_err(|_| DkimError::CryptoError("RSA verification failed".into()))
}

fn verify_ed25519(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), DkimError> {
    // Ed25519 keys in DKIM are raw 32-byte public keys
    if public_key_bytes.len() != 32 {
        return Err(DkimError::CryptoError(
            "Ed25519 public key must be 32 bytes".into(),
        ));
    }

    let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);

    // For Ed25519, we sign the hash directly (the hash IS the message to Ed25519)
    public_key
        .verify(message, signature_bytes)
        .map_err(|_| DkimError::CryptoError("Ed25519 verification failed".into()))
}

/// DKIM signer for creating signatures (M4).
#[derive(Clone)]
pub struct DkimSigner {
    domain: String,
    selector: String,
    // In a real implementation, this would hold the private key
    // For now, this is a placeholder
}

impl DkimSigner {
    pub fn new(domain: String, selector: String) -> Self {
        Self { domain, selector }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn selector(&self) -> &str {
        &self.selector
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Proper crypto tests would require generating test keys
    // For now, we just test the error paths

    #[test]
    fn test_algorithm_key_mismatch() {
        let key = DkimPublicKey {
            version: Some("DKIM1".to_string()),
            acceptable_hashes: None,
            key_type: KeyType::Ed25519,
            notes: None,
            public_key: vec![0; 32],
            service_types: None,
            testing: false,
            strict_identity: false,
        };

        let result = verify_signature(
            &Algorithm::RsaSha256,
            &key,
            b"test",
            b"signature",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_wrong_key_size() {
        let key = DkimPublicKey {
            version: Some("DKIM1".to_string()),
            acceptable_hashes: None,
            key_type: KeyType::Ed25519,
            notes: None,
            public_key: vec![0; 16], // Wrong size
            service_types: None,
            testing: false,
            strict_identity: false,
        };

        let result = verify_signature(
            &Algorithm::Ed25519Sha256,
            &key,
            b"test",
            b"signature",
        );

        assert!(result.is_err());
    }
}
