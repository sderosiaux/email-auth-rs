use super::signature::Algorithm;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};

/// Verify a DKIM signature
pub fn verify_signature(
    algorithm: &Algorithm,
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    match algorithm {
        Algorithm::RsaSha1 => {
            verify_rsa(
                public_key_der,
                message,
                signature,
                &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            )
        }
        Algorithm::RsaSha256 => {
            verify_rsa(
                public_key_der,
                message,
                signature,
                &signature::RSA_PKCS1_2048_8192_SHA256,
            )
            .or_else(|_| {
                verify_rsa(
                    public_key_der,
                    message,
                    signature,
                    &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                )
            })
        }
        Algorithm::Ed25519Sha256 => verify_ed25519(public_key_der, message, signature),
    }
}

fn verify_rsa(
    public_key_der: &[u8],
    message: &[u8],
    sig: &[u8],
    params: &'static dyn VerificationAlgorithm,
) -> Result<bool, String> {
    let public_key = UnparsedPublicKey::new(params, public_key_der);

    match public_key.verify(message, sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn verify_ed25519(public_key_raw: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, String> {
    // Ed25519 public keys in DKIM are raw 32-byte keys
    if public_key_raw.len() != 32 {
        return Err(format!(
            "invalid Ed25519 public key length: {}",
            public_key_raw.len()
        ));
    }

    let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key_raw);

    match public_key.verify(message, sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_invalid_ed25519_key_length() {
        let result = super::verify_ed25519(&[0u8; 16], b"message", &[0u8; 64]);
        assert!(result.is_err());
    }
}
