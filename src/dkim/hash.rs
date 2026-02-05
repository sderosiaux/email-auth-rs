//! DKIM hash computation

use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use super::signature::Algorithm;

/// Compute body hash
pub fn compute_body_hash(body: &[u8], algorithm: Algorithm) -> Vec<u8> {
    match algorithm {
        Algorithm::RsaSha1 => {
            let digest = ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, body);
            digest.as_ref().to_vec()
        }
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            let digest = ring::digest::digest(&SHA256, body);
            digest.as_ref().to_vec()
        }
    }
}

/// Compute header hash for signing/verification
pub fn compute_header_hash(data: &[u8], algorithm: Algorithm) -> Vec<u8> {
    match algorithm {
        Algorithm::RsaSha1 => {
            let digest = ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, data);
            digest.as_ref().to_vec()
        }
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            let digest = ring::digest::digest(&SHA256, data);
            digest.as_ref().to_vec()
        }
    }
}

/// Create incremental hash context
pub fn create_hash_context(algorithm: Algorithm) -> HashContext {
    match algorithm {
        Algorithm::RsaSha1 => HashContext::Sha1(Context::new(&SHA1_FOR_LEGACY_USE_ONLY)),
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            HashContext::Sha256(Context::new(&SHA256))
        }
    }
}

pub enum HashContext {
    Sha1(Context),
    Sha256(Context),
}

impl HashContext {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            HashContext::Sha1(ctx) => ctx.update(data),
            HashContext::Sha256(ctx) => ctx.update(data),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        match self {
            HashContext::Sha1(ctx) => ctx.finish().as_ref().to_vec(),
            HashContext::Sha256(ctx) => ctx.finish().as_ref().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_body_hash_sha256() {
        // Empty body with CRLF
        let hash = compute_body_hash(b"\r\n", Algorithm::RsaSha256);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&hash);
        // Known hash of CRLF
        assert_eq!(b64, "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=");
    }

    #[test]
    fn test_body_hash_sha1() {
        let hash = compute_body_hash(b"\r\n", Algorithm::RsaSha1);
        assert_eq!(hash.len(), 20); // SHA-1 is 160 bits = 20 bytes
    }
}
