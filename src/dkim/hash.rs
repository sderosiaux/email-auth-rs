use ring::digest::{self, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use super::signature::{Algorithm, DkimSignature};
use super::canon;

pub fn compute_body_hash(canonicalized_body: &str, algorithm: Algorithm, length_limit: Option<usize>) -> Vec<u8> {
    let body_bytes = canonicalized_body.as_bytes();

    let bytes_to_hash = match length_limit {
        Some(len) if len < body_bytes.len() => &body_bytes[..len],
        _ => body_bytes,
    };

    match algorithm {
        Algorithm::RsaSha1 => {
            digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, bytes_to_hash).as_ref().to_vec()
        }
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            digest::digest(&SHA256, bytes_to_hash).as_ref().to_vec()
        }
    }
}

pub fn compute_header_hash(headers: &str, sig: &DkimSignature) -> Vec<u8> {
    let canonicalized = canon::canonicalize_headers_for_signing(headers, sig);

    match sig.algorithm {
        Algorithm::RsaSha1 => {
            digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, canonicalized.as_bytes()).as_ref().to_vec()
        }
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            digest::digest(&SHA256, canonicalized.as_bytes()).as_ref().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_body_hash_sha256() {
        let body = "test\r\n";
        let hash = compute_body_hash(body, Algorithm::RsaSha256, None);
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn test_body_hash_with_length_limit() {
        let body = "hello world\r\n";
        let hash_full = compute_body_hash(body, Algorithm::RsaSha256, None);
        let hash_limited = compute_body_hash(body, Algorithm::RsaSha256, Some(5));
        assert_ne!(hash_full, hash_limited);
    }
}
