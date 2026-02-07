use super::signature::parse_tags;
use base64::Engine;

/// DKIM public key record from DNS TXT.
#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub revoked: bool,
    pub hash_algorithms: Option<Vec<HashAlgorithm>>,
    pub service_types: Option<Vec<String>>,
    pub flags: Vec<KeyFlag>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyFlag {
    Testing,
    Strict,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyParseError {
    MissingPublicKey,
    InvalidBase64(String),
    InvalidSyntax(String),
}

impl std::fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPublicKey => write!(f, "missing p= tag"),
            Self::InvalidBase64(s) => write!(f, "invalid base64: {s}"),
            Self::InvalidSyntax(s) => write!(f, "invalid syntax: {s}"),
        }
    }
}

impl DkimPublicKey {
    pub fn parse(txt_record: &str) -> Result<Self, KeyParseError> {
        let tags = parse_tags(txt_record)
            .map_err(|e| KeyParseError::InvalidSyntax(e.to_string()))?;

        let get = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        // v= optional, but if present must be "DKIM1"
        if let Some(v) = get("v") {
            if v.trim() != "DKIM1" {
                return Err(KeyParseError::InvalidSyntax(format!(
                    "invalid version: {v}"
                )));
            }
        }

        // k= key type (default rsa)
        let key_type = match get("k").unwrap_or("rsa").trim().to_ascii_lowercase().as_str() {
            "rsa" => KeyType::Rsa,
            "ed25519" => KeyType::Ed25519,
            other => {
                return Err(KeyParseError::InvalidSyntax(format!(
                    "unknown key type: {other}"
                )))
            }
        };

        // p= public key (required)
        let p_str = get("p").ok_or(KeyParseError::MissingPublicKey)?;
        let p_trimmed = p_str.trim();
        let revoked = p_trimmed.is_empty();
        let public_key = if revoked {
            Vec::new()
        } else {
            let cleaned: String = p_trimmed.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .map_err(|e| KeyParseError::InvalidBase64(e.to_string()))?;
            // For RSA: strip SPKI wrapper if present, ring needs PKCS#1
            if key_type == KeyType::Rsa {
                strip_rsa_spki(&raw)
            } else {
                raw
            }
        };

        // h= hash algorithms
        let hash_algorithms = get("h").map(|s| {
            s.split(':')
                .filter_map(|h| match h.trim().to_ascii_lowercase().as_str() {
                    "sha1" => Some(HashAlgorithm::Sha1),
                    "sha256" => Some(HashAlgorithm::Sha256),
                    _ => None,
                })
                .collect()
        });

        // s= service types
        let service_types = get("s").map(|s| {
            s.split(':')
                .map(|t| t.trim().to_string())
                .collect()
        });

        // t= flags
        let flags = get("t")
            .map(|s| {
                s.split(':')
                    .filter_map(|f| match f.trim() {
                        "y" => Some(KeyFlag::Testing),
                        "s" => Some(KeyFlag::Strict),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let notes = get("n").map(|s| s.to_string());

        Ok(DkimPublicKey {
            key_type,
            public_key,
            revoked,
            hash_algorithms,
            service_types,
            flags,
            notes,
        })
    }

    pub fn is_testing(&self) -> bool {
        self.flags.contains(&KeyFlag::Testing)
    }

    pub fn is_strict(&self) -> bool {
        self.flags.contains(&KeyFlag::Strict)
    }

    pub fn allows_hash(&self, alg: super::Algorithm) -> bool {
        let Some(ref hashes) = self.hash_algorithms else {
            return true; // no restriction
        };
        let needed = match alg {
            super::Algorithm::RsaSha1 => HashAlgorithm::Sha1,
            super::Algorithm::RsaSha256 | super::Algorithm::Ed25519Sha256 => HashAlgorithm::Sha256,
        };
        hashes.contains(&needed)
    }

    pub fn allows_email(&self) -> bool {
        let Some(ref services) = self.service_types else {
            return true; // default "*"
        };
        services.iter().any(|s| s == "*" || s == "email")
    }
}

/// Strip SubjectPublicKeyInfo (SPKI) wrapper from RSA key to get PKCS#1 RSAPublicKey.
/// ring expects PKCS#1 format for RSA verification.
fn strip_rsa_spki(der: &[u8]) -> Vec<u8> {
    // SPKI structure: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { RSAPublicKey } }
    // RSA OID: 1.2.840.113549.1.1.1 → bytes 06 09 2a 86 48 86 f7 0d 01 01 01
    let rsa_oid: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    // Check if this looks like SPKI (contains RSA OID)
    if let Some(_) = find_subsequence(der, rsa_oid) {
        // Parse ASN.1 to extract the BIT STRING contents
        if let Some(pkcs1) = extract_pkcs1_from_spki(der) {
            return pkcs1;
        }
    }

    // Already PKCS#1 or unknown format — return as-is
    der.to_vec()
}

fn extract_pkcs1_from_spki(der: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    // Outer SEQUENCE
    if *der.get(pos)? != 0x30 {
        return None;
    }
    pos += 1;
    let (_, new_pos) = read_asn1_length(der, pos)?;
    pos = new_pos;

    // Inner SEQUENCE (AlgorithmIdentifier)
    if *der.get(pos)? != 0x30 {
        return None;
    }
    pos += 1;
    let (inner_len, new_pos) = read_asn1_length(der, pos)?;
    pos = new_pos + inner_len; // skip AlgorithmIdentifier

    // BIT STRING
    if *der.get(pos)? != 0x03 {
        return None;
    }
    pos += 1;
    let (bit_len, new_pos) = read_asn1_length(der, pos)?;
    pos = new_pos;

    // Skip unused-bits byte (should be 0x00)
    if *der.get(pos)? != 0x00 {
        return None;
    }
    pos += 1;

    // Rest is PKCS#1 RSAPublicKey
    let end = pos + bit_len - 1;
    if end > der.len() {
        return None;
    }
    Some(der[pos..end].to_vec())
}

fn read_asn1_length(der: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *der.get(pos)?;
    if first < 0x80 {
        Some((first as usize, pos + 1))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (*der.get(pos + 1 + i)? as usize);
        }
        Some((length, pos + 1 + num_bytes))
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_key() {
        let key = DkimPublicKey::parse("p=dGVzdA==").unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.revoked);
    }

    #[test]
    fn test_full_key() {
        let key = DkimPublicKey::parse(
            "v=DKIM1; k=rsa; h=sha256; s=email; t=y:s; n=test key; p=dGVzdA==",
        )
        .unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(key.is_testing());
        assert!(key.is_strict());
        assert!(key.allows_email());
        assert_eq!(key.notes.as_deref(), Some("test key"));
    }

    #[test]
    fn test_revoked_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; p=").unwrap();
        assert!(key.revoked);
    }

    #[test]
    fn test_sha256_only() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; h=sha256; p=dGVzdA==").unwrap();
        assert!(key.allows_hash(super::super::Algorithm::RsaSha256));
        assert!(!key.allows_hash(super::super::Algorithm::RsaSha1));
    }

    #[test]
    fn test_ed25519_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=ed25519; p=dGVzdA==").unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_service_types() {
        let key = DkimPublicKey::parse("v=DKIM1; s=other; p=dGVzdA==").unwrap();
        assert!(!key.allows_email());

        let key2 = DkimPublicKey::parse("v=DKIM1; s=email; p=dGVzdA==").unwrap();
        assert!(key2.allows_email());
    }

    #[test]
    fn test_spki_stripping() {
        // Real 2048-bit RSA SPKI key from fixture
        let b64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArUg0luedcbMuBW0FPq+t96pkNP5ZQweGKvwSb8jNSvpvtRF5DZe3v6iXW9+C0wRxvhALD77DaQ9Bl4o8G+Mib3dPsv05iQw05r5g+BVziu5Fg7xx+BvEUlsM24niyZcHNHRvvina0OcCTWxtFTLO+hiVOxJt2GouO0GQ4ZGhgCzqC/ehJWnIksE2g43AEqBtIYznkdS0avsu/IUaIY5WfyMCVcn4SCIaNDAa/U/43h6OrIiIarS8JvOZs25J+avkj2DeVCapdiWzPSwZPFAopIxj+EX/a/6tiVOOVBEeQvSr1ZI7Ncsp8XSbgK8hb48nxdHcfPg16ux2ACzFafGMJwIDAQAB";
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let pkcs1 = strip_rsa_spki(&raw);
        // Should be shorter (SPKI header stripped)
        assert!(pkcs1.len() < raw.len());
        // Should start with SEQUENCE tag (PKCS#1 RSAPublicKey)
        assert_eq!(pkcs1[0], 0x30);
    }
}
