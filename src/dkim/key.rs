use base64::{engine::general_purpose::STANDARD, Engine};

use crate::dkim::signature::*;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFlag {
    Testing,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimPublicKey {
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub revoked: bool,
    pub hash_algorithms: Option<Vec<HashAlgorithm>>,
    pub service_types: Option<Vec<String>>,
    pub flags: Vec<KeyFlag>,
    pub notes: Option<String>,
}

// ---------------------------------------------------------------------------
// Tag=value parser (same format as signature, reused logic)
// ---------------------------------------------------------------------------

fn parse_tag_value_list(input: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for pair in input.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((tag, value)) = pair.split_once('=') {
            result.push((tag.trim().to_string(), value.trim().to_string()));
        }
    }
    result
}

fn permfail_malformed(detail: impl Into<String>) -> DkimResult {
    DkimResult::PermFail {
        kind: PermFailKind::MalformedSignature,
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------------------
// DkimPublicKey::parse
// ---------------------------------------------------------------------------

impl DkimPublicKey {
    /// Parse a DKIM key record from a TXT DNS response (RFC 6376 Section 3.6.1).
    pub fn parse(txt_record: &str) -> Result<DkimPublicKey, DkimResult> {
        let tags = parse_tag_value_list(txt_record);

        let find = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(t, _)| t == name)
                .map(|(_, v)| v.as_str())
        };

        // v= optional, but if present must be "DKIM1"
        if let Some(v) = find("v") {
            if v != "DKIM1" {
                return Err(permfail_malformed(format!(
                    "unsupported key version: {}",
                    v
                )));
            }
        }

        // k= key type (default "rsa")
        let key_type = match find("k").unwrap_or("rsa") {
            "rsa" => KeyType::Rsa,
            "ed25519" => KeyType::Ed25519,
            other => {
                return Err(permfail_malformed(format!("unknown key type: {}", other)));
            }
        };

        // p= required, base64 public key. Empty → revoked.
        let p_raw = find("p").ok_or_else(|| permfail_malformed("missing p= tag"))?;
        let (public_key, revoked) = if p_raw.is_empty() {
            (Vec::new(), true)
        } else {
            let cleaned: String = p_raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            let decoded = STANDARD.decode(&cleaned).map_err(|_| {
                permfail_malformed("invalid base64 in p= tag")
            })?;
            (decoded, false)
        };

        // h= optional, colon-separated hash algorithms
        let hash_algorithms = find("h").map(|h_raw| {
            h_raw
                .split(':')
                .filter_map(|s| match s.trim() {
                    "sha1" => Some(HashAlgorithm::Sha1),
                    "sha256" => Some(HashAlgorithm::Sha256),
                    _ => None,
                })
                .collect::<Vec<_>>()
        });

        // s= optional, colon-separated service types
        let service_types = find("s").map(|s_raw| {
            s_raw
                .split(':')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        });

        // t= optional, colon-separated flags
        let flags = if let Some(t_raw) = find("t") {
            t_raw
                .split(':')
                .filter_map(|s| match s.trim() {
                    "y" => Some(KeyFlag::Testing),
                    "s" => Some(KeyFlag::Strict),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };

        // n= optional notes (human-readable)
        let notes = find("n").map(|s| s.to_string());

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
}

// ---------------------------------------------------------------------------
// SPKI stripping for ring RSA compatibility
// ---------------------------------------------------------------------------

/// RSA OID: 1.2.840.113549.1.1.1
const RSA_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

/// Strip the SubjectPublicKeyInfo (SPKI) DER wrapper from an RSA public key,
/// returning the inner PKCS#1 RSAPublicKey bytes.
///
/// ring's RSA verification expects PKCS#1 format (raw RSA key), but DKIM DNS
/// records store keys in SPKI (SubjectPublicKeyInfo) DER format. This function
/// parses the ASN.1 structure:
///
/// ```text
/// SEQUENCE {                    -- SubjectPublicKeyInfo
///   SEQUENCE {                  -- AlgorithmIdentifier
///     OID 1.2.840.113549.1.1.1  -- rsaEncryption
///     NULL                      -- parameters
///   }
///   BIT STRING {                -- subjectPublicKey
///     <PKCS#1 RSAPublicKey>
///   }
/// }
/// ```
///
/// If the input does not appear to be SPKI-wrapped (no RSA OID found), it is
/// returned as-is under the assumption it is already PKCS#1.
pub fn strip_spki_wrapper(key_bytes: &[u8]) -> Vec<u8> {
    // Quick check: does the blob contain the RSA OID?
    if !contains_slice(key_bytes, RSA_OID) {
        return key_bytes.to_vec();
    }

    // Try to parse the SPKI structure.
    match parse_spki(key_bytes) {
        Some(inner) => inner,
        None => key_bytes.to_vec(),
    }
}

/// Parse DER length. Returns (length_value, bytes_consumed).
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0] as usize;
    if first < 0x80 {
        // Short form
        Some((first, 1))
    } else if first == 0x80 {
        // Indefinite length — not valid in DER
        None
    } else {
        // Long form: first byte indicates number of length bytes
        let num_bytes = first & 0x7f;
        if num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = length.checked_shl(8)?;
            length = length.checked_add(data[1 + i] as usize)?;
        }
        Some((length, 1 + num_bytes))
    }
}

/// Attempt to parse SPKI DER and extract the inner PKCS#1 key bytes.
fn parse_spki(data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;

    // Outer SEQUENCE tag
    if data.get(pos)? != &0x30 {
        return None;
    }
    pos += 1;
    let (_, len_size) = parse_der_length(&data[pos..])?;
    pos += len_size;

    // Inner SEQUENCE (AlgorithmIdentifier)
    if data.get(pos)? != &0x30 {
        return None;
    }
    pos += 1;
    let (algo_len, algo_len_size) = parse_der_length(&data[pos..])?;
    pos += algo_len_size;

    // Verify RSA OID is inside the AlgorithmIdentifier
    let algo_bytes = data.get(pos..pos + algo_len)?;
    if !contains_slice(algo_bytes, RSA_OID) {
        return None;
    }
    pos += algo_len;

    // BIT STRING tag
    if data.get(pos)? != &0x03 {
        return None;
    }
    pos += 1;
    let (bitstring_len, bs_len_size) = parse_der_length(&data[pos..])?;
    pos += bs_len_size;

    // First byte of BIT STRING is unused-bits count (must be 0 for keys)
    if data.get(pos)? != &0x00 {
        return None;
    }
    pos += 1;

    // Remaining bytes are the PKCS#1 RSAPublicKey
    let inner_len = bitstring_len.checked_sub(1)?;
    let inner = data.get(pos..pos + inner_len)?;
    Some(inner.to_vec())
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_key() {
        let key_data = STANDARD.encode(b"fake-rsa-key");
        let record = format!("p={}", key_data);
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.public_key, b"fake-rsa-key");
        assert!(!key.revoked);
        assert!(key.hash_algorithms.is_none());
        assert!(key.service_types.is_none());
        assert!(key.flags.is_empty());
        assert!(key.notes.is_none());
    }

    #[test]
    fn parse_full_key() {
        let key_data = STANDARD.encode(b"rsa-key-bytes");
        let record = format!(
            "v=DKIM1; k=rsa; p={}; h=sha256; s=email:*; t=y:s; n=test key",
            key_data
        );
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.public_key, b"rsa-key-bytes");
        assert!(!key.revoked);
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha256])
        );
        assert_eq!(
            key.service_types,
            Some(vec!["email".to_string(), "*".to_string()])
        );
        assert_eq!(key.flags, vec![KeyFlag::Testing, KeyFlag::Strict]);
        assert_eq!(key.notes, Some("test key".to_string()));
    }

    #[test]
    fn parse_revoked_key() {
        let record = "v=DKIM1; p=";
        let key = DkimPublicKey::parse(record).unwrap();
        assert!(key.revoked);
        assert!(key.public_key.is_empty());
    }

    #[test]
    fn parse_h_tag() {
        let key_data = STANDARD.encode(b"k");
        let record = format!("p={}; h=sha1:sha256", key_data);
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256])
        );
    }

    #[test]
    fn parse_s_tag() {
        let key_data = STANDARD.encode(b"k");
        let record = format!("p={}; s=email", key_data);
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(
            key.service_types,
            Some(vec!["email".to_string()])
        );
    }

    #[test]
    fn parse_t_flags() {
        let key_data = STANDARD.encode(b"k");
        let record = format!("p={}; t=y", key_data);
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.flags, vec![KeyFlag::Testing]);

        let record = format!("p={}; t=s", key_data);
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.flags, vec![KeyFlag::Strict]);
    }

    #[test]
    fn unknown_tags_ignored() {
        let key_data = STANDARD.encode(b"k");
        let record = format!("p={}; x=unknown; foo=bar", key_data);
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.public_key, b"k");
    }

    #[test]
    fn parse_ed25519_key() {
        // Ed25519 public key is 32 bytes
        let key_bytes = [0xABu8; 32];
        let key_data = STANDARD.encode(&key_bytes);
        let record = format!("v=DKIM1; k=ed25519; p={}", key_data);
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
        assert_eq!(key.public_key.len(), 32);
        assert_eq!(key.public_key, key_bytes.to_vec());
    }

    #[test]
    fn invalid_version() {
        let key_data = STANDARD.encode(b"k");
        let record = format!("v=DKIM2; p={}", key_data);
        let err = DkimPublicKey::parse(&record).unwrap_err();
        assert!(matches!(
            err,
            DkimResult::PermFail {
                kind: PermFailKind::MalformedSignature,
                ..
            }
        ));
    }

    #[test]
    fn missing_p_tag() {
        let record = "v=DKIM1; k=rsa";
        let err = DkimPublicKey::parse(record).unwrap_err();
        assert!(matches!(
            err,
            DkimResult::PermFail {
                kind: PermFailKind::MalformedSignature,
                ..
            }
        ));
    }

    #[test]
    fn strip_spki_rsa_wrapper() {
        // Build a minimal SPKI-wrapped RSA key for testing.
        // Inner PKCS#1 key (fake, just some bytes for testing)
        let pkcs1_key = b"\x30\x0d\x02\x01\x00\x02\x08\xff\xff\xff\xff\xff\xff\xff\xff";

        // AlgorithmIdentifier: SEQUENCE { OID rsaEncryption, NULL }
        let algo_oid = &RSA_OID[2..]; // Skip the 0x06 0x09 tag+length from constant
        let mut algo_id = Vec::new();
        // OID tag + length + value
        algo_id.push(0x06);
        algo_id.push(algo_oid.len() as u8);
        algo_id.extend_from_slice(algo_oid);
        // NULL
        algo_id.push(0x05);
        algo_id.push(0x00);

        // Wrap AlgorithmIdentifier in SEQUENCE
        let mut algo_seq = Vec::new();
        algo_seq.push(0x30);
        algo_seq.push(algo_id.len() as u8);
        algo_seq.extend_from_slice(&algo_id);

        // BIT STRING: 0x03 + length + 0x00 (unused bits) + pkcs1_key
        let mut bitstring = Vec::new();
        bitstring.push(0x03);
        bitstring.push((pkcs1_key.len() + 1) as u8); // +1 for unused-bits byte
        bitstring.push(0x00); // unused bits
        bitstring.extend_from_slice(pkcs1_key);

        // Outer SEQUENCE
        let inner_len = algo_seq.len() + bitstring.len();
        let mut spki = Vec::new();
        spki.push(0x30);
        spki.push(inner_len as u8);
        spki.extend_from_slice(&algo_seq);
        spki.extend_from_slice(&bitstring);

        let result = strip_spki_wrapper(&spki);
        assert_eq!(result, pkcs1_key);
    }

    #[test]
    fn strip_spki_passthrough_non_spki() {
        // Already PKCS#1 (no SPKI wrapper) — should be returned as-is
        let pkcs1 = b"\x30\x0d\x02\x01\x00";
        let result = strip_spki_wrapper(pkcs1);
        assert_eq!(result, pkcs1.to_vec());
    }
}
