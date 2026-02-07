use base64::Engine;
use super::{HashAlgorithm, KeyFlag, KeyType};

/// Parsed DKIM DNS public key record.
#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    pub version: Option<String>,
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub revoked: bool,
    pub hash_algorithms: Option<Vec<HashAlgorithm>>,
    pub service_types: Vec<String>,
    pub flags: Vec<KeyFlag>,
    pub notes: Option<String>,
}

impl DkimPublicKey {
    /// Parse a DKIM DNS TXT record (concatenated strings).
    pub fn parse(txt: &str) -> Result<Self, String> {
        let tags = parse_tags(txt);

        // Check for duplicate tags
        {
            let mut seen = std::collections::HashSet::new();
            for (name, _) in &tags {
                if !seen.insert(name.as_str()) {
                    return Err(format!("duplicate key tag: {}", name));
                }
            }
        }

        let get = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        // v= optional, if present must be "DKIM1"
        let version = get("v").map(|v| {
            let v = v.trim();
            if !v.eq_ignore_ascii_case("DKIM1") {
                return Err(format!("invalid key version: {}", v));
            }
            Ok(v.to_string())
        }).transpose()?;

        // k= key type, default "rsa"
        let key_type = if let Some(k) = get("k") {
            match k.trim().to_ascii_lowercase().as_str() {
                "rsa" => KeyType::Rsa,
                "ed25519" => KeyType::Ed25519,
                _ => return Err(format!("unknown key type: {}", k)),
            }
        } else {
            KeyType::Rsa
        };

        // p= public key (required)
        let p_value = get("p").ok_or("missing p= tag")?;
        let p_clean: String = p_value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let revoked = p_clean.is_empty();
        let public_key = if revoked {
            Vec::new()
        } else {
            let der = base64::engine::general_purpose::STANDARD
                .decode(&p_clean)
                .map_err(|e| format!("invalid p= base64: {}", e))?;
            // For RSA keys, DKIM p= contains SubjectPublicKeyInfo (SPKI) DER.
            // ring expects raw PKCS#1 RSAPublicKey bytes, so strip the SPKI wrapper.
            if key_type == KeyType::Rsa {
                strip_rsa_spki(&der).unwrap_or(der)
            } else {
                der
            }
        };

        // h= hash algorithms (optional)
        let hash_algorithms = get("h").map(|v| {
            v.split(':')
                .filter_map(|h| match h.trim().to_ascii_lowercase().as_str() {
                    "sha1" => Some(HashAlgorithm::Sha1),
                    "sha256" => Some(HashAlgorithm::Sha256),
                    _ => None, // Unknown hash algorithms ignored
                })
                .collect::<Vec<_>>()
        });

        // s= service types (default "*")
        let service_types = if let Some(s) = get("s") {
            s.split(':').map(|t| t.trim().to_string()).collect()
        } else {
            vec!["*".to_string()]
        };

        // t= flags
        let flags = if let Some(t) = get("t") {
            t.split(':')
                .filter_map(|f| match f.trim() {
                    "y" => Some(KeyFlag::Testing),
                    "s" => Some(KeyFlag::Strict),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };

        let notes = get("n").map(|v| v.trim().to_string());

        Ok(DkimPublicKey {
            version,
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

/// Strip SubjectPublicKeyInfo (SPKI) wrapper from an RSA public key DER,
/// returning the inner PKCS#1 RSAPublicKey bytes that ring expects.
///
/// SPKI structure:
///   SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { RSAPublicKey } }
///
/// If the input doesn't look like SPKI, returns None (caller should use as-is).
fn strip_rsa_spki(der: &[u8]) -> Option<Vec<u8>> {
    // RSA SPKI prefix: SEQUENCE > SEQUENCE > OID 1.2.840.113549.1.1.1 > NULL > BIT STRING
    // The OID for rsaEncryption is: 06 09 2a 86 48 86 f7 0d 01 01 01
    let rsa_oid: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    // Must start with SEQUENCE tag (0x30)
    if der.first() != Some(&0x30) {
        return None;
    }

    // Check if it contains the RSA OID — if not, it's probably already PKCS#1
    if !der.windows(rsa_oid.len()).any(|w| w == rsa_oid) {
        return None;
    }

    // Parse outer SEQUENCE
    let (_, rest) = parse_asn1_tag_len(der)?;

    // Parse inner SEQUENCE (AlgorithmIdentifier)
    if rest.first() != Some(&0x30) {
        return None;
    }
    let (algo_len, algo_rest) = parse_asn1_tag_len(rest)?;
    let after_algo = &algo_rest[algo_len..];

    // After AlgorithmIdentifier comes BIT STRING (tag 0x03)
    if after_algo.first() != Some(&0x03) {
        return None;
    }
    let (bs_len, bs_content) = parse_asn1_tag_len(after_algo)?;

    // BIT STRING first byte is number of unused bits (should be 0 for keys)
    if bs_content.is_empty() || bs_content[0] != 0 {
        return None;
    }

    // The rest is the RSAPublicKey DER
    Some(bs_content[1..bs_len].to_vec())
}

/// Parse ASN.1 tag + length, returning (content_length, content_start_slice).
fn parse_asn1_tag_len(data: &[u8]) -> Option<(usize, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let _tag = data[0];
    let (len, offset) = if data[1] & 0x80 == 0 {
        (data[1] as usize, 2)
    } else {
        let num_bytes = (data[1] & 0x7f) as usize;
        if data.len() < 2 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[2 + i] as usize;
        }
        (len, 2 + num_bytes)
    };
    Some((len, &data[offset..]))
}

fn parse_tags(s: &str) -> Vec<(String, String)> {
    let mut tags = Vec::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(eq) = part.find('=') {
            let name = part[..eq].trim().to_string();
            let value = part[eq + 1..].trim().to_string();
            tags.push((name, value));
        }
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let key = DkimPublicKey::parse("p=dGVzdA==").unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.revoked);
        assert_eq!(key.public_key, b"test");
    }

    #[test]
    fn test_parse_full() {
        let key = DkimPublicKey::parse(
            "v=DKIM1; k=rsa; h=sha256; s=email; t=y:s; p=dGVzdA==; n=test key",
        )
        .unwrap();
        assert_eq!(key.version, Some("DKIM1".to_string()));
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.hash_algorithms, Some(vec![HashAlgorithm::Sha256]));
        assert_eq!(key.service_types, vec!["email".to_string()]);
        assert!(key.flags.contains(&KeyFlag::Testing));
        assert!(key.flags.contains(&KeyFlag::Strict));
        assert_eq!(key.notes, Some("test key".to_string()));
    }

    #[test]
    fn test_revoked_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; p=").unwrap();
        assert!(key.revoked);
        assert!(key.public_key.is_empty());
    }

    #[test]
    fn test_ed25519_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=ed25519; p=dGVzdA==").unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_service_types() {
        let key = DkimPublicKey::parse("p=dGVzdA==; s=email:other").unwrap();
        assert_eq!(key.service_types, vec!["email", "other"]);
    }

    #[test]
    fn test_default_service_type() {
        let key = DkimPublicKey::parse("p=dGVzdA==").unwrap();
        assert_eq!(key.service_types, vec!["*"]);
    }

    #[test]
    fn test_hash_algorithm_constraint() {
        let key = DkimPublicKey::parse("p=dGVzdA==; h=sha256").unwrap();
        assert_eq!(key.hash_algorithms, Some(vec![HashAlgorithm::Sha256]));
    }
}
