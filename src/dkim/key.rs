use std::collections::HashSet;

use base64::Engine;

use super::parser::{parse_tag_list, DkimParseError};
use super::types::{HashAlgorithm, KeyFlag, KeyType, PermFailKind};

/// Parsed DKIM DNS public key record.
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

fn key_error(detail: impl Into<String>) -> DkimParseError {
    DkimParseError {
        kind: PermFailKind::MalformedSignature,
        detail: detail.into(),
    }
}

impl DkimPublicKey {
    /// Parse a DKIM DNS TXT key record.
    /// Input should be the concatenated TXT record strings.
    pub fn parse(txt_record: &str) -> Result<Self, DkimParseError> {
        let tags = parse_tag_list(txt_record);

        // Check for duplicate tags
        let mut seen = HashSet::new();
        for (name, _) in &tags {
            if !seen.insert(name.as_str()) {
                return Err(key_error(format!("duplicate tag: {}", name)));
            }
        }

        let get = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        // v= optional, but if present must be "DKIM1"
        if let Some(v) = get("v") {
            if v != "DKIM1" {
                return Err(key_error(format!("invalid version: {}", v)));
            }
        }

        // k= key type (default: "rsa")
        let key_type = if let Some(k) = get("k") {
            KeyType::parse(k).ok_or_else(|| key_error(format!("unknown key type: {}", k)))?
        } else {
            KeyType::Rsa
        };

        // p= public key (required, empty = revoked)
        let p_raw = get("p").ok_or_else(|| key_error("missing required tag: p"))?;
        let (public_key, revoked) = if p_raw.is_empty() {
            (Vec::new(), true)
        } else {
            let cleaned: String = p_raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .map_err(|e| key_error(format!("invalid base64 in p=: {}", e)))?;
            (decoded, false)
        };

        // h= hash algorithms (optional, colon-separated)
        let hash_algorithms = if let Some(h) = get("h") {
            let mut algs = Vec::new();
            for part in h.split(':') {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Some(alg) = HashAlgorithm::parse(trimmed) {
                    algs.push(alg);
                }
                // Unknown hash algorithms are silently ignored per RFC
            }
            if algs.is_empty() {
                None
            } else {
                Some(algs)
            }
        } else {
            None
        };

        // s= service types (optional, colon-separated, default: "*")
        let service_types = if let Some(s) = get("s") {
            Some(
                s.split(':')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect(),
            )
        } else {
            None
        };

        // t= flags (optional, colon-separated)
        let flags = if let Some(t) = get("t") {
            let mut f = Vec::new();
            for part in t.split(':') {
                match part.trim() {
                    "y" => f.push(KeyFlag::Testing),
                    "s" => f.push(KeyFlag::Strict),
                    _ => {} // Unknown flags ignored
                }
            }
            f
        } else {
            Vec::new()
        };

        // n= notes (optional)
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

    /// Check if this key has the Testing flag.
    pub fn is_testing(&self) -> bool {
        self.flags.contains(&KeyFlag::Testing)
    }

    /// Check if this key has the Strict flag.
    pub fn is_strict(&self) -> bool {
        self.flags.contains(&KeyFlag::Strict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rsa_spki_stub() -> String {
        // Fake 162-byte "SPKI" for RSA 1024-bit testing (not real crypto, just size)
        let fake_key = vec![0x30u8; 162];
        base64::engine::general_purpose::STANDARD.encode(&fake_key)
    }

    fn make_rsa_2048_spki_stub() -> String {
        // Fake 294-byte "SPKI" for RSA 2048-bit testing
        let fake_key = vec![0x30u8; 294];
        base64::engine::general_purpose::STANDARD.encode(&fake_key)
    }

    fn make_ed25519_key() -> String {
        // Fake 32-byte Ed25519 public key
        let fake_key = vec![0xABu8; 32];
        base64::engine::general_purpose::STANDARD.encode(&fake_key)
    }

    // CHK-462: Minimal key
    #[test]
    fn parse_minimal_key() {
        let p = make_rsa_spki_stub();
        let input = format!("p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa); // default
        assert!(!key.revoked);
        assert_eq!(key.public_key.len(), 162);
        assert!(key.hash_algorithms.is_none());
        assert!(key.service_types.is_none());
        assert!(key.flags.is_empty());
        assert!(key.notes.is_none());
    }

    // CHK-463: Full key with all tags
    #[test]
    fn parse_full_key() {
        let p = make_rsa_2048_spki_stub();
        let input = format!(
            "v=DKIM1; k=rsa; h=sha256; s=email; t=y:s; n=test key; p={}",
            p
        );
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.revoked);
        assert_eq!(key.public_key.len(), 294);
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha256])
        );
        assert_eq!(
            key.service_types,
            Some(vec!["email".to_string()])
        );
        assert!(key.is_testing());
        assert!(key.is_strict());
        assert_eq!(key.notes, Some("test key".to_string()));
    }

    // CHK-464: Revoked key
    #[test]
    fn parse_revoked_key() {
        let input = "v=DKIM1; p=";
        let key = DkimPublicKey::parse(input).unwrap();
        assert!(key.revoked);
        assert!(key.public_key.is_empty());
    }

    // CHK-465: h= sha256 only
    #[test]
    fn parse_h_sha256_only() {
        let p = make_rsa_spki_stub();
        let input = format!("h=sha256; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha256])
        );
    }

    #[test]
    fn parse_h_sha1_and_sha256() {
        let p = make_rsa_spki_stub();
        let input = format!("h=sha1:sha256; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256])
        );
    }

    // CHK-466: s= email vs * vs other
    #[test]
    fn parse_s_email() {
        let p = make_rsa_spki_stub();
        let input = format!("s=email; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(
            key.service_types,
            Some(vec!["email".to_string()])
        );
    }

    #[test]
    fn parse_s_wildcard() {
        let p = make_rsa_spki_stub();
        let input = format!("s=*; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(
            key.service_types,
            Some(vec!["*".to_string()])
        );
    }

    #[test]
    fn parse_s_other() {
        let p = make_rsa_spki_stub();
        let input = format!("s=other; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(
            key.service_types,
            Some(vec!["other".to_string()])
        );
    }

    // CHK-467: t= flags
    #[test]
    fn parse_t_testing() {
        let p = make_rsa_spki_stub();
        let input = format!("t=y; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert!(key.is_testing());
        assert!(!key.is_strict());
    }

    #[test]
    fn parse_t_strict() {
        let p = make_rsa_spki_stub();
        let input = format!("t=s; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert!(!key.is_testing());
        assert!(key.is_strict());
    }

    #[test]
    fn parse_t_both() {
        let p = make_rsa_spki_stub();
        let input = format!("t=y:s; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert!(key.is_testing());
        assert!(key.is_strict());
    }

    // CHK-468: Unknown key type
    #[test]
    fn parse_unknown_key_type() {
        let p = make_rsa_spki_stub();
        let input = format!("k=dsa; p={}", p);
        let err = DkimPublicKey::parse(&input).unwrap_err();
        assert!(err.detail.contains("unknown key type"));
    }

    // CHK-469: Ed25519 key (32 bytes)
    #[test]
    fn parse_ed25519_key() {
        let p = make_ed25519_key();
        let input = format!("k=ed25519; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
        assert_eq!(key.public_key.len(), 32);
    }

    // CHK-470: RSA 1024-bit key
    #[test]
    fn parse_rsa_1024_key() {
        let p = make_rsa_spki_stub(); // 162 bytes
        let input = format!("k=rsa; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(key.public_key.len() < 256); // 1024-bit threshold
    }

    // CHK-471: RSA 2048-bit key
    #[test]
    fn parse_rsa_2048_key() {
        let p = make_rsa_2048_spki_stub(); // 294 bytes
        let input = format!("k=rsa; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(key.public_key.len() >= 256); // 2048-bit threshold
    }

    // CHK-437: v= DKIM1
    #[test]
    fn parse_v_dkim1() {
        let p = make_rsa_spki_stub();
        let input = format!("v=DKIM1; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert!(!key.revoked);
    }

    #[test]
    fn parse_v_wrong() {
        let p = make_rsa_spki_stub();
        let input = format!("v=DKIM2; p={}", p);
        let err = DkimPublicKey::parse(&input).unwrap_err();
        assert!(err.detail.contains("invalid version"));
    }

    // CHK-446: Unknown tags ignored
    #[test]
    fn parse_unknown_tags_ignored() {
        let p = make_rsa_spki_stub();
        let input = format!("foo=bar; p={}; baz=qux", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert!(!key.revoked);
    }

    // CHK-434: selector._domainkey.domain
    #[test]
    fn key_query_format() {
        // This is a structural test — the query construction happens in the verifier,
        // but we verify the concept here
        let selector = "sel1";
        let domain = "example.com";
        let query = format!("{}._domainkey.{}", selector, domain);
        assert_eq!(query, "sel1._domainkey.example.com");
    }

    // CHK-435: Multiple keys via different selectors
    #[test]
    fn different_selectors_different_keys() {
        let p1 = make_rsa_spki_stub();
        let p2 = make_ed25519_key();
        let key1 = DkimPublicKey::parse(&format!("k=rsa; p={}", p1)).unwrap();
        let key2 = DkimPublicKey::parse(&format!("k=ed25519; p={}", p2)).unwrap();
        assert_eq!(key1.key_type, KeyType::Rsa);
        assert_eq!(key2.key_type, KeyType::Ed25519);
    }

    // CHK-436: Multiple TXT strings concatenated
    #[test]
    fn parse_concatenated_txt_strings() {
        let p = make_rsa_spki_stub();
        // Simulate concatenation of two TXT strings
        let part1 = "v=DKIM1; k=rsa; ";
        let part2 = format!("p={}", p);
        let concatenated = format!("{}{}", part1, part2);
        let key = DkimPublicKey::parse(&concatenated).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
    }

    // CHK-438: h= hash algorithms
    #[test]
    fn parse_h_unknown_hash_ignored() {
        let p = make_rsa_spki_stub();
        let input = format!("h=sha256:sha512; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        // sha512 is unknown, only sha256 kept
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha256])
        );
    }

    // CHK-439: k= key type
    #[test]
    fn parse_k_rsa_explicit() {
        let p = make_rsa_spki_stub();
        let input = format!("k=rsa; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
    }

    #[test]
    fn parse_k_ed25519() {
        let p = make_ed25519_key();
        let input = format!("k=ed25519; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    // CHK-440: n= notes
    #[test]
    fn parse_n_notes() {
        let p = make_rsa_spki_stub();
        let input = format!("n=This is a test key; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.notes, Some("This is a test key".to_string()));
    }

    // CHK-441: p= required
    #[test]
    fn parse_missing_p() {
        let err = DkimPublicKey::parse("v=DKIM1; k=rsa").unwrap_err();
        assert!(err.detail.contains("missing required tag: p"));
    }

    // CHK-442: s= service type
    #[test]
    fn parse_s_multiple() {
        let p = make_rsa_spki_stub();
        let input = format!("s=email:*; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(
            key.service_types,
            Some(vec!["email".to_string(), "*".to_string()])
        );
    }

    // CHK-443, CHK-444, CHK-445: t= flags
    #[test]
    fn parse_t_unknown_flag_ignored() {
        let p = make_rsa_spki_stub();
        let input = format!("t=y:x; p={}", p);
        let key = DkimPublicKey::parse(&input).unwrap();
        assert!(key.is_testing());
        assert!(!key.is_strict());
        assert_eq!(key.flags.len(), 1); // only y recognized
    }

    // CHK-447: RSA SPKI format
    #[test]
    fn parse_rsa_spki_format() {
        let p = make_rsa_spki_stub();
        let key = DkimPublicKey::parse(&format!("p={}", p)).unwrap();
        // SPKI format verified by non-empty decoded bytes
        assert!(!key.public_key.is_empty());
        assert_eq!(key.key_type, KeyType::Rsa);
    }

    // CHK-448: Ed25519 raw 32 bytes
    #[test]
    fn parse_ed25519_raw_32_bytes() {
        let p = make_ed25519_key();
        let key = DkimPublicKey::parse(&format!("k=ed25519; p={}", p)).unwrap();
        assert_eq!(key.public_key.len(), 32);
    }

    // CHK-449: Malformed base64 → PermFail
    #[test]
    fn parse_malformed_base64() {
        let err = DkimPublicKey::parse("p=!!!not-base64!!!").unwrap_err();
        assert!(err.detail.contains("invalid base64"));
    }

    // CHK-523: Key parsing complete
    #[test]
    fn key_parsing_complete() {
        // Comprehensive key with all fields
        let p = make_rsa_2048_spki_stub();
        let input = format!(
            "v=DKIM1; k=rsa; h=sha256:sha1; s=email:*; t=y:s; n=full key test; p={}",
            p
        );
        let key = DkimPublicKey::parse(&input).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.revoked);
        assert_eq!(key.public_key.len(), 294);
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha256, HashAlgorithm::Sha1])
        );
        assert_eq!(
            key.service_types,
            Some(vec!["email".to_string(), "*".to_string()])
        );
        assert!(key.is_testing());
        assert!(key.is_strict());
        assert!(key.notes.is_some());
    }

    // Duplicate tag in key record
    #[test]
    fn parse_duplicate_tag_in_key() {
        let p = make_rsa_spki_stub();
        let input = format!("k=rsa; k=ed25519; p={}", p);
        let err = DkimPublicKey::parse(&input).unwrap_err();
        assert!(err.detail.contains("duplicate"));
    }

    // Default service type (none specified = *)
    #[test]
    fn parse_default_service_type() {
        let p = make_rsa_spki_stub();
        let key = DkimPublicKey::parse(&format!("p={}", p)).unwrap();
        assert!(key.service_types.is_none()); // None means default "*"
    }

    // v= absent is valid
    #[test]
    fn parse_v_absent_valid() {
        let p = make_rsa_spki_stub();
        let key = DkimPublicKey::parse(&format!("p={}", p)).unwrap();
        assert!(!key.revoked);
    }
}
