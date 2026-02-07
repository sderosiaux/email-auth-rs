use std::collections::HashSet;
use std::fmt;

use base64::Engine;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// DKIM key type (RFC 6376 Section 3.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

impl KeyType {
    fn parse(s: &str) -> Result<Self, KeyParseError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rsa" => Ok(Self::Rsa),
            "ed25519" => Ok(Self::Ed25519),
            other => Err(KeyParseError(format!("unknown key type: {other}"))),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa => write!(f, "rsa"),
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}

/// Acceptable hash algorithm for DKIM key (RFC 6376 Section 3.6.1, h= tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            _ => None, // Unknown algorithms are ignored per RFC
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha256 => write!(f, "sha256"),
        }
    }
}

/// DKIM key flags (RFC 6376 Section 3.6.1, t= tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFlag {
    /// y: this domain is testing DKIM
    Testing,
    /// s: i= domain must exactly match d= (no subdomains)
    Strict,
}

impl KeyFlag {
    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "y" => Some(Self::Testing),
            "s" => Some(Self::Strict),
            _ => None, // Unknown flags are ignored per RFC
        }
    }
}

impl fmt::Display for KeyFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Testing => write!(f, "y"),
            Self::Strict => write!(f, "s"),
        }
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Parse error for DKIM key records.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("DKIM key parse error: {0}")]
pub struct KeyParseError(pub String);

// ---------------------------------------------------------------------------
// DkimPublicKey
// ---------------------------------------------------------------------------

/// Parsed DKIM public key record from DNS TXT (RFC 6376 Section 3.6.1).
///
/// Retrieved from `<selector>._domainkey.<domain>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimPublicKey {
    /// Version (if present, must be "DKIM1").
    pub version: Option<String>,
    /// Key type. Default: Rsa.
    pub key_type: KeyType,
    /// Public key data (decoded from base64). Empty Vec means revoked.
    pub public_key: Vec<u8>,
    /// Whether this key has been revoked (p= was empty).
    pub revoked: bool,
    /// Acceptable hash algorithms (h= tag, colon-separated). None = all accepted.
    pub hash_algorithms: Option<Vec<HashAlgorithm>>,
    /// Service types (s= tag, colon-separated). Default: ["*"].
    pub service_types: Vec<String>,
    /// Key flags (t= tag).
    pub flags: Vec<KeyFlag>,
    /// Human-readable notes (n= tag). Stored but not used for logic.
    pub notes: Option<String>,
}

impl DkimPublicKey {
    /// Parse a DKIM public key from a DNS TXT record value.
    ///
    /// When multiple TXT strings are returned, they should be concatenated
    /// before calling this function.
    pub fn parse(txt_record: &str) -> Result<Self, KeyParseError> {
        let tags = parse_tag_value_list(txt_record)?;

        // v= optional, but must be "DKIM1" if present
        let version = if let Some(v) = tags.get("v") {
            let v = v.trim().to_string();
            if v != "DKIM1" {
                return Err(KeyParseError(format!(
                    "invalid key version: {v} (expected DKIM1)"
                )));
            }
            Some(v)
        } else {
            None
        };

        // k= key type, default "rsa"
        let key_type = if let Some(k) = tags.get("k") {
            KeyType::parse(k)?
        } else {
            KeyType::Rsa
        };

        // p= public key, required
        let p_val = tags
            .get("p")
            .ok_or_else(|| KeyParseError("missing required tag: p".into()))?;
        let p_trimmed = p_val.trim();
        let revoked = p_trimmed.is_empty();
        let public_key = if revoked {
            Vec::new()
        } else {
            decode_base64(p_trimmed)?
        };

        // h= acceptable hash algorithms (colon-separated)
        let hash_algorithms = tags.get("h").map(|v| {
            v.split(':')
                .filter_map(|s| HashAlgorithm::parse(s))
                .collect()
        });

        // s= service types (colon-separated), default "*"
        let service_types = if let Some(s) = tags.get("s") {
            s.split(':')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        } else {
            vec!["*".to_string()]
        };

        // t= flags (colon-separated)
        let flags = if let Some(t) = tags.get("t") {
            t.split(':')
                .filter_map(|v| KeyFlag::parse(v))
                .collect()
        } else {
            Vec::new()
        };

        // n= notes
        let notes = tags.get("n").map(|v| v.trim().to_string());

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

    /// Check if this key is in testing mode (t=y).
    pub fn is_testing(&self) -> bool {
        self.flags.contains(&KeyFlag::Testing)
    }

    /// Check if strict mode is enabled (t=s), meaning i= must exactly match d=.
    pub fn is_strict(&self) -> bool {
        self.flags.contains(&KeyFlag::Strict)
    }

    /// Check if email service is acceptable.
    pub fn accepts_email(&self) -> bool {
        self.service_types.iter().any(|s| s == "*" || s == "email")
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type TagMap = std::collections::HashMap<String, String>;

/// Parse `tag=value` list separated by semicolons with duplicate detection.
fn parse_tag_value_list(input: &str) -> Result<TagMap, KeyParseError> {
    let mut tags = TagMap::new();
    let mut seen = HashSet::new();

    for pair in input.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (tag, value) = pair
            .split_once('=')
            .ok_or_else(|| KeyParseError(format!("malformed tag=value: {pair}")))?;
        let tag = tag.trim().to_ascii_lowercase();
        let value = value.trim().to_string();

        if !seen.insert(tag.clone()) {
            return Err(KeyParseError(format!("duplicate tag: {tag}")));
        }
        tags.insert(tag, value);
    }
    Ok(tags)
}

/// Decode base64 with embedded whitespace stripped.
fn decode_base64(input: &str) -> Result<Vec<u8>, KeyParseError> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| KeyParseError(format!("invalid base64: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    #[test]
    fn parse_minimal_rsa_key() {
        let p = encode(b"fake-rsa-key");
        let record = format!("p={p}");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.public_key, b"fake-rsa-key");
        assert!(!key.revoked);
        assert!(key.hash_algorithms.is_none());
        assert_eq!(key.service_types, vec!["*"]);
        assert!(key.flags.is_empty());
        assert!(key.notes.is_none());
        assert!(key.version.is_none());
    }

    #[test]
    fn parse_full_key_record() {
        let p = encode(b"keydata");
        let record = format!("v=DKIM1; k=rsa; p={p}; h=sha256; s=email; t=y:s; n=test key");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.version, Some("DKIM1".into()));
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.public_key, b"keydata");
        assert!(!key.revoked);
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha256])
        );
        assert_eq!(key.service_types, vec!["email"]);
        assert!(key.is_testing());
        assert!(key.is_strict());
        assert_eq!(key.notes, Some("test key".into()));
    }

    #[test]
    fn revoked_key_empty_p() {
        let record = "v=DKIM1; p=";
        let key = DkimPublicKey::parse(record).unwrap();
        assert!(key.revoked);
        assert!(key.public_key.is_empty());
    }

    #[test]
    fn missing_p_tag_error() {
        let record = "v=DKIM1; k=rsa";
        let err = DkimPublicKey::parse(record).unwrap_err();
        assert!(err.0.contains("missing required tag: p"), "{err}");
    }

    #[test]
    fn invalid_version_error() {
        let p = encode(b"key");
        let record = format!("v=DKIM2; p={p}");
        let err = DkimPublicKey::parse(&record).unwrap_err();
        assert!(err.0.contains("invalid key version"), "{err}");
    }

    #[test]
    fn version_dkim1_accepted() {
        let p = encode(b"key");
        let record = format!("v=DKIM1; p={p}");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.version, Some("DKIM1".into()));
    }

    #[test]
    fn ed25519_key_type() {
        let p = encode(b"ed-key");
        let record = format!("k=ed25519; p={p}");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    #[test]
    fn unknown_key_type_error() {
        let p = encode(b"key");
        let record = format!("k=dsa; p={p}");
        let err = DkimPublicKey::parse(&record).unwrap_err();
        assert!(err.0.contains("unknown key type: dsa"), "{err}");
    }

    #[test]
    fn hash_algorithms_multiple() {
        let p = encode(b"key");
        let record = format!("p={p}; h=sha1:sha256");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(
            key.hash_algorithms,
            Some(vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256])
        );
    }

    #[test]
    fn service_types_multiple() {
        let p = encode(b"key");
        let record = format!("p={p}; s=email:*");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.service_types, vec!["email", "*"]);
    }

    #[test]
    fn service_types_default_star() {
        let p = encode(b"key");
        let record = format!("p={p}");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.service_types, vec!["*"]);
    }

    #[test]
    fn flags_testing_only() {
        let p = encode(b"key");
        let record = format!("p={p}; t=y");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert!(key.is_testing());
        assert!(!key.is_strict());
    }

    #[test]
    fn flags_strict_only() {
        let p = encode(b"key");
        let record = format!("p={p}; t=s");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert!(!key.is_testing());
        assert!(key.is_strict());
    }

    #[test]
    fn flags_both() {
        let p = encode(b"key");
        let record = format!("p={p}; t=y:s");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert!(key.is_testing());
        assert!(key.is_strict());
    }

    #[test]
    fn flags_unknown_ignored() {
        let p = encode(b"key");
        let record = format!("p={p}; t=y:x:s:z");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.flags.len(), 2);
        assert!(key.is_testing());
        assert!(key.is_strict());
    }

    #[test]
    fn accepts_email_star() {
        let p = encode(b"key");
        let key = DkimPublicKey::parse(&format!("p={p}")).unwrap();
        assert!(key.accepts_email());
    }

    #[test]
    fn accepts_email_explicit() {
        let p = encode(b"key");
        let key = DkimPublicKey::parse(&format!("p={p}; s=email")).unwrap();
        assert!(key.accepts_email());
    }

    #[test]
    fn rejects_non_email_service() {
        let p = encode(b"key");
        let key = DkimPublicKey::parse(&format!("p={p}; s=other")).unwrap();
        assert!(!key.accepts_email());
    }

    #[test]
    fn duplicate_tag_error() {
        let p = encode(b"key");
        let record = format!("p={p}; k=rsa; k=ed25519");
        let err = DkimPublicKey::parse(&record).unwrap_err();
        assert!(err.0.contains("duplicate tag: k"), "{err}");
    }

    #[test]
    fn unknown_tags_ignored() {
        let p = encode(b"key");
        let record = format!("p={p}; foo=bar; unknown=value");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.public_key, b"key");
    }

    #[test]
    fn whitespace_tolerance() {
        let p = encode(b"key");
        let record = format!("  p = {p} ;  k = rsa  ");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
    }

    #[test]
    fn trailing_semicolon_ok() {
        let p = encode(b"key");
        let record = format!("p={p};");
        assert!(DkimPublicKey::parse(&record).is_ok());
    }

    #[test]
    fn key_type_default_rsa() {
        let p = encode(b"key");
        let record = format!("p={p}");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
    }

    #[test]
    fn display_key_type() {
        assert_eq!(KeyType::Rsa.to_string(), "rsa");
        assert_eq!(KeyType::Ed25519.to_string(), "ed25519");
    }

    #[test]
    fn display_key_flag() {
        assert_eq!(KeyFlag::Testing.to_string(), "y");
        assert_eq!(KeyFlag::Strict.to_string(), "s");
    }

    #[test]
    fn notes_stored() {
        let p = encode(b"key");
        let record = format!("p={p}; n=this is a note");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.notes, Some("this is a note".into()));
    }

    #[test]
    fn base64_with_whitespace_in_key() {
        let raw = base64::engine::general_purpose::STANDARD.encode(b"keydata");
        // Insert spaces into the base64 string
        let spaced = format!("{} {}", &raw[..4], &raw[4..]);
        let record = format!("p={spaced}");
        let key = DkimPublicKey::parse(&record).unwrap();
        assert_eq!(key.public_key, b"keydata");
    }

    #[test]
    fn malformed_tag_value_error() {
        let err = DkimPublicKey::parse("no_equals_here").unwrap_err();
        assert!(err.0.contains("malformed tag=value"), "{err}");
    }

    #[test]
    fn hash_algorithms_none_when_absent() {
        let p = encode(b"key");
        let key = DkimPublicKey::parse(&format!("p={p}")).unwrap();
        assert!(key.hash_algorithms.is_none());
    }
}
