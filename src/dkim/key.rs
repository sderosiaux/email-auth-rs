//! DKIM DNS public key record parsing

use base64::Engine;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyParseError {
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
    #[error("invalid key type: {0}")]
    InvalidKeyType(String),
    #[error("key revoked (empty p=)")]
    KeyRevoked,
    #[error("missing public key")]
    MissingKey,
}

/// Key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    #[default]
    Rsa,
    Ed25519,
}

/// Key flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFlag {
    Testing,    // y - testing mode
    SameDomain, // s - i= must exactly match d=
}

/// Parsed DKIM public key from DNS
#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    pub version: Option<String>,
    pub acceptable_hashes: Option<Vec<String>>,
    pub key_type: KeyType,
    pub notes: Option<String>,
    pub public_key: Vec<u8>,
    pub service_types: Option<Vec<String>>,
    pub flags: Vec<KeyFlag>,
}

impl DkimPublicKey {
    pub fn parse(txt_record: &str) -> Result<Self, KeyParseError> {
        let mut version = None;
        let mut acceptable_hashes = None;
        let mut key_type = KeyType::default();
        let mut notes = None;
        let mut public_key = None;
        let mut service_types = None;
        let mut flags = Vec::new();

        // Parse tag=value pairs
        for part in txt_record.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let eq_pos = match part.find('=') {
                Some(p) => p,
                None => continue,
            };

            let tag = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim();

            match tag.as_str() {
                "v" => version = Some(value.to_string()),
                "h" => {
                    acceptable_hashes = Some(
                        value
                            .split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "k" => {
                    key_type = match value.to_lowercase().as_str() {
                        "rsa" => KeyType::Rsa,
                        "ed25519" => KeyType::Ed25519,
                        other => return Err(KeyParseError::InvalidKeyType(other.to_string())),
                    };
                }
                "n" => notes = Some(value.to_string()),
                "p" => {
                    if value.is_empty() {
                        return Err(KeyParseError::KeyRevoked);
                    }
                    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                    public_key = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&cleaned)
                            .map_err(|e| KeyParseError::InvalidBase64(e.to_string()))?,
                    );
                }
                "s" => {
                    service_types = Some(
                        value
                            .split(':')
                            .map(|s| s.trim().to_string())
                            .collect(),
                    );
                }
                "t" => {
                    for flag in value.split(':') {
                        match flag.trim().to_lowercase().as_str() {
                            "y" => flags.push(KeyFlag::Testing),
                            "s" => flags.push(KeyFlag::SameDomain),
                            _ => {} // Unknown flags ignored
                        }
                    }
                }
                _ => {} // Unknown tags ignored
            }
        }

        let public_key = public_key.ok_or(KeyParseError::MissingKey)?;

        Ok(DkimPublicKey {
            version,
            acceptable_hashes,
            key_type,
            notes,
            public_key,
            service_types,
            flags,
        })
    }

    /// Check if this key accepts the given hash algorithm
    pub fn accepts_hash(&self, hash: &str) -> bool {
        match &self.acceptable_hashes {
            Some(hashes) => hashes.iter().any(|h| h == hash),
            None => true, // No restriction = accept all
        }
    }

    /// Check if key is in testing mode
    pub fn is_testing(&self) -> bool {
        self.flags.contains(&KeyFlag::Testing)
    }

    /// Check if strict domain matching is required
    pub fn requires_same_domain(&self) -> bool {
        self.flags.contains(&KeyFlag::SameDomain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let key = DkimPublicKey::parse("p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1").unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.public_key.is_empty());
    }

    #[test]
    fn test_parse_with_version() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1").unwrap();
        assert_eq!(key.version, Some("DKIM1".to_string()));
        assert_eq!(key.key_type, KeyType::Rsa);
    }

    #[test]
    fn test_parse_ed25519() {
        let key = DkimPublicKey::parse("v=DKIM1; k=ed25519; p=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=").unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_revoked_key() {
        let result = DkimPublicKey::parse("v=DKIM1; p=");
        assert!(matches!(result, Err(KeyParseError::KeyRevoked)));
    }

    #[test]
    fn test_hash_restriction() {
        let key = DkimPublicKey::parse("h=sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1").unwrap();
        assert!(key.accepts_hash("sha256"));
        assert!(!key.accepts_hash("sha1"));
    }

    #[test]
    fn test_flags() {
        let key = DkimPublicKey::parse("t=y:s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1").unwrap();
        assert!(key.is_testing());
        assert!(key.requires_same_domain());
    }
}
