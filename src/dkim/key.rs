//! DKIM public key record parsing.

use super::DkimError;
use base64::Engine;

/// Key type in DKIM public key record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    #[default]
    Rsa,
    Ed25519,
}

/// Parsed DKIM public key from DNS.
#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    pub version: Option<String>,
    pub acceptable_hashes: Option<Vec<String>>,
    pub key_type: KeyType,
    pub notes: Option<String>,
    pub public_key: Vec<u8>,
    pub service_types: Option<Vec<String>>,
    pub testing: bool,
    pub strict_identity: bool,
}

impl DkimPublicKey {
    /// Parse a DKIM public key DNS TXT record.
    pub fn parse(txt: &str) -> Result<Self, DkimError> {
        let mut version = None;
        let mut acceptable_hashes = None;
        let mut key_type = KeyType::Rsa;
        let mut notes = None;
        let mut public_key = None;
        let mut service_types = None;
        let mut testing = false;
        let mut strict_identity = false;

        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = match part.split_once('=') {
                Some((t, v)) => (t.trim(), v.trim()),
                None => continue,
            };

            match tag.to_lowercase().as_str() {
                "v" => {
                    version = Some(val.to_string());
                }
                "h" => {
                    acceptable_hashes = Some(
                        val.split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "k" => {
                    key_type = match val.to_lowercase().as_str() {
                        "rsa" => KeyType::Rsa,
                        "ed25519" => KeyType::Ed25519,
                        _ => {
                            return Err(DkimError::InvalidKey(format!(
                                "unknown key type: {}",
                                val
                            )))
                        }
                    };
                }
                "n" => {
                    notes = Some(val.to_string());
                }
                "p" => {
                    if val.is_empty() {
                        // Empty p= means key is revoked
                        public_key = Some(Vec::new());
                    } else {
                        let clean: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                        public_key = Some(
                            base64::engine::general_purpose::STANDARD
                                .decode(&clean)
                                .map_err(|e| {
                                    DkimError::InvalidKey(format!("invalid p= base64: {}", e))
                                })?,
                        );
                    }
                }
                "s" => {
                    service_types = Some(
                        val.split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "t" => {
                    for flag in val.split(':') {
                        match flag.trim().to_lowercase().as_str() {
                            "y" => testing = true,
                            "s" => strict_identity = true,
                            _ => {} // Ignore unknown flags
                        }
                    }
                }
                _ => {} // Ignore unknown tags
            }
        }

        let public_key =
            public_key.ok_or_else(|| DkimError::InvalidKey("missing p= tag".into()))?;

        // Validate version if present
        if let Some(ref v) = version {
            if v != "DKIM1" {
                return Err(DkimError::InvalidKey(format!(
                    "invalid version: {}",
                    v
                )));
            }
        }

        Ok(Self {
            version,
            acceptable_hashes,
            key_type,
            notes,
            public_key,
            service_types,
            testing,
            strict_identity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; p=MTIzNDU2Nzg5MA==").unwrap();
        assert_eq!(key.version, Some("DKIM1".to_string()));
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.public_key.is_empty());
    }

    #[test]
    fn test_parse_revoked_key() {
        let key = DkimPublicKey::parse("v=DKIM1; p=").unwrap();
        assert!(key.public_key.is_empty());
    }

    #[test]
    fn test_parse_ed25519_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=ed25519; p=MTIz").unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_parse_with_flags() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; t=y:s; p=MTIz").unwrap();
        assert!(key.testing);
        assert!(key.strict_identity);
    }

    #[test]
    fn test_parse_with_hash_restriction() {
        let key = DkimPublicKey::parse("v=DKIM1; h=sha256; k=rsa; p=MTIz").unwrap();
        assert_eq!(key.acceptable_hashes, Some(vec!["sha256".to_string()]));
    }
}
