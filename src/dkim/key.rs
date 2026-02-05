use super::DkimError;
use base64::{engine::general_purpose::STANDARD, Engine};

/// Key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    #[default]
    Rsa,
    Ed25519,
}

/// Key flags
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFlag {
    /// Testing mode
    Testing,
    /// i= domain must exactly match d=
    SameDomainOnly,
}

/// Parsed DKIM public key record
#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    pub version: Option<String>,
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub acceptable_hashes: Option<Vec<String>>,
    pub service_types: Option<Vec<String>>,
    pub flags: Vec<KeyFlag>,
    pub notes: Option<String>,
}

impl DkimPublicKey {
    /// Parse a DKIM public key TXT record
    pub fn parse(txt: &str) -> Result<Self, DkimError> {
        let mut version = None;
        let mut key_type = KeyType::Rsa;
        let mut public_key = None;
        let mut acceptable_hashes = None;
        let mut service_types = None;
        let mut flags = Vec::new();
        let mut notes = None;

        // Parse tag=value pairs
        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = match part.split_once('=') {
                Some((t, v)) => (t.trim().to_lowercase(), v.trim()),
                None => continue, // Skip malformed parts
            };

            match tag.as_str() {
                "v" => {
                    version = Some(val.to_string());
                }
                "k" => {
                    key_type = match val.to_lowercase().as_str() {
                        "rsa" => KeyType::Rsa,
                        "ed25519" => KeyType::Ed25519,
                        _ => return Err(DkimError::Parse(format!("unknown key type: {}", val))),
                    };
                }
                "p" => {
                    if val.is_empty() {
                        // Empty p= means key is revoked
                        public_key = Some(Vec::new());
                    } else {
                        // Remove whitespace from base64
                        let cleaned: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                        public_key = Some(
                            STANDARD
                                .decode(&cleaned)
                                .map_err(|e| DkimError::Parse(format!("invalid p= base64: {}", e)))?,
                        );
                    }
                }
                "h" => {
                    acceptable_hashes = Some(
                        val.split(':')
                            .map(|s| s.trim().to_lowercase())
                            .filter(|s| !s.is_empty())
                            .collect(),
                    );
                }
                "s" => {
                    service_types = Some(
                        val.split(':')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect(),
                    );
                }
                "t" => {
                    for flag in val.split(':') {
                        match flag.trim().to_lowercase().as_str() {
                            "y" => flags.push(KeyFlag::Testing),
                            "s" => flags.push(KeyFlag::SameDomainOnly),
                            _ => {} // Ignore unknown flags
                        }
                    }
                }
                "n" => {
                    notes = Some(val.to_string());
                }
                _ => {
                    // Ignore unknown tags
                }
            }
        }

        // p= is required
        let public_key = public_key.ok_or_else(|| DkimError::Parse("missing p= tag".to_string()))?;

        // Validate version if present
        if let Some(ref v) = version {
            if v != "DKIM1" {
                return Err(DkimError::Parse(format!("invalid version: {}", v)));
            }
        }

        Ok(Self {
            version,
            key_type,
            public_key,
            acceptable_hashes,
            service_types,
            flags,
            notes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rsa_key() {
        let txt = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==";
        let key = DkimPublicKey::parse(txt).unwrap();
        assert_eq!(key.version, Some("DKIM1".to_string()));
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.public_key.is_empty());
    }

    #[test]
    fn test_parse_revoked_key() {
        let txt = "v=DKIM1; p=";
        let key = DkimPublicKey::parse(txt).unwrap();
        assert!(key.public_key.is_empty());
    }

    #[test]
    fn test_parse_ed25519_key() {
        let txt = "v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let key = DkimPublicKey::parse(txt).unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_parse_flags() {
        let txt = "v=DKIM1; k=rsa; t=y:s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==";
        let key = DkimPublicKey::parse(txt).unwrap();
        assert!(key.flags.contains(&KeyFlag::Testing));
        assert!(key.flags.contains(&KeyFlag::SameDomainOnly));
    }

    #[test]
    fn test_parse_hash_restrictions() {
        let txt = "v=DKIM1; k=rsa; h=sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==";
        let key = DkimPublicKey::parse(txt).unwrap();
        assert_eq!(key.acceptable_hashes, Some(vec!["sha256".to_string()]));
    }
}
