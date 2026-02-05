use super::signature::Algorithm;
use super::DkimError;
use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    pub version: Option<String>,
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub hash_algorithms: Option<Vec<String>>,
    pub service_types: Option<Vec<String>>,
    pub flags: Vec<String>,
    pub notes: Option<String>,
}

impl DkimPublicKey {
    pub fn parse(txt: &str) -> Result<Self, DkimError> {
        let mut version = None;
        let mut key_type = KeyType::Rsa;
        let mut public_key = None;
        let mut hash_algorithms = None;
        let mut service_types = None;
        let mut flags = Vec::new();
        let mut notes = None;

        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let eq_pos = match part.find('=') {
                Some(pos) => pos,
                None => continue, // Ignore malformed tags
            };

            let tag = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim();

            match tag.as_str() {
                "v" => {
                    version = Some(value.to_string());
                }
                "k" => {
                    key_type = match value.to_lowercase().as_str() {
                        "rsa" => KeyType::Rsa,
                        "ed25519" => KeyType::Ed25519,
                        _ => {
                            return Err(DkimError::Parse(format!(
                                "unknown key type: {}",
                                value
                            )))
                        }
                    };
                }
                "p" => {
                    if value.is_empty() {
                        // Empty p= means key is revoked
                        public_key = Some(Vec::new());
                    } else {
                        let clean: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                        public_key = Some(
                            base64::engine::general_purpose::STANDARD
                                .decode(&clean)
                                .map_err(|e| {
                                    DkimError::Parse(format!("invalid p= base64: {}", e))
                                })?,
                        );
                    }
                }
                "h" => {
                    hash_algorithms = Some(
                        value
                            .split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "s" => {
                    service_types = Some(
                        value
                            .split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "t" => {
                    flags = value
                        .split(':')
                        .map(|s| s.trim().to_lowercase())
                        .collect();
                }
                "n" => {
                    notes = Some(value.to_string());
                }
                _ => {
                    // Ignore unknown tags
                }
            }
        }

        let public_key =
            public_key.ok_or_else(|| DkimError::Parse("missing p= tag".to_string()))?;

        Ok(DkimPublicKey {
            version,
            key_type,
            public_key,
            hash_algorithms,
            service_types,
            flags,
            notes,
        })
    }

    /// Check if this key supports the given signature algorithm
    pub fn supports_algorithm(&self, algorithm: &Algorithm) -> bool {
        // Check key type compatibility
        match (self.key_type, algorithm) {
            (KeyType::Rsa, Algorithm::RsaSha1) => {}
            (KeyType::Rsa, Algorithm::RsaSha256) => {}
            (KeyType::Ed25519, Algorithm::Ed25519Sha256) => {}
            _ => return false,
        }

        // Check hash algorithm restrictions
        if let Some(ref allowed) = self.hash_algorithms {
            let hash = match algorithm {
                Algorithm::RsaSha1 => "sha1",
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => "sha256",
            };
            if !allowed.iter().any(|h| h == hash) {
                return false;
            }
        }

        true
    }

    /// Check if key has the "testing" flag
    pub fn is_testing(&self) -> bool {
        self.flags.iter().any(|f| f == "y")
    }

    /// Check if key has the "strict" flag (i= must match d= exactly)
    pub fn is_strict(&self) -> bool {
        self.flags.iter().any(|f| f == "s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rsa_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; p=MIGfMA0=").unwrap();
        assert_eq!(key.version, Some("DKIM1".to_string()));
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.public_key.is_empty());
    }

    #[test]
    fn test_parse_revoked_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; p=").unwrap();
        assert!(key.public_key.is_empty());
    }

    #[test]
    fn test_parse_with_hash_restriction() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; h=sha256; p=MIGfMA0=").unwrap();
        assert_eq!(
            key.hash_algorithms,
            Some(vec!["sha256".to_string()])
        );
        assert!(key.supports_algorithm(&Algorithm::RsaSha256));
        assert!(!key.supports_algorithm(&Algorithm::RsaSha1));
    }

    #[test]
    fn test_parse_ed25519_key() {
        let key = DkimPublicKey::parse("v=DKIM1; k=ed25519; p=abc=").unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
        assert!(key.supports_algorithm(&Algorithm::Ed25519Sha256));
        assert!(!key.supports_algorithm(&Algorithm::RsaSha256));
    }
}
