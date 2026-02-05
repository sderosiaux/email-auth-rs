use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyParseError {
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
    #[error("invalid key type: {0}")]
    InvalidKeyType(String),
    #[error("key revoked")]
    KeyRevoked,
}

/// DKIM public key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    #[default]
    Rsa,
    Ed25519,
}

/// Key flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFlag {
    /// Testing mode (y)
    Testing,
    /// Strict mode - i= must exactly match d= (s)
    Strict,
}

/// Parsed DKIM public key record from DNS
#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    /// Version (should be "DKIM1")
    pub version: Option<String>,
    /// Acceptable hash algorithms
    pub hash_algorithms: Option<Vec<String>>,
    /// Key type
    pub key_type: KeyType,
    /// Notes
    pub notes: Option<String>,
    /// Public key data (empty = revoked)
    pub public_key: Vec<u8>,
    /// Service types
    pub service_types: Vec<String>,
    /// Flags
    pub flags: Vec<KeyFlag>,
}

impl DkimPublicKey {
    /// Parse DKIM key record from DNS TXT value
    pub fn parse(txt: &str) -> Result<Self, KeyParseError> {
        let mut version = None;
        let mut hash_algorithms = None;
        let mut key_type = KeyType::Rsa;
        let mut notes = None;
        let mut public_key = None;
        let mut service_types = vec!["*".to_string()];
        let mut flags = Vec::new();

        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = match part.split_once('=') {
                Some((t, v)) => (t.trim().to_lowercase(), v.trim()),
                None => continue,
            };

            match tag.as_str() {
                "v" => version = Some(val.to_string()),
                "h" => {
                    hash_algorithms = Some(
                        val.split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "k" => {
                    key_type = match val.to_lowercase().as_str() {
                        "rsa" => KeyType::Rsa,
                        "ed25519" => KeyType::Ed25519,
                        _ => return Err(KeyParseError::InvalidKeyType(val.to_string())),
                    };
                }
                "n" => notes = Some(val.to_string()),
                "p" => {
                    // Remove whitespace from base64
                    let val_clean: String = val.chars().filter(|c| !c.is_whitespace()).collect();

                    if val_clean.is_empty() {
                        // Empty p= means key is revoked
                        public_key = Some(Vec::new());
                    } else {
                        use base64::Engine;
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(&val_clean)
                            .map_err(|_| KeyParseError::InvalidBase64("p".to_string()))?;
                        public_key = Some(decoded);
                    }
                }
                "s" => {
                    service_types = val.split(':').map(|s| s.trim().to_string()).collect();
                }
                "t" => {
                    for flag in val.split(':') {
                        match flag.trim().to_lowercase().as_str() {
                            "y" => flags.push(KeyFlag::Testing),
                            "s" => flags.push(KeyFlag::Strict),
                            _ => {} // Ignore unknown flags
                        }
                    }
                }
                _ => {} // Ignore unknown tags
            }
        }

        let public_key = public_key.unwrap_or_default();

        // Check if key is revoked (empty p=)
        if public_key.is_empty() {
            return Err(KeyParseError::KeyRevoked);
        }

        Ok(DkimPublicKey {
            version,
            hash_algorithms,
            key_type,
            notes,
            public_key,
            service_types,
            flags,
        })
    }

    /// Check if key allows the given hash algorithm
    pub fn allows_hash(&self, hash: &str) -> bool {
        match &self.hash_algorithms {
            Some(allowed) => allowed.iter().any(|h| h == hash),
            None => true, // No restriction
        }
    }

    /// Check if key is in testing mode
    pub fn is_testing(&self) -> bool {
        self.flags.contains(&KeyFlag::Testing)
    }

    /// Check if key requires strict i= matching
    pub fn is_strict(&self) -> bool {
        self.flags.contains(&KeyFlag::Strict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        // Minimal key with just p= (base64 of "test" for testing)
        let key = DkimPublicKey::parse("p=dGVzdA==").unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.public_key, b"test");
    }

    #[test]
    fn test_parse_full() {
        let key = DkimPublicKey::parse(
            "v=DKIM1; k=rsa; h=sha256; t=y:s; s=email; p=dGVzdA==",
        )
        .unwrap();

        assert_eq!(key.version, Some("DKIM1".to_string()));
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.hash_algorithms, Some(vec!["sha256".to_string()]));
        assert!(key.is_testing());
        assert!(key.is_strict());
        assert_eq!(key.service_types, vec!["email"]);
    }

    #[test]
    fn test_parse_ed25519() {
        let key = DkimPublicKey::parse("k=ed25519; p=dGVzdA==").unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_parse_revoked() {
        let result = DkimPublicKey::parse("p=");
        assert!(matches!(result, Err(KeyParseError::KeyRevoked)));
    }

    #[test]
    fn test_allows_hash() {
        let key = DkimPublicKey::parse("h=sha256; p=dGVzdA==").unwrap();
        assert!(key.allows_hash("sha256"));
        assert!(!key.allows_hash("sha1"));

        // No restriction
        let key = DkimPublicKey::parse("p=dGVzdA==").unwrap();
        assert!(key.allows_hash("sha256"));
        assert!(key.allows_hash("sha1"));
    }
}
