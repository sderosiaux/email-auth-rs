use super::{Algorithm, DkimError};
use base64::Engine;

#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyFlag {
    Testing,  // y
    Strict,   // s - i= domain must exactly match d=
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    pub version: Option<String>,
    pub acceptable_hashes: Option<Vec<HashAlgorithm>>,
    pub key_type: KeyType,
    pub notes: Option<String>,
    pub public_key: Vec<u8>,
    pub service_types: Option<Vec<String>>,
    pub flags: Vec<KeyFlag>,
}

impl DkimPublicKey {
    pub fn parse(record: &str) -> Result<Self, DkimError> {
        let mut version = None;
        let mut acceptable_hashes = None;
        let mut key_type = KeyType::Rsa;
        let mut notes = None;
        let mut public_key = None;
        let mut service_types = None;
        let mut flags = Vec::new();

        // Normalize the record (remove quotes and join multiple strings)
        let normalized = record.replace('"', "");

        for part in normalized.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let eq_pos = match part.find('=') {
                Some(p) => p,
                None => continue,
            };

            let tag = part[..eq_pos].trim();
            let value = part[eq_pos + 1..].trim();

            match tag {
                "v" => {
                    version = Some(value.to_string());
                }
                "h" => {
                    let hashes: Vec<HashAlgorithm> = value
                        .split(':')
                        .filter_map(|h| match h.trim().to_lowercase().as_str() {
                            "sha1" => Some(HashAlgorithm::Sha1),
                            "sha256" => Some(HashAlgorithm::Sha256),
                            _ => None,
                        })
                        .collect();
                    if !hashes.is_empty() {
                        acceptable_hashes = Some(hashes);
                    }
                }
                "k" => {
                    key_type = match value.to_lowercase().as_str() {
                        "ed25519" => KeyType::Ed25519,
                        _ => KeyType::Rsa,
                    };
                }
                "n" => {
                    notes = Some(value.to_string());
                }
                "p" => {
                    let clean = value.replace([' ', '\t'], "");
                    if clean.is_empty() {
                        public_key = Some(Vec::new()); // Revoked key
                    } else {
                        public_key = Some(
                            base64::engine::general_purpose::STANDARD
                                .decode(&clean)
                                .map_err(|e| DkimError::ParseError(format!("invalid public key base64: {}", e)))?,
                        );
                    }
                }
                "s" => {
                    service_types = Some(value.split(':').map(|s| s.trim().to_string()).collect());
                }
                "t" => {
                    for flag in value.split(':') {
                        match flag.trim().to_lowercase().as_str() {
                            "y" => flags.push(KeyFlag::Testing),
                            "s" => flags.push(KeyFlag::Strict),
                            _ => {}
                        }
                    }
                }
                _ => {
                    // Ignore unknown tags
                }
            }
        }

        let public_key = public_key.ok_or_else(|| DkimError::ParseError("missing p= tag".into()))?;

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

    pub fn supports_algorithm(&self, algorithm: &Algorithm) -> bool {
        // Check key type compatibility
        match (&self.key_type, algorithm) {
            (KeyType::Rsa, Algorithm::RsaSha1) => {}
            (KeyType::Rsa, Algorithm::RsaSha256) => {}
            (KeyType::Ed25519, Algorithm::Ed25519Sha256) => {}
            _ => return false,
        }

        // Check hash algorithm restrictions
        if let Some(ref hashes) = self.acceptable_hashes {
            let required_hash = match algorithm {
                Algorithm::RsaSha1 => HashAlgorithm::Sha1,
                Algorithm::RsaSha256 => HashAlgorithm::Sha256,
                Algorithm::Ed25519Sha256 => HashAlgorithm::Sha256,
            };
            if !hashes.contains(&required_hash) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let key = DkimPublicKey::parse("p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==").unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.public_key.is_empty());
    }

    #[test]
    fn test_parse_full() {
        let key = DkimPublicKey::parse("v=DKIM1; k=rsa; h=sha256; t=y:s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==").unwrap();
        assert_eq!(key.version, Some("DKIM1".to_string()));
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(key.flags.contains(&KeyFlag::Testing));
        assert!(key.flags.contains(&KeyFlag::Strict));
    }

    #[test]
    fn test_revoked_key() {
        let key = DkimPublicKey::parse("v=DKIM1; p=").unwrap();
        assert!(key.public_key.is_empty());
    }

    #[test]
    fn test_hash_restriction() {
        let key = DkimPublicKey::parse("h=sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==").unwrap();
        assert!(key.supports_algorithm(&Algorithm::RsaSha256));
        assert!(!key.supports_algorithm(&Algorithm::RsaSha1));
    }
}
