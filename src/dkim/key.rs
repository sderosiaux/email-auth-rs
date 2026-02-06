use base64::Engine;

#[derive(Debug, Clone)]
pub struct DkimPublicKey {
    pub version: Option<String>,
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub hash_algorithms: Option<Vec<String>>,
    pub service_types: Option<Vec<String>>,
    pub flags: Option<Vec<String>>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

impl KeyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rsa" => Some(KeyType::Rsa),
            "ed25519" => Some(KeyType::Ed25519),
            _ => None,
        }
    }
}

pub fn parse_key_record(txt: &str) -> Result<DkimPublicKey, String> {
    let mut version = None;
    let mut key_type = KeyType::Rsa;
    let mut public_key = None;
    let mut hash_algorithms = None;
    let mut service_types = None;
    let mut flags = None;
    let mut notes = None;

    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (key, value) = match part.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };

        let key = key.trim().to_lowercase();
        let value = value.trim().replace([' ', '\t', '\r', '\n'], "");

        match key.as_str() {
            "v" => version = Some(value),
            "k" => {
                key_type = KeyType::from_str(&value).ok_or_else(|| format!("Unknown key type: {}", value))?;
            }
            "p" => {
                if value.is_empty() {
                    return Err("Key revoked (empty p= tag)".into());
                }
                public_key = Some(
                    base64::engine::general_purpose::STANDARD
                        .decode(&value)
                        .map_err(|e| format!("Invalid base64 in p= tag: {}", e))?
                );
            }
            "h" => {
                hash_algorithms = Some(value.split(':').map(|s| s.to_string()).collect());
            }
            "s" => {
                service_types = Some(value.split(':').map(|s| s.to_string()).collect());
            }
            "t" => {
                flags = Some(value.split(':').map(|s| s.to_string()).collect());
            }
            "n" => notes = Some(value),
            _ => {}
        }
    }

    let public_key = public_key.ok_or("Missing p= tag")?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rsa_key() {
        let txt = "v=DKIM1; k=rsa; p=dGVzdA==";
        let key = parse_key_record(txt).unwrap();

        assert_eq!(key.version, Some("DKIM1".into()));
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.public_key, b"test");
    }

    #[test]
    fn test_parse_ed25519_key() {
        let txt = "k=ed25519; p=dGVzdA==";
        let key = parse_key_record(txt).unwrap();

        assert_eq!(key.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_revoked_key() {
        let txt = "v=DKIM1; k=rsa; p=";
        let result = parse_key_record(txt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("revoked"));
    }

    #[test]
    fn test_missing_key() {
        let txt = "v=DKIM1; k=rsa";
        let result = parse_key_record(txt);
        assert!(result.is_err());
    }
}
