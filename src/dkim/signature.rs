use super::DkimError;
use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

impl Algorithm {
    pub fn from_str(s: &str) -> Result<Self, DkimError> {
        match s.to_lowercase().as_str() {
            "rsa-sha1" => Ok(Algorithm::RsaSha1),
            "rsa-sha256" => Ok(Algorithm::RsaSha256),
            "ed25519-sha256" => Ok(Algorithm::Ed25519Sha256),
            _ => Err(DkimError::Parse(format!("unknown algorithm: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizationMethod {
    Simple,
    Relaxed,
}

impl Default for CanonicalizationMethod {
    fn default() -> Self {
        CanonicalizationMethod::Simple
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Canonicalization {
    pub header: CanonicalizationMethod,
    pub body: CanonicalizationMethod,
}

impl Canonicalization {
    pub fn from_str(s: &str) -> Result<Self, DkimError> {
        let parts: Vec<&str> = s.split('/').collect();
        let header = match parts.first().map(|s| s.to_lowercase()).as_deref() {
            Some("simple") | None => CanonicalizationMethod::Simple,
            Some("relaxed") => CanonicalizationMethod::Relaxed,
            Some(other) => {
                return Err(DkimError::Parse(format!(
                    "unknown canonicalization: {}",
                    other
                )))
            }
        };
        let body = match parts.get(1).map(|s| s.to_lowercase()).as_deref() {
            Some("simple") | None => CanonicalizationMethod::Simple,
            Some("relaxed") => CanonicalizationMethod::Relaxed,
            Some(other) => {
                return Err(DkimError::Parse(format!(
                    "unknown canonicalization: {}",
                    other
                )))
            }
        };
        Ok(Canonicalization { header, body })
    }
}

#[derive(Debug, Clone)]
pub struct DkimSignature {
    pub version: u8,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub canonicalization: Canonicalization,
    pub domain: String,
    pub signed_headers: Vec<String>,
    pub auid: Option<String>,
    pub body_length: Option<u64>,
    pub selector: String,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
}

impl DkimSignature {
    pub fn parse(header_value: &str) -> Result<Self, DkimError> {
        let mut version = None;
        let mut algorithm = None;
        let mut signature = None;
        let mut body_hash = None;
        let mut canonicalization = Canonicalization::default();
        let mut domain = None;
        let mut signed_headers: Option<Vec<String>> = None;
        let mut auid = None;
        let mut body_length = None;
        let mut selector = None;
        let mut timestamp = None;
        let mut expiration = None;

        // Unfold the header (remove CRLF + whitespace)
        let unfolded = header_value
            .replace("\r\n", "")
            .replace('\n', "")
            .replace('\t', " ");

        for part in unfolded.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let eq_pos = part
                .find('=')
                .ok_or_else(|| DkimError::Parse(format!("missing = in tag: {}", part)))?;

            let tag = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim();

            match tag.as_str() {
                "v" => {
                    version = Some(
                        value
                            .parse::<u8>()
                            .map_err(|_| DkimError::Parse("invalid version".to_string()))?,
                    );
                }
                "a" => {
                    algorithm = Some(Algorithm::from_str(value)?);
                }
                "b" => {
                    // Remove whitespace from base64
                    let clean: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                    signature = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&clean)
                            .map_err(|e| DkimError::Parse(format!("invalid b= base64: {}", e)))?,
                    );
                }
                "bh" => {
                    let clean: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                    body_hash = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&clean)
                            .map_err(|e| DkimError::Parse(format!("invalid bh= base64: {}", e)))?,
                    );
                }
                "c" => {
                    canonicalization = Canonicalization::from_str(value)?;
                }
                "d" => {
                    domain = Some(value.to_lowercase());
                }
                "h" => {
                    signed_headers = Some(
                        value
                            .split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "i" => {
                    auid = Some(value.to_string());
                }
                "l" => {
                    body_length = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| DkimError::Parse("invalid l= value".to_string()))?,
                    );
                }
                "s" => {
                    selector = Some(value.to_string());
                }
                "t" => {
                    timestamp = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| DkimError::Parse("invalid t= value".to_string()))?,
                    );
                }
                "x" => {
                    expiration = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| DkimError::Parse("invalid x= value".to_string()))?,
                    );
                }
                _ => {
                    // Ignore unknown tags (forward compatibility)
                }
            }
        }

        // Validate required fields
        let version = version.ok_or_else(|| DkimError::Parse("missing v= tag".to_string()))?;
        if version != 1 {
            return Err(DkimError::Parse(format!("unsupported version: {}", version)));
        }

        let algorithm =
            algorithm.ok_or_else(|| DkimError::Parse("missing a= tag".to_string()))?;
        let signature =
            signature.ok_or_else(|| DkimError::Parse("missing b= tag".to_string()))?;
        let body_hash =
            body_hash.ok_or_else(|| DkimError::Parse("missing bh= tag".to_string()))?;
        let domain = domain.ok_or_else(|| DkimError::Parse("missing d= tag".to_string()))?;
        let signed_headers =
            signed_headers.ok_or_else(|| DkimError::Parse("missing h= tag".to_string()))?;
        let selector = selector.ok_or_else(|| DkimError::Parse("missing s= tag".to_string()))?;

        // h= must include "from"
        if !signed_headers.iter().any(|h| h == "from") {
            return Err(DkimError::Parse("h= must include from".to_string()));
        }

        // Validate i= is subdomain of d=
        if let Some(ref id) = auid {
            if let Some(at_pos) = id.rfind('@') {
                let id_domain = &id[at_pos + 1..].to_lowercase();
                if id_domain != &domain && !id_domain.ends_with(&format!(".{}", domain)) {
                    return Err(DkimError::Parse(
                        "i= domain must be subdomain of d=".to_string(),
                    ));
                }
            }
        }

        Ok(DkimSignature {
            version,
            algorithm,
            signature,
            body_hash,
            canonicalization,
            domain,
            signed_headers,
            auid,
            body_length,
            selector,
            timestamp,
            expiration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        // Use valid base64 strings (dGVzdA== is "test" encoded)
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; \
             h=from:to:subject; bh=dGVzdA==; b=c2lnbmF0dXJl",
        )
        .unwrap();

        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "selector");
        assert_eq!(sig.signed_headers, vec!["from", "to", "subject"]);
    }

    #[test]
    fn test_canonicalization_parsing() {
        let c = Canonicalization::from_str("relaxed/simple").unwrap();
        assert_eq!(c.header, CanonicalizationMethod::Relaxed);
        assert_eq!(c.body, CanonicalizationMethod::Simple);

        let c = Canonicalization::from_str("relaxed").unwrap();
        assert_eq!(c.header, CanonicalizationMethod::Relaxed);
        assert_eq!(c.body, CanonicalizationMethod::Simple);
    }

    #[test]
    fn test_missing_from_in_h() {
        let result = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; \
             h=to:subject; bh=abc=; b=xyz=",
        );
        assert!(result.is_err());
    }
}
