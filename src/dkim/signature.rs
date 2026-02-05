use super::DkimError;
use base64::Engine;

#[derive(Debug, Clone, PartialEq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

impl Algorithm {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rsa-sha1" => Some(Algorithm::RsaSha1),
            "rsa-sha256" => Some(Algorithm::RsaSha256),
            "ed25519-sha256" => Some(Algorithm::Ed25519Sha256),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::RsaSha1 => "rsa-sha1",
            Algorithm::RsaSha256 => "rsa-sha256",
            Algorithm::Ed25519Sha256 => "ed25519-sha256",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CanonicalizationMethod {
    Simple,
    Relaxed,
}

impl CanonicalizationMethod {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "relaxed" => CanonicalizationMethod::Relaxed,
            _ => CanonicalizationMethod::Simple,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CanonicalizationMethod::Simple => "simple",
            CanonicalizationMethod::Relaxed => "relaxed",
        }
    }
}

impl std::fmt::Display for CanonicalizationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Canonicalization {
    pub header: CanonicalizationMethod,
    pub body: CanonicalizationMethod,
}

impl Default for Canonicalization {
    fn default() -> Self {
        Self {
            header: CanonicalizationMethod::Simple,
            body: CanonicalizationMethod::Simple,
        }
    }
}

impl Canonicalization {
    pub fn parse(s: &str) -> Self {
        let parts: Vec<&str> = s.split('/').collect();
        let header = CanonicalizationMethod::parse(parts.first().unwrap_or(&"simple"));
        let body = if parts.len() > 1 {
            CanonicalizationMethod::parse(parts[1])
        } else {
            CanonicalizationMethod::Simple
        };
        Self { header, body }
    }
}

impl std::fmt::Display for Canonicalization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.header, self.body)
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
    pub copied_headers: Option<Vec<String>>,
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
        let mut copied_headers = None;

        // Remove folding whitespace and parse tags
        let normalized = header_value
            .replace("\r\n", "")
            .replace('\n', "")
            .replace('\t', " ");

        for part in normalized.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let eq_pos = part.find('=').ok_or_else(|| DkimError::ParseError("invalid tag".into()))?;
            let tag = part[..eq_pos].trim();
            let value = part[eq_pos + 1..].trim();

            match tag {
                "v" => {
                    version = Some(value.parse().map_err(|_| DkimError::ParseError("invalid version".into()))?);
                }
                "a" => {
                    algorithm = Algorithm::parse(value);
                    if algorithm.is_none() {
                        return Err(DkimError::ParseError(format!("unknown algorithm: {}", value)));
                    }
                }
                "b" => {
                    let clean = value.replace([' ', '\t'], "");
                    signature = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&clean)
                            .map_err(|e| DkimError::ParseError(format!("invalid signature base64: {}", e)))?,
                    );
                }
                "bh" => {
                    let clean = value.replace([' ', '\t'], "");
                    body_hash = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&clean)
                            .map_err(|e| DkimError::ParseError(format!("invalid body hash base64: {}", e)))?,
                    );
                }
                "c" => {
                    canonicalization = Canonicalization::parse(value);
                }
                "d" => {
                    domain = Some(value.to_lowercase());
                }
                "h" => {
                    signed_headers = Some(
                        value
                            .split(':')
                            .map(|h| h.trim().to_lowercase())
                            .collect(),
                    );
                }
                "i" => {
                    auid = Some(value.to_string());
                }
                "l" => {
                    body_length = value.parse().ok();
                }
                "s" => {
                    selector = Some(value.to_string());
                }
                "t" => {
                    timestamp = value.parse().ok();
                }
                "x" => {
                    expiration = value.parse().ok();
                }
                "z" => {
                    copied_headers = Some(value.split('|').map(|s| s.to_string()).collect());
                }
                _ => {
                    // Ignore unknown tags for forward compatibility
                }
            }
        }

        // Validate required tags
        let version = version.ok_or_else(|| DkimError::ParseError("missing v= tag".into()))?;
        if version != 1 {
            return Err(DkimError::ParseError("version must be 1".into()));
        }

        let algorithm = algorithm.ok_or_else(|| DkimError::ParseError("missing a= tag".into()))?;
        let signature = signature.ok_or_else(|| DkimError::ParseError("missing b= tag".into()))?;
        let body_hash = body_hash.ok_or_else(|| DkimError::ParseError("missing bh= tag".into()))?;
        let domain = domain.ok_or_else(|| DkimError::ParseError("missing d= tag".into()))?;
        let signed_headers = signed_headers.ok_or_else(|| DkimError::ParseError("missing h= tag".into()))?;
        let selector = selector.ok_or_else(|| DkimError::ParseError("missing s= tag".into()))?;

        // Validate h= includes "from"
        if !signed_headers.iter().any(|h| h == "from") {
            return Err(DkimError::ParseError("h= must include from".into()));
        }

        // Validate i= is subdomain of d=
        if let Some(ref auid) = auid {
            let auid_domain = auid.split('@').nth(1).unwrap_or(auid);
            if !auid_domain.to_lowercase().ends_with(&domain) {
                return Err(DkimError::ParseError("i= must be subdomain of d=".into()));
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
            copied_headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; \
             h=from:to:subject; bh=dGVzdA==; b=c2lnbmF0dXJl"
        );
        assert!(sig.is_ok(), "Parse error: {:?}", sig.err());
        let sig = sig.unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "selector");
    }

    #[test]
    fn test_parse_missing_from_header() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; \
             h=to:subject; bh=abc123==; b=sig123=="
        );
        assert!(sig.is_err());
    }

    #[test]
    fn test_canonicalization_parse() {
        assert_eq!(Canonicalization::parse("relaxed/relaxed").header, CanonicalizationMethod::Relaxed);
        assert_eq!(Canonicalization::parse("relaxed/relaxed").body, CanonicalizationMethod::Relaxed);
        assert_eq!(Canonicalization::parse("simple").header, CanonicalizationMethod::Simple);
        assert_eq!(Canonicalization::parse("simple").body, CanonicalizationMethod::Simple);
    }
}
