use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("missing required tag: {0}")]
    MissingTag(String),
    #[error("invalid version")]
    InvalidVersion,
    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
    #[error("duplicate tag: {0}")]
    DuplicateTag(String),
    #[error("i= not subdomain of d=")]
    AuidDomainMismatch,
}

/// DKIM signature algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

/// Canonicalization method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CanonicalizationMethod {
    #[default]
    Simple,
    Relaxed,
}

/// Canonicalization for header and body
#[derive(Debug, Clone, Copy, Default)]
pub struct Canonicalization {
    pub header: CanonicalizationMethod,
    pub body: CanonicalizationMethod,
}

/// Parsed DKIM-Signature header
#[derive(Debug, Clone)]
pub struct DkimSignature {
    pub version: u8,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub canonicalization: Canonicalization,
    pub domain: String,
    pub headers: Vec<String>,
    pub auid: Option<String>,
    pub body_length: Option<u64>,
    pub selector: String,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
}

impl DkimSignature {
    /// Parse DKIM-Signature header value
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        let mut version = None;
        let mut algorithm = None;
        let mut signature = None;
        let mut body_hash = None;
        let mut canon = Canonicalization::default();
        let mut domain = None;
        let mut headers: Option<Vec<String>> = None;
        let mut auid = None;
        let mut body_length = None;
        let mut selector = None;
        let mut timestamp = None;
        let mut expiration = None;

        // Parse tag=value pairs
        for part in value.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = part
                .split_once('=')
                .ok_or_else(|| ParseError::MissingTag(part.to_string()))?;

            let tag = tag.trim().to_lowercase();
            let val = val.trim();
            // Remove whitespace from base64 values
            let val_no_ws: String = val.chars().filter(|c| !c.is_whitespace()).collect();

            match tag.as_str() {
                "v" => {
                    if val != "1" {
                        return Err(ParseError::InvalidVersion);
                    }
                    version = Some(1);
                }
                "a" => {
                    algorithm = Some(match val.to_lowercase().as_str() {
                        "rsa-sha1" => Algorithm::RsaSha1,
                        "rsa-sha256" => Algorithm::RsaSha256,
                        "ed25519-sha256" => Algorithm::Ed25519Sha256,
                        _ => return Err(ParseError::InvalidAlgorithm(val.to_string())),
                    });
                }
                "b" => {
                    use base64::Engine;
                    signature = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&val_no_ws)
                            .map_err(|_| ParseError::InvalidBase64("b".to_string()))?,
                    );
                }
                "bh" => {
                    use base64::Engine;
                    body_hash = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&val_no_ws)
                            .map_err(|_| ParseError::InvalidBase64("bh".to_string()))?,
                    );
                }
                "c" => {
                    let parts: Vec<&str> = val.split('/').collect();
                    canon.header = match parts.first().map(|s| s.to_lowercase()).as_deref() {
                        Some("simple") | None => CanonicalizationMethod::Simple,
                        Some("relaxed") => CanonicalizationMethod::Relaxed,
                        _ => CanonicalizationMethod::Simple,
                    };
                    canon.body = match parts.get(1).map(|s| s.to_lowercase()).as_deref() {
                        Some("simple") | None => CanonicalizationMethod::Simple,
                        Some("relaxed") => CanonicalizationMethod::Relaxed,
                        _ => CanonicalizationMethod::Simple,
                    };
                }
                "d" => domain = Some(val.to_lowercase()),
                "h" => {
                    headers = Some(
                        val.split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "i" => auid = Some(val.to_string()),
                "l" => body_length = val.parse().ok(),
                "s" => selector = Some(val.to_string()),
                "t" => timestamp = val.parse().ok(),
                "x" => expiration = val.parse().ok(),
                _ => {} // Ignore unknown tags
            }
        }

        let domain = domain.ok_or_else(|| ParseError::MissingTag("d".to_string()))?;
        let headers = headers.ok_or_else(|| ParseError::MissingTag("h".to_string()))?;

        // Validate h= includes "from"
        if !headers.iter().any(|h| h == "from") {
            return Err(ParseError::MissingTag("from in h=".to_string()));
        }

        // Validate i= is subdomain of d=
        if let Some(ref i) = auid {
            if let Some(at_pos) = i.rfind('@') {
                let i_domain = &i[at_pos + 1..].to_lowercase();
                if i_domain != &domain && !i_domain.ends_with(&format!(".{}", domain)) {
                    return Err(ParseError::AuidDomainMismatch);
                }
            }
        }

        Ok(DkimSignature {
            version: version.ok_or_else(|| ParseError::MissingTag("v".to_string()))?,
            algorithm: algorithm.ok_or_else(|| ParseError::MissingTag("a".to_string()))?,
            signature: signature.ok_or_else(|| ParseError::MissingTag("b".to_string()))?,
            body_hash: body_hash.ok_or_else(|| ParseError::MissingTag("bh".to_string()))?,
            canonicalization: canon,
            domain,
            headers,
            auid,
            body_length,
            selector: selector.ok_or_else(|| ParseError::MissingTag("s".to_string()))?,
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
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; \
             h=from:to:subject; bh=AAAA; b=BBBB",
        )
        .unwrap();

        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "selector");
        assert_eq!(sig.headers, vec!["from", "to", "subject"]);
    }

    #[test]
    fn test_parse_canonicalization() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=sel; \
             h=from; bh=AAAA; b=BBBB",
        )
        .unwrap();

        assert_eq!(sig.canonicalization.header, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.canonicalization.body, CanonicalizationMethod::Simple);
    }

    #[test]
    fn test_missing_from_in_h() {
        let result = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=sel; h=to:subject; bh=AAAA; b=BBBB",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_auid_mismatch() {
        let result = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=sel; i=user@other.com; \
             h=from; bh=AAAA; b=BBBB",
        );
        assert!(matches!(result, Err(ParseError::AuidDomainMismatch)));
    }
}
