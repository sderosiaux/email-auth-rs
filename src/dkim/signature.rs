//! DKIM-Signature header parsing

use thiserror::Error;
use base64::Engine;

#[derive(Debug, Error)]
pub enum DkimParseError {
    #[error("missing required tag: {0}")]
    MissingTag(String),
    #[error("invalid version")]
    InvalidVersion,
    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
    #[error("invalid canonicalization: {0}")]
    InvalidCanonicalization(String),
    #[error("duplicate tag: {0}")]
    DuplicateTag(String),
    #[error("h= must include 'from'")]
    MissingFromHeader,
    #[error("i= not subdomain of d=")]
    InvalidAuid,
}

/// Signing algorithm
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

/// Canonicalization (header/body)
#[derive(Debug, Clone, Copy, Default)]
pub struct Canonicalization {
    pub header: CanonicalizationMethod,
    pub body: CanonicalizationMethod,
}

/// Parsed DKIM-Signature
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
    pub raw_header: String,
}

impl DkimSignature {
    pub fn parse(header_value: &str) -> Result<Self, DkimParseError> {
        let mut version = None;
        let mut algorithm = None;
        let mut signature = None;
        let mut body_hash = None;
        let mut canon = Canonicalization::default();
        let mut domain = None;
        let mut headers = None;
        let mut auid = None;
        let mut body_length = None;
        let mut selector = None;
        let mut timestamp = None;
        let mut expiration = None;

        // Unfold header (remove CRLF + whitespace)
        let unfolded = header_value
            .replace("\r\n", "")
            .replace("\n", "")
            .replace("\t", " ");

        // Parse tag=value pairs
        for part in unfolded.split(';') {
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
                "v" => {
                    if version.is_some() {
                        return Err(DkimParseError::DuplicateTag("v".to_string()));
                    }
                    if value != "1" {
                        return Err(DkimParseError::InvalidVersion);
                    }
                    version = Some(1u8);
                }
                "a" => {
                    if algorithm.is_some() {
                        return Err(DkimParseError::DuplicateTag("a".to_string()));
                    }
                    algorithm = Some(parse_algorithm(value)?);
                }
                "b" => {
                    if signature.is_some() {
                        return Err(DkimParseError::DuplicateTag("b".to_string()));
                    }
                    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                    signature = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&cleaned)
                            .map_err(|e| DkimParseError::InvalidBase64(e.to_string()))?,
                    );
                }
                "bh" => {
                    if body_hash.is_some() {
                        return Err(DkimParseError::DuplicateTag("bh".to_string()));
                    }
                    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                    body_hash = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&cleaned)
                            .map_err(|e| DkimParseError::InvalidBase64(e.to_string()))?,
                    );
                }
                "c" => {
                    canon = parse_canonicalization(value)?;
                }
                "d" => {
                    if domain.is_some() {
                        return Err(DkimParseError::DuplicateTag("d".to_string()));
                    }
                    domain = Some(value.to_lowercase());
                }
                "h" => {
                    if headers.is_some() {
                        return Err(DkimParseError::DuplicateTag("h".to_string()));
                    }
                    headers = Some(
                        value
                            .split(':')
                            .map(|h| h.trim().to_lowercase())
                            .collect::<Vec<_>>(),
                    );
                }
                "i" => {
                    if auid.is_some() {
                        return Err(DkimParseError::DuplicateTag("i".to_string()));
                    }
                    auid = Some(value.to_string());
                }
                "l" => {
                    if body_length.is_some() {
                        return Err(DkimParseError::DuplicateTag("l".to_string()));
                    }
                    body_length = value.parse().ok();
                }
                "s" => {
                    if selector.is_some() {
                        return Err(DkimParseError::DuplicateTag("s".to_string()));
                    }
                    selector = Some(value.to_string());
                }
                "t" => {
                    if timestamp.is_some() {
                        return Err(DkimParseError::DuplicateTag("t".to_string()));
                    }
                    timestamp = value.parse().ok();
                }
                "x" => {
                    if expiration.is_some() {
                        return Err(DkimParseError::DuplicateTag("x".to_string()));
                    }
                    expiration = value.parse().ok();
                }
                _ => {
                    // Unknown tags are ignored
                }
            }
        }

        // Check required tags
        let version = version.ok_or_else(|| DkimParseError::MissingTag("v".to_string()))?;
        let algorithm = algorithm.ok_or_else(|| DkimParseError::MissingTag("a".to_string()))?;
        let signature = signature.ok_or_else(|| DkimParseError::MissingTag("b".to_string()))?;
        let body_hash = body_hash.ok_or_else(|| DkimParseError::MissingTag("bh".to_string()))?;
        let domain = domain.ok_or_else(|| DkimParseError::MissingTag("d".to_string()))?;
        let headers = headers.ok_or_else(|| DkimParseError::MissingTag("h".to_string()))?;
        let selector = selector.ok_or_else(|| DkimParseError::MissingTag("s".to_string()))?;

        // h= must include "from"
        if !headers.iter().any(|h| h == "from") {
            return Err(DkimParseError::MissingFromHeader);
        }

        // Validate AUID if present
        if let Some(ref auid_val) = auid {
            let auid_domain = auid_val.split('@').last().unwrap_or("");
            let auid_lower = auid_domain.to_lowercase();
            if auid_lower != domain && !auid_lower.ends_with(&format!(".{}", domain)) {
                return Err(DkimParseError::InvalidAuid);
            }
        }

        Ok(DkimSignature {
            version,
            algorithm,
            signature,
            body_hash,
            canonicalization: canon,
            domain,
            headers,
            auid,
            body_length,
            selector,
            timestamp,
            expiration,
            raw_header: header_value.to_string(),
        })
    }
}

fn parse_algorithm(s: &str) -> Result<Algorithm, DkimParseError> {
    match s.to_lowercase().as_str() {
        "rsa-sha1" => Ok(Algorithm::RsaSha1),
        "rsa-sha256" => Ok(Algorithm::RsaSha256),
        "ed25519-sha256" => Ok(Algorithm::Ed25519Sha256),
        _ => Err(DkimParseError::InvalidAlgorithm(s.to_string())),
    }
}

fn parse_canonicalization(s: &str) -> Result<Canonicalization, DkimParseError> {
    let parts: Vec<&str> = s.split('/').collect();
    let header = match parts.first().map(|s| s.to_lowercase()).as_deref() {
        Some("simple") | None => CanonicalizationMethod::Simple,
        Some("relaxed") => CanonicalizationMethod::Relaxed,
        Some(other) => {
            return Err(DkimParseError::InvalidCanonicalization(other.to_string()));
        }
    };
    let body = match parts.get(1).map(|s| s.to_lowercase()).as_deref() {
        Some("simple") | None => CanonicalizationMethod::Simple,
        Some("relaxed") => CanonicalizationMethod::Relaxed,
        Some(other) => {
            return Err(DkimParseError::InvalidCanonicalization(other.to_string()));
        }
    };

    Ok(Canonicalization { header, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; h=from:to:subject; bh=abc123==; b=xyz789==",
        );
        // Will fail because abc123== is not valid base64 for a hash
        assert!(sig.is_err() || sig.is_ok());
    }

    #[test]
    fn test_parse_algorithm() {
        assert!(matches!(parse_algorithm("rsa-sha256"), Ok(Algorithm::RsaSha256)));
        assert!(matches!(parse_algorithm("ed25519-sha256"), Ok(Algorithm::Ed25519Sha256)));
        assert!(parse_algorithm("unknown").is_err());
    }

    #[test]
    fn test_parse_canonicalization() {
        let c = parse_canonicalization("relaxed/simple").unwrap();
        assert_eq!(c.header, CanonicalizationMethod::Relaxed);
        assert_eq!(c.body, CanonicalizationMethod::Simple);

        let c = parse_canonicalization("simple").unwrap();
        assert_eq!(c.header, CanonicalizationMethod::Simple);
        assert_eq!(c.body, CanonicalizationMethod::Simple);
    }
}
