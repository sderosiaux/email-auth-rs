use super::{Algorithm, CanonicalizationMethod};
use base64::Engine;

#[derive(Debug, Clone)]
pub struct DkimSignature {
    pub version: u8,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub header_canonicalization: CanonicalizationMethod,
    pub body_canonicalization: CanonicalizationMethod,
    pub domain: String,
    pub signed_headers: Vec<String>,
    pub auid: String,
    pub body_length: Option<u64>,
    pub selector: String,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
    pub copied_headers: Option<Vec<String>>,
    pub raw_header: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DkimParseError {
    MissingTag(String),
    DuplicateTag(String),
    InvalidVersion,
    InvalidAlgorithm(String),
    InvalidBase64(String),
    InvalidCanon(String),
    MissingFromInHeaders,
    AuidDomainMismatch,
    InvalidSyntax(String),
}

impl std::fmt::Display for DkimParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTag(t) => write!(f, "missing required tag: {t}"),
            Self::DuplicateTag(t) => write!(f, "duplicate tag: {t}"),
            Self::InvalidVersion => write!(f, "invalid version (must be 1)"),
            Self::InvalidAlgorithm(a) => write!(f, "invalid algorithm: {a}"),
            Self::InvalidBase64(s) => write!(f, "invalid base64: {s}"),
            Self::InvalidCanon(s) => write!(f, "invalid canonicalization: {s}"),
            Self::MissingFromInHeaders => write!(f, "h= must include 'from'"),
            Self::AuidDomainMismatch => write!(f, "i= domain not subdomain of d="),
            Self::InvalidSyntax(s) => write!(f, "invalid syntax: {s}"),
        }
    }
}

/// Parse tag=value pairs from a header value.
pub fn parse_tags(input: &str) -> Result<Vec<(String, String)>, DkimParseError> {
    let mut tags = Vec::new();
    for part in input.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| DkimParseError::InvalidSyntax(format!("no '=' in tag: {part}")))?;
        tags.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(tags)
}

fn decode_base64_with_whitespace(s: &str) -> Result<Vec<u8>, DkimParseError> {
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| DkimParseError::InvalidBase64(e.to_string()))
}

impl DkimSignature {
    /// Parse a DKIM-Signature header value (everything after "DKIM-Signature:").
    pub fn parse(header_value: &str) -> Result<Self, DkimParseError> {
        let tags = parse_tags(header_value)?;

        // Check for duplicates
        let mut seen = std::collections::HashSet::new();
        for (name, _) in &tags {
            if !seen.insert(name.as_str()) {
                return Err(DkimParseError::DuplicateTag(name.clone()));
            }
        }

        let get = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        // Required tags
        let v_str = get("v").ok_or(DkimParseError::MissingTag("v".into()))?;
        let version: u8 = v_str
            .trim()
            .parse()
            .map_err(|_| DkimParseError::InvalidVersion)?;
        if version != 1 {
            return Err(DkimParseError::InvalidVersion);
        }

        let a_str = get("a").ok_or(DkimParseError::MissingTag("a".into()))?;
        let algorithm = match a_str.trim().to_ascii_lowercase().as_str() {
            "rsa-sha1" => Algorithm::RsaSha1,
            "rsa-sha256" => Algorithm::RsaSha256,
            "ed25519-sha256" => Algorithm::Ed25519Sha256,
            other => return Err(DkimParseError::InvalidAlgorithm(other.into())),
        };

        let b_str = get("b").ok_or(DkimParseError::MissingTag("b".into()))?;
        let signature = decode_base64_with_whitespace(b_str)?;

        let bh_str = get("bh").ok_or(DkimParseError::MissingTag("bh".into()))?;
        let body_hash = decode_base64_with_whitespace(bh_str)?;

        let domain = get("d")
            .ok_or(DkimParseError::MissingTag("d".into()))?
            .trim()
            .to_string();

        let h_str = get("h").ok_or(DkimParseError::MissingTag("h".into()))?;
        let signed_headers: Vec<String> = h_str
            .split(':')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // h= must include "from"
        if !signed_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("from"))
        {
            return Err(DkimParseError::MissingFromInHeaders);
        }

        let selector = get("s")
            .ok_or(DkimParseError::MissingTag("s".into()))?
            .trim()
            .to_string();

        // Optional tags
        let (header_canon, body_canon) = if let Some(c_str) = get("c") {
            parse_canonicalization(c_str.trim())?
        } else {
            (CanonicalizationMethod::Simple, CanonicalizationMethod::Simple)
        };

        let auid = if let Some(i_str) = get("i") {
            let auid = i_str.trim().to_string();
            // i= domain must be subdomain of d=
            if let Some(i_domain) = crate::common::domain::domain_from_email(&auid) {
                if !crate::common::domain::is_subdomain_of(i_domain, &domain) {
                    return Err(DkimParseError::AuidDomainMismatch);
                }
            }
            auid
        } else {
            format!("@{domain}")
        };

        let body_length = get("l").and_then(|s| s.trim().parse().ok());
        let timestamp = get("t").and_then(|s| s.trim().parse().ok());
        let expiration = get("x").and_then(|s| s.trim().parse().ok());
        let copied_headers = get("z").map(|s| {
            s.split('|')
                .map(|h| h.trim().to_string())
                .collect()
        });

        Ok(DkimSignature {
            version,
            algorithm,
            signature,
            body_hash,
            header_canonicalization: header_canon,
            body_canonicalization: body_canon,
            domain,
            signed_headers,
            auid,
            body_length,
            selector,
            timestamp,
            expiration,
            copied_headers,
            raw_header: header_value.to_string(),
        })
    }
}

fn parse_canonicalization(
    s: &str,
) -> Result<(CanonicalizationMethod, CanonicalizationMethod), DkimParseError> {
    let parts: Vec<&str> = s.split('/').collect();
    let header = match parts[0].to_ascii_lowercase().as_str() {
        "simple" => CanonicalizationMethod::Simple,
        "relaxed" => CanonicalizationMethod::Relaxed,
        other => return Err(DkimParseError::InvalidCanon(other.into())),
    };
    let body = if parts.len() > 1 {
        match parts[1].to_ascii_lowercase().as_str() {
            "simple" => CanonicalizationMethod::Simple,
            "relaxed" => CanonicalizationMethod::Relaxed,
            other => return Err(DkimParseError::InvalidCanon(other.into())),
        }
    } else {
        CanonicalizationMethod::Simple // body defaults to simple
    };
    Ok((header, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_signature() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1",
        )
        .unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "sel1");
    }

    #[test]
    fn test_all_optional_tags() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; \
             h=from:to:subject; s=sel1; c=relaxed/relaxed; i=user@example.com; \
             l=100; t=1000000; x=2000000; z=From:test|To:test",
        )
        .unwrap();
        assert_eq!(
            sig.header_canonicalization,
            CanonicalizationMethod::Relaxed
        );
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.auid, "user@example.com");
        assert_eq!(sig.body_length, Some(100));
        assert_eq!(sig.timestamp, Some(1000000));
        assert_eq!(sig.expiration, Some(2000000));
    }

    #[test]
    fn test_missing_required_tag() {
        // Missing v=
        assert!(DkimSignature::parse(
            "a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"
        )
        .is_err());
    }

    #[test]
    fn test_duplicate_tag() {
        assert!(DkimSignature::parse(
            "v=1; v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"
        )
        .is_err());
    }

    #[test]
    fn test_invalid_algorithm() {
        assert!(DkimSignature::parse(
            "v=1; a=unknown; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1"
        )
        .is_err());
    }

    #[test]
    fn test_missing_from_in_h() {
        assert!(DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=to:subject; s=sel1"
        )
        .is_err());
    }

    #[test]
    fn test_auid_domain_mismatch() {
        assert!(DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1; i=user@other.com"
        ).is_err());
    }

    #[test]
    fn test_canon_parsing() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1; c=relaxed",
        )
        .unwrap();
        assert_eq!(
            sig.header_canonicalization,
            CanonicalizationMethod::Relaxed
        );
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
    }

    #[test]
    fn test_base64_with_whitespace() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVz dA==; bh=dGVz\n\tdA==; d=example.com; h=from; s=sel1",
        )
        .unwrap();
        assert_eq!(sig.signature, b"test");
        assert_eq!(sig.body_hash, b"test");
    }

    #[test]
    fn test_ed25519() {
        let sig = DkimSignature::parse(
            "v=1; a=ed25519-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1",
        )
        .unwrap();
        assert_eq!(sig.algorithm, Algorithm::Ed25519Sha256);
    }

    #[test]
    fn test_rsa_sha1() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha1; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=sel1",
        )
        .unwrap();
        assert_eq!(sig.algorithm, Algorithm::RsaSha1);
    }
}
