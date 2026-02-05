//! DKIM signature parsing.

use super::DkimError;
use base64::Engine;

/// DKIM signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

impl Algorithm {
    fn from_str(s: &str) -> Result<Self, DkimError> {
        match s.to_lowercase().as_str() {
            "rsa-sha1" => Ok(Algorithm::RsaSha1),
            "rsa-sha256" => Ok(Algorithm::RsaSha256),
            "ed25519-sha256" => Ok(Algorithm::Ed25519Sha256),
            _ => Err(DkimError::InvalidSignature(format!(
                "unknown algorithm: {}",
                s
            ))),
        }
    }
}

/// Canonicalization method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CanonicalizationMethod {
    #[default]
    Simple,
    Relaxed,
}

/// Header and body canonicalization settings.
#[derive(Debug, Clone, Copy, Default)]
pub struct Canonicalization {
    pub header: CanonicalizationMethod,
    pub body: CanonicalizationMethod,
}

impl Canonicalization {
    fn parse(s: &str) -> Result<Self, DkimError> {
        let parts: Vec<&str> = s.split('/').collect();
        let header = match parts.first().map(|s| s.to_lowercase()).as_deref() {
            Some("simple") | None => CanonicalizationMethod::Simple,
            Some("relaxed") => CanonicalizationMethod::Relaxed,
            Some(other) => {
                return Err(DkimError::InvalidSignature(format!(
                    "unknown canonicalization: {}",
                    other
                )))
            }
        };
        let body = match parts.get(1).map(|s| s.to_lowercase()).as_deref() {
            Some("simple") | None => CanonicalizationMethod::Simple,
            Some("relaxed") => CanonicalizationMethod::Relaxed,
            Some(other) => {
                return Err(DkimError::InvalidSignature(format!(
                    "unknown canonicalization: {}",
                    other
                )))
            }
        };
        Ok(Self { header, body })
    }
}

/// Parsed DKIM-Signature header.
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
    /// Parse a DKIM-Signature header value.
    pub fn parse(value: &str) -> Result<Self, DkimError> {
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

        // Parse tag=value pairs
        for part in value.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = match part.split_once('=') {
                Some((t, v)) => (t.trim(), v.trim()),
                None => continue,
            };

            match tag.to_lowercase().as_str() {
                "v" => {
                    version = Some(
                        val.parse()
                            .map_err(|_| DkimError::InvalidSignature("invalid version".into()))?,
                    );
                }
                "a" => {
                    algorithm = Some(Algorithm::from_str(val)?);
                }
                "b" => {
                    // Remove whitespace from base64
                    let clean: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                    signature = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&clean)
                            .map_err(|e| {
                                DkimError::InvalidSignature(format!("invalid b= base64: {}", e))
                            })?,
                    );
                }
                "bh" => {
                    let clean: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                    body_hash = Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(&clean)
                            .map_err(|e| {
                                DkimError::InvalidSignature(format!("invalid bh= base64: {}", e))
                            })?,
                    );
                }
                "c" => {
                    canonicalization = Canonicalization::parse(val)?;
                }
                "d" => {
                    domain = Some(val.to_lowercase());
                }
                "h" => {
                    signed_headers = Some(
                        val.split(':')
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    );
                }
                "i" => {
                    auid = Some(val.to_string());
                }
                "l" => {
                    body_length = Some(val.parse().map_err(|_| {
                        DkimError::InvalidSignature("invalid l= value".into())
                    })?);
                }
                "s" => {
                    selector = Some(val.to_string());
                }
                "t" => {
                    timestamp = Some(val.parse().map_err(|_| {
                        DkimError::InvalidSignature("invalid t= value".into())
                    })?);
                }
                "x" => {
                    expiration = Some(val.parse().map_err(|_| {
                        DkimError::InvalidSignature("invalid x= value".into())
                    })?);
                }
                _ => {} // Ignore unknown tags
            }
        }

        // Check required tags
        let version =
            version.ok_or_else(|| DkimError::InvalidSignature("missing v= tag".into()))?;
        if version != 1 {
            return Err(DkimError::InvalidSignature(format!(
                "unsupported version: {}",
                version
            )));
        }

        let algorithm =
            algorithm.ok_or_else(|| DkimError::InvalidSignature("missing a= tag".into()))?;
        let signature =
            signature.ok_or_else(|| DkimError::InvalidSignature("missing b= tag".into()))?;
        let body_hash =
            body_hash.ok_or_else(|| DkimError::InvalidSignature("missing bh= tag".into()))?;
        let domain = domain.ok_or_else(|| DkimError::InvalidSignature("missing d= tag".into()))?;
        let signed_headers =
            signed_headers.ok_or_else(|| DkimError::InvalidSignature("missing h= tag".into()))?;
        let selector =
            selector.ok_or_else(|| DkimError::InvalidSignature("missing s= tag".into()))?;

        // h= must include "from"
        if !signed_headers.iter().any(|h| h == "from") {
            return Err(DkimError::InvalidSignature(
                "h= must include from header".into(),
            ));
        }

        // Check i= is subdomain of d=
        if let Some(ref auid) = auid {
            let auid_domain = auid.rsplit_once('@').map(|(_, d)| d).unwrap_or(auid);
            if !crate::common::domain::is_subdomain_of(auid_domain, &domain) {
                return Err(DkimError::InvalidSignature(
                    "i= not subdomain of d=".into(),
                ));
            }
        }

        Ok(Self {
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
    fn test_parse_minimal_signature() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; \
             h=from:to:subject; bh=abc123==; b=def456==",
        );
        // Will fail due to invalid base64, but tests parsing flow
        assert!(sig.is_err()); // base64 is invalid

        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; \
             h=from:to:subject; bh=MTIz; b=NDU2",
        )
        .unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "selector");
    }

    #[test]
    fn test_parse_canonicalization() {
        let c = Canonicalization::parse("relaxed/simple").unwrap();
        assert_eq!(c.header, CanonicalizationMethod::Relaxed);
        assert_eq!(c.body, CanonicalizationMethod::Simple);

        let c = Canonicalization::parse("simple").unwrap();
        assert_eq!(c.header, CanonicalizationMethod::Simple);
        assert_eq!(c.body, CanonicalizationMethod::Simple);
    }

    #[test]
    fn test_missing_from_in_h() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; d=example.com; s=selector; \
             h=to:subject; bh=MTIz; b=NDU2",
        );
        assert!(sig.is_err());
    }
}
