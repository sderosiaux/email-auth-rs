use super::DkimError;
use base64::{engine::general_purpose::STANDARD, Engine};

/// DKIM signing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

impl Algorithm {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rsa-sha1" => Some(Self::RsaSha1),
            "rsa-sha256" => Some(Self::RsaSha256),
            "ed25519-sha256" => Some(Self::Ed25519Sha256),
            _ => None,
        }
    }
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

impl Canonicalization {
    pub fn from_str(s: &str) -> Self {
        let parts: Vec<&str> = s.split('/').collect();
        let header = match parts.first().map(|s| s.to_lowercase()).as_deref() {
            Some("relaxed") => CanonicalizationMethod::Relaxed,
            _ => CanonicalizationMethod::Simple,
        };
        let body = match parts.get(1).map(|s| s.to_lowercase()).as_deref() {
            Some("relaxed") => CanonicalizationMethod::Relaxed,
            _ => CanonicalizationMethod::Simple,
        };
        Self { header, body }
    }
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
    pub signed_headers: Vec<String>,
    pub auid: Option<String>,
    pub body_length: Option<u64>,
    pub selector: String,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
}

impl DkimSignature {
    /// Parse a DKIM-Signature header value
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

        // Unfold header (remove CRLF + whitespace)
        let unfolded = Self::unfold(value);

        // Parse tag=value pairs
        for part in unfolded.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = part
                .split_once('=')
                .ok_or_else(|| DkimError::Parse(format!("invalid tag-value: {}", part)))?;

            let tag = tag.trim().to_lowercase();
            let val = val.trim();

            match tag.as_str() {
                "v" => {
                    version = Some(
                        val.parse()
                            .map_err(|_| DkimError::Parse("invalid version".to_string()))?,
                    );
                }
                "a" => {
                    algorithm = Algorithm::from_str(val);
                    if algorithm.is_none() {
                        return Err(DkimError::Parse(format!("unknown algorithm: {}", val)));
                    }
                }
                "b" => {
                    // Remove whitespace from base64
                    let cleaned: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                    signature = Some(
                        STANDARD
                            .decode(&cleaned)
                            .map_err(|e| DkimError::Parse(format!("invalid b= base64: {}", e)))?,
                    );
                }
                "bh" => {
                    let cleaned: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                    body_hash = Some(
                        STANDARD
                            .decode(&cleaned)
                            .map_err(|e| DkimError::Parse(format!("invalid bh= base64: {}", e)))?,
                    );
                }
                "c" => {
                    canonicalization = Canonicalization::from_str(val);
                }
                "d" => {
                    domain = Some(val.to_string());
                }
                "h" => {
                    signed_headers = Some(
                        val.split(':')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect(),
                    );
                }
                "i" => {
                    auid = Some(val.to_string());
                }
                "l" => {
                    body_length = Some(
                        val.parse()
                            .map_err(|_| DkimError::Parse("invalid l= value".to_string()))?,
                    );
                }
                "s" => {
                    selector = Some(val.to_string());
                }
                "t" => {
                    timestamp = Some(
                        val.parse()
                            .map_err(|_| DkimError::Parse("invalid t= value".to_string()))?,
                    );
                }
                "x" => {
                    expiration = Some(
                        val.parse()
                            .map_err(|_| DkimError::Parse("invalid x= value".to_string()))?,
                    );
                }
                "q" | "z" => {
                    // Ignore q= (query method) and z= (copied headers)
                }
                _ => {
                    // Ignore unknown tags for forward compatibility
                }
            }
        }

        // Validate required fields
        let version = version.ok_or_else(|| DkimError::Parse("missing v= tag".to_string()))?;
        if version != 1 {
            return Err(DkimError::Parse(format!("unsupported version: {}", version)));
        }

        let algorithm = algorithm.ok_or_else(|| DkimError::Parse("missing a= tag".to_string()))?;
        let signature = signature.ok_or_else(|| DkimError::Parse("missing b= tag".to_string()))?;
        let body_hash = body_hash.ok_or_else(|| DkimError::Parse("missing bh= tag".to_string()))?;
        let domain = domain.ok_or_else(|| DkimError::Parse("missing d= tag".to_string()))?;
        let signed_headers = signed_headers.ok_or_else(|| DkimError::Parse("missing h= tag".to_string()))?;
        let selector = selector.ok_or_else(|| DkimError::Parse("missing s= tag".to_string()))?;

        // h= must include "from"
        if !signed_headers.iter().any(|h| h.to_lowercase() == "from") {
            return Err(DkimError::Parse("h= must include 'from'".to_string()));
        }

        // x= must be >= t= if both present
        if let (Some(t), Some(x)) = (timestamp, expiration) {
            if x < t {
                return Err(DkimError::Parse("x= must be >= t=".to_string()));
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

    fn unfold(s: &str) -> String {
        // Remove CRLF followed by whitespace (header folding)
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next(); // consume \n
                // Skip following whitespace but keep at least one space
                let mut had_ws = false;
                while let Some(&ws) = chars.peek() {
                    if ws == ' ' || ws == '\t' {
                        had_ws = true;
                        chars.next();
                    } else {
                        break;
                    }
                }
                if had_ws {
                    result.push(' ');
                }
            } else if c == '\n' {
                // Handle LF-only folding
                let mut had_ws = false;
                while let Some(&ws) = chars.peek() {
                    if ws == ' ' || ws == '\t' {
                        had_ws = true;
                        chars.next();
                    } else {
                        break;
                    }
                }
                if had_ws {
                    result.push(' ');
                }
            } else {
                result.push(c);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signature() {
        // Use valid base64 for bh= and b= (these decode to "bodyhash" and "signature")
        let sig = "v=1; a=rsa-sha256; d=example.com; s=selector; \
                   h=from:to:subject; bh=Ym9keWhhc2g=; b=c2lnbmF0dXJl";

        let parsed = DkimSignature::parse(sig).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.algorithm, Algorithm::RsaSha256);
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.selector, "selector");
        assert_eq!(parsed.signed_headers, vec!["from", "to", "subject"]);
    }

    #[test]
    fn test_canonicalization_parsing() {
        let c = Canonicalization::from_str("relaxed/relaxed");
        assert_eq!(c.header, CanonicalizationMethod::Relaxed);
        assert_eq!(c.body, CanonicalizationMethod::Relaxed);

        let c = Canonicalization::from_str("simple");
        assert_eq!(c.header, CanonicalizationMethod::Simple);
        assert_eq!(c.body, CanonicalizationMethod::Simple);

        let c = Canonicalization::from_str("relaxed");
        assert_eq!(c.header, CanonicalizationMethod::Relaxed);
        assert_eq!(c.body, CanonicalizationMethod::Simple);
    }

    #[test]
    fn test_unfold() {
        let folded = "v=1; a=rsa-sha256;\r\n d=example.com";
        let unfolded = DkimSignature::unfold(folded);
        assert!(unfolded.contains("d=example.com"));
        assert!(!unfolded.contains("\r\n"));
    }

    #[test]
    fn test_missing_from_header() {
        let sig = "v=1; a=rsa-sha256; d=example.com; s=selector; \
                   h=to:subject; bh=Ym9keWhhc2g=; b=c2lnbmF0dXJl";

        let result = DkimSignature::parse(sig);
        assert!(result.is_err());
    }
}
