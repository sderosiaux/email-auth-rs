use base64::Engine;
use super::{Algorithm, CanonicalizationMethod};
use crate::common::domain;

/// Parsed DKIM-Signature header.
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

impl DkimSignature {
    /// Parse a DKIM-Signature header value.
    pub fn parse(header_value: &str) -> Result<Self, String> {
        let raw_header = header_value.to_string();

        // Unfold header (remove CRLF before whitespace)
        let unfolded = header_value
            .replace("\r\n ", " ")
            .replace("\r\n\t", "\t");

        // Parse tag=value pairs
        let tags = parse_tags(&unfolded)?;

        // Check for duplicate tags
        {
            let mut seen = std::collections::HashSet::new();
            for (name, _) in &tags {
                if !seen.insert(name.as_str()) {
                    return Err(format!("duplicate tag: {}", name));
                }
            }
        }

        let get = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        // Required tags
        let version: u8 = get("v")
            .ok_or("missing v= tag")?
            .trim()
            .parse()
            .map_err(|_| "invalid v= value")?;
        if version != 1 {
            return Err(format!("unsupported DKIM version: {}", version));
        }

        let algorithm = Algorithm::parse(get("a").ok_or("missing a= tag")?.trim())?;

        let sig_b64 = get("b").ok_or("missing b= tag")?;
        let sig_clean: String = sig_b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&sig_clean)
            .map_err(|e| format!("invalid b= base64: {}", e))?;

        let bh_b64 = get("bh").ok_or("missing bh= tag")?;
        let bh_clean: String = bh_b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let body_hash = base64::engine::general_purpose::STANDARD
            .decode(&bh_clean)
            .map_err(|e| format!("invalid bh= base64: {}", e))?;

        let dkim_domain = get("d").ok_or("missing d= tag")?.trim().to_string();
        let selector = get("s").ok_or("missing s= tag")?.trim().to_string();

        let h_value = get("h").ok_or("missing h= tag")?;
        let signed_headers: Vec<String> = h_value
            .split(':')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // h= must include "from"
        if !signed_headers.iter().any(|h| h.eq_ignore_ascii_case("from")) {
            return Err("h= must include From header".to_string());
        }

        // Optional tags
        let (header_canon, body_canon) = if let Some(c) = get("c") {
            parse_canonicalization(c.trim())?
        } else {
            (CanonicalizationMethod::Simple, CanonicalizationMethod::Simple)
        };

        let auid = if let Some(i) = get("i") {
            let i = i.trim().to_string();
            // Validate i= is subdomain of or equal to d=
            if let Some(i_domain) = domain::domain_from_email(&i) {
                if !domain::is_subdomain_of(i_domain, &dkim_domain) {
                    return Err(format!(
                        "i= domain {} is not subdomain of d= {}",
                        i_domain, dkim_domain
                    ));
                }
            }
            i
        } else {
            format!("@{}", dkim_domain)
        };

        let body_length = get("l").and_then(|v| v.trim().parse().ok());
        let timestamp = get("t").and_then(|v| v.trim().parse().ok());
        let expiration = get("x").and_then(|v| v.trim().parse().ok());

        // Validate x >= t if both present
        if let (Some(t), Some(x)) = (timestamp, expiration) {
            if x < t {
                return Err("x= must be >= t=".to_string());
            }
        }

        let copied_headers = get("z").map(|v| {
            v.split('|')
                .map(|s| s.trim().to_string())
                .collect()
        });

        Ok(DkimSignature {
            version,
            algorithm,
            signature,
            body_hash,
            header_canonicalization: header_canon,
            body_canonicalization: body_canon,
            domain: dkim_domain,
            signed_headers,
            auid,
            body_length,
            selector,
            timestamp,
            expiration,
            copied_headers,
            raw_header,
        })
    }
}

fn parse_canonicalization(
    s: &str,
) -> Result<(CanonicalizationMethod, CanonicalizationMethod), String> {
    let parts: Vec<&str> = s.splitn(2, '/').collect();
    let header = match parts[0].to_ascii_lowercase().as_str() {
        "simple" => CanonicalizationMethod::Simple,
        "relaxed" => CanonicalizationMethod::Relaxed,
        _ => return Err(format!("unknown canonicalization: {}", parts[0])),
    };
    let body = if parts.len() > 1 {
        match parts[1].to_ascii_lowercase().as_str() {
            "simple" => CanonicalizationMethod::Simple,
            "relaxed" => CanonicalizationMethod::Relaxed,
            _ => return Err(format!("unknown body canonicalization: {}", parts[1])),
        }
    } else {
        CanonicalizationMethod::Simple
    };
    Ok((header, body))
}

fn parse_tags(s: &str) -> Result<Vec<(String, String)>, String> {
    let mut tags = Vec::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(eq) = part.find('=') {
            let name = part[..eq].trim().to_string();
            let value = part[eq + 1..].trim().to_string();
            tags.push((name, value));
        }
    }
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from:to",
        )
        .unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "sel1");
        assert_eq!(sig.signed_headers, vec!["from", "to"]);
    }

    #[test]
    fn test_parse_with_canonicalization() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from; c=relaxed/relaxed",
        )
        .unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Relaxed);
    }

    #[test]
    fn test_parse_c_header_only() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from; c=relaxed",
        )
        .unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
    }

    #[test]
    fn test_missing_required_tag() {
        assert!(DkimSignature::parse("v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1").is_err());
    }

    #[test]
    fn test_duplicate_tag() {
        assert!(DkimSignature::parse(
            "v=1; a=rsa-sha256; a=ed25519-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from",
        ).is_err());
    }

    #[test]
    fn test_h_missing_from() {
        assert!(DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=to:subject",
        ).is_err());
    }

    #[test]
    fn test_i_not_subdomain() {
        assert!(DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from; i=user@other.com",
        ).is_err());
    }

    #[test]
    fn test_i_subdomain_ok() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from; i=user@sub.example.com",
        ).unwrap();
        assert_eq!(sig.auid, "user@sub.example.com");
    }

    #[test]
    fn test_default_i() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from",
        ).unwrap();
        assert_eq!(sig.auid, "@example.com");
    }

    #[test]
    fn test_base64_with_whitespace() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVz\r\n dA==; bh=dGVzdA==; d=example.com; s=sel1; h=from",
        ).unwrap();
        assert_eq!(sig.signature, b"test");
    }

    #[test]
    fn test_unknown_tag_ignored() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from; x-custom=value",
        ).unwrap();
        assert_eq!(sig.domain, "example.com");
    }

    #[test]
    fn test_unknown_algorithm() {
        assert!(DkimSignature::parse(
            "v=1; a=unknown-algo; b=dGVzdA==; bh=dGVzdA==; d=example.com; s=sel1; h=from",
        ).is_err());
    }
}
