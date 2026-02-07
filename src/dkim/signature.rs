use std::collections::HashSet;
use std::fmt;

use base64::Engine;

use crate::common::domain;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// DKIM signature algorithm (RFC 6376 Section 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

impl Algorithm {
    fn parse(s: &str) -> Result<Self, DkimParseError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rsa-sha1" => Ok(Self::RsaSha1),
            "rsa-sha256" => Ok(Self::RsaSha256),
            "ed25519-sha256" => Ok(Self::Ed25519Sha256),
            other => Err(DkimParseError(format!("unknown algorithm: {other}"))),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RsaSha1 => write!(f, "rsa-sha1"),
            Self::RsaSha256 => write!(f, "rsa-sha256"),
            Self::Ed25519Sha256 => write!(f, "ed25519-sha256"),
        }
    }
}

/// Canonicalization method (RFC 6376 Section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizationMethod {
    Simple,
    Relaxed,
}

impl CanonicalizationMethod {
    fn parse(s: &str) -> Result<Self, DkimParseError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "simple" => Ok(Self::Simple),
            "relaxed" => Ok(Self::Relaxed),
            other => Err(DkimParseError(format!(
                "unknown canonicalization: {other}"
            ))),
        }
    }
}

impl fmt::Display for CanonicalizationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Simple => write!(f, "simple"),
            Self::Relaxed => write!(f, "relaxed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Parse error for DKIM signature headers. Maps to PermFail in verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("DKIM signature parse error: {0}")]
pub struct DkimParseError(pub String);

// ---------------------------------------------------------------------------
// DkimSignature
// ---------------------------------------------------------------------------

/// Parsed DKIM-Signature header (RFC 6376 Section 3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSignature {
    /// Version (must be 1).
    pub version: u32,
    /// Signing algorithm.
    pub algorithm: Algorithm,
    /// Signature data (decoded from base64).
    pub signature: Vec<u8>,
    /// Body hash (decoded from base64).
    pub body_hash: Vec<u8>,
    /// Signing domain (d=).
    pub domain: String,
    /// Selector (s=).
    pub selector: String,
    /// Signed header fields (h=), preserved in original order.
    pub signed_headers: Vec<String>,
    /// Header canonicalization method.
    pub header_canonicalization: CanonicalizationMethod,
    /// Body canonicalization method.
    pub body_canonicalization: CanonicalizationMethod,
    /// Agent or User Identifier (i=). Defaults to `@<domain>`.
    pub auid: String,
    /// Body length limit (l=).
    pub body_length: Option<u64>,
    /// Query methods (q=). Default "dns/txt".
    pub query_methods: String,
    /// Signature timestamp (t=).
    pub timestamp: Option<u64>,
    /// Signature expiration (x=).
    pub expiration: Option<u64>,
    /// Copied header fields (z=), pipe-separated, each as (name, value).
    pub copied_headers: Vec<(String, String)>,
    /// The raw header value (after unfolding) for b= removal during verification.
    pub raw_header: String,
}

impl DkimSignature {
    /// Parse a DKIM-Signature header value.
    ///
    /// `header_value` is the value part after "DKIM-Signature:" (may contain
    /// folded lines with CRLF+WSP).
    pub fn parse(header_value: &str) -> Result<Self, DkimParseError> {
        // Unfold: replace CRLF followed by whitespace with a single space.
        let unfolded = unfold(header_value);
        let tags = parse_tag_value_list(&unfolded)?;

        // --- Required tags ---
        let v_str = require_tag(&tags, "v")?;
        let version: u32 = v_str
            .parse()
            .map_err(|_| DkimParseError(format!("invalid version: {v_str}")))?;
        if version != 1 {
            return Err(DkimParseError(format!(
                "unsupported DKIM version: {version}"
            )));
        }

        let a_str = require_tag(&tags, "a")?;
        let algorithm = Algorithm::parse(&a_str)?;

        let b_str = require_tag(&tags, "b")?;
        let signature = decode_base64(&b_str)?;

        let bh_str = require_tag(&tags, "bh")?;
        let body_hash = decode_base64(&bh_str)?;

        let d_val = require_tag(&tags, "d")?;
        let domain = d_val.trim().to_ascii_lowercase();

        let s_val = require_tag(&tags, "s")?;
        let selector = s_val.trim().to_ascii_lowercase();

        let h_val = require_tag(&tags, "h")?;
        let signed_headers: Vec<String> = h_val
            .split(':')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if signed_headers.is_empty() {
            return Err(DkimParseError("h= tag is empty".into()));
        }
        // h= must contain "from"
        if !signed_headers.iter().any(|h| h == "from") {
            return Err(DkimParseError(
                "h= tag must contain \"from\"".into(),
            ));
        }

        // --- Optional tags ---

        // c= canonicalization: header[/body], default simple/simple
        let (header_canon, body_canon) = if let Some(c_val) = tags.get("c") {
            parse_canonicalization(c_val)?
        } else {
            (CanonicalizationMethod::Simple, CanonicalizationMethod::Simple)
        };

        // i= AUID
        let auid = if let Some(i_val) = tags.get("i") {
            let i_trimmed = i_val.trim().to_string();
            // i= domain part must be subdomain of or equal to d=
            let i_domain = i_trimmed
                .rsplit_once('@')
                .map(|(_, d)| d)
                .unwrap_or(&i_trimmed);
            if !domain::is_subdomain_of(i_domain, &domain) {
                return Err(DkimParseError(format!(
                    "i= domain \"{i_domain}\" is not a subdomain of d= \"{domain}\""
                )));
            }
            i_trimmed
        } else {
            format!("@{domain}")
        };

        // l= body length
        let body_length = tags
            .get("l")
            .map(|v| {
                v.trim()
                    .parse::<u64>()
                    .map_err(|_| DkimParseError(format!("invalid l= value: {v}")))
            })
            .transpose()?;

        // q= query methods
        let query_methods = tags
            .get("q")
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| "dns/txt".to_string());

        // t= timestamp
        let timestamp = tags
            .get("t")
            .map(|v| {
                v.trim()
                    .parse::<u64>()
                    .map_err(|_| DkimParseError(format!("invalid t= value: {v}")))
            })
            .transpose()?;

        // x= expiration
        let expiration = tags
            .get("x")
            .map(|v| {
                v.trim()
                    .parse::<u64>()
                    .map_err(|_| DkimParseError(format!("invalid x= value: {v}")))
            })
            .transpose()?;

        // x= must be >= t= if both present (per spec)
        if let (Some(t), Some(x)) = (timestamp, expiration) {
            if x < t {
                return Err(DkimParseError(format!(
                    "x= ({x}) is less than t= ({t})"
                )));
            }
        }

        // z= copied headers: pipe-separated, each entry is "name:value"
        let copied_headers = tags
            .get("z")
            .map(|v| {
                v.split('|')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        if let Some((name, value)) = s.split_once(':') {
                            (name.trim().to_string(), value.trim().to_string())
                        } else {
                            (s.to_string(), String::new())
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(DkimSignature {
            version,
            algorithm,
            signature,
            body_hash,
            domain,
            selector,
            signed_headers,
            header_canonicalization: header_canon,
            body_canonicalization: body_canon,
            auid,
            body_length,
            query_methods,
            timestamp,
            expiration,
            copied_headers,
            raw_header: unfolded,
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Unfold CRLF+WSP sequences (RFC 5322 header folding).
fn unfold(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if i + 2 < len && bytes[i] == b'\r' && bytes[i + 1] == b'\n' && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t') {
            // Replace CRLF+WSP with a single space
            result.push(' ');
            i += 3;
            // Skip any additional WSP after the fold
            while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// Ordered map preserving insertion order for tags. We use a Vec of tuples
/// with duplicate detection.
type TagMap = std::collections::HashMap<String, String>;

/// Parse `tag=value` list separated by semicolons.
/// Returns PermFail on duplicate tags.
fn parse_tag_value_list(input: &str) -> Result<TagMap, DkimParseError> {
    let mut tags = TagMap::new();
    let mut seen = HashSet::new();

    for pair in input.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (tag, value) = pair
            .split_once('=')
            .ok_or_else(|| DkimParseError(format!("malformed tag=value: {pair}")))?;
        let tag = tag.trim().to_ascii_lowercase();
        let value = value.trim().to_string();

        if !seen.insert(tag.clone()) {
            return Err(DkimParseError(format!("duplicate tag: {tag}")));
        }
        tags.insert(tag, value);
    }
    Ok(tags)
}

/// Get a required tag or return parse error.
fn require_tag(tags: &TagMap, name: &str) -> Result<String, DkimParseError> {
    tags.get(name)
        .cloned()
        .ok_or_else(|| DkimParseError(format!("missing required tag: {name}")))
}

/// Decode base64 with embedded whitespace stripped.
fn decode_base64(input: &str) -> Result<Vec<u8>, DkimParseError> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| DkimParseError(format!("invalid base64: {e}")))
}

/// Parse c= tag value into (header, body) canonicalization methods.
fn parse_canonicalization(
    val: &str,
) -> Result<(CanonicalizationMethod, CanonicalizationMethod), DkimParseError> {
    let val = val.trim();
    if let Some((header, body)) = val.split_once('/') {
        Ok((
            CanonicalizationMethod::parse(header)?,
            CanonicalizationMethod::parse(body)?,
        ))
    } else {
        // Only header specified; body defaults to simple
        Ok((CanonicalizationMethod::parse(val)?, CanonicalizationMethod::Simple))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid DKIM-Signature value for testing.
    fn minimal_sig() -> String {
        let b_val = base64::engine::general_purpose::STANDARD.encode(b"fakesig");
        let bh_val = base64::engine::general_purpose::STANDARD.encode(b"fakehash");
        format!("v=1; a=rsa-sha256; b={b_val}; bh={bh_val}; d=example.com; s=sel; h=from:to")
    }

    #[test]
    fn parse_minimal_valid() {
        let sig = DkimSignature::parse(&minimal_sig()).unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "sel");
        assert_eq!(sig.signed_headers, vec!["from", "to"]);
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(sig.auid, "@example.com");
        assert!(sig.body_length.is_none());
        assert!(sig.timestamp.is_none());
        assert!(sig.expiration.is_none());
        assert!(sig.copied_headers.is_empty());
        assert_eq!(sig.query_methods, "dns/txt");
        assert_eq!(sig.signature, b"fakesig");
        assert_eq!(sig.body_hash, b"fakehash");
    }

    #[test]
    fn parse_all_algorithms() {
        for (input, expected) in [
            ("rsa-sha1", Algorithm::RsaSha1),
            ("rsa-sha256", Algorithm::RsaSha256),
            ("ed25519-sha256", Algorithm::Ed25519Sha256),
        ] {
            let b = base64::engine::general_purpose::STANDARD.encode(b"s");
            let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
            let raw = format!("v=1; a={input}; b={b}; bh={bh}; d=d.com; s=s; h=from");
            let sig = DkimSignature::parse(&raw).unwrap();
            assert_eq!(sig.algorithm, expected);
        }
    }

    #[test]
    fn unknown_algorithm_fails() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=1; a=dsa-sha1; b={b}; bh={bh}; d=d.com; s=s; h=from");
        assert!(DkimSignature::parse(&raw).is_err());
    }

    #[test]
    fn missing_required_tag_v() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=s; h=from");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("missing required tag: v"), "{err}");
    }

    #[test]
    fn missing_required_tag_a() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=1; b={b}; bh={bh}; d=d.com; s=s; h=from");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("missing required tag: a"), "{err}");
    }

    #[test]
    fn missing_required_tag_b() {
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=1; a=rsa-sha256; bh={bh}; d=d.com; s=s; h=from");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("missing required tag: b"), "{err}");
    }

    #[test]
    fn missing_required_tag_bh() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let raw = format!("v=1; a=rsa-sha256; b={b}; d=d.com; s=s; h=from");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("missing required tag: bh"), "{err}");
    }

    #[test]
    fn missing_required_tag_d() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=1; a=rsa-sha256; b={b}; bh={bh}; s=s; h=from");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("missing required tag: d"), "{err}");
    }

    #[test]
    fn missing_required_tag_s() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; h=from");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("missing required tag: s"), "{err}");
    }

    #[test]
    fn missing_required_tag_h() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("missing required tag: h"), "{err}");
    }

    #[test]
    fn duplicate_tag_error() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; d=other.com");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("duplicate tag: d"), "{err}");
    }

    #[test]
    fn h_missing_from_error() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=to:subject");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("must contain \"from\""), "{err}");
    }

    #[test]
    fn h_from_case_insensitive() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        // "From" in mixed case should be accepted (lowered during parsing)
        let raw = format!("v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=To:From:Subject");
        let sig = DkimSignature::parse(&raw).unwrap();
        assert!(sig.signed_headers.contains(&"from".to_string()));
    }

    #[test]
    fn i_subdomain_valid() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=example.com; s=sel; h=from; i=user@mail.example.com"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.auid, "user@mail.example.com");
    }

    #[test]
    fn i_equal_to_d_valid() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=example.com; s=sel; h=from; i=user@example.com"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.auid, "user@example.com");
    }

    #[test]
    fn i_not_subdomain_error() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=example.com; s=sel; h=from; i=user@other.com"
        );
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("not a subdomain"), "{err}");
    }

    #[test]
    fn i_default_when_absent() {
        let sig = DkimSignature::parse(&minimal_sig()).unwrap();
        assert_eq!(sig.auid, "@example.com");
    }

    #[test]
    fn canonicalization_relaxed_relaxed() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; c=relaxed/relaxed"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Relaxed);
    }

    #[test]
    fn canonicalization_header_only_body_defaults_simple() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; c=relaxed"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
    }

    #[test]
    fn canonicalization_default_simple_simple() {
        let sig = DkimSignature::parse(&minimal_sig()).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
    }

    #[test]
    fn version_must_be_1() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!("v=2; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from");
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("unsupported DKIM version"), "{err}");
    }

    #[test]
    fn folded_header_unfolding() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        // Simulate folded header with CRLF + space
        let raw = format!(
            "v=1; a=rsa-sha256;\r\n b={b};\r\n\tbh={bh}; d=d.com; s=sel; h=from"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
    }

    #[test]
    fn base64_with_whitespace() {
        // Embed spaces/tabs/newlines in base64 value
        let b_raw = base64::engine::general_purpose::STANDARD.encode(b"fakesig");
        let b_spaced = format!("{} {}", &b_raw[..4], &b_raw[4..]);
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b_spaced}; bh={bh}; d=d.com; s=sel; h=from"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.signature, b"fakesig");
    }

    #[test]
    fn z_tag_parsed() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; z=From:foo|To:bar|Subject:baz"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(
            sig.copied_headers,
            vec![
                ("From".to_string(), "foo".to_string()),
                ("To".to_string(), "bar".to_string()),
                ("Subject".to_string(), "baz".to_string()),
            ]
        );
    }

    #[test]
    fn timestamp_and_expiration() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; t=1000; x=2000"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.timestamp, Some(1000));
        assert_eq!(sig.expiration, Some(2000));
    }

    #[test]
    fn expiration_before_timestamp_error() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; t=2000; x=1000"
        );
        let err = DkimSignature::parse(&raw).unwrap_err();
        assert!(err.0.contains("x= (1000) is less than t= (2000)"), "{err}");
    }

    #[test]
    fn body_length_parsed() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; l=1024"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.body_length, Some(1024));
    }

    #[test]
    fn unknown_tags_ignored() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; foo=bar; xyz=123"
        );
        // Should not error on unknown tags
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.domain, "d.com");
    }

    #[test]
    fn trailing_semicolon_ok() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from;"
        );
        assert!(DkimSignature::parse(&raw).is_ok());
    }

    #[test]
    fn whitespace_tolerance() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "  v = 1 ;  a = rsa-sha256 ;  b = {b} ;  bh = {bh} ;  d = d.com ;  s = sel ;  h = from  "
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.domain, "d.com");
    }

    #[test]
    fn display_algorithm() {
        assert_eq!(Algorithm::RsaSha1.to_string(), "rsa-sha1");
        assert_eq!(Algorithm::RsaSha256.to_string(), "rsa-sha256");
        assert_eq!(Algorithm::Ed25519Sha256.to_string(), "ed25519-sha256");
    }

    #[test]
    fn display_canonicalization() {
        assert_eq!(CanonicalizationMethod::Simple.to_string(), "simple");
        assert_eq!(CanonicalizationMethod::Relaxed.to_string(), "relaxed");
    }

    #[test]
    fn ed25519_algorithm() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=ed25519-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.algorithm, Algorithm::Ed25519Sha256);
    }

    #[test]
    fn query_method_override() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"s");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"h");
        let raw = format!(
            "v=1; a=rsa-sha256; b={b}; bh={bh}; d=d.com; s=sel; h=from; q=dns/txt"
        );
        let sig = DkimSignature::parse(&raw).unwrap();
        assert_eq!(sig.query_methods, "dns/txt");
    }

    #[test]
    fn malformed_tag_value_error() {
        let raw = "v=1; this_has_no_equals; a=rsa-sha256";
        let err = DkimSignature::parse(raw).unwrap_err();
        assert!(err.0.contains("malformed tag=value"), "{err}");
    }

    #[test]
    fn unfold_crlf_tab() {
        let input = "hello\r\n\tworld";
        assert_eq!(unfold(input), "hello world");
    }

    #[test]
    fn unfold_crlf_space() {
        let input = "hello\r\n world";
        assert_eq!(unfold(input), "hello world");
    }

    #[test]
    fn unfold_multiple_wsp() {
        let input = "hello\r\n   world";
        assert_eq!(unfold(input), "hello world");
    }

    #[test]
    fn unfold_no_folding() {
        let input = "hello world";
        assert_eq!(unfold(input), "hello world");
    }
}
