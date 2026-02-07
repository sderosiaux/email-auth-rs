// ---------------------------------------------------------------------------
// ARC header parsing (RFC 8617)
// ---------------------------------------------------------------------------

use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::{BTreeMap, HashSet};

use crate::dkim::signature::{Algorithm, CanonicalizationMethod};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcParseError {
    MissingTag(String),
    DuplicateTag(String),
    InvalidInstance(String),
    InvalidAlgorithm(String),
    InvalidBase64(String),
    InvalidCv(String),
    ForbiddenTag(String),
    ForbiddenHeader(String),
}

impl std::fmt::Display for ArcParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTag(s) => write!(f, "missing tag: {}", s),
            Self::DuplicateTag(s) => write!(f, "duplicate tag: {}", s),
            Self::InvalidInstance(s) => write!(f, "invalid instance: {}", s),
            Self::InvalidAlgorithm(s) => write!(f, "invalid algorithm: {}", s),
            Self::InvalidBase64(s) => write!(f, "invalid base64: {}", s),
            Self::InvalidCv(s) => write!(f, "invalid cv: {}", s),
            Self::ForbiddenTag(s) => write!(f, "forbidden tag: {}", s),
            Self::ForbiddenHeader(s) => write!(f, "forbidden header: {}", s),
        }
    }
}

impl std::error::Error for ArcParseError {}

// ---------------------------------------------------------------------------
// Chain validation status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainValidationStatus {
    /// cv=none — valid only for instance 1
    None,
    /// cv=pass — valid for instance > 1
    Pass,
    /// cv=fail
    Fail,
}

impl std::fmt::Display for ChainValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
        }
    }
}

// ---------------------------------------------------------------------------
// ARC header types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcAuthenticationResults {
    pub instance: u32,
    /// Raw authres content after "i=N;"
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcMessageSignature {
    pub instance: u32,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub domain: String,
    pub selector: String,
    pub signed_headers: Vec<String>,
    pub header_canonicalization: CanonicalizationMethod,
    pub body_canonicalization: CanonicalizationMethod,
    pub timestamp: Option<u64>,
    pub body_length: Option<u64>,
    /// Original header value for b= stripping during verification
    pub raw_header: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcSeal {
    pub instance: u32,
    pub cv: ChainValidationStatus,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub domain: String,
    pub selector: String,
    pub timestamp: Option<u64>,
    /// Original header value for b= stripping
    pub raw_header: String,
}

#[derive(Debug, Clone)]
pub struct ArcSet {
    pub instance: u32,
    pub aar: ArcAuthenticationResults,
    pub ams: ArcMessageSignature,
    pub seal: ArcSeal,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse tag=value list (RFC 6376 Section 3.2). Checks for duplicate tags.
fn parse_tag_value_list(input: &str) -> Result<Vec<(String, String)>, ArcParseError> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for pair in input.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((tag, value)) = pair.split_once('=') {
            let tag = tag.trim().to_string();
            if !seen.insert(tag.clone()) {
                return Err(ArcParseError::DuplicateTag(tag));
            }
            result.push((tag, value.trim().to_string()));
        }
    }
    Ok(result)
}

/// Lookup helper over parsed tag list.
fn find_tag<'a>(tags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(t, _)| t == name)
        .map(|(_, v)| v.as_str())
}

/// Strip all whitespace from base64 then decode.
fn decode_base64_permissive(val: &str) -> Result<Vec<u8>, ArcParseError> {
    let cleaned: String = val.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD
        .decode(&cleaned)
        .map_err(|e| ArcParseError::InvalidBase64(e.to_string()))
}

/// Parse `a=` tag value into Algorithm.
fn parse_algorithm(val: &str) -> Result<Algorithm, ArcParseError> {
    match val {
        "rsa-sha1" => Ok(Algorithm::RsaSha1),
        "rsa-sha256" => Ok(Algorithm::RsaSha256),
        "ed25519-sha256" => Ok(Algorithm::Ed25519Sha256),
        other => Err(ArcParseError::InvalidAlgorithm(other.to_string())),
    }
}

/// Parse and validate instance value (must be 1..=50).
fn parse_instance(val: &str) -> Result<u32, ArcParseError> {
    let n: u32 = val
        .trim()
        .parse()
        .map_err(|_| ArcParseError::InvalidInstance(val.to_string()))?;
    if !(1..=50).contains(&n) {
        return Err(ArcParseError::InvalidInstance(format!(
            "{} (must be 1-50)",
            n
        )));
    }
    Ok(n)
}

/// Parse `c=` tag into (header, body) canonicalization methods.
fn parse_canonicalization(
    val: &str,
) -> Result<(CanonicalizationMethod, CanonicalizationMethod), ArcParseError> {
    let parse_one = |s: &str| -> Result<CanonicalizationMethod, ArcParseError> {
        match s.trim() {
            "simple" => Ok(CanonicalizationMethod::Simple),
            "relaxed" => Ok(CanonicalizationMethod::Relaxed),
            other => Err(ArcParseError::InvalidAlgorithm(format!(
                "unknown canonicalization: {}",
                other
            ))),
        }
    };
    let parts: Vec<&str> = val.split('/').collect();
    match parts.len() {
        1 => {
            let header = parse_one(parts[0])?;
            Ok((header, CanonicalizationMethod::Simple))
        }
        2 => {
            let header = parse_one(parts[0])?;
            let body = parse_one(parts[1])?;
            Ok((header, body))
        }
        _ => Err(ArcParseError::InvalidAlgorithm(
            "invalid c= format".to_string(),
        )),
    }
}

/// Unfold header: remove CRLF+WSP sequences per RFC 5322.
fn unfold(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if i + 2 < len
            && bytes[i] == b'\r'
            && bytes[i + 1] == b'\n'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t')
        {
            i += 2; // skip CRLF, keep the following WSP
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Headers that MUST NOT appear in the AMS h= list (case-insensitive).
const FORBIDDEN_AMS_HEADERS: &[&str] = &[
    "arc-authentication-results",
    "arc-message-signature",
    "arc-seal",
    "authentication-results",
];

// ---------------------------------------------------------------------------
// ArcAuthenticationResults::parse
// ---------------------------------------------------------------------------

impl ArcAuthenticationResults {
    /// Parse an ARC-Authentication-Results header value.
    ///
    /// Format: `i=<N>; <authres payload>`
    /// The header_value is everything after "ARC-Authentication-Results:".
    pub fn parse(header_value: &str) -> Result<Self, ArcParseError> {
        let unfolded = unfold(header_value);
        let trimmed = unfolded.trim();

        // Find the first semicolon — everything before it must contain i=N.
        let first_semi = trimmed
            .find(';')
            .ok_or_else(|| ArcParseError::MissingTag("i".to_string()))?;

        let i_part = trimmed[..first_semi].trim();
        let payload_part = trimmed[first_semi + 1..].trim();

        let (tag, val) = i_part
            .split_once('=')
            .ok_or_else(|| ArcParseError::MissingTag("i".to_string()))?;

        if tag.trim() != "i" {
            return Err(ArcParseError::MissingTag("i".to_string()));
        }

        let instance = parse_instance(val)?;

        Ok(ArcAuthenticationResults {
            instance,
            payload: payload_part.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// ArcMessageSignature::parse
// ---------------------------------------------------------------------------

impl ArcMessageSignature {
    /// Parse an ARC-Message-Signature header value (everything after
    /// "ARC-Message-Signature:").
    ///
    /// Required tags: i, a, b, bh, d, s, h.
    /// Optional: c (default relaxed/relaxed), t, l.
    pub fn parse(header_value: &str) -> Result<Self, ArcParseError> {
        let unfolded = unfold(header_value);
        let tags = parse_tag_value_list(&unfolded)?;

        // i= (required, 1-50)
        let instance = parse_instance(
            find_tag(&tags, "i").ok_or_else(|| ArcParseError::MissingTag("i".to_string()))?,
        )?;

        // a= (required)
        let algorithm = parse_algorithm(
            find_tag(&tags, "a").ok_or_else(|| ArcParseError::MissingTag("a".to_string()))?,
        )?;

        // b= (required)
        let b_raw =
            find_tag(&tags, "b").ok_or_else(|| ArcParseError::MissingTag("b".to_string()))?;
        let signature = decode_base64_permissive(b_raw)?;

        // bh= (required)
        let bh_raw =
            find_tag(&tags, "bh").ok_or_else(|| ArcParseError::MissingTag("bh".to_string()))?;
        let body_hash = decode_base64_permissive(bh_raw)?;

        // d= (required)
        let domain = find_tag(&tags, "d")
            .ok_or_else(|| ArcParseError::MissingTag("d".to_string()))?
            .to_ascii_lowercase();

        // s= (required)
        let selector = find_tag(&tags, "s")
            .ok_or_else(|| ArcParseError::MissingTag("s".to_string()))?
            .to_string();

        // h= (required)
        let h_raw =
            find_tag(&tags, "h").ok_or_else(|| ArcParseError::MissingTag("h".to_string()))?;
        let signed_headers: Vec<String> = h_raw
            .split(':')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // h= MUST NOT include ARC headers or Authentication-Results
        for hdr in &signed_headers {
            let lower = hdr.to_ascii_lowercase();
            if FORBIDDEN_AMS_HEADERS.contains(&lower.as_str()) {
                return Err(ArcParseError::ForbiddenHeader(format!(
                    "{} must not appear in AMS h= list",
                    hdr
                )));
            }
        }

        // c= (optional, default relaxed/relaxed for ARC — unlike DKIM's simple/simple)
        let (header_canonicalization, body_canonicalization) =
            if let Some(c_raw) = find_tag(&tags, "c") {
                parse_canonicalization(c_raw)?
            } else {
                (
                    CanonicalizationMethod::Relaxed,
                    CanonicalizationMethod::Relaxed,
                )
            };

        // t= (optional)
        let timestamp = find_tag(&tags, "t")
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| ArcParseError::InvalidInstance(format!("bad t= value: {}", v)))
            })
            .transpose()?;

        // l= (optional)
        let body_length = find_tag(&tags, "l")
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| ArcParseError::InvalidInstance(format!("bad l= value: {}", v)))
            })
            .transpose()?;

        Ok(ArcMessageSignature {
            instance,
            algorithm,
            signature,
            body_hash,
            domain,
            selector,
            signed_headers,
            header_canonicalization,
            body_canonicalization,
            timestamp,
            body_length,
            raw_header: header_value.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// ArcSeal::parse
// ---------------------------------------------------------------------------

impl ArcSeal {
    /// Parse an ARC-Seal header value (everything after "ARC-Seal:").
    ///
    /// Required tags: i, cv, a, b, d, s.
    /// Optional: t.
    /// Forbidden: h.
    pub fn parse(header_value: &str) -> Result<Self, ArcParseError> {
        let unfolded = unfold(header_value);
        let tags = parse_tag_value_list(&unfolded)?;

        // h= is forbidden in ARC-Seal
        if find_tag(&tags, "h").is_some() {
            return Err(ArcParseError::ForbiddenTag(
                "h= not allowed in ARC-Seal".to_string(),
            ));
        }

        // i= (required, 1-50)
        let instance = parse_instance(
            find_tag(&tags, "i").ok_or_else(|| ArcParseError::MissingTag("i".to_string()))?,
        )?;

        // cv= (required)
        let cv_raw =
            find_tag(&tags, "cv").ok_or_else(|| ArcParseError::MissingTag("cv".to_string()))?;
        let cv = match cv_raw {
            "none" => ChainValidationStatus::None,
            "pass" => ChainValidationStatus::Pass,
            "fail" => ChainValidationStatus::Fail,
            other => return Err(ArcParseError::InvalidCv(other.to_string())),
        };

        // a= (required)
        let algorithm = parse_algorithm(
            find_tag(&tags, "a").ok_or_else(|| ArcParseError::MissingTag("a".to_string()))?,
        )?;

        // b= (required)
        let b_raw =
            find_tag(&tags, "b").ok_or_else(|| ArcParseError::MissingTag("b".to_string()))?;
        let signature = decode_base64_permissive(b_raw)?;

        // d= (required)
        let domain = find_tag(&tags, "d")
            .ok_or_else(|| ArcParseError::MissingTag("d".to_string()))?
            .to_ascii_lowercase();

        // s= (required)
        let selector = find_tag(&tags, "s")
            .ok_or_else(|| ArcParseError::MissingTag("s".to_string()))?
            .to_string();

        // t= (optional)
        let timestamp = find_tag(&tags, "t")
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| ArcParseError::InvalidInstance(format!("bad t= value: {}", v)))
            })
            .transpose()?;

        Ok(ArcSeal {
            instance,
            cv,
            algorithm,
            signature,
            domain,
            selector,
            timestamp,
            raw_header: header_value.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// collect_arc_sets
// ---------------------------------------------------------------------------

/// Scan message headers for ARC-Authentication-Results, ARC-Message-Signature,
/// and ARC-Seal headers. Parse each, group by instance, validate that instances
/// form a continuous 1..=N sequence with exactly one of each type per instance,
/// and return sorted `ArcSet`s.
///
/// `headers` is a slice of (name, value) pairs in message order.
/// Returns `Ok(vec![])` if no ARC headers are present.
pub fn collect_arc_sets(headers: &[(&str, &str)]) -> Result<Vec<ArcSet>, ArcParseError> {
    let mut aars: BTreeMap<u32, ArcAuthenticationResults> = BTreeMap::new();
    let mut amss: BTreeMap<u32, ArcMessageSignature> = BTreeMap::new();
    let mut seals: BTreeMap<u32, ArcSeal> = BTreeMap::new();

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "arc-authentication-results" => {
                let aar = ArcAuthenticationResults::parse(value)?;
                let i = aar.instance;
                if aars.contains_key(&i) {
                    return Err(ArcParseError::InvalidInstance(format!(
                        "duplicate AAR for instance {}",
                        i
                    )));
                }
                aars.insert(i, aar);
            }
            "arc-message-signature" => {
                let ams = ArcMessageSignature::parse(value)?;
                let i = ams.instance;
                if amss.contains_key(&i) {
                    return Err(ArcParseError::InvalidInstance(format!(
                        "duplicate AMS for instance {}",
                        i
                    )));
                }
                amss.insert(i, ams);
            }
            "arc-seal" => {
                let seal = ArcSeal::parse(value)?;
                let i = seal.instance;
                if seals.contains_key(&i) {
                    return Err(ArcParseError::InvalidInstance(format!(
                        "duplicate ARC-Seal for instance {}",
                        i
                    )));
                }
                seals.insert(i, seal);
            }
            _ => {}
        }
    }

    // No ARC headers at all — not an error.
    if aars.is_empty() && amss.is_empty() && seals.is_empty() {
        return Ok(Vec::new());
    }

    // Determine max instance across all three header types.
    let max_instance = *aars
        .keys()
        .chain(amss.keys())
        .chain(seals.keys())
        .max()
        .unwrap_or(&0);

    if max_instance > 50 {
        return Err(ArcParseError::InvalidInstance(format!(
            "instance {} exceeds maximum of 50",
            max_instance
        )));
    }

    // Verify continuous 1..=N and each instance has all three components.
    for i in 1..=max_instance {
        if !aars.contains_key(&i) {
            return Err(ArcParseError::MissingTag(format!(
                "missing ARC-Authentication-Results for instance {}",
                i
            )));
        }
        if !amss.contains_key(&i) {
            return Err(ArcParseError::MissingTag(format!(
                "missing ARC-Message-Signature for instance {}",
                i
            )));
        }
        if !seals.contains_key(&i) {
            return Err(ArcParseError::MissingTag(format!(
                "missing ARC-Seal for instance {}",
                i
            )));
        }
    }

    // Build sorted result.
    let mut sets = Vec::with_capacity(max_instance as usize);
    for i in 1..=max_instance {
        sets.push(ArcSet {
            instance: i,
            aar: aars.remove(&i).unwrap(),
            ams: amss.remove(&i).unwrap(),
            seal: seals.remove(&i).unwrap(),
        });
    }

    Ok(sets)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    fn minimal_aar(instance: u32) -> String {
        format!("i={}; spf=pass smtp.mailfrom=example.com", instance)
    }

    fn minimal_ams(instance: u32) -> String {
        format!(
            "i={}; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel; h=from:to:subject",
            instance,
            b64(b"fakesig"),
            b64(b"fakehash"),
        )
    }

    fn minimal_seal(instance: u32, cv: &str) -> String {
        format!(
            "i={}; cv={}; a=rsa-sha256; b={}; d=example.com; s=sel",
            instance,
            cv,
            b64(b"sealsig"),
        )
    }

    // 1. parse_aar_valid
    #[test]
    fn parse_aar_valid() {
        let aar =
            ArcAuthenticationResults::parse("i=1; spf=pass smtp.mailfrom=example.com").unwrap();
        assert_eq!(aar.instance, 1);
        assert_eq!(aar.payload, "spf=pass smtp.mailfrom=example.com");
    }

    // 2. parse_aar_missing_instance
    #[test]
    fn parse_aar_missing_instance() {
        let err = ArcAuthenticationResults::parse("spf=pass").unwrap_err();
        assert!(matches!(err, ArcParseError::MissingTag(_)));
    }

    // 3. parse_aar_instance_0
    #[test]
    fn parse_aar_instance_0() {
        let err = ArcAuthenticationResults::parse("i=0; spf=pass smtp.mailfrom=example.com")
            .unwrap_err();
        assert!(matches!(err, ArcParseError::InvalidInstance(_)));
    }

    // 4. parse_aar_instance_51
    #[test]
    fn parse_aar_instance_51() {
        let err = ArcAuthenticationResults::parse("i=51; spf=pass smtp.mailfrom=example.com")
            .unwrap_err();
        assert!(matches!(err, ArcParseError::InvalidInstance(_)));
    }

    // 5. parse_ams_valid
    #[test]
    fn parse_ams_valid() {
        let ams = ArcMessageSignature::parse(&minimal_ams(1)).unwrap();
        assert_eq!(ams.instance, 1);
        assert_eq!(ams.algorithm, Algorithm::RsaSha256);
        assert_eq!(ams.signature, b"fakesig");
        assert_eq!(ams.body_hash, b"fakehash");
        assert_eq!(ams.domain, "example.com");
        assert_eq!(ams.selector, "sel");
        assert_eq!(ams.signed_headers, vec!["from", "to", "subject"]);
        assert_eq!(ams.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(ams.body_canonicalization, CanonicalizationMethod::Relaxed);
        assert!(ams.timestamp.is_none());
        assert!(ams.body_length.is_none());
    }

    // 6. parse_ams_optional_tags
    #[test]
    fn parse_ams_optional_tags() {
        let val = format!(
            "i=2; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel; h=from:to; \
             c=simple/relaxed; t=1700000000; l=512",
            b64(b"sig"),
            b64(b"hash"),
        );
        let ams = ArcMessageSignature::parse(&val).unwrap();
        assert_eq!(ams.instance, 2);
        assert_eq!(ams.header_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(ams.body_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(ams.timestamp, Some(1700000000));
        assert_eq!(ams.body_length, Some(512));
    }

    // 7. parse_ams_missing_tag
    #[test]
    fn parse_ams_missing_tag() {
        let val = format!(
            "i=1; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = ArcMessageSignature::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::MissingTag(ref t) if t == "h"));
    }

    // 8. parse_ams_forbidden_header (arc-seal in h=)
    #[test]
    fn parse_ams_forbidden_header() {
        let val = format!(
            "i=1; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel; h=from:to:ARC-Seal",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = ArcMessageSignature::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::ForbiddenHeader(_)));
    }

    // 9. parse_ams_forbidden_auth_results
    #[test]
    fn parse_ams_forbidden_auth_results() {
        let val = format!(
            "i=1; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel; \
             h=from:Authentication-Results",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = ArcMessageSignature::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::ForbiddenHeader(_)));
    }

    // 10. parse_ams_default_canon (no c= -> relaxed/relaxed)
    #[test]
    fn parse_ams_default_canon() {
        let ams = ArcMessageSignature::parse(&minimal_ams(1)).unwrap();
        assert_eq!(ams.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(ams.body_canonicalization, CanonicalizationMethod::Relaxed);
    }

    // 11. parse_seal_valid (cv=none)
    #[test]
    fn parse_seal_valid() {
        let seal = ArcSeal::parse(&minimal_seal(1, "none")).unwrap();
        assert_eq!(seal.instance, 1);
        assert_eq!(seal.cv, ChainValidationStatus::None);
        assert_eq!(seal.algorithm, Algorithm::RsaSha256);
        assert_eq!(seal.signature, b"sealsig");
        assert_eq!(seal.domain, "example.com");
        assert_eq!(seal.selector, "sel");
        assert!(seal.timestamp.is_none());
    }

    // 12. parse_seal_cv_pass
    #[test]
    fn parse_seal_cv_pass() {
        let seal = ArcSeal::parse(&minimal_seal(2, "pass")).unwrap();
        assert_eq!(seal.cv, ChainValidationStatus::Pass);
    }

    // 13. parse_seal_cv_fail
    #[test]
    fn parse_seal_cv_fail() {
        let seal = ArcSeal::parse(&minimal_seal(2, "fail")).unwrap();
        assert_eq!(seal.cv, ChainValidationStatus::Fail);
    }

    // 14. parse_seal_with_h_tag -> ForbiddenTag
    #[test]
    fn parse_seal_with_h_tag() {
        let val = format!(
            "i=1; cv=none; a=rsa-sha256; b={}; d=example.com; s=sel; h=from:to",
            b64(b"sig"),
        );
        let err = ArcSeal::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::ForbiddenTag(ref s) if s.contains("h=")));
    }

    // 15. parse_seal_missing_cv
    #[test]
    fn parse_seal_missing_cv() {
        let val = format!(
            "i=1; a=rsa-sha256; b={}; d=example.com; s=sel",
            b64(b"sig"),
        );
        let err = ArcSeal::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::MissingTag(ref t) if t == "cv"));
    }

    // 16. parse_seal_invalid_cv
    #[test]
    fn parse_seal_invalid_cv() {
        let val = format!(
            "i=1; cv=maybe; a=rsa-sha256; b={}; d=example.com; s=sel",
            b64(b"sig"),
        );
        let err = ArcSeal::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::InvalidCv(ref s) if s == "maybe"));
    }

    // 17. collect_single_set
    #[test]
    fn collect_single_set() {
        let aar_val = minimal_aar(1);
        let ams_val = minimal_ams(1);
        let seal_val = minimal_seal(1, "none");

        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Authentication-Results", &aar_val),
            ("ARC-Message-Signature", &ams_val),
            ("ARC-Seal", &seal_val),
        ];

        let sets = collect_arc_sets(&headers).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].instance, 1);
        assert_eq!(sets[0].aar.instance, 1);
        assert_eq!(sets[0].ams.instance, 1);
        assert_eq!(sets[0].seal.instance, 1);
    }

    // 18. collect_multiple_sets — 3 sets, sorted by instance
    #[test]
    fn collect_multiple_sets() {
        let aar1 = minimal_aar(1);
        let aar2 = minimal_aar(2);
        let aar3 = minimal_aar(3);
        let ams1 = minimal_ams(1);
        let ams2 = minimal_ams(2);
        let ams3 = minimal_ams(3);
        let seal1 = minimal_seal(1, "none");
        let seal2 = minimal_seal(2, "pass");
        let seal3 = minimal_seal(3, "pass");

        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Seal", seal3.as_str()),
            ("ARC-Message-Signature", ams3.as_str()),
            ("ARC-Authentication-Results", aar3.as_str()),
            ("ARC-Seal", seal2.as_str()),
            ("ARC-Message-Signature", ams2.as_str()),
            ("ARC-Authentication-Results", aar2.as_str()),
            ("ARC-Seal", seal1.as_str()),
            ("ARC-Message-Signature", ams1.as_str()),
            ("ARC-Authentication-Results", aar1.as_str()),
        ];

        let sets = collect_arc_sets(&headers).unwrap();
        assert_eq!(sets.len(), 3);
        assert_eq!(sets[0].instance, 1);
        assert_eq!(sets[1].instance, 2);
        assert_eq!(sets[2].instance, 3);
    }

    // 19. collect_missing_header_in_set — set 1 missing AAR
    #[test]
    fn collect_missing_header_in_set() {
        let ams_val = minimal_ams(1);
        let seal_val = minimal_seal(1, "none");

        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Message-Signature", &ams_val),
            ("ARC-Seal", &seal_val),
        ];

        let err = collect_arc_sets(&headers).unwrap_err();
        assert!(matches!(err, ArcParseError::MissingTag(ref s) if s.contains("instance 1")));
    }

    // 20. collect_instance_gap — instances 1,3 (no 2)
    #[test]
    fn collect_instance_gap() {
        let aar1 = minimal_aar(1);
        let aar3 = minimal_aar(3);
        let ams1 = minimal_ams(1);
        let ams3 = minimal_ams(3);
        let seal1 = minimal_seal(1, "none");
        let seal3 = minimal_seal(3, "pass");

        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Authentication-Results", aar1.as_str()),
            ("ARC-Message-Signature", ams1.as_str()),
            ("ARC-Seal", seal1.as_str()),
            ("ARC-Authentication-Results", aar3.as_str()),
            ("ARC-Message-Signature", ams3.as_str()),
            ("ARC-Seal", seal3.as_str()),
        ];

        let err = collect_arc_sets(&headers).unwrap_err();
        assert!(matches!(err, ArcParseError::MissingTag(ref s) if s.contains("instance 2")));
    }

    // 21. collect_duplicate_instance — two AMS with same instance
    #[test]
    fn collect_duplicate_instance() {
        let aar1 = minimal_aar(1);
        let ams1a = minimal_ams(1);
        let ams1b = minimal_ams(1);
        let seal1 = minimal_seal(1, "none");

        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Authentication-Results", aar1.as_str()),
            ("ARC-Message-Signature", ams1a.as_str()),
            ("ARC-Message-Signature", ams1b.as_str()),
            ("ARC-Seal", seal1.as_str()),
        ];

        let err = collect_arc_sets(&headers).unwrap_err();
        assert!(
            matches!(err, ArcParseError::InvalidInstance(ref s) if s.contains("duplicate"))
        );
    }

    // 22. collect_empty — no ARC headers
    #[test]
    fn collect_empty() {
        let headers: Vec<(&str, &str)> = vec![
            ("From", "sender@example.com"),
            ("To", "rcpt@example.com"),
            ("Subject", "Hello"),
        ];
        let sets = collect_arc_sets(&headers).unwrap();
        assert!(sets.is_empty());
    }

    // 23. collect_over_50 — instance > 50 triggers error at parse level
    #[test]
    fn collect_over_50() {
        let aar = "i=51; spf=pass";
        let headers: Vec<(&str, &str)> = vec![("ARC-Authentication-Results", aar)];
        let err = collect_arc_sets(&headers).unwrap_err();
        assert!(matches!(err, ArcParseError::InvalidInstance(_)));
    }

    // 24. parse_ams_duplicate_tag
    #[test]
    fn parse_ams_duplicate_tag() {
        let val = format!(
            "i=1; a=rsa-sha256; a=ed25519-sha256; b={}; bh={}; d=example.com; s=sel; h=from",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = ArcMessageSignature::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::DuplicateTag(ref t) if t == "a"));
    }

    // 25. ams_raw_header_preserved
    #[test]
    fn ams_raw_header_preserved() {
        let val = minimal_ams(1);
        let ams = ArcMessageSignature::parse(&val).unwrap();
        assert_eq!(ams.raw_header, val);
    }

    // --- Additional edge-case tests ---

    #[test]
    fn parse_aar_multiline_payload() {
        let val = "i=1; dkim=pass header.d=example.com;\r\n spf=pass smtp.mailfrom=example.com";
        let aar = ArcAuthenticationResults::parse(val).unwrap();
        assert_eq!(aar.instance, 1);
        assert!(aar.payload.contains("dkim=pass"));
        assert!(aar.payload.contains("spf=pass"));
    }

    #[test]
    fn parse_ams_ed25519_algorithm() {
        let val = format!(
            "i=1; a=ed25519-sha256; b={}; bh={}; d=example.com; s=sel; h=from",
            b64(b"sig"),
            b64(b"hash"),
        );
        let ams = ArcMessageSignature::parse(&val).unwrap();
        assert_eq!(ams.algorithm, Algorithm::Ed25519Sha256);
    }

    #[test]
    fn parse_seal_with_timestamp() {
        let val = format!(
            "i=1; cv=none; a=rsa-sha256; b={}; d=example.com; s=sel; t=1700000000",
            b64(b"sig"),
        );
        let seal = ArcSeal::parse(&val).unwrap();
        assert_eq!(seal.timestamp, Some(1700000000));
    }

    #[test]
    fn parse_ams_forbidden_arc_message_signature() {
        let val = format!(
            "i=1; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel; \
             h=from:arc-message-signature",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = ArcMessageSignature::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::ForbiddenHeader(_)));
    }

    #[test]
    fn parse_ams_forbidden_arc_authentication_results() {
        let val = format!(
            "i=1; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel; \
             h=from:ARC-Authentication-Results",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = ArcMessageSignature::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::ForbiddenHeader(_)));
    }

    #[test]
    fn collect_case_insensitive_header_names() {
        let aar_val = minimal_aar(1);
        let ams_val = minimal_ams(1);
        let seal_val = minimal_seal(1, "none");

        let headers: Vec<(&str, &str)> = vec![
            ("arc-authentication-results", &aar_val),
            ("Arc-Message-Signature", &ams_val),
            ("ARC-SEAL", &seal_val),
        ];

        let sets = collect_arc_sets(&headers).unwrap();
        assert_eq!(sets.len(), 1);
    }

    #[test]
    fn seal_raw_header_preserved() {
        let val = minimal_seal(1, "none");
        let seal = ArcSeal::parse(&val).unwrap();
        assert_eq!(seal.raw_header, val);
    }

    #[test]
    fn parse_ams_instance_50_valid() {
        let val = format!(
            "i=50; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel; h=from",
            b64(b"sig"),
            b64(b"hash"),
        );
        let ams = ArcMessageSignature::parse(&val).unwrap();
        assert_eq!(ams.instance, 50);
    }

    #[test]
    fn parse_seal_invalid_algorithm() {
        let val = format!(
            "i=1; cv=none; a=rsa-sha512; b={}; d=example.com; s=sel",
            b64(b"sig"),
        );
        let err = ArcSeal::parse(&val).unwrap_err();
        assert!(matches!(err, ArcParseError::InvalidAlgorithm(_)));
    }

    #[test]
    fn parse_ams_domain_lowercased() {
        let val = format!(
            "i=1; a=rsa-sha256; b={}; bh={}; d=EXAMPLE.COM; s=sel; h=from",
            b64(b"sig"),
            b64(b"hash"),
        );
        let ams = ArcMessageSignature::parse(&val).unwrap();
        assert_eq!(ams.domain, "example.com");
    }

    #[test]
    fn parse_seal_domain_lowercased() {
        let val = format!(
            "i=1; cv=none; a=rsa-sha256; b={}; d=EXAMPLE.COM; s=sel",
            b64(b"sig"),
        );
        let seal = ArcSeal::parse(&val).unwrap();
        assert_eq!(seal.domain, "example.com");
    }
}
