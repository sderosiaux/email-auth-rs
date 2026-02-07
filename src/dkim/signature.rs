use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashSet;

use crate::common::domain::{is_subdomain_of, normalize_domain};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizationMethod {
    Simple,
    Relaxed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSignature {
    pub version: u32,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimResult {
    Pass {
        domain: String,
        selector: String,
        testing: bool,
    },
    Fail {
        kind: FailureKind,
        detail: String,
    },
    PermFail {
        kind: PermFailKind,
        detail: String,
    },
    TempFail {
        reason: String,
    },
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureKind {
    BodyHashMismatch,
    SignatureVerificationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermFailKind {
    MalformedSignature,
    KeyRevoked,
    KeyNotFound,
    ExpiredSignature,
    AlgorithmMismatch,
    HashNotPermitted,
    ServiceTypeMismatch,
    StrictModeViolation,
    DomainMismatch,
}

// ---------------------------------------------------------------------------
// Tag=value parser
// ---------------------------------------------------------------------------

/// Parse DKIM tag=value list (RFC 6376 Section 3.2).
/// Returns pairs in order. Caller must check for duplicates.
fn parse_tag_value_list(input: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for pair in input.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((tag, value)) = pair.split_once('=') {
            result.push((tag.trim().to_string(), value.trim().to_string()));
        }
    }
    result
}

/// Decode base64 with all whitespace stripped first (RFC 6376 permits FWS in
/// base64 values).
fn decode_base64_permissive(val: &str) -> Result<Vec<u8>, DkimResult> {
    let cleaned: String = val.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD.decode(&cleaned).map_err(|_| DkimResult::PermFail {
        kind: PermFailKind::MalformedSignature,
        detail: "invalid base64".to_string(),
    })
}

fn permfail_malformed(detail: impl Into<String>) -> DkimResult {
    DkimResult::PermFail {
        kind: PermFailKind::MalformedSignature,
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------------------
// DkimSignature::parse
// ---------------------------------------------------------------------------

impl DkimSignature {
    /// Parse a DKIM-Signature header field value (everything after
    /// "DKIM-Signature:") into a `DkimSignature`.
    pub fn parse(header_value: &str) -> Result<DkimSignature, DkimResult> {
        // Unfold: remove CRLF followed by whitespace (RFC 5322 Section 2.2.3).
        let unfolded = unfold(header_value);
        let tags = parse_tag_value_list(&unfolded);

        // Check for duplicate tags.
        {
            let mut seen = HashSet::new();
            for (tag, _) in &tags {
                if !seen.insert(tag.as_str()) {
                    return Err(permfail_malformed(format!("duplicate tag: {}", tag)));
                }
            }
        }

        // Helper to look up a tag.
        let find = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(t, _)| t == name)
                .map(|(_, v)| v.as_str())
        };

        // v= (required, must be "1")
        let version_str = find("v").ok_or_else(|| permfail_malformed("missing v= tag"))?;
        if version_str != "1" {
            return Err(permfail_malformed(format!(
                "unsupported version: {}",
                version_str
            )));
        }

        // a= (required)
        let algo_str = find("a").ok_or_else(|| permfail_malformed("missing a= tag"))?;
        let algorithm = match algo_str {
            "rsa-sha1" => Algorithm::RsaSha1,
            "rsa-sha256" => Algorithm::RsaSha256,
            "ed25519-sha256" => Algorithm::Ed25519Sha256,
            other => {
                return Err(permfail_malformed(format!("unknown algorithm: {}", other)));
            }
        };

        // b= (required)
        let b_raw = find("b").ok_or_else(|| permfail_malformed("missing b= tag"))?;
        let signature = decode_base64_permissive(b_raw)?;

        // bh= (required)
        let bh_raw = find("bh").ok_or_else(|| permfail_malformed("missing bh= tag"))?;
        let body_hash = decode_base64_permissive(bh_raw)?;

        // d= (required)
        let domain_raw = find("d").ok_or_else(|| permfail_malformed("missing d= tag"))?;
        let domain = normalize_domain(domain_raw);

        // h= (required, must include "from")
        let h_raw = find("h").ok_or_else(|| permfail_malformed("missing h= tag"))?;
        let signed_headers: Vec<String> = h_raw
            .split(':')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !signed_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("from"))
        {
            return Err(permfail_malformed("h= must include from"));
        }

        // s= (required)
        let selector_raw = find("s").ok_or_else(|| permfail_malformed("missing s= tag"))?;
        let selector = selector_raw.to_string();

        // c= (optional, default simple/simple)
        let (header_canon, body_canon) = if let Some(c_raw) = find("c") {
            parse_canonicalization(c_raw)?
        } else {
            (CanonicalizationMethod::Simple, CanonicalizationMethod::Simple)
        };

        // i= (optional, default "@{d=}")
        let auid = if let Some(i_raw) = find("i") {
            let i_val = i_raw.to_string();
            // i= domain part must be subdomain of or equal to d=
            let i_domain = i_val
                .rsplit_once('@')
                .map(|(_, d)| normalize_domain(d))
                .unwrap_or_default();
            if !is_subdomain_of(&i_domain, &domain) {
                return Err(DkimResult::PermFail {
                    kind: PermFailKind::DomainMismatch,
                    detail: format!(
                        "i= domain '{}' is not subdomain of d= '{}'",
                        i_domain, domain
                    ),
                });
            }
            i_val
        } else {
            format!("@{}", domain)
        };

        // l= (optional)
        let body_length = if let Some(l_raw) = find("l") {
            Some(l_raw.parse::<u64>().map_err(|_| {
                permfail_malformed(format!("invalid l= value: {}", l_raw))
            })?)
        } else {
            None
        };

        // t= (optional)
        let timestamp = if let Some(t_raw) = find("t") {
            Some(
                t_raw
                    .parse::<u64>()
                    .map_err(|_| permfail_malformed(format!("invalid t= value: {}", t_raw)))?,
            )
        } else {
            None
        };

        // x= (optional)
        let expiration = if let Some(x_raw) = find("x") {
            Some(
                x_raw
                    .parse::<u64>()
                    .map_err(|_| permfail_malformed(format!("invalid x= value: {}", x_raw)))?,
            )
        } else {
            None
        };

        // z= (optional, pipe-separated copied header fields)
        let copied_headers = find("z").map(|z_raw| {
            z_raw
                .split('|')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>()
        });

        Ok(DkimSignature {
            version: 1,
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

/// Unfold header: remove CRLF+WSP sequences per RFC 5322.
fn unfold(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if i + 2 < len && bytes[i] == b'\r' && bytes[i + 1] == b'\n' && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t') {
            // Skip CRLF, keep the following whitespace character
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Parse c= tag value into (header, body) canonicalization methods.
fn parse_canonicalization(
    val: &str,
) -> Result<(CanonicalizationMethod, CanonicalizationMethod), DkimResult> {
    let parts: Vec<&str> = val.split('/').collect();
    let parse_one = |s: &str| -> Result<CanonicalizationMethod, DkimResult> {
        match s.trim() {
            "simple" => Ok(CanonicalizationMethod::Simple),
            "relaxed" => Ok(CanonicalizationMethod::Relaxed),
            other => Err(permfail_malformed(format!(
                "unknown canonicalization: {}",
                other
            ))),
        }
    };
    match parts.len() {
        1 => {
            let header = parse_one(parts[0])?;
            // body defaults to simple when only header specified
            Ok((header, CanonicalizationMethod::Simple))
        }
        2 => {
            let header = parse_one(parts[0])?;
            let body = parse_one(parts[1])?;
            Ok((header, body))
        }
        _ => Err(permfail_malformed("invalid c= format")),
    }
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

    fn minimal_sig() -> String {
        format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from:to; s=sel1",
            b64(b"fakesig"),
            b64(b"fakehash"),
        )
    }

    #[test]
    fn parse_minimal_valid() {
        let sig = DkimSignature::parse(&minimal_sig()).unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.signature, b"fakesig");
        assert_eq!(sig.body_hash, b"fakehash");
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "sel1");
        assert_eq!(sig.signed_headers, vec!["from", "to"]);
        assert_eq!(sig.auid, "@example.com");
        assert_eq!(
            sig.header_canonicalization,
            CanonicalizationMethod::Simple
        );
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
        assert!(sig.body_length.is_none());
        assert!(sig.timestamp.is_none());
        assert!(sig.expiration.is_none());
        assert!(sig.copied_headers.is_none());
    }

    #[test]
    fn parse_all_optional_tags() {
        let val = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from:to:subject; \
             s=sel1; c=relaxed/relaxed; i=user@sub.example.com; l=1234; \
             t=1000; x=2000; z=From:test|To:test2",
            b64(b"sig"),
            b64(b"hash"),
        );
        let sig = DkimSignature::parse(&val).unwrap();
        assert_eq!(
            sig.header_canonicalization,
            CanonicalizationMethod::Relaxed
        );
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.auid, "user@sub.example.com");
        assert_eq!(sig.body_length, Some(1234));
        assert_eq!(sig.timestamp, Some(1000));
        assert_eq!(sig.expiration, Some(2000));
        assert_eq!(
            sig.copied_headers,
            Some(vec!["From:test".to_string(), "To:test2".to_string()])
        );
        assert_eq!(
            sig.signed_headers,
            vec!["from", "to", "subject"]
        );
    }

    #[test]
    fn parse_folded_header() {
        let val = format!(
            "v=1; a=rsa-sha256;\r\n b={};\r\n\tbh={};\r\n d=example.com; h=from; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let sig = DkimSignature::parse(&val).unwrap();
        assert_eq!(sig.signature, b"sig");
    }

    #[test]
    fn base64_with_whitespace() {
        // Insert spaces and newlines in base64 values
        let b_val = "ZmFr ZXNp Zw==";
        let bh_val = "ZmFr\r\n ZWhhc2g=";
        let val = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel",
            b_val, bh_val,
        );
        let sig = DkimSignature::parse(&val).unwrap();
        assert_eq!(sig.signature, b"fakesig");
        assert_eq!(sig.body_hash, b"fakehash");
    }

    #[test]
    fn missing_required_tag() {
        // Missing h=
        let val = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = DkimSignature::parse(&val).unwrap_err();
        assert!(matches!(
            err,
            DkimResult::PermFail {
                kind: PermFailKind::MalformedSignature,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_tag() {
        let val = format!(
            "v=1; a=rsa-sha256; a=rsa-sha1; b={}; bh={}; d=example.com; h=from; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = DkimSignature::parse(&val).unwrap_err();
        match err {
            DkimResult::PermFail { kind, detail } => {
                assert_eq!(kind, PermFailKind::MalformedSignature);
                assert!(detail.contains("duplicate"));
            }
            other => panic!("expected PermFail, got {:?}", other),
        }
    }

    #[test]
    fn unknown_tag_ignored() {
        let val = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel; foo=bar",
            b64(b"sig"),
            b64(b"hash"),
        );
        let sig = DkimSignature::parse(&val).unwrap();
        assert_eq!(sig.domain, "example.com");
    }

    #[test]
    fn invalid_algorithm() {
        let val = format!(
            "v=1; a=rsa-sha512; b={}; bh={}; d=example.com; h=from; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = DkimSignature::parse(&val).unwrap_err();
        assert!(matches!(
            err,
            DkimResult::PermFail {
                kind: PermFailKind::MalformedSignature,
                ..
            }
        ));
    }

    #[test]
    fn h_missing_from() {
        let val = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=to:subject; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = DkimSignature::parse(&val).unwrap_err();
        assert!(matches!(
            err,
            DkimResult::PermFail {
                kind: PermFailKind::MalformedSignature,
                ..
            }
        ));
    }

    #[test]
    fn i_not_subdomain_of_d() {
        let val = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel; i=user@other.com",
            b64(b"sig"),
            b64(b"hash"),
        );
        let err = DkimSignature::parse(&val).unwrap_err();
        assert!(matches!(
            err,
            DkimResult::PermFail {
                kind: PermFailKind::DomainMismatch,
                ..
            }
        ));
    }

    #[test]
    fn c_parsing_variants() {
        // relaxed only -> body defaults to simple
        let mk = |c: &str| {
            format!(
                "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel; c={}",
                b64(b"s"),
                b64(b"h"),
                c,
            )
        };

        let sig = DkimSignature::parse(&mk("relaxed")).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);

        let sig = DkimSignature::parse(&mk("simple/relaxed")).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Relaxed);

        let sig = DkimSignature::parse(&mk("relaxed/relaxed")).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Relaxed);

        let sig = DkimSignature::parse(&mk("simple")).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);

        let sig = DkimSignature::parse(&mk("simple/simple")).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
    }

    #[test]
    fn raw_header_preserved() {
        let val = minimal_sig();
        let sig = DkimSignature::parse(&val).unwrap();
        assert_eq!(sig.raw_header, val);
    }

    #[test]
    fn ed25519_algorithm() {
        let val = format!(
            "v=1; a=ed25519-sha256; b={}; bh={}; d=example.com; h=from; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let sig = DkimSignature::parse(&val).unwrap();
        assert_eq!(sig.algorithm, Algorithm::Ed25519Sha256);
    }

    #[test]
    fn rsa_sha1_algorithm() {
        let val = format!(
            "v=1; a=rsa-sha1; b={}; bh={}; d=example.com; h=from; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let sig = DkimSignature::parse(&val).unwrap();
        assert_eq!(sig.algorithm, Algorithm::RsaSha1);
    }

    #[test]
    fn from_case_insensitive_in_h() {
        let val = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=From:to; s=sel",
            b64(b"sig"),
            b64(b"hash"),
        );
        let sig = DkimSignature::parse(&val).unwrap();
        assert_eq!(sig.signed_headers, vec!["From", "to"]);
    }
}
