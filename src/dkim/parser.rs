use std::collections::HashSet;

use base64::Engine;

use super::types::{Algorithm, CanonicalizationMethod, DkimSignature, PermFailKind};

/// Error from DKIM signature or key parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimParseError {
    pub kind: PermFailKind,
    pub detail: String,
}

impl std::fmt::Display for DkimParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for DkimParseError {}

fn malformed(detail: impl Into<String>) -> DkimParseError {
    DkimParseError {
        kind: PermFailKind::MalformedSignature,
        detail: detail.into(),
    }
}

fn domain_mismatch(detail: impl Into<String>) -> DkimParseError {
    DkimParseError {
        kind: PermFailKind::DomainMismatch,
        detail: detail.into(),
    }
}

/// Parse tag=value pairs from a DKIM header or key record string.
/// Handles folded headers (CRLF+WSP) and whitespace around tags/values.
pub fn parse_tag_list(input: &str) -> Vec<(String, String)> {
    // Unfold: remove CRLF followed by whitespace
    let unfolded = unfold(input);

    let mut tags = Vec::new();
    for part in unfolded.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((name, value)) = trimmed.split_once('=') {
            tags.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    tags
}

/// Unfold headers: remove CRLF followed by whitespace.
fn unfold(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'\r' && bytes[i + 1] == b'\n' {
            // Check if next char after CRLF is whitespace
            if i + 2 < bytes.len() && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t') {
                // Skip CRLF, keep the whitespace
                i += 2;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Decode base64 with whitespace stripped.
fn decode_base64(value: &str) -> Result<Vec<u8>, DkimParseError> {
    let cleaned: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| malformed(format!("invalid base64: {}", e)))
}

impl DkimSignature {
    /// Parse a DKIM-Signature header value into a DkimSignature.
    /// The input is the header value (everything after "DKIM-Signature:").
    pub fn parse(header_value: &str) -> Result<Self, DkimParseError> {
        let raw_header = header_value.to_string();
        let tags = parse_tag_list(header_value);

        // Check for duplicate tags
        let mut seen = HashSet::new();
        for (name, _) in &tags {
            if !seen.insert(name.as_str()) {
                return Err(malformed(format!("duplicate tag: {}", name)));
            }
        }

        let get = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        // Required tags
        let version_str = get("v").ok_or_else(|| malformed("missing required tag: v"))?;
        let version: u8 = version_str
            .parse()
            .map_err(|_| malformed(format!("invalid version: {}", version_str)))?;
        if version != 1 {
            return Err(malformed(format!("unsupported version: {}", version)));
        }

        let algo_str = get("a").ok_or_else(|| malformed("missing required tag: a"))?;
        let algorithm = Algorithm::parse(algo_str)
            .ok_or_else(|| malformed(format!("unknown algorithm: {}", algo_str)))?;

        let b_raw = get("b").ok_or_else(|| malformed("missing required tag: b"))?;
        let signature = decode_base64(b_raw)?;

        let bh_raw = get("bh").ok_or_else(|| malformed("missing required tag: bh"))?;
        let body_hash = decode_base64(bh_raw)?;

        let domain = get("d")
            .ok_or_else(|| malformed("missing required tag: d"))?
            .to_string();

        let h_raw = get("h").ok_or_else(|| malformed("missing required tag: h"))?;
        let signed_headers: Vec<String> = h_raw
            .split(':')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // h= must include "from" (case-insensitive)
        if !signed_headers.iter().any(|h| h.eq_ignore_ascii_case("from")) {
            return Err(malformed("h= tag must include \"from\""));
        }

        let selector = get("s")
            .ok_or_else(|| malformed("missing required tag: s"))?
            .to_string();

        // Optional tags
        let (header_canonicalization, body_canonicalization) = if let Some(c_val) = get("c") {
            parse_canonicalization(c_val)?
        } else {
            (CanonicalizationMethod::Simple, CanonicalizationMethod::Simple)
        };

        let auid = if let Some(i_val) = get("i") {
            i_val.to_string()
        } else {
            format!("@{}", domain)
        };

        // Validate i= is subdomain of or equal to d=
        validate_auid_domain(&auid, &domain)?;

        let body_length = if let Some(l_val) = get("l") {
            Some(
                l_val
                    .parse::<u64>()
                    .map_err(|_| malformed(format!("invalid l= value: {}", l_val)))?,
            )
        } else {
            None
        };

        // q= is parsed but only dns/txt is defined; we just accept it
        // (CHK-328)

        let timestamp = if let Some(t_val) = get("t") {
            Some(
                t_val
                    .parse::<u64>()
                    .map_err(|_| malformed(format!("invalid t= value: {}", t_val)))?,
            )
        } else {
            None
        };

        let expiration = if let Some(x_val) = get("x") {
            Some(
                x_val
                    .parse::<u64>()
                    .map_err(|_| malformed(format!("invalid x= value: {}", x_val)))?,
            )
        } else {
            None
        };

        let copied_headers = get("z").map(|z_val| {
            z_val
                .split('|')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>()
        });

        Ok(DkimSignature {
            version,
            algorithm,
            signature,
            body_hash,
            header_canonicalization,
            body_canonicalization,
            domain,
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

/// Parse c= tag value into (header, body) canonicalization methods.
fn parse_canonicalization(
    value: &str,
) -> Result<(CanonicalizationMethod, CanonicalizationMethod), DkimParseError> {
    if let Some((header, body)) = value.split_once('/') {
        let h = CanonicalizationMethod::parse(header.trim())
            .ok_or_else(|| malformed(format!("unknown header canonicalization: {}", header)))?;
        let b = CanonicalizationMethod::parse(body.trim())
            .ok_or_else(|| malformed(format!("unknown body canonicalization: {}", body)))?;
        Ok((h, b))
    } else {
        let h = CanonicalizationMethod::parse(value.trim())
            .ok_or_else(|| malformed(format!("unknown canonicalization: {}", value)))?;
        // Body defaults to Simple when only header is specified
        Ok((h, CanonicalizationMethod::Simple))
    }
}

/// Validate that i= AUID domain is subdomain of or equal to d=.
fn validate_auid_domain(auid: &str, domain: &str) -> Result<(), DkimParseError> {
    // Extract domain part from i= (everything after @)
    let i_domain = if let Some(at_pos) = auid.rfind('@') {
        &auid[at_pos + 1..]
    } else {
        auid
    };

    let i_lower = i_domain.to_ascii_lowercase();
    let d_lower = domain.to_ascii_lowercase();

    if i_lower == d_lower {
        return Ok(());
    }

    // i= domain must be subdomain of d=
    if i_lower.ends_with(&format!(".{}", d_lower)) {
        return Ok(());
    }

    Err(domain_mismatch(format!(
        "i= domain '{}' is not subdomain of d= '{}'",
        i_domain, domain
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkim::types::*;

    // Helper: build a minimal valid DKIM-Signature header value
    fn minimal_sig() -> String {
        let b = base64::engine::general_purpose::STANDARD.encode(b"fakesig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"fakehash");
        format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1",
            b, bh
        )
    }

    // CHK-450: Minimal valid signature
    #[test]
    fn parse_minimal_signature() {
        let sig = DkimSignature::parse(&minimal_sig()).unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "sel1");
        assert_eq!(sig.signed_headers, vec!["from"]);
        assert_eq!(sig.auid, "@example.com"); // default
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

    // CHK-254..CHK-269: DkimSignature struct fields
    #[test]
    fn signature_has_all_fields() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=ed25519-sha256; b={}; bh={}; d=example.com; h=from:to:subject; \
             s=sel1; c=relaxed/relaxed; i=user@example.com; l=100; t=1000; x=2000; \
             z=From:user@example.com|To:dest@example.com",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::Ed25519Sha256);
        assert_eq!(sig.signature, b"sig");
        assert_eq!(sig.body_hash, b"hash");
        assert_eq!(
            sig.header_canonicalization,
            CanonicalizationMethod::Relaxed
        );
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.signed_headers, vec!["from", "to", "subject"]);
        assert_eq!(sig.auid, "user@example.com");
        assert_eq!(sig.body_length, Some(100));
        assert_eq!(sig.selector, "sel1");
        assert_eq!(sig.timestamp, Some(1000));
        assert_eq!(sig.expiration, Some(2000));
        assert_eq!(
            sig.copied_headers,
            Some(vec![
                "From:user@example.com".to_string(),
                "To:dest@example.com".to_string()
            ])
        );
    }

    // CHK-451: All optional tags present
    #[test]
    fn parse_all_optional_tags() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; \
             c=relaxed/simple; i=user@sub.example.com; l=500; q=dns/txt; t=12345; x=99999; \
             z=From:test",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(
            sig.header_canonicalization,
            CanonicalizationMethod::Relaxed
        );
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(sig.auid, "user@sub.example.com");
        assert_eq!(sig.body_length, Some(500));
        assert_eq!(sig.timestamp, Some(12345));
        assert_eq!(sig.expiration, Some(99999));
        assert_eq!(sig.copied_headers, Some(vec!["From:test".to_string()]));
    }

    // CHK-452: Folded header value
    #[test]
    fn parse_folded_header() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256;\r\n b={};\r\n\tbh={}; d=example.com;\r\n h=from; s=sel1",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
    }

    // CHK-453: Base64 with embedded whitespace
    #[test]
    fn parse_base64_with_whitespace() {
        let raw_b = base64::engine::general_purpose::STANDARD.encode(b"signaturedata");
        let raw_bh = base64::engine::general_purpose::STANDARD.encode(b"bodyhashdata");
        // Insert spaces in the middle of base64
        let spaced_b = format!(
            "{} {}",
            &raw_b[..raw_b.len() / 2],
            &raw_b[raw_b.len() / 2..]
        );
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1",
            spaced_b, raw_bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.signature, b"signaturedata");
    }

    // CHK-454: Missing required tag → PermFail
    #[test]
    fn parse_missing_required_tag_v() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("v"));
    }

    #[test]
    fn parse_missing_required_tag_b() {
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; bh={}; d=example.com; h=from; s=sel1",
            bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
    }

    #[test]
    fn parse_missing_required_tag_d() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!("v=1; a=rsa-sha256; b={}; bh={}; h=from; s=sel1", b, bh);
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("d"));
    }

    #[test]
    fn parse_missing_required_tag_h() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; s=sel1",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("h"));
    }

    #[test]
    fn parse_missing_required_tag_s() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("s"));
    }

    // CHK-455: Duplicate tag → PermFail
    #[test]
    fn parse_duplicate_tag() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("duplicate"));
    }

    // CHK-456: Unknown tag → ignored
    #[test]
    fn parse_unknown_tag_ignored() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; x_custom=hello",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.domain, "example.com");
    }

    // CHK-457: Invalid algorithm → PermFail
    #[test]
    fn parse_invalid_algorithm() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-md5; b={}; bh={}; d=example.com; h=from; s=sel1",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("unknown algorithm"));
    }

    // CHK-458: Case-insensitive algorithm
    #[test]
    fn parse_case_insensitive_algorithm() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=RSA-SHA256; b={}; bh={}; d=example.com; h=from; s=sel1",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
    }

    // CHK-459: h= missing "from" → PermFail
    #[test]
    fn parse_h_missing_from() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=to:subject; s=sel1",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("from"));
    }

    // CHK-460: i= not subdomain of d= → PermFail
    #[test]
    fn parse_i_not_subdomain() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; i=user@other.com",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::DomainMismatch);
    }

    // CHK-461: c= parsing variants
    #[test]
    fn parse_c_relaxed_relaxed() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; c=relaxed/relaxed",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(
            sig.header_canonicalization,
            CanonicalizationMethod::Relaxed
        );
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Relaxed);
    }

    #[test]
    fn parse_c_simple_only() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; c=simple",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.header_canonicalization, CanonicalizationMethod::Simple);
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
    }

    #[test]
    fn parse_c_relaxed_only_body_defaults_simple() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; c=relaxed",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(
            sig.header_canonicalization,
            CanonicalizationMethod::Relaxed
        );
        assert_eq!(sig.body_canonicalization, CanonicalizationMethod::Simple);
    }

    // CHK-270..CHK-275: Algorithm enum
    #[test]
    fn algorithm_parse_all_variants() {
        assert_eq!(Algorithm::parse("rsa-sha1"), Some(Algorithm::RsaSha1));
        assert_eq!(Algorithm::parse("rsa-sha256"), Some(Algorithm::RsaSha256));
        assert_eq!(
            Algorithm::parse("ed25519-sha256"),
            Some(Algorithm::Ed25519Sha256)
        );
        assert_eq!(Algorithm::parse("RSA-SHA256"), Some(Algorithm::RsaSha256));
        assert!(Algorithm::parse("unknown").is_none());
    }

    // CHK-276..CHK-280: CanonicalizationMethod enum
    #[test]
    fn canonicalization_parse() {
        assert_eq!(
            CanonicalizationMethod::parse("simple"),
            Some(CanonicalizationMethod::Simple)
        );
        assert_eq!(
            CanonicalizationMethod::parse("relaxed"),
            Some(CanonicalizationMethod::Relaxed)
        );
        assert_eq!(
            CanonicalizationMethod::parse("SIMPLE"),
            Some(CanonicalizationMethod::Simple)
        );
        assert!(CanonicalizationMethod::parse("unknown").is_none());
    }

    // CHK-292..CHK-310: Result types exist
    #[test]
    fn result_types_exist() {
        let _pass = DkimResult::Pass {
            domain: "example.com".into(),
            selector: "sel1".into(),
            testing: false,
        };
        let _fail = DkimResult::Fail {
            kind: FailureKind::BodyHashMismatch,
            detail: "test".into(),
        };
        let _permfail = DkimResult::PermFail {
            kind: PermFailKind::MalformedSignature,
            detail: "test".into(),
        };
        let _tempfail = DkimResult::TempFail {
            reason: "dns".into(),
        };
        let _none = DkimResult::None;

        // FailureKind variants
        let _ = FailureKind::BodyHashMismatch;
        let _ = FailureKind::SignatureVerificationFailed;

        // PermFailKind variants
        let _ = PermFailKind::MalformedSignature;
        let _ = PermFailKind::KeyRevoked;
        let _ = PermFailKind::KeyNotFound;
        let _ = PermFailKind::ExpiredSignature;
        let _ = PermFailKind::AlgorithmMismatch;
        let _ = PermFailKind::HashNotPermitted;
        let _ = PermFailKind::ServiceTypeMismatch;
        let _ = PermFailKind::StrictModeViolation;
        let _ = PermFailKind::DomainMismatch;
    }

    // CHK-311: Tag=value pairs
    #[test]
    fn tag_list_parsing() {
        let tags = parse_tag_list("a=b; c=d; e=f");
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0], ("a".into(), "b".into()));
        assert_eq!(tags[1], ("c".into(), "d".into()));
        assert_eq!(tags[2], ("e".into(), "f".into()));
    }

    // CHK-312: Folded headers
    #[test]
    fn unfold_crlf_space() {
        let input = "hello\r\n world";
        let result = unfold(input);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn unfold_crlf_tab() {
        let input = "hello\r\n\tworld";
        let result = unfold(input);
        assert_eq!(result, "hello\tworld");
    }

    // CHK-313: Strip whitespace
    #[test]
    fn tag_list_strips_whitespace() {
        let tags = parse_tag_list("  a = b ; c = d  ");
        assert_eq!(tags[0], ("a".into(), "b".into()));
        assert_eq!(tags[1], ("c".into(), "d".into()));
    }

    // CHK-314: Base64 whitespace handling
    #[test]
    fn decode_base64_with_spaces() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"test data");
        let spaced = format!("{} {}", &encoded[..4], &encoded[4..]);
        let decoded = decode_base64(&spaced).unwrap();
        assert_eq!(decoded, b"test data");
    }

    // CHK-315: Version must be 1
    #[test]
    fn parse_version_not_1() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=2; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert!(err.detail.contains("version"));
    }

    // CHK-325: i= default to @d=
    #[test]
    fn parse_i_defaults_to_at_domain() {
        let sig = DkimSignature::parse(&minimal_sig()).unwrap();
        assert_eq!(sig.auid, "@example.com");
    }

    // CHK-326: i= subdomain valid
    #[test]
    fn parse_i_subdomain_valid() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; i=user@sub.example.com",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.auid, "user@sub.example.com");
    }

    // CHK-337: raw_header stored
    #[test]
    fn parse_stores_raw_header() {
        let input = minimal_sig();
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.raw_header, input);
    }

    // CHK-320: h= colon-separated
    #[test]
    fn parse_h_multiple_headers() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from:to:subject:date; s=sel1",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(
            sig.signed_headers,
            vec!["from", "to", "subject", "date"]
        );
    }

    // CHK-331: z= pipe-separated
    #[test]
    fn parse_z_copied_headers() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; z=From:a|To:b|Cc:c",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(
            sig.copied_headers,
            Some(vec![
                "From:a".to_string(),
                "To:b".to_string(),
                "Cc:c".to_string()
            ])
        );
    }

    // CHK-521: All types defined with typed enums
    #[test]
    fn all_types_are_typed_enums() {
        // Algorithm
        let a = Algorithm::RsaSha256;
        assert_eq!(a.hash_algorithm(), HashAlgorithm::Sha256);
        let a = Algorithm::RsaSha1;
        assert_eq!(a.hash_algorithm(), HashAlgorithm::Sha1);

        // CanonicalizationMethod
        let _ = CanonicalizationMethod::Simple;
        let _ = CanonicalizationMethod::Relaxed;

        // KeyType
        let _ = KeyType::Rsa;
        let _ = KeyType::Ed25519;

        // HashAlgorithm
        let _ = HashAlgorithm::Sha1;
        let _ = HashAlgorithm::Sha256;

        // KeyFlag
        let _ = KeyFlag::Testing;
        let _ = KeyFlag::Strict;
    }

    // CHK-522: Signature parsing complete
    #[test]
    fn parse_rsa_sha1_signature() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha1; b={}; bh={}; d=example.com; h=from; s=sel1",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.algorithm, Algorithm::RsaSha1);
    }

    #[test]
    fn parse_ed25519_signature() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=ed25519-sha256; b={}; bh={}; d=example.com; h=from; s=sel1",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.algorithm, Algorithm::Ed25519Sha256);
    }

    // CHK-334: Missing required → PermFail
    #[test]
    fn parse_missing_bh() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; d=example.com; h=from; s=sel1",
            b
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("bh"));
    }

    // CHK-333: Duplicate tags PermFail
    #[test]
    fn parse_duplicate_d_tag() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; d=other.com; h=from; s=sel1",
            b, bh
        );
        let err = DkimSignature::parse(&input).unwrap_err();
        assert_eq!(err.kind, PermFailKind::MalformedSignature);
        assert!(err.detail.contains("duplicate"));
    }

    // CHK-335: h= must include from (case-insensitive)
    #[test]
    fn parse_h_from_case_insensitive() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=From:To; s=sel1",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.signed_headers[0], "From");
    }

    // CHK-336: i= not subdomain → PermFail
    #[test]
    fn validate_auid_domain_equal() {
        assert!(validate_auid_domain("user@example.com", "example.com").is_ok());
    }

    #[test]
    fn validate_auid_domain_subdomain() {
        assert!(validate_auid_domain("user@sub.example.com", "example.com").is_ok());
    }

    #[test]
    fn validate_auid_domain_different() {
        assert!(validate_auid_domain("user@other.com", "example.com").is_err());
    }

    #[test]
    fn validate_auid_domain_case_insensitive() {
        assert!(validate_auid_domain("user@EXAMPLE.COM", "example.com").is_ok());
    }

    // CHK-327: l= body length
    #[test]
    fn parse_l_body_length() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; l=12345",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.body_length, Some(12345));
    }

    // CHK-329, CHK-330: t= and x=
    #[test]
    fn parse_timestamp_expiration() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; t=1000000; x=2000000",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.timestamp, Some(1000000));
        assert_eq!(sig.expiration, Some(2000000));
    }

    // CHK-332: Unknown tags ignored
    #[test]
    fn parse_multiple_unknown_tags() {
        let b = base64::engine::general_purpose::STANDARD.encode(b"sig");
        let bh = base64::engine::general_purpose::STANDARD.encode(b"hash");
        let input = format!(
            "v=1; a=rsa-sha256; b={}; bh={}; d=example.com; h=from; s=sel1; foo=bar; baz=qux",
            b, bh
        );
        let sig = DkimSignature::parse(&input).unwrap();
        assert_eq!(sig.selector, "sel1");
    }
}
