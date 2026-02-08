use base64::Engine;

use crate::dkim::types::{Algorithm, CanonicalizationMethod};

use super::types::{
    ArcAuthenticationResults, ArcMessageSignature, ArcSeal, ArcSet, ChainValidationStatus,
};

/// ARC parse error.
#[derive(Debug)]
pub struct ArcParseError {
    pub detail: String,
}

impl ArcParseError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// Parse tag=value pairs from a header value (shared with DKIM).
fn parse_tags(value: &str) -> Vec<(String, String)> {
    let mut tags = Vec::new();
    for part in value.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let tag_name = trimmed[..eq_pos].trim().to_ascii_lowercase();
            let tag_value = trimmed[eq_pos + 1..].trim().to_string();
            tags.push((tag_name, tag_value));
        }
    }
    tags
}

/// Decode base64 with whitespace removal.
fn decode_base64(value: &str) -> Result<Vec<u8>, ArcParseError> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| ArcParseError::new(format!("malformed base64: {}", e)))
}

/// Parse ARC-Authentication-Results header value.
/// Format: `i=<N>; <authres-payload>`
pub fn parse_aar(value: &str) -> Result<ArcAuthenticationResults, ArcParseError> {
    let trimmed = value.trim();

    // Find first semicolon — everything before is i=N
    let semi_pos = trimmed
        .find(';')
        .ok_or_else(|| ArcParseError::new("AAR missing semicolon after i= tag"))?;

    let i_part = trimmed[..semi_pos].trim();
    let payload = trimmed[semi_pos + 1..].trim().to_string();

    // Parse i= tag
    let instance = parse_instance_from_part(i_part)?;

    Ok(ArcAuthenticationResults {
        instance,
        payload,
        raw_header: value.to_string(),
    })
}

/// Parse i=<N> from a tag part like "i=1" or " i = 2 ".
fn parse_instance_from_part(part: &str) -> Result<u32, ArcParseError> {
    let trimmed = part.trim();
    if !trimmed.to_ascii_lowercase().starts_with("i=") && !trimmed.to_ascii_lowercase().starts_with("i =") {
        return Err(ArcParseError::new(format!(
            "expected i= tag, got '{}'",
            trimmed
        )));
    }
    let eq_pos = trimmed
        .find('=')
        .ok_or_else(|| ArcParseError::new("no = in i= tag"))?;
    let num_str = trimmed[eq_pos + 1..].trim();
    let instance: u32 = num_str
        .parse()
        .map_err(|_| ArcParseError::new(format!("invalid instance number: '{}'", num_str)))?;
    validate_instance(instance)?;
    Ok(instance)
}

fn validate_instance(instance: u32) -> Result<(), ArcParseError> {
    if instance < 1 || instance > 50 {
        return Err(ArcParseError::new(format!(
            "instance {} outside valid range 1-50",
            instance
        )));
    }
    Ok(())
}

/// Parse ARC-Message-Signature header value.
pub fn parse_ams(value: &str) -> Result<ArcMessageSignature, ArcParseError> {
    let tags = parse_tags(value);

    // Check for duplicates
    check_duplicate_tags(&tags)?;

    let mut instance = None;
    let mut algorithm = None;
    let mut signature = None;
    let mut body_hash = None;
    let mut domain = None;
    let mut selector = None;
    let mut signed_headers = None;
    let mut header_canon = CanonicalizationMethod::Relaxed;
    let mut body_canon = CanonicalizationMethod::Relaxed;
    let mut timestamp = None;
    let mut body_length = None;

    for (tag, val) in &tags {
        match tag.as_str() {
            "i" => {
                let i: u32 = val
                    .parse()
                    .map_err(|_| ArcParseError::new(format!("invalid i= value: '{}'", val)))?;
                validate_instance(i)?;
                instance = Some(i);
            }
            "a" => {
                algorithm = Some(
                    Algorithm::parse(val)
                        .ok_or_else(|| ArcParseError::new(format!("unknown algorithm: '{}'", val)))?,
                );
            }
            "b" => {
                signature = Some(decode_base64(val)?);
            }
            "bh" => {
                body_hash = Some(decode_base64(val)?);
            }
            "d" => {
                domain = Some(val.to_string());
            }
            "s" => {
                selector = Some(val.to_string());
            }
            "h" => {
                let hdrs: Vec<String> = val
                    .split(':')
                    .map(|h| h.trim().to_string())
                    .filter(|h| !h.is_empty())
                    .collect();
                // RFC 8617 §5.1: h= MUST NOT include ARC-* or Authentication-Results
                for hdr in &hdrs {
                    let lower = hdr.to_ascii_lowercase();
                    if lower == "arc-authentication-results"
                        || lower == "arc-message-signature"
                        || lower == "arc-seal"
                        || lower == "authentication-results"
                    {
                        return Err(ArcParseError::new(format!(
                            "AMS h= must not include '{}' (RFC 8617)",
                            hdr
                        )));
                    }
                }
                signed_headers = Some(hdrs);
            }
            "c" => {
                let parts: Vec<&str> = val.split('/').collect();
                header_canon = CanonicalizationMethod::parse(parts[0])
                    .unwrap_or(CanonicalizationMethod::Relaxed);
                if parts.len() > 1 {
                    body_canon = CanonicalizationMethod::parse(parts[1])
                        .unwrap_or(CanonicalizationMethod::Relaxed);
                }
            }
            "t" => {
                timestamp = val.parse::<u64>().ok();
            }
            "l" => {
                body_length = val.parse::<u64>().ok();
            }
            _ => {} // Unknown tags ignored
        }
    }

    Ok(ArcMessageSignature {
        instance: instance.ok_or_else(|| ArcParseError::new("missing required tag: i"))?,
        algorithm: algorithm.ok_or_else(|| ArcParseError::new("missing required tag: a"))?,
        signature: signature.ok_or_else(|| ArcParseError::new("missing required tag: b"))?,
        body_hash: body_hash.ok_or_else(|| ArcParseError::new("missing required tag: bh"))?,
        domain: domain.ok_or_else(|| ArcParseError::new("missing required tag: d"))?,
        selector: selector.ok_or_else(|| ArcParseError::new("missing required tag: s"))?,
        signed_headers: signed_headers
            .ok_or_else(|| ArcParseError::new("missing required tag: h"))?,
        header_canonicalization: header_canon,
        body_canonicalization: body_canon,
        timestamp,
        body_length,
        raw_header: value.to_string(),
    })
}

/// Parse ARC-Seal header value.
pub fn parse_seal(value: &str) -> Result<ArcSeal, ArcParseError> {
    let tags = parse_tags(value);

    check_duplicate_tags(&tags)?;

    let mut instance = None;
    let mut cv = None;
    let mut algorithm = None;
    let mut signature = None;
    let mut domain = None;
    let mut selector = None;
    let mut timestamp = None;
    let mut has_h_tag = false;

    for (tag, val) in &tags {
        match tag.as_str() {
            "i" => {
                let i: u32 = val
                    .parse()
                    .map_err(|_| ArcParseError::new(format!("invalid i= value: '{}'", val)))?;
                validate_instance(i)?;
                instance = Some(i);
            }
            "cv" => {
                cv = Some(match val.to_ascii_lowercase().as_str() {
                    "none" => ChainValidationStatus::None,
                    "pass" => ChainValidationStatus::Pass,
                    "fail" => ChainValidationStatus::Fail,
                    _ => {
                        return Err(ArcParseError::new(format!(
                            "invalid cv= value: '{}'",
                            val
                        )))
                    }
                });
            }
            "a" => {
                algorithm = Some(
                    Algorithm::parse(val)
                        .ok_or_else(|| ArcParseError::new(format!("unknown algorithm: '{}'", val)))?,
                );
            }
            "b" => {
                signature = Some(decode_base64(val)?);
            }
            "d" => {
                domain = Some(val.to_string());
            }
            "s" => {
                selector = Some(val.to_string());
            }
            "t" => {
                timestamp = val.parse::<u64>().ok();
            }
            "h" => {
                has_h_tag = true;
            }
            _ => {} // Ignore unknown
        }
    }

    // h= tag MUST NOT be present in AS
    if has_h_tag {
        return Err(ArcParseError::new(
            "ARC-Seal must not contain h= tag (RFC 8617 §4.1.3)",
        ));
    }

    Ok(ArcSeal {
        instance: instance.ok_or_else(|| ArcParseError::new("missing required tag: i"))?,
        cv: cv.ok_or_else(|| ArcParseError::new("missing required tag: cv"))?,
        algorithm: algorithm.ok_or_else(|| ArcParseError::new("missing required tag: a"))?,
        signature: signature.ok_or_else(|| ArcParseError::new("missing required tag: b"))?,
        domain: domain.ok_or_else(|| ArcParseError::new("missing required tag: d"))?,
        selector: selector.ok_or_else(|| ArcParseError::new("missing required tag: s"))?,
        timestamp,
        raw_header: value.to_string(),
    })
}

/// Check for duplicate tag names.
fn check_duplicate_tags(tags: &[(String, String)]) -> Result<(), ArcParseError> {
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            if tags[i].0 == tags[j].0 {
                return Err(ArcParseError::new(format!(
                    "duplicate tag: '{}'",
                    tags[i].0
                )));
            }
        }
    }
    Ok(())
}

/// Collect and group ARC headers from message headers into ARC Sets.
/// Returns ordered Vec<ArcSet> (ascending by instance) or error.
pub fn collect_arc_sets(
    headers: &[(&str, &str)],
) -> Result<Vec<ArcSet>, ArcParseError> {
    let mut aars: Vec<ArcAuthenticationResults> = Vec::new();
    let mut amss: Vec<ArcMessageSignature> = Vec::new();
    let mut seals: Vec<ArcSeal> = Vec::new();

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "arc-authentication-results" => {
                aars.push(parse_aar(value)?);
            }
            "arc-message-signature" => {
                amss.push(parse_ams(value)?);
            }
            "arc-seal" => {
                seals.push(parse_seal(value)?);
            }
            _ => {}
        }
    }

    if aars.is_empty() && amss.is_empty() && seals.is_empty() {
        return Ok(Vec::new());
    }

    // Check max 50
    let max_instance = aars
        .iter()
        .map(|a| a.instance)
        .chain(amss.iter().map(|a| a.instance))
        .chain(seals.iter().map(|a| a.instance))
        .max()
        .unwrap_or(0);

    if max_instance > 50 {
        return Err(ArcParseError::new(format!(
            "instance {} exceeds maximum of 50",
            max_instance
        )));
    }

    // Group by instance
    let mut sets: Vec<ArcSet> = Vec::new();
    for i in 1..=max_instance {
        let aar: Vec<_> = aars.iter().filter(|a| a.instance == i).collect();
        let ams: Vec<_> = amss.iter().filter(|a| a.instance == i).collect();
        let seal: Vec<_> = seals.iter().filter(|a| a.instance == i).collect();

        // Each instance must have exactly one of each
        if aar.len() != 1 || ams.len() != 1 || seal.len() != 1 {
            if aar.is_empty() && ams.is_empty() && seal.is_empty() {
                return Err(ArcParseError::new(format!(
                    "gap in ARC instance sequence: missing instance {}",
                    i
                )));
            }
            if aar.len() > 1 || ams.len() > 1 || seal.len() > 1 {
                return Err(ArcParseError::new(format!(
                    "duplicate ARC headers for instance {}",
                    i
                )));
            }
            return Err(ArcParseError::new(format!(
                "incomplete ARC set for instance {}: AAR={}, AMS={}, AS={}",
                i,
                aar.len(),
                ams.len(),
                seal.len()
            )));
        }

        sets.push(ArcSet {
            instance: i,
            aar: aar[0].clone(),
            ams: ams[0].clone(),
            seal: seal[0].clone(),
        });
    }

    Ok(sets)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── CHK-875: Valid AAR with instance 1 ──────────────────────────

    #[test]
    fn parse_valid_aar() {
        let aar = parse_aar("i=1; spf=pass smtp.mailfrom=example.com").unwrap();
        assert_eq!(aar.instance, 1);
        assert_eq!(aar.payload, "spf=pass smtp.mailfrom=example.com");
    }

    // ─── CHK-876: Valid AMS with all required tags ───────────────────

    #[test]
    fn parse_valid_ams() {
        let ams = parse_ams(
            "i=1; a=rsa-sha256; d=example.com; s=sel1; \
             b=dGVzdA==; bh=dGVzdA==; h=from:to:subject",
        )
        .unwrap();
        assert_eq!(ams.instance, 1);
        assert_eq!(ams.algorithm, Algorithm::RsaSha256);
        assert_eq!(ams.domain, "example.com");
        assert_eq!(ams.selector, "sel1");
        assert_eq!(ams.signed_headers, vec!["from", "to", "subject"]);
    }

    // ─── CHK-877: Valid AS with all cv values ────────────────────────

    #[test]
    fn parse_seal_cv_none() {
        let seal = parse_seal("i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==").unwrap();
        assert_eq!(seal.cv, ChainValidationStatus::None);
    }

    #[test]
    fn parse_seal_cv_pass() {
        let seal = parse_seal("i=2; cv=pass; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==").unwrap();
        assert_eq!(seal.cv, ChainValidationStatus::Pass);
    }

    #[test]
    fn parse_seal_cv_fail() {
        let seal = parse_seal("i=3; cv=fail; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==").unwrap();
        assert_eq!(seal.cv, ChainValidationStatus::Fail);
    }

    // ─── CHK-878: AS with h= tag → Fail ─────────────────────────────

    #[test]
    fn seal_with_h_tag_fails() {
        let result =
            parse_seal("i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; h=from:to");
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("h= tag"));
    }

    // ─── CHK-879: Missing required tag → Fail ────────────────────────

    #[test]
    fn ams_missing_i_tag() {
        let result = parse_ams("a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from");
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("missing required tag: i"));
    }

    #[test]
    fn seal_missing_cv_tag() {
        let result = parse_seal("i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==");
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("missing required tag: cv"));
    }

    // ─── CHK-880: Instance 0 or 51 → Fail ───────────────────────────

    #[test]
    fn instance_0_fails() {
        let result = parse_aar("i=0; test=pass");
        assert!(result.is_err());
    }

    #[test]
    fn instance_51_fails() {
        let result = parse_aar("i=51; test=pass");
        assert!(result.is_err());
    }

    // ─── CHK-881: Duplicate tags → Fail ──────────────────────────────

    #[test]
    fn ams_duplicate_tag_fails() {
        let result = parse_ams(
            "i=1; a=rsa-sha256; a=ed25519-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("duplicate tag"));
    }

    // ─── CHK-790: AMS no v= tag ─────────────────────────────────────

    #[test]
    fn ams_no_version_tag() {
        // AMS should parse fine without v= — it's not required
        let ams = parse_ams(
            "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
        )
        .unwrap();
        assert_eq!(ams.instance, 1);
    }

    // ─── CHK-791: h= MUST NOT include ARC-* or Auth-Results ─────────

    #[test]
    fn ams_h_rejects_arc_headers() {
        let result = parse_ams(
            "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from:arc-seal",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("must not"));
    }

    #[test]
    fn ams_h_rejects_authentication_results() {
        let result = parse_ams(
            "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from:Authentication-Results",
        );
        assert!(result.is_err());
    }

    // ─── CHK-821: Unknown algorithm → Fail ───────────────────────────

    #[test]
    fn unknown_algorithm_fails() {
        let result = parse_ams(
            "i=1; a=bad-algo; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("unknown algorithm"));
    }

    // ─── CHK-820: Malformed base64 → Fail ────────────────────────────

    #[test]
    fn malformed_base64_fails() {
        let result = parse_ams(
            "i=1; a=rsa-sha256; d=ex.com; s=s1; b=!!!not-base64!!!; bh=dGVzdA==; h=from",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("base64"));
    }

    // ─── CHK-804-808: collect_arc_sets tests ─────────────────────────

    #[test]
    fn collect_empty_headers() {
        let sets = collect_arc_sets(&[("from", "test@example.com")]).unwrap();
        assert!(sets.is_empty());
    }

    #[test]
    fn collect_single_valid_set() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let sets = collect_arc_sets(&headers).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].instance, 1);
    }

    // ─── CHK-824: Instance gaps → Fail ───────────────────────────────

    #[test]
    fn collect_instance_gap_fails() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
            // Skip instance 2, jump to 3
            ("ARC-Authentication-Results", "i=3; spf=pass"),
            (
                "ARC-Message-Signature",
                "i=3; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=3; cv=pass; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let result = collect_arc_sets(&headers);
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("gap"));
    }

    // ─── CHK-823: Duplicate headers same instance → Fail ─────────────

    #[test]
    fn collect_duplicate_instance_fails() {
        let headers = vec![
            ("ARC-Authentication-Results", "i=1; spf=pass"),
            ("ARC-Authentication-Results", "i=1; dkim=pass"), // duplicate
            (
                "ARC-Message-Signature",
                "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from",
            ),
            (
                "ARC-Seal",
                "i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==",
            ),
        ];
        let result = collect_arc_sets(&headers);
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("duplicate"));
    }

    // ─── AMS c= tag parsing ─────────────────────────────────────────

    #[test]
    fn ams_c_tag_parsing() {
        let ams = parse_ams(
            "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from; c=relaxed/simple",
        )
        .unwrap();
        assert_eq!(ams.header_canonicalization, CanonicalizationMethod::Relaxed);
        assert_eq!(ams.body_canonicalization, CanonicalizationMethod::Simple);
    }

    // ─── AMS optional tags ──────────────────────────────────────────

    #[test]
    fn ams_optional_tags() {
        let ams = parse_ams(
            "i=1; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; bh=dGVzdA==; h=from; t=1700000000; l=100",
        )
        .unwrap();
        assert_eq!(ams.timestamp, Some(1700000000));
        assert_eq!(ams.body_length, Some(100));
    }

    // ─── AS optional t= tag ─────────────────────────────────────────

    #[test]
    fn seal_optional_timestamp() {
        let seal = parse_seal(
            "i=1; cv=none; a=rsa-sha256; d=ex.com; s=s1; b=dGVzdA==; t=1700000000",
        )
        .unwrap();
        assert_eq!(seal.timestamp, Some(1700000000));
    }
}
