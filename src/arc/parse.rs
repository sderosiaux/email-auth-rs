use super::{
    ArcAuthenticationResults, ArcMessageSignature, ArcSeal, ArcSet, ChainValidationStatus,
};
use crate::dkim::signature::parse_tags;
use crate::dkim::{Algorithm, CanonicalizationMethod};
use base64::Engine;

#[derive(Debug, Clone, PartialEq)]
pub enum ArcParseError {
    MissingTag(String),
    InvalidInstance(String),
    InvalidAlgorithm(String),
    InvalidCv(String),
    InvalidBase64(String),
    InvalidCanon(String),
    ForbiddenTag(String),
    DuplicateTag(String),
    InvalidSyntax(String),
}

impl std::fmt::Display for ArcParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTag(t) => write!(f, "missing required tag: {t}"),
            Self::InvalidInstance(s) => write!(f, "invalid instance: {s}"),
            Self::InvalidAlgorithm(s) => write!(f, "invalid algorithm: {s}"),
            Self::InvalidCv(s) => write!(f, "invalid cv: {s}"),
            Self::InvalidBase64(s) => write!(f, "invalid base64: {s}"),
            Self::InvalidCanon(s) => write!(f, "invalid canonicalization: {s}"),
            Self::ForbiddenTag(t) => write!(f, "forbidden tag: {t}"),
            Self::DuplicateTag(t) => write!(f, "duplicate tag: {t}"),
            Self::InvalidSyntax(s) => write!(f, "invalid syntax: {s}"),
        }
    }
}

/// Parse an ARC-Authentication-Results header value.
pub fn parse_aar(value: &str) -> Result<ArcAuthenticationResults, ArcParseError> {
    let trimmed = value.trim();
    // Format: i=<N>; <payload>
    // Find the first semicolon after i=
    let instance = if let Some(rest) = trimmed.strip_prefix("i=") {
        if let Some(semi) = rest.find(';') {
            let num_str = rest[..semi].trim();
            let instance = parse_instance(num_str)?;
            let payload = rest[semi + 1..].trim().to_string();
            return Ok(ArcAuthenticationResults {
                instance,
                payload,
                raw_value: value.to_string(),
            });
        }
        // No semicolon — just i=N
        let instance = parse_instance(rest.trim())?;
        return Ok(ArcAuthenticationResults {
            instance,
            payload: String::new(),
            raw_value: value.to_string(),
        });
    } else {
        // Try tag parsing approach
        let tags = parse_tags(value)
            .map_err(|e| ArcParseError::InvalidSyntax(e.to_string()))?;
        let i_val = tags
            .iter()
            .find(|(n, _)| n == "i")
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| ArcParseError::MissingTag("i".into()))?;
        parse_instance(i_val.trim())?
    };

    // Reconstruct payload (everything after i=N;)
    let payload = if let Some(pos) = trimmed.find(';') {
        trimmed[pos + 1..].trim().to_string()
    } else {
        String::new()
    };

    Ok(ArcAuthenticationResults {
        instance,
        payload,
        raw_value: value.to_string(),
    })
}

/// Parse an ARC-Message-Signature header value.
pub fn parse_ams(value: &str) -> Result<ArcMessageSignature, ArcParseError> {
    let tags = parse_tags(value)
        .map_err(|e| ArcParseError::InvalidSyntax(e.to_string()))?;

    // Check for duplicate tags
    check_duplicates(&tags)?;

    let get = |name: &str| -> Option<&str> {
        tags.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };

    // Required tags
    let instance = parse_instance(
        get("i").ok_or_else(|| ArcParseError::MissingTag("i".into()))?.trim(),
    )?;

    let algorithm = parse_algorithm(
        get("a").ok_or_else(|| ArcParseError::MissingTag("a".into()))?.trim(),
    )?;

    let sig_b64 = get("b").ok_or_else(|| ArcParseError::MissingTag("b".into()))?;
    let signature = decode_base64(sig_b64)?;

    let bh_b64 = get("bh").ok_or_else(|| ArcParseError::MissingTag("bh".into()))?;
    let body_hash = decode_base64(bh_b64)?;

    let domain = get("d")
        .ok_or_else(|| ArcParseError::MissingTag("d".into()))?
        .trim()
        .to_ascii_lowercase();

    let selector = get("s")
        .ok_or_else(|| ArcParseError::MissingTag("s".into()))?
        .trim()
        .to_string();

    let h_str = get("h").ok_or_else(|| ArcParseError::MissingTag("h".into()))?;
    let signed_headers: Vec<String> = h_str
        .split(':')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    // Optional tags
    let (header_canon, body_canon) = if let Some(c) = get("c") {
        parse_canonicalization(c.trim())?
    } else {
        (CanonicalizationMethod::Relaxed, CanonicalizationMethod::Relaxed)
    };

    let timestamp = get("t")
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| ArcParseError::InvalidSyntax(format!("invalid timestamp: {s}")))
        })
        .transpose()?;

    let body_length = get("l")
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| ArcParseError::InvalidSyntax(format!("invalid body length: {s}")))
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
        header_canonicalization: header_canon,
        body_canonicalization: body_canon,
        timestamp,
        body_length,
        raw_value: value.to_string(),
    })
}

/// Parse an ARC-Seal header value.
pub fn parse_seal(value: &str) -> Result<ArcSeal, ArcParseError> {
    let tags = parse_tags(value)
        .map_err(|e| ArcParseError::InvalidSyntax(e.to_string()))?;

    check_duplicates(&tags)?;

    let get = |name: &str| -> Option<&str> {
        tags.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };

    // Check for forbidden h= tag
    if get("h").is_some() {
        return Err(ArcParseError::ForbiddenTag("h".into()));
    }

    // Required tags
    let instance = parse_instance(
        get("i").ok_or_else(|| ArcParseError::MissingTag("i".into()))?.trim(),
    )?;

    let cv = match get("cv")
        .ok_or_else(|| ArcParseError::MissingTag("cv".into()))?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "none" => ChainValidationStatus::None,
        "pass" => ChainValidationStatus::Pass,
        "fail" => ChainValidationStatus::Fail,
        other => return Err(ArcParseError::InvalidCv(other.into())),
    };

    let algorithm = parse_algorithm(
        get("a").ok_or_else(|| ArcParseError::MissingTag("a".into()))?.trim(),
    )?;

    let sig_b64 = get("b").ok_or_else(|| ArcParseError::MissingTag("b".into()))?;
    let signature = decode_base64(sig_b64)?;

    let domain = get("d")
        .ok_or_else(|| ArcParseError::MissingTag("d".into()))?
        .trim()
        .to_ascii_lowercase();

    let selector = get("s")
        .ok_or_else(|| ArcParseError::MissingTag("s".into()))?
        .trim()
        .to_string();

    let timestamp = get("t")
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| ArcParseError::InvalidSyntax(format!("invalid timestamp: {s}")))
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
        raw_value: value.to_string(),
    })
}

/// Collect ARC Sets from message headers.
/// Returns sorted sets (by instance) or error string.
pub fn collect_arc_sets(headers: &[(&str, &str)]) -> Result<Vec<ArcSet>, String> {
    use std::collections::HashMap;

    let mut aars: HashMap<u32, ArcAuthenticationResults> = HashMap::new();
    let mut amss: HashMap<u32, ArcMessageSignature> = HashMap::new();
    let mut seals: HashMap<u32, ArcSeal> = HashMap::new();

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("ARC-Authentication-Results") {
            let aar = parse_aar(value).map_err(|e| format!("AAR parse error: {e}"))?;
            if aars.contains_key(&aar.instance) {
                return Err(format!("duplicate AAR instance {}", aar.instance));
            }
            aars.insert(aar.instance, aar);
        } else if name.eq_ignore_ascii_case("ARC-Message-Signature") {
            let ams = parse_ams(value).map_err(|e| format!("AMS parse error: {e}"))?;
            if amss.contains_key(&ams.instance) {
                return Err(format!("duplicate AMS instance {}", ams.instance));
            }
            amss.insert(ams.instance, ams);
        } else if name.eq_ignore_ascii_case("ARC-Seal") {
            let seal = parse_seal(value).map_err(|e| format!("AS parse error: {e}"))?;
            if seals.contains_key(&seal.instance) {
                return Err(format!("duplicate AS instance {}", seal.instance));
            }
            seals.insert(seal.instance, seal);
        }
    }

    if aars.is_empty() && amss.is_empty() && seals.is_empty() {
        return Ok(Vec::new());
    }

    // Determine max instance
    let max_instance = *aars
        .keys()
        .chain(amss.keys())
        .chain(seals.keys())
        .max()
        .unwrap_or(&0);

    if max_instance > 50 {
        return Err("instance exceeds 50".into());
    }

    // Validate continuous sequence 1..N
    let mut sets = Vec::new();
    for i in 1..=max_instance {
        let aar = aars
            .remove(&i)
            .ok_or_else(|| format!("missing AAR for instance {i}"))?;
        let ams = amss
            .remove(&i)
            .ok_or_else(|| format!("missing AMS for instance {i}"))?;
        let seal = seals
            .remove(&i)
            .ok_or_else(|| format!("missing AS for instance {i}"))?;
        sets.push(ArcSet {
            instance: i,
            aar,
            ams,
            seal,
        });
    }

    // Check no leftover instances
    if !aars.is_empty() || !amss.is_empty() || !seals.is_empty() {
        return Err("non-contiguous instance numbers".into());
    }

    Ok(sets)
}

fn parse_instance(s: &str) -> Result<u32, ArcParseError> {
    let n = s
        .parse::<u32>()
        .map_err(|_| ArcParseError::InvalidInstance(s.into()))?;
    if n < 1 || n > 50 {
        return Err(ArcParseError::InvalidInstance(format!(
            "{n} out of range 1-50"
        )));
    }
    Ok(n)
}

fn parse_algorithm(s: &str) -> Result<Algorithm, ArcParseError> {
    match s.to_ascii_lowercase().as_str() {
        "rsa-sha256" => Ok(Algorithm::RsaSha256),
        "rsa-sha1" => Ok(Algorithm::RsaSha1),
        "ed25519-sha256" => Ok(Algorithm::Ed25519Sha256),
        other => Err(ArcParseError::InvalidAlgorithm(other.into())),
    }
}

fn decode_base64(s: &str) -> Result<Vec<u8>, ArcParseError> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| ArcParseError::InvalidBase64(e.to_string()))
}

fn parse_canonicalization(
    s: &str,
) -> Result<(CanonicalizationMethod, CanonicalizationMethod), ArcParseError> {
    let parts: Vec<&str> = s.split('/').collect();
    let header = match parts[0].to_ascii_lowercase().as_str() {
        "relaxed" => CanonicalizationMethod::Relaxed,
        "simple" => CanonicalizationMethod::Simple,
        other => return Err(ArcParseError::InvalidCanon(other.into())),
    };
    let body = if parts.len() > 1 {
        match parts[1].to_ascii_lowercase().as_str() {
            "relaxed" => CanonicalizationMethod::Relaxed,
            "simple" => CanonicalizationMethod::Simple,
            other => return Err(ArcParseError::InvalidCanon(other.into())),
        }
    } else {
        CanonicalizationMethod::Simple
    };
    Ok((header, body))
}

fn check_duplicates(tags: &[(String, String)]) -> Result<(), ArcParseError> {
    let mut seen = std::collections::HashSet::new();
    for (name, _) in tags {
        if !seen.insert(name.as_str()) {
            return Err(ArcParseError::DuplicateTag(name.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_aar() {
        let aar = parse_aar(" i=1; mx.example.com; spf=pass smtp.mailfrom=sender.com").unwrap();
        assert_eq!(aar.instance, 1);
        assert!(aar.payload.contains("spf=pass"));
    }

    #[test]
    fn test_parse_ams() {
        let ams = parse_ams(
            " i=1; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from:to:subject; c=relaxed/relaxed",
        )
        .unwrap();
        assert_eq!(ams.instance, 1);
        assert_eq!(ams.algorithm, Algorithm::RsaSha256);
        assert_eq!(ams.domain, "example.com");
        assert_eq!(ams.selector, "sel1");
        assert_eq!(ams.signed_headers, vec!["from", "to", "subject"]);
    }

    #[test]
    fn test_parse_seal() {
        let seal = parse_seal(
            " i=1; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==",
        )
        .unwrap();
        assert_eq!(seal.instance, 1);
        assert_eq!(seal.cv, ChainValidationStatus::None);
        assert_eq!(seal.algorithm, Algorithm::RsaSha256);
    }

    #[test]
    fn test_seal_with_h_tag_fails() {
        let result = parse_seal(
            " i=1; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; h=from",
        );
        assert!(matches!(result, Err(ArcParseError::ForbiddenTag(_))));
    }

    #[test]
    fn test_instance_out_of_range() {
        let result = parse_seal(
            " i=0; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==",
        );
        assert!(matches!(result, Err(ArcParseError::InvalidInstance(_))));

        let result = parse_seal(
            " i=51; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==",
        );
        assert!(matches!(result, Err(ArcParseError::InvalidInstance(_))));
    }

    #[test]
    fn test_missing_required_tag() {
        // Missing b= in AMS
        let result = parse_ams(
            " i=1; a=rsa-sha256; d=example.com; s=sel1; bh=dGVzdA==; h=from",
        );
        assert!(matches!(result, Err(ArcParseError::MissingTag(_))));
    }

    #[test]
    fn test_collect_arc_sets() {
        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Authentication-Results", " i=1; mx.example.com; spf=pass"),
            ("ARC-Message-Signature", " i=1; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from"),
            ("ARC-Seal", " i=1; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
        ];
        let sets = collect_arc_sets(&headers).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].instance, 1);
    }

    #[test]
    fn test_collect_arc_sets_gap() {
        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Authentication-Results", " i=1; mx.example.com; spf=pass"),
            ("ARC-Message-Signature", " i=1; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from"),
            ("ARC-Seal", " i=1; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
            // Skip instance 2
            ("ARC-Authentication-Results", " i=3; mx.example.com; spf=pass"),
            ("ARC-Message-Signature", " i=3; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from"),
            ("ARC-Seal", " i=3; cv=pass; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
        ];
        let result = collect_arc_sets(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_instance() {
        let headers: Vec<(&str, &str)> = vec![
            ("ARC-Seal", " i=1; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
            ("ARC-Seal", " i=1; cv=none; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="),
        ];
        let result = collect_arc_sets(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_seal_cv_values() {
        for (cv_str, expected) in [
            ("none", ChainValidationStatus::None),
            ("pass", ChainValidationStatus::Pass),
            ("fail", ChainValidationStatus::Fail),
        ] {
            let seal = parse_seal(&format!(
                " i=1; cv={cv_str}; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="
            ))
            .unwrap();
            assert_eq!(seal.cv, expected);
        }
    }
}
