use std::fmt;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    Relaxed,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureOption {
    Zero,
    One,
    D,
    S,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportFormat {
    Afrf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportUri {
    pub address: String,
    pub max_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    pub policy: Policy,
    pub subdomain_policy: Policy,
    pub non_existent_subdomain_policy: Option<Policy>,
    pub dkim_alignment: AlignmentMode,
    pub spf_alignment: AlignmentMode,
    pub percent: u8,
    pub failure_options: Vec<FailureOption>,
    pub report_format: ReportFormat,
    pub report_interval: u32,
    pub rua: Vec<ReportUri>,
    pub ruf: Vec<ReportUri>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcParseError {
    MissingVersion,
    VersionNotFirst,
    MissingPolicy,
    InvalidPolicy(String),
    InvalidUri(String),
}

impl fmt::Display for DmarcParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVersion => write!(f, "missing v=DMARC1 tag"),
            Self::VersionNotFirst => write!(f, "v= tag must be the first tag"),
            Self::MissingPolicy => write!(f, "missing p= tag"),
            Self::InvalidPolicy(v) => write!(f, "invalid policy: {v}"),
            Self::InvalidUri(v) => write!(f, "invalid URI: {v}"),
        }
    }
}

impl std::error::Error for DmarcParseError {}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

impl DmarcRecord {
    /// Parse a DMARC TXT record string into a structured `DmarcRecord`.
    ///
    /// Implements RFC 7489 section 6.3 with RFC 9091 np= extension.
    pub fn parse(txt: &str) -> Result<DmarcRecord, DmarcParseError> {
        let tags = parse_tags(txt);

        // v= must exist and be first.
        if tags.is_empty() {
            return Err(DmarcParseError::MissingVersion);
        }
        let (first_key, first_val) = &tags[0];
        if !first_key.eq_ignore_ascii_case("v") {
            return Err(DmarcParseError::VersionNotFirst);
        }
        if !first_val.eq_ignore_ascii_case("dmarc1") {
            return Err(DmarcParseError::MissingVersion);
        }

        // Collect remaining tags. For duplicates, first occurrence wins.
        let mut p_val: Option<&str> = Option::None;
        let mut sp_val: Option<&str> = Option::None;
        let mut np_val: Option<&str> = Option::None;
        let mut adkim_val: Option<&str> = Option::None;
        let mut aspf_val: Option<&str> = Option::None;
        let mut pct_val: Option<&str> = Option::None;
        let mut fo_val: Option<&str> = Option::None;
        let mut rf_val: Option<&str> = Option::None;
        let mut ri_val: Option<&str> = Option::None;
        let mut rua_val: Option<&str> = Option::None;
        let mut ruf_val: Option<&str> = Option::None;

        for (key, val) in &tags[1..] {
            let k = key.to_ascii_lowercase();
            match k.as_str() {
                "p" => {
                    if p_val.is_none() {
                        p_val = Some(val.as_str());
                    }
                }
                "sp" => {
                    if sp_val.is_none() {
                        sp_val = Some(val.as_str());
                    }
                }
                "np" => {
                    if np_val.is_none() {
                        np_val = Some(val.as_str());
                    }
                }
                "adkim" => {
                    if adkim_val.is_none() {
                        adkim_val = Some(val.as_str());
                    }
                }
                "aspf" => {
                    if aspf_val.is_none() {
                        aspf_val = Some(val.as_str());
                    }
                }
                "pct" => {
                    if pct_val.is_none() {
                        pct_val = Some(val.as_str());
                    }
                }
                "fo" => {
                    if fo_val.is_none() {
                        fo_val = Some(val.as_str());
                    }
                }
                "rf" => {
                    if rf_val.is_none() {
                        rf_val = Some(val.as_str());
                    }
                }
                "ri" => {
                    if ri_val.is_none() {
                        ri_val = Some(val.as_str());
                    }
                }
                "rua" => {
                    if rua_val.is_none() {
                        rua_val = Some(val.as_str());
                    }
                }
                "ruf" => {
                    if ruf_val.is_none() {
                        ruf_val = Some(val.as_str());
                    }
                }
                _ => {} // unknown tags silently ignored
            }
        }

        // p= is required.
        let policy = match p_val {
            Some(v) => parse_policy(v)?,
            Option::None => return Err(DmarcParseError::MissingPolicy),
        };

        let subdomain_policy = match sp_val {
            Some(v) => parse_policy(v)?,
            Option::None => policy.clone(),
        };

        let non_existent_subdomain_policy = match np_val {
            Some(v) => Some(parse_policy(v)?),
            Option::None => Option::None,
        };

        let dkim_alignment = parse_alignment(adkim_val);
        let spf_alignment = parse_alignment(aspf_val);

        let percent = match pct_val {
            Some(v) => v.parse::<u8>().unwrap_or(100).min(100),
            Option::None => 100,
        };

        let failure_options = parse_failure_options(fo_val);

        let report_format = match rf_val {
            Some(v) if v.eq_ignore_ascii_case("afrf") => ReportFormat::Afrf,
            _ => ReportFormat::Afrf,
        };

        let report_interval = match ri_val {
            Some(v) => v.parse::<u32>().unwrap_or(86400),
            Option::None => 86400,
        };

        let rua = parse_uri_list(rua_val)?;
        let ruf = parse_uri_list(ruf_val)?;

        Ok(DmarcRecord {
            policy,
            subdomain_policy,
            non_existent_subdomain_policy,
            dkim_alignment,
            spf_alignment,
            percent,
            failure_options,
            report_format,
            report_interval,
            rua,
            ruf,
        })
    }
}

// ---------------------------------------------------------------------------
// Tag=value parser
// ---------------------------------------------------------------------------

/// Split a DMARC record into (tag, value) pairs.
/// Tags are semicolon-separated; whitespace around tags and values is trimmed.
fn parse_tags(txt: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(eq) = part.find('=') {
            let tag = part[..eq].trim().to_string();
            let val = part[eq + 1..].trim().to_string();
            if !tag.is_empty() {
                result.push((tag, val));
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

fn parse_policy(val: &str) -> Result<Policy, DmarcParseError> {
    match val.to_ascii_lowercase().as_str() {
        "none" => Ok(Policy::None),
        "quarantine" => Ok(Policy::Quarantine),
        "reject" => Ok(Policy::Reject),
        _ => Err(DmarcParseError::InvalidPolicy(val.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Alignment
// ---------------------------------------------------------------------------

fn parse_alignment(val: Option<&str>) -> AlignmentMode {
    match val {
        Some(v) if v.eq_ignore_ascii_case("s") => AlignmentMode::Strict,
        _ => AlignmentMode::Relaxed,
    }
}

// ---------------------------------------------------------------------------
// Failure options (fo=)
// ---------------------------------------------------------------------------

fn parse_failure_options(val: Option<&str>) -> Vec<FailureOption> {
    let val = match val {
        Some(v) if !v.is_empty() => v,
        _ => return vec![FailureOption::Zero],
    };

    let mut opts = Vec::new();
    for part in val.split(':') {
        let part = part.trim();
        match part {
            "0" => opts.push(FailureOption::Zero),
            "1" => opts.push(FailureOption::One),
            "d" | "D" => opts.push(FailureOption::D),
            "s" | "S" => opts.push(FailureOption::S),
            _ => {} // unknown ignored
        }
    }
    if opts.is_empty() {
        opts.push(FailureOption::Zero);
    }
    opts
}

// ---------------------------------------------------------------------------
// URI list (rua= / ruf=)
// ---------------------------------------------------------------------------

fn parse_uri_list(val: Option<&str>) -> Result<Vec<ReportUri>, DmarcParseError> {
    let val = match val {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(Vec::new()),
    };

    let mut uris = Vec::new();
    for part in val.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        uris.push(parse_report_uri(part)?);
    }
    Ok(uris)
}

/// Parse a single report URI.
///
/// Format: `mailto:address[!size[unit]]`
/// - Units: k=1024, m=1024^2, g=1024^3, t=1024^4 (case-insensitive)
/// - Malformed size -> None for max_size (no error)
fn parse_report_uri(raw: &str) -> Result<ReportUri, DmarcParseError> {
    if raw.len() < 7 || !raw[..7].eq_ignore_ascii_case("mailto:") {
        return Err(DmarcParseError::InvalidUri(raw.to_string()));
    }

    let after_mailto = &raw[7..];

    let (address, max_size) = if let Some(bang) = after_mailto.find('!') {
        let addr = &after_mailto[..bang];
        let size_str = &after_mailto[bang + 1..];
        (addr.to_string(), parse_size_limit(size_str))
    } else {
        (after_mailto.to_string(), Option::None)
    };

    Ok(ReportUri { address, max_size })
}

/// Parse a size limit string like "10m", "500k", "1024", "5g".
/// Returns None if malformed.
fn parse_size_limit(s: &str) -> Option<u64> {
    if s.is_empty() {
        return Option::None;
    }

    let last = s.as_bytes()[s.len() - 1];
    let (num_str, multiplier) = match last.to_ascii_lowercase() {
        b'k' => (&s[..s.len() - 1], 1024u64),
        b'm' => (&s[..s.len() - 1], 1024u64 * 1024),
        b'g' => (&s[..s.len() - 1], 1024u64 * 1024 * 1024),
        b't' => (&s[..s.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        b'0'..=b'9' => (s, 1u64),
        _ => return Option::None,
    };

    let num: u64 = num_str.parse().ok()?;
    Some(num.saturating_mul(multiplier))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> DmarcRecord {
        DmarcRecord::parse(input).expect("expected successful parse")
    }

    fn err(input: &str) -> DmarcParseError {
        DmarcRecord::parse(input).expect_err("expected parse error")
    }

    // 1. minimal_valid
    #[test]
    fn minimal_valid() {
        let rec = ok("v=DMARC1; p=none");
        assert_eq!(rec.policy, Policy::None);
        assert_eq!(rec.subdomain_policy, Policy::None);
        assert_eq!(rec.non_existent_subdomain_policy, None);
        assert_eq!(rec.dkim_alignment, AlignmentMode::Relaxed);
        assert_eq!(rec.spf_alignment, AlignmentMode::Relaxed);
        assert_eq!(rec.percent, 100);
        assert_eq!(rec.failure_options, vec![FailureOption::Zero]);
        assert_eq!(rec.report_format, ReportFormat::Afrf);
        assert_eq!(rec.report_interval, 86400);
        assert!(rec.rua.is_empty());
        assert!(rec.ruf.is_empty());
    }

    // 2. full_record
    #[test]
    fn full_record() {
        let rec = ok(
            "v=DMARC1; p=reject; sp=quarantine; np=none; adkim=s; aspf=s; \
             pct=50; fo=0:1:d:s; rf=afrf; ri=3600; \
             rua=mailto:agg@example.com!10m; \
             ruf=mailto:fail@example.com",
        );
        assert_eq!(rec.policy, Policy::Reject);
        assert_eq!(rec.subdomain_policy, Policy::Quarantine);
        assert_eq!(rec.non_existent_subdomain_policy, Some(Policy::None));
        assert_eq!(rec.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(rec.spf_alignment, AlignmentMode::Strict);
        assert_eq!(rec.percent, 50);
        assert_eq!(
            rec.failure_options,
            vec![FailureOption::Zero, FailureOption::One, FailureOption::D, FailureOption::S]
        );
        assert_eq!(rec.report_format, ReportFormat::Afrf);
        assert_eq!(rec.report_interval, 3600);
        assert_eq!(rec.rua.len(), 1);
        assert_eq!(rec.rua[0].address, "agg@example.com");
        assert_eq!(rec.rua[0].max_size, Some(10 * 1024 * 1024));
        assert_eq!(rec.ruf.len(), 1);
        assert_eq!(rec.ruf[0].address, "fail@example.com");
        assert_eq!(rec.ruf[0].max_size, None);
    }

    // 3. missing_version
    #[test]
    fn missing_version() {
        assert_eq!(err("p=none"), DmarcParseError::VersionNotFirst);
    }

    // 4. version_not_first
    #[test]
    fn version_not_first() {
        assert_eq!(
            err("p=none; v=DMARC1"),
            DmarcParseError::VersionNotFirst
        );
    }

    // 5. missing_policy
    #[test]
    fn missing_policy() {
        assert_eq!(err("v=DMARC1"), DmarcParseError::MissingPolicy);
    }

    // 6. invalid_policy
    #[test]
    fn invalid_policy() {
        assert_eq!(
            err("v=DMARC1; p=invalid"),
            DmarcParseError::InvalidPolicy("invalid".into())
        );
    }

    // 7. case_insensitive_version
    #[test]
    fn case_insensitive_version() {
        let rec = ok("v=dmarc1; p=none");
        assert_eq!(rec.policy, Policy::None);
    }

    // 8. case_insensitive_policy
    #[test]
    fn case_insensitive_policy() {
        let rec = ok("v=DMARC1; p=Quarantine");
        assert_eq!(rec.policy, Policy::Quarantine);
    }

    // 9. unknown_tags_ignored
    #[test]
    fn unknown_tags_ignored() {
        let rec = ok("v=DMARC1; p=none; custom=value; foo=bar");
        assert_eq!(rec.policy, Policy::None);
    }

    // 10. trailing_semicolons
    #[test]
    fn trailing_semicolons() {
        let rec = ok("v=DMARC1; p=none;");
        assert_eq!(rec.policy, Policy::None);
    }

    // 11. whitespace_variations
    #[test]
    fn whitespace_variations() {
        let rec = ok("v=DMARC1 ;  p = reject ;  pct = 75 ");
        assert_eq!(rec.policy, Policy::Reject);
        assert_eq!(rec.percent, 75);
    }

    // 12. no_semicolons_spaces
    #[test]
    fn no_semicolons_spaces() {
        let rec = ok("v=DMARC1;p=none;pct=75");
        assert_eq!(rec.policy, Policy::None);
        assert_eq!(rec.percent, 75);
    }

    // 13. duplicate_p_first_wins
    #[test]
    fn duplicate_p_first_wins() {
        let rec = ok("v=DMARC1; p=none; p=reject");
        assert_eq!(rec.policy, Policy::None);
    }

    // 14. pct_over_100_clamped
    #[test]
    fn pct_over_100_clamped() {
        let rec = ok("v=DMARC1; p=none; pct=200");
        assert_eq!(rec.percent, 100);
    }

    // 15. pct_non_numeric_default
    #[test]
    fn pct_non_numeric_default() {
        let rec = ok("v=DMARC1; p=none; pct=abc");
        assert_eq!(rec.percent, 100);
    }

    // 16. pct_zero
    #[test]
    fn pct_zero() {
        let rec = ok("v=DMARC1; p=none; pct=0");
        assert_eq!(rec.percent, 0);
    }

    // 17. fo_multiple_options
    #[test]
    fn fo_multiple_options() {
        let rec = ok("v=DMARC1; p=none; fo=0:1:d:s");
        assert_eq!(
            rec.failure_options,
            vec![FailureOption::Zero, FailureOption::One, FailureOption::D, FailureOption::S]
        );
    }

    // 18. fo_unknown_ignored
    #[test]
    fn fo_unknown_ignored() {
        let rec = ok("v=DMARC1; p=none; fo=0:x:1");
        assert_eq!(
            rec.failure_options,
            vec![FailureOption::Zero, FailureOption::One]
        );
    }

    // 19. fo_default
    #[test]
    fn fo_default() {
        let rec = ok("v=DMARC1; p=none");
        assert_eq!(rec.failure_options, vec![FailureOption::Zero]);
    }

    // 20. np_tag
    #[test]
    fn np_tag() {
        let rec = ok("v=DMARC1; p=none; np=reject");
        assert_eq!(rec.non_existent_subdomain_policy, Some(Policy::Reject));
    }

    // 21. sp_defaults_to_p
    #[test]
    fn sp_defaults_to_p() {
        let rec = ok("v=DMARC1; p=reject");
        assert_eq!(rec.subdomain_policy, Policy::Reject);
    }

    // 22. sp_different_from_p
    #[test]
    fn sp_different_from_p() {
        let rec = ok("v=DMARC1; p=none; sp=quarantine");
        assert_eq!(rec.policy, Policy::None);
        assert_eq!(rec.subdomain_policy, Policy::Quarantine);
    }

    // 23. adkim_strict
    #[test]
    fn adkim_strict() {
        let rec = ok("v=DMARC1; p=none; adkim=s");
        assert_eq!(rec.dkim_alignment, AlignmentMode::Strict);
    }

    // 24. aspf_strict
    #[test]
    fn aspf_strict() {
        let rec = ok("v=DMARC1; p=none; aspf=s");
        assert_eq!(rec.spf_alignment, AlignmentMode::Strict);
    }

    // 25. ri_parsing
    #[test]
    fn ri_parsing() {
        let rec = ok("v=DMARC1; p=none; ri=7200");
        assert_eq!(rec.report_interval, 7200);
    }

    #[test]
    fn ri_non_numeric_default() {
        let rec = ok("v=DMARC1; p=none; ri=abc");
        assert_eq!(rec.report_interval, 86400);
    }

    // 26. rua_single_uri
    #[test]
    fn rua_single_uri() {
        let rec = ok("v=DMARC1; p=none; rua=mailto:reports@example.com");
        assert_eq!(rec.rua.len(), 1);
        assert_eq!(rec.rua[0].address, "reports@example.com");
        assert_eq!(rec.rua[0].max_size, None);
    }

    // 27. rua_with_size_limit
    #[test]
    fn rua_with_size_limit() {
        let rec = ok("v=DMARC1; p=none; rua=mailto:reports@example.com!10m");
        assert_eq!(rec.rua.len(), 1);
        assert_eq!(rec.rua[0].address, "reports@example.com");
        assert_eq!(rec.rua[0].max_size, Some(10 * 1024 * 1024));
    }

    // 28. rua_multiple_uris
    #[test]
    fn rua_multiple_uris() {
        let rec = ok(
            "v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com!5k",
        );
        assert_eq!(rec.rua.len(), 2);
        assert_eq!(rec.rua[0].address, "a@example.com");
        assert_eq!(rec.rua[0].max_size, None);
        assert_eq!(rec.rua[1].address, "b@example.com");
        assert_eq!(rec.rua[1].max_size, Some(5 * 1024));
    }

    // 29. rua_non_mailto_rejected
    #[test]
    fn rua_non_mailto_rejected() {
        assert_eq!(
            err("v=DMARC1; p=none; rua=https://example.com"),
            DmarcParseError::InvalidUri("https://example.com".into())
        );
    }

    // 30. ruf_parsing
    #[test]
    fn ruf_parsing() {
        let rec = ok("v=DMARC1; p=none; ruf=mailto:forensic@example.com!1g");
        assert_eq!(rec.ruf.len(), 1);
        assert_eq!(rec.ruf[0].address, "forensic@example.com");
        assert_eq!(rec.ruf[0].max_size, Some(1024 * 1024 * 1024));
    }

    // 31. size_units_parsing
    #[test]
    fn size_units_parsing() {
        assert_eq!(parse_size_limit("1024"), Some(1024));
        assert_eq!(parse_size_limit("5k"), Some(5 * 1024));
        assert_eq!(parse_size_limit("5K"), Some(5 * 1024));
        assert_eq!(parse_size_limit("10m"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size_limit("10M"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size_limit("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size_limit("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size_limit("1t"), Some(1024u64 * 1024 * 1024 * 1024));
        assert_eq!(parse_size_limit("1T"), Some(1024u64 * 1024 * 1024 * 1024));
        assert_eq!(parse_size_limit("abc"), None);
        assert_eq!(parse_size_limit(""), None);
    }

    // 32. reject_policy
    #[test]
    fn reject_policy() {
        let rec = ok("v=DMARC1; p=reject");
        assert_eq!(rec.policy, Policy::Reject);
    }

    // 33. empty_rua
    #[test]
    fn empty_rua() {
        let rec = ok("v=DMARC1; p=none; rua=");
        assert!(rec.rua.is_empty());
    }

    // -- additional edge cases --

    #[test]
    fn empty_input() {
        assert_eq!(err(""), DmarcParseError::MissingVersion);
    }

    #[test]
    fn version_wrong_value() {
        assert_eq!(err("v=DMARC2; p=none"), DmarcParseError::MissingVersion);
    }

    #[test]
    fn alignment_defaults_relaxed() {
        let rec = ok("v=DMARC1; p=none; adkim=r; aspf=r");
        assert_eq!(rec.dkim_alignment, AlignmentMode::Relaxed);
        assert_eq!(rec.spf_alignment, AlignmentMode::Relaxed);
    }

    #[test]
    fn alignment_unknown_defaults_relaxed() {
        let rec = ok("v=DMARC1; p=none; adkim=x; aspf=z");
        assert_eq!(rec.dkim_alignment, AlignmentMode::Relaxed);
        assert_eq!(rec.spf_alignment, AlignmentMode::Relaxed);
    }

    #[test]
    fn fo_all_unknown_defaults_to_zero() {
        let rec = ok("v=DMARC1; p=none; fo=x:y:z");
        assert_eq!(rec.failure_options, vec![FailureOption::Zero]);
    }

    #[test]
    fn np_absent_is_none() {
        let rec = ok("v=DMARC1; p=reject");
        assert_eq!(rec.non_existent_subdomain_policy, None);
    }

    #[test]
    fn rua_size_malformed_skipped() {
        let rec = ok("v=DMARC1; p=none; rua=mailto:a@b.com!xyz");
        assert_eq!(rec.rua[0].address, "a@b.com");
        assert_eq!(rec.rua[0].max_size, None);
    }

    #[test]
    fn multiple_trailing_semicolons() {
        let rec = ok("v=DMARC1; p=none;;;");
        assert_eq!(rec.policy, Policy::None);
    }

    #[test]
    fn case_insensitive_mailto() {
        let rec = ok("v=DMARC1; p=none; rua=MAILTO:test@example.com");
        assert_eq!(rec.rua[0].address, "test@example.com");
    }
}
