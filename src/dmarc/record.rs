use std::fmt;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcError {
    /// Record does not start with `v=DMARC1`.
    MissingVersion,
    /// `v=` tag present but value is not `DMARC1`.
    InvalidVersion(String),
    /// Required `p=` tag is missing.
    MissingPolicy,
    /// `p=` value is not one of none/quarantine/reject.
    InvalidPolicy(String),
    /// Generic parse failure.
    ParseError(String),
}

impl fmt::Display for DmarcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVersion => write!(f, "v=DMARC1 must be the first tag"),
            Self::InvalidVersion(v) => write!(f, "invalid DMARC version: {v}"),
            Self::MissingPolicy => write!(f, "required tag p= is missing"),
            Self::InvalidPolicy(v) => write!(f, "invalid policy value: {v}"),
            Self::ParseError(msg) => write!(f, "DMARC parse error: {msg}"),
        }
    }
}

impl std::error::Error for DmarcError {}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

impl Policy {
    fn parse(s: &str) -> Result<Self, DmarcError> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "quarantine" => Ok(Self::Quarantine),
            "reject" => Ok(Self::Reject),
            _ => Err(DmarcError::InvalidPolicy(s.to_string())),
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlignmentMode {
    Relaxed,
    Strict,
}

impl AlignmentMode {
    fn parse(s: &str) -> Result<Self, DmarcError> {
        match s.to_ascii_lowercase().as_str() {
            "r" => Ok(Self::Relaxed),
            "s" => Ok(Self::Strict),
            _ => Err(DmarcError::ParseError(format!(
                "invalid alignment mode: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureOption {
    /// `0` -- generate report if all mechanisms fail
    Zero,
    /// `1` -- generate report if any mechanism fails
    One,
    /// `d` -- generate report on DKIM failure
    DkimFailure,
    /// `s` -- generate report on SPF failure
    SpfFailure,
}

impl FailureOption {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "0" => Some(Self::Zero),
            "1" => Some(Self::One),
            "d" => Some(Self::DkimFailure),
            "s" => Some(Self::SpfFailure),
            _ => Option::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReportFormat {
    Afrf,
    Other(String),
}

impl ReportFormat {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "afrf" => Self::Afrf,
            other => Self::Other(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// ReportUri
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportUri {
    pub scheme: String,
    pub address: String,
    pub max_size: Option<u64>,
}

impl ReportUri {
    /// Parse a single URI from a DMARC rua/ruf value.
    ///
    /// Format: `mailto:user@example.com` or `mailto:user@example.com!10m`
    fn parse(raw: &str) -> Result<Self, DmarcError> {
        let raw = raw.trim();

        let (scheme, rest) = raw
            .split_once(':')
            .ok_or_else(|| DmarcError::ParseError(format!("URI missing scheme: {raw}")))?;

        let scheme = scheme.to_ascii_lowercase();

        // DMARC only supports mailto: URIs (RFC 7489 Section 6.2)
        if scheme != "mailto" {
            return Err(DmarcError::ParseError(format!(
                "unsupported URI scheme: {scheme} (only mailto is supported)"
            )));
        }

        // Split on `!` for optional size limit
        let (address, max_size) = if let Some((addr, size_spec)) = rest.rsplit_once('!') {
            let size = parse_size_spec(size_spec)?;
            (addr.to_string(), Some(size))
        } else {
            (rest.to_string(), Option::None)
        };

        Ok(Self {
            scheme,
            address,
            max_size,
        })
    }
}

/// Parse a size spec like `10m`, `500k`, `1g`, `2t`, or bare number (bytes).
fn parse_size_spec(s: &str) -> Result<u64, DmarcError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(DmarcError::ParseError("empty size spec".to_string()));
    }

    let last = s.as_bytes()[s.len() - 1];
    let (num_str, multiplier) = match last.to_ascii_lowercase() {
        b'k' => (&s[..s.len() - 1], 1024u64),
        b'm' => (&s[..s.len() - 1], 1024 * 1024),
        b'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        b't' => (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024),
        _ => (s, 1u64),
    };

    let n: u64 = num_str
        .parse()
        .map_err(|_| DmarcError::ParseError(format!("invalid size number: {s}")))?;

    Ok(n.saturating_mul(multiplier))
}

/// Parse a comma-separated list of URIs.
fn parse_uri_list(value: &str) -> Result<Vec<ReportUri>, DmarcError> {
    let mut uris = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        uris.push(ReportUri::parse(part)?);
    }
    Ok(uris)
}

/// Parse colon-separated failure options. Unknown tokens are silently ignored.
fn parse_failure_options(value: &str) -> Vec<FailureOption> {
    value
        .split(':')
        .filter_map(|s| FailureOption::parse(s))
        .collect()
}

// ---------------------------------------------------------------------------
// DmarcRecord
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    /// Domain policy (required).
    pub policy: Policy,
    /// Subdomain policy. Defaults to `policy` when absent.
    pub subdomain_policy: Policy,
    /// Non-existent subdomain policy (RFC 9091). Optional, no default.
    pub non_existent_subdomain_policy: Option<Policy>,
    /// DKIM alignment mode. Default: Relaxed.
    pub dkim_alignment: AlignmentMode,
    /// SPF alignment mode. Default: Relaxed.
    pub spf_alignment: AlignmentMode,
    /// Percentage of messages subject to policy. 0-100, default 100.
    pub percent: u8,
    /// Failure reporting options.
    pub failure_options: Vec<FailureOption>,
    /// Report format.
    pub report_format: ReportFormat,
    /// Report interval in seconds. Default 86400.
    pub report_interval: u32,
    /// Aggregate report URIs.
    pub rua: Vec<ReportUri>,
    /// Forensic/failure report URIs.
    pub ruf: Vec<ReportUri>,
}

impl DmarcRecord {
    /// Parse a raw DMARC TXT record string into a structured `DmarcRecord`.
    pub fn parse(raw: &str) -> Result<Self, DmarcError> {
        let tags = parse_tags(raw)?;

        // v= must be first tag and must be DMARC1
        match tags.first() {
            Some((key, value)) if key.eq_ignore_ascii_case("v") => {
                if !value.eq_ignore_ascii_case("DMARC1") {
                    return Err(DmarcError::InvalidVersion(value.clone()));
                }
            }
            _ => return Err(DmarcError::MissingVersion),
        }

        // Extract p= (required)
        let policy = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("p"))
            .map(|(_, v)| Policy::parse(v))
            .ok_or(DmarcError::MissingPolicy)??;

        // sp= defaults to p
        let subdomain_policy = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("sp"))
            .map(|(_, v)| Policy::parse(v))
            .transpose()?
            .unwrap_or(policy);

        // np= (RFC 9091) — optional, no default
        let non_existent_subdomain_policy = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("np"))
            .map(|(_, v)| Policy::parse(v))
            .transpose()?;

        // adkim= default Relaxed
        let dkim_alignment = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("adkim"))
            .map(|(_, v)| AlignmentMode::parse(v))
            .transpose()?
            .unwrap_or(AlignmentMode::Relaxed);

        // aspf= default Relaxed
        let spf_alignment = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("aspf"))
            .map(|(_, v)| AlignmentMode::parse(v))
            .transpose()?
            .unwrap_or(AlignmentMode::Relaxed);

        // pct= default 100, clamp 0-100
        let percent = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("pct"))
            .map(|(_, v)| parse_pct(v))
            .unwrap_or(100);

        // fo= default "0"
        let failure_options = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("fo"))
            .map(|(_, v)| parse_failure_options(v))
            .unwrap_or_else(|| vec![FailureOption::Zero]);

        // rf= default "afrf"
        let report_format = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("rf"))
            .map(|(_, v)| ReportFormat::parse(v))
            .unwrap_or(ReportFormat::Afrf);

        // ri= default 86400
        let report_interval = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("ri"))
            .and_then(|(_, v)| u32::from_str(v.trim()).ok())
            .unwrap_or(86400);

        // rua=
        let rua = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("rua"))
            .map(|(_, v)| parse_uri_list(v))
            .transpose()?
            .unwrap_or_default();

        // ruf=
        let ruf = tags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("ruf"))
            .map(|(_, v)| parse_uri_list(v))
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
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

/// Parse a DMARC record into ordered (tag, value) pairs.
/// Tags are separated by `;`. Each pair is `tag=value` with optional whitespace.
fn parse_tags(raw: &str) -> Result<Vec<(String, String)>, DmarcError> {
    let mut tags = Vec::new();

    for segment in raw.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }

        let (key, value) = segment.split_once('=').ok_or_else(|| {
            DmarcError::ParseError(format!("tag missing '=' separator: {segment}"))
        })?;

        tags.push((key.trim().to_string(), value.trim().to_string()));
    }

    Ok(tags)
}

/// Parse pct value with clamping to 0-100.
fn parse_pct(s: &str) -> u8 {
    match s.trim().parse::<i64>() {
        Ok(n) if n > 100 => 100,
        Ok(n) if n < 0 => 0,
        Ok(n) => n as u8,
        Err(_) => 100, // default on parse failure
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Minimal valid record --

    #[test]
    fn minimal_valid_record() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(rec.policy, Policy::None);
        assert_eq!(rec.subdomain_policy, Policy::None); // defaults to p
        assert_eq!(rec.non_existent_subdomain_policy, Option::None);
        assert_eq!(rec.dkim_alignment, AlignmentMode::Relaxed);
        assert_eq!(rec.spf_alignment, AlignmentMode::Relaxed);
        assert_eq!(rec.percent, 100);
        assert_eq!(rec.failure_options, vec![FailureOption::Zero]);
        assert_eq!(rec.report_format, ReportFormat::Afrf);
        assert_eq!(rec.report_interval, 86400);
        assert!(rec.rua.is_empty());
        assert!(rec.ruf.is_empty());
    }

    #[test]
    fn minimal_quarantine() {
        let rec = DmarcRecord::parse("v=DMARC1; p=quarantine").unwrap();
        assert_eq!(rec.policy, Policy::Quarantine);
    }

    #[test]
    fn minimal_reject() {
        let rec = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert_eq!(rec.policy, Policy::Reject);
    }

    // -- Full record with all tags --

    #[test]
    fn full_record_all_tags() {
        let raw = "v=DMARC1; p=reject; sp=quarantine; np=none; \
                   adkim=s; aspf=s; pct=50; fo=0:1:d:s; rf=afrf; ri=3600; \
                   rua=mailto:agg@example.com!10m,mailto:agg2@example.com; \
                   ruf=mailto:fail@example.com";
        let rec = DmarcRecord::parse(raw).unwrap();

        assert_eq!(rec.policy, Policy::Reject);
        assert_eq!(rec.subdomain_policy, Policy::Quarantine);
        assert_eq!(rec.non_existent_subdomain_policy, Some(Policy::None));
        assert_eq!(rec.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(rec.spf_alignment, AlignmentMode::Strict);
        assert_eq!(rec.percent, 50);
        assert_eq!(
            rec.failure_options,
            vec![
                FailureOption::Zero,
                FailureOption::One,
                FailureOption::DkimFailure,
                FailureOption::SpfFailure,
            ]
        );
        assert_eq!(rec.report_format, ReportFormat::Afrf);
        assert_eq!(rec.report_interval, 3600);

        assert_eq!(rec.rua.len(), 2);
        assert_eq!(rec.rua[0].scheme, "mailto");
        assert_eq!(rec.rua[0].address, "agg@example.com");
        assert_eq!(rec.rua[0].max_size, Some(10 * 1024 * 1024));
        assert_eq!(rec.rua[1].scheme, "mailto");
        assert_eq!(rec.rua[1].address, "agg2@example.com");
        assert_eq!(rec.rua[1].max_size, Option::None);

        assert_eq!(rec.ruf.len(), 1);
        assert_eq!(rec.ruf[0].address, "fail@example.com");
    }

    // -- v= validation --

    #[test]
    fn missing_v_tag() {
        let err = DmarcRecord::parse("p=none").unwrap_err();
        assert_eq!(err, DmarcError::MissingVersion);
    }

    #[test]
    fn v_not_first_tag() {
        let err = DmarcRecord::parse("p=none; v=DMARC1").unwrap_err();
        assert_eq!(err, DmarcError::MissingVersion);
    }

    #[test]
    fn invalid_version_value() {
        let err = DmarcRecord::parse("v=DMARC2; p=none").unwrap_err();
        assert_eq!(err, DmarcError::InvalidVersion("DMARC2".to_string()));
    }

    #[test]
    fn v_case_insensitive() {
        // DMARC1 should be matched case-insensitively
        let rec = DmarcRecord::parse("v=dmarc1; p=none").unwrap();
        assert_eq!(rec.policy, Policy::None);
    }

    // -- p= validation --

    #[test]
    fn missing_p_tag() {
        let err = DmarcRecord::parse("v=DMARC1").unwrap_err();
        assert_eq!(err, DmarcError::MissingPolicy);
    }

    #[test]
    fn invalid_p_value() {
        let err = DmarcRecord::parse("v=DMARC1; p=invalid").unwrap_err();
        assert_eq!(err, DmarcError::InvalidPolicy("invalid".to_string()));
    }

    #[test]
    fn p_case_insensitive() {
        let rec = DmarcRecord::parse("v=DMARC1; p=Quarantine").unwrap();
        assert_eq!(rec.policy, Policy::Quarantine);
    }

    // -- sp= --

    #[test]
    fn sp_defaults_to_p() {
        let rec = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert_eq!(rec.subdomain_policy, Policy::Reject);
    }

    #[test]
    fn sp_explicit() {
        let rec = DmarcRecord::parse("v=DMARC1; p=reject; sp=none").unwrap();
        assert_eq!(rec.subdomain_policy, Policy::None);
    }

    #[test]
    fn sp_invalid() {
        let err = DmarcRecord::parse("v=DMARC1; p=reject; sp=bad").unwrap_err();
        assert_eq!(err, DmarcError::InvalidPolicy("bad".to_string()));
    }

    // -- np= (RFC 9091) --

    #[test]
    fn np_absent_is_none_option() {
        let rec = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert_eq!(rec.non_existent_subdomain_policy, Option::None);
    }

    #[test]
    fn np_present() {
        let rec = DmarcRecord::parse("v=DMARC1; p=reject; np=quarantine").unwrap();
        assert_eq!(
            rec.non_existent_subdomain_policy,
            Some(Policy::Quarantine)
        );
    }

    // -- adkim/aspf --

    #[test]
    fn alignment_defaults_relaxed() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(rec.dkim_alignment, AlignmentMode::Relaxed);
        assert_eq!(rec.spf_alignment, AlignmentMode::Relaxed);
    }

    #[test]
    fn alignment_strict() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; adkim=s; aspf=s").unwrap();
        assert_eq!(rec.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(rec.spf_alignment, AlignmentMode::Strict);
    }

    #[test]
    fn alignment_mixed() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; adkim=s; aspf=r").unwrap();
        assert_eq!(rec.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(rec.spf_alignment, AlignmentMode::Relaxed);
    }

    // -- pct= --

    #[test]
    fn pct_default_100() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(rec.percent, 100);
    }

    #[test]
    fn pct_explicit() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; pct=25").unwrap();
        assert_eq!(rec.percent, 25);
    }

    #[test]
    fn pct_zero() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; pct=0").unwrap();
        assert_eq!(rec.percent, 0);
    }

    #[test]
    fn pct_clamp_above_100() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; pct=200").unwrap();
        assert_eq!(rec.percent, 100);
    }

    #[test]
    fn pct_clamp_negative() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; pct=-5").unwrap();
        assert_eq!(rec.percent, 0);
    }

    #[test]
    fn pct_non_numeric_defaults() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; pct=abc").unwrap();
        assert_eq!(rec.percent, 100); // falls back to default
    }

    // -- fo= --

    #[test]
    fn fo_default_zero() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(rec.failure_options, vec![FailureOption::Zero]);
    }

    #[test]
    fn fo_single_one() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; fo=1").unwrap();
        assert_eq!(rec.failure_options, vec![FailureOption::One]);
    }

    #[test]
    fn fo_multiple_colon_separated() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; fo=0:1:d:s").unwrap();
        assert_eq!(
            rec.failure_options,
            vec![
                FailureOption::Zero,
                FailureOption::One,
                FailureOption::DkimFailure,
                FailureOption::SpfFailure,
            ]
        );
    }

    #[test]
    fn fo_unknown_tokens_ignored() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; fo=0:x:1").unwrap();
        assert_eq!(
            rec.failure_options,
            vec![FailureOption::Zero, FailureOption::One]
        );
    }

    #[test]
    fn fo_case_insensitive() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; fo=D:S").unwrap();
        assert_eq!(
            rec.failure_options,
            vec![FailureOption::DkimFailure, FailureOption::SpfFailure]
        );
    }

    // -- rf= --

    #[test]
    fn rf_default_afrf() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(rec.report_format, ReportFormat::Afrf);
    }

    #[test]
    fn rf_explicit_afrf() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; rf=afrf").unwrap();
        assert_eq!(rec.report_format, ReportFormat::Afrf);
    }

    #[test]
    fn rf_other_format() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; rf=iodef").unwrap();
        assert_eq!(rec.report_format, ReportFormat::Other("iodef".to_string()));
    }

    // -- ri= --

    #[test]
    fn ri_default() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(rec.report_interval, 86400);
    }

    #[test]
    fn ri_explicit() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; ri=3600").unwrap();
        assert_eq!(rec.report_interval, 3600);
    }

    #[test]
    fn ri_non_numeric_defaults() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; ri=abc").unwrap();
        assert_eq!(rec.report_interval, 86400);
    }

    // -- rua/ruf URI parsing --

    #[test]
    fn rua_single_uri() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:dmarc@example.com").unwrap();
        assert_eq!(rec.rua.len(), 1);
        assert_eq!(rec.rua[0].scheme, "mailto");
        assert_eq!(rec.rua[0].address, "dmarc@example.com");
        assert_eq!(rec.rua[0].max_size, Option::None);
    }

    #[test]
    fn rua_with_size_limit_megabytes() {
        let rec =
            DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:dmarc@example.com!10m").unwrap();
        assert_eq!(rec.rua[0].max_size, Some(10 * 1024 * 1024));
    }

    #[test]
    fn rua_with_size_limit_kilobytes() {
        let rec =
            DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:dmarc@example.com!500k").unwrap();
        assert_eq!(rec.rua[0].max_size, Some(500 * 1024));
    }

    #[test]
    fn rua_with_size_limit_gigabytes() {
        let rec =
            DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:dmarc@example.com!2g").unwrap();
        assert_eq!(rec.rua[0].max_size, Some(2 * 1024 * 1024 * 1024));
    }

    #[test]
    fn rua_with_size_limit_terabytes() {
        let rec =
            DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:dmarc@example.com!1t").unwrap();
        assert_eq!(rec.rua[0].max_size, Some(1024 * 1024 * 1024 * 1024));
    }

    #[test]
    fn rua_with_size_limit_bare_bytes() {
        let rec =
            DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:dmarc@example.com!4096").unwrap();
        assert_eq!(rec.rua[0].max_size, Some(4096));
    }

    #[test]
    fn rua_with_uppercase_unit() {
        let rec =
            DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:dmarc@example.com!10M").unwrap();
        assert_eq!(rec.rua[0].max_size, Some(10 * 1024 * 1024));
    }

    #[test]
    fn rua_multiple_uris() {
        let rec = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@x.com!5m,mailto:b@y.com,mailto:c@z.com!1g",
        )
        .unwrap();
        assert_eq!(rec.rua.len(), 3);
        assert_eq!(rec.rua[0].address, "a@x.com");
        assert_eq!(rec.rua[0].max_size, Some(5 * 1024 * 1024));
        assert_eq!(rec.rua[1].address, "b@y.com");
        assert_eq!(rec.rua[1].max_size, Option::None);
        assert_eq!(rec.rua[2].address, "c@z.com");
        assert_eq!(rec.rua[2].max_size, Some(1024 * 1024 * 1024));
    }

    #[test]
    fn ruf_parsed_same_as_rua() {
        let rec =
            DmarcRecord::parse("v=DMARC1; p=none; ruf=mailto:forensic@example.com!1m").unwrap();
        assert_eq!(rec.ruf.len(), 1);
        assert_eq!(rec.ruf[0].scheme, "mailto");
        assert_eq!(rec.ruf[0].address, "forensic@example.com");
        assert_eq!(rec.ruf[0].max_size, Some(1024 * 1024));
    }

    // -- Unknown tags --

    #[test]
    fn unknown_tags_ignored() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none; x-custom=hello; future=42").unwrap();
        assert_eq!(rec.policy, Policy::None);
    }

    // -- Whitespace tolerance --

    #[test]
    fn whitespace_around_tags() {
        let rec =
            DmarcRecord::parse("  v=DMARC1 ;  p=reject  ;  pct=50  ;  adkim=s  ;  ").unwrap();
        assert_eq!(rec.policy, Policy::Reject);
        assert_eq!(rec.percent, 50);
        assert_eq!(rec.dkim_alignment, AlignmentMode::Strict);
    }

    #[test]
    fn no_spaces() {
        let rec = DmarcRecord::parse("v=DMARC1;p=none;pct=75").unwrap();
        assert_eq!(rec.policy, Policy::None);
        assert_eq!(rec.percent, 75);
    }

    #[test]
    fn trailing_semicolon() {
        let rec = DmarcRecord::parse("v=DMARC1; p=none;").unwrap();
        assert_eq!(rec.policy, Policy::None);
    }

    // -- Edge cases --

    #[test]
    fn empty_string() {
        let err = DmarcRecord::parse("").unwrap_err();
        assert_eq!(err, DmarcError::MissingVersion);
    }

    #[test]
    fn only_whitespace() {
        let err = DmarcRecord::parse("   ").unwrap_err();
        assert_eq!(err, DmarcError::MissingVersion);
    }

    #[test]
    fn duplicate_tags_first_wins() {
        // RFC 7489 says duplicate tags SHOULD be ignored; we take the first occurrence
        let rec = DmarcRecord::parse("v=DMARC1; p=reject; p=none").unwrap();
        assert_eq!(rec.policy, Policy::Reject);
    }

    // -- Policy Display --

    #[test]
    fn policy_display() {
        assert_eq!(Policy::None.to_string(), "none");
        assert_eq!(Policy::Quarantine.to_string(), "quarantine");
        assert_eq!(Policy::Reject.to_string(), "reject");
    }

    // -- ReportUri direct parsing --

    #[test]
    fn report_uri_non_mailto_rejected() {
        let err = DmarcRecord::parse("v=DMARC1; p=none; rua=https://example.com/dmarc").unwrap_err();
        assert!(matches!(err, DmarcError::ParseError(ref s) if s.contains("unsupported URI scheme")), "{err}");
    }

    #[test]
    fn report_uri_missing_scheme() {
        let err = ReportUri::parse("no-scheme-here").unwrap_err();
        assert!(matches!(err, DmarcError::ParseError(_)));
    }

    // -- size spec edge cases --

    #[test]
    fn size_spec_empty_is_error() {
        let err = parse_size_spec("").unwrap_err();
        assert!(matches!(err, DmarcError::ParseError(_)));
    }

    #[test]
    fn size_spec_non_numeric_is_error() {
        let err = parse_size_spec("abc").unwrap_err();
        assert!(matches!(err, DmarcError::ParseError(_)));
    }

    // -- DmarcError Display --

    #[test]
    fn error_display() {
        assert_eq!(
            DmarcError::MissingVersion.to_string(),
            "v=DMARC1 must be the first tag"
        );
        assert_eq!(
            DmarcError::InvalidVersion("X".into()).to_string(),
            "invalid DMARC version: X"
        );
        assert_eq!(
            DmarcError::MissingPolicy.to_string(),
            "required tag p= is missing"
        );
        assert_eq!(
            DmarcError::InvalidPolicy("bad".into()).to_string(),
            "invalid policy value: bad"
        );
    }
}
