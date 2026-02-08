use super::types::{
    AlignmentMode, DmarcRecord, FailureOption, Policy, ReportFormat, ReportUri,
};

/// DMARC record parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcParseError {
    pub detail: String,
}

impl std::fmt::Display for DmarcParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for DmarcParseError {}

impl DmarcRecord {
    /// Parse a DMARC TXT record string into a DmarcRecord.
    pub fn parse(record: &str) -> Result<Self, DmarcParseError> {
        let tags = parse_tag_list(record)?;

        // v= MUST be first tag
        if tags.is_empty() {
            return Err(DmarcParseError { detail: "empty record".into() });
        }
        let (first_tag, first_val) = &tags[0];
        if !first_tag.eq_ignore_ascii_case("v") {
            return Err(DmarcParseError {
                detail: format!("v= must be first tag, found '{}='", first_tag),
            });
        }
        if !first_val.eq_ignore_ascii_case("DMARC1") {
            return Err(DmarcParseError {
                detail: format!("invalid version: '{}', expected 'DMARC1'", first_val),
            });
        }

        // Find p= (required). Use first occurrence.
        let policy_val = tags.iter()
            .find(|(t, _)| t.eq_ignore_ascii_case("p"))
            .map(|(_, v)| v.as_str());
        let policy = match policy_val {
            Some(v) => Policy::parse(v).ok_or_else(|| DmarcParseError {
                detail: format!("invalid p= value: '{}'", v),
            })?,
            None => return Err(DmarcParseError { detail: "missing required p= tag".into() }),
        };

        // Optional tags — use first occurrence for each
        let mut sp = None;
        let mut np = None;
        let mut adkim = None;
        let mut aspf = None;
        let mut pct = None;
        let mut fo = None;
        let mut rf = None;
        let mut ri = None;
        let mut rua = None;
        let mut ruf = None;

        for (tag, val) in &tags[1..] {
            let tag_lower = tag.to_ascii_lowercase();
            match tag_lower.as_str() {
                "p" => {} // already handled, skip duplicates
                "v" => {} // skip duplicate v=
                "sp" if sp.is_none() => sp = Some(val.as_str()),
                "np" if np.is_none() => np = Some(val.as_str()),
                "adkim" if adkim.is_none() => adkim = Some(val.as_str()),
                "aspf" if aspf.is_none() => aspf = Some(val.as_str()),
                "pct" if pct.is_none() => pct = Some(val.as_str()),
                "fo" if fo.is_none() => fo = Some(val.as_str()),
                "rf" if rf.is_none() => rf = Some(val.as_str()),
                "ri" if ri.is_none() => ri = Some(val.as_str()),
                "rua" if rua.is_none() => rua = Some(val.as_str()),
                "ruf" if ruf.is_none() => ruf = Some(val.as_str()),
                _ => {} // unknown tags ignored
            }
        }

        let subdomain_policy = sp
            .and_then(|v| Policy::parse(v))
            .unwrap_or(policy);

        let non_existent_subdomain_policy = np
            .and_then(|v| Policy::parse(v));

        let dkim_alignment = adkim
            .and_then(|v| AlignmentMode::parse(v))
            .unwrap_or(AlignmentMode::Relaxed);

        let spf_alignment = aspf
            .and_then(|v| AlignmentMode::parse(v))
            .unwrap_or(AlignmentMode::Relaxed);

        let percent = parse_pct(pct);

        let failure_options = parse_fo(fo);

        let report_format = rf
            .and_then(|v| ReportFormat::parse(v))
            .unwrap_or(ReportFormat::Afrf);

        let report_interval = parse_ri(ri);

        let rua_uris = rua
            .map(|v| parse_uri_list(v))
            .transpose()?
            .unwrap_or_default();

        let ruf_uris = ruf
            .map(|v| parse_uri_list(v))
            .transpose()?
            .unwrap_or_default();

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
            rua: rua_uris,
            ruf: ruf_uris,
        })
    }
}

/// Parse tag=value pairs from a semicolon-separated record.
fn parse_tag_list(record: &str) -> Result<Vec<(String, String)>, DmarcParseError> {
    let mut tags = Vec::new();
    for part in record.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (tag, val) = match trimmed.find('=') {
            Some(pos) => (trimmed[..pos].trim(), trimmed[pos + 1..].trim()),
            None => continue, // no = sign, skip
        };
        if tag.is_empty() {
            continue;
        }
        tags.push((tag.to_string(), val.to_string()));
    }
    Ok(tags)
}

/// Parse pct= value. Clamp to 0-100, non-numeric → default 100.
fn parse_pct(val: Option<&str>) -> u8 {
    match val {
        Some(v) => {
            match v.parse::<i64>() {
                Ok(n) if n > 100 => 100,
                Ok(n) if n < 0 => 0,
                Ok(n) => n as u8,
                Err(_) => 100, // non-numeric → default
            }
        }
        None => 100,
    }
}

/// Parse fo= value. Colon-separated, unknown options ignored. Default: [Zero].
fn parse_fo(val: Option<&str>) -> Vec<FailureOption> {
    match val {
        Some(v) => {
            let opts: Vec<FailureOption> = v
                .split(':')
                .filter_map(|s| FailureOption::parse(s.trim()))
                .collect();
            if opts.is_empty() {
                vec![FailureOption::Zero]
            } else {
                opts
            }
        }
        None => vec![FailureOption::Zero],
    }
}

/// Parse ri= value. Non-numeric → default 86400.
fn parse_ri(val: Option<&str>) -> u32 {
    match val {
        Some(v) => v.parse::<u32>().unwrap_or(86400),
        None => 86400,
    }
}

/// Parse a comma-separated list of report URIs.
fn parse_uri_list(val: &str) -> Result<Vec<ReportUri>, DmarcParseError> {
    let mut uris = Vec::new();
    for part in val.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        uris.push(parse_report_uri(trimmed)?);
    }
    Ok(uris)
}

/// Parse a single report URI: `mailto:address[!size[unit]]`.
fn parse_report_uri(uri: &str) -> Result<ReportUri, DmarcParseError> {
    let lower = uri.to_ascii_lowercase();
    if !lower.starts_with("mailto:") {
        return Err(DmarcParseError {
            detail: format!("unsupported URI scheme (only mailto: accepted): '{}'", uri),
        });
    }

    let after_scheme = &uri[7..]; // skip "mailto:"

    // Check for size suffix: address!size[unit]
    let (address, max_size) = if let Some(bang_pos) = after_scheme.rfind('!') {
        let addr = &after_scheme[..bang_pos];
        let size_str = &after_scheme[bang_pos + 1..];
        let max = parse_size_suffix(size_str)?;
        (addr.to_string(), Some(max))
    } else {
        (after_scheme.to_string(), None)
    };

    if address.is_empty() {
        return Err(DmarcParseError {
            detail: "empty mailto: address".into(),
        });
    }

    Ok(ReportUri { address, max_size })
}

/// Parse size suffix: number + optional unit (k/m/g/t).
fn parse_size_suffix(s: &str) -> Result<u64, DmarcParseError> {
    if s.is_empty() {
        return Err(DmarcParseError { detail: "empty size suffix".into() });
    }

    let s_lower = s.to_ascii_lowercase();
    let (num_str, multiplier) = if s_lower.ends_with('k') {
        (&s_lower[..s_lower.len() - 1], 1024u64)
    } else if s_lower.ends_with('m') {
        (&s_lower[..s_lower.len() - 1], 1024u64 * 1024)
    } else if s_lower.ends_with('g') {
        (&s_lower[..s_lower.len() - 1], 1024u64 * 1024 * 1024)
    } else if s_lower.ends_with('t') {
        (&s_lower[..s_lower.len() - 1], 1024u64 * 1024 * 1024 * 1024)
    } else {
        (s_lower.as_str(), 1u64)
    };

    let num: u64 = num_str.parse().map_err(|_| DmarcParseError {
        detail: format!("invalid size number: '{}'", num_str),
    })?;

    Ok(num * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmarc::types::*;

    // ─── CHK-681: Minimal valid ──────────────────────────────────────

    #[test]
    fn minimal_valid_record() {
        let r = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(r.policy, Policy::None);
        assert_eq!(r.subdomain_policy, Policy::None); // defaults to p=
        assert_eq!(r.dkim_alignment, AlignmentMode::Relaxed);
        assert_eq!(r.spf_alignment, AlignmentMode::Relaxed);
        assert_eq!(r.percent, 100);
        assert_eq!(r.failure_options, vec![FailureOption::Zero]);
        assert_eq!(r.report_format, ReportFormat::Afrf);
        assert_eq!(r.report_interval, 86400);
        assert!(r.rua.is_empty());
        assert!(r.ruf.is_empty());
        assert!(r.non_existent_subdomain_policy.is_none());
    }

    // ─── CHK-682: Full record ────────────────────────────────────────

    #[test]
    fn full_record_all_tags() {
        let record = "v=DMARC1; p=reject; sp=quarantine; np=none; \
            adkim=s; aspf=s; pct=50; fo=0:1:d:s; rf=afrf; ri=3600; \
            rua=mailto:agg@example.com!10m; ruf=mailto:fail@example.com";
        let r = DmarcRecord::parse(record).unwrap();
        assert_eq!(r.policy, Policy::Reject);
        assert_eq!(r.subdomain_policy, Policy::Quarantine);
        assert_eq!(r.non_existent_subdomain_policy, Some(Policy::None));
        assert_eq!(r.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(r.spf_alignment, AlignmentMode::Strict);
        assert_eq!(r.percent, 50);
        assert_eq!(r.failure_options, vec![
            FailureOption::Zero,
            FailureOption::One,
            FailureOption::D,
            FailureOption::S,
        ]);
        assert_eq!(r.report_format, ReportFormat::Afrf);
        assert_eq!(r.report_interval, 3600);
        assert_eq!(r.rua.len(), 1);
        assert_eq!(r.rua[0].address, "agg@example.com");
        assert_eq!(r.rua[0].max_size, Some(10 * 1024 * 1024));
        assert_eq!(r.ruf.len(), 1);
        assert_eq!(r.ruf[0].address, "fail@example.com");
        assert_eq!(r.ruf[0].max_size, None);
    }

    // ─── CHK-683: Missing v= ─────────────────────────────────────────

    #[test]
    fn missing_v_tag() {
        let result = DmarcRecord::parse("p=none");
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("v="));
    }

    // ─── CHK-684: v= not first ──────────────────────────────────────

    #[test]
    fn v_not_first_tag() {
        let result = DmarcRecord::parse("p=none; v=DMARC1");
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("v="));
    }

    // ─── CHK-685: Invalid p= value ──────────────────────────────────

    #[test]
    fn invalid_policy_value() {
        let result = DmarcRecord::parse("v=DMARC1; p=invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("p="));
    }

    // ─── CHK-686: Unknown tags ignored ──────────────────────────────

    #[test]
    fn unknown_tags_ignored() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; x=unknown; y=other").unwrap();
        assert_eq!(r.policy, Policy::None);
    }

    // ─── CHK-687: Case insensitivity ─────────────────────────────────

    #[test]
    fn case_insensitive_tags_and_values() {
        let r = DmarcRecord::parse("v=dmarc1; p=Quarantine; ADKIM=S; ASPF=R").unwrap();
        assert_eq!(r.policy, Policy::Quarantine);
        assert_eq!(r.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(r.spf_alignment, AlignmentMode::Relaxed);
    }

    // ─── CHK-688: URI size limits ────────────────────────────────────

    #[test]
    fn uri_size_limits() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@b.com!100k,mailto:c@d.com!5m"
        ).unwrap();
        assert_eq!(r.rua.len(), 2);
        assert_eq!(r.rua[0].max_size, Some(100 * 1024));
        assert_eq!(r.rua[1].max_size, Some(5 * 1024 * 1024));
    }

    #[test]
    fn uri_size_bare_bytes() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@b.com!5000"
        ).unwrap();
        assert_eq!(r.rua[0].max_size, Some(5000));
    }

    #[test]
    fn uri_size_gigabytes() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@b.com!2g"
        ).unwrap();
        assert_eq!(r.rua[0].max_size, Some(2 * 1024 * 1024 * 1024));
    }

    #[test]
    fn uri_size_terabytes() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@b.com!1t"
        ).unwrap();
        assert_eq!(r.rua[0].max_size, Some(1024u64 * 1024 * 1024 * 1024));
    }

    // ─── CHK-689: Multiple URIs ──────────────────────────────────────

    #[test]
    fn multiple_rua_uris() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@b.com,mailto:c@d.com,mailto:e@f.com"
        ).unwrap();
        assert_eq!(r.rua.len(), 3);
        assert_eq!(r.rua[0].address, "a@b.com");
        assert_eq!(r.rua[1].address, "c@d.com");
        assert_eq!(r.rua[2].address, "e@f.com");
    }

    // ─── CHK-690: Non-mailto URI ─────────────────────────────────────

    #[test]
    fn non_mailto_uri_rejected() {
        let result = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=https://example.com/report"
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("mailto"));
    }

    // ─── CHK-691: Trailing semicolons ────────────────────────────────

    #[test]
    fn trailing_semicolons_valid() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject;").unwrap();
        assert_eq!(r.policy, Policy::Reject);
    }

    #[test]
    fn multiple_trailing_semicolons() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject;;;").unwrap();
        assert_eq!(r.policy, Policy::Reject);
    }

    // ─── CHK-692: Whitespace variations ──────────────────────────────

    #[test]
    fn whitespace_around_tags() {
        let r = DmarcRecord::parse("  v = DMARC1 ; p = none ; pct = 75  ").unwrap();
        assert_eq!(r.policy, Policy::None);
        assert_eq!(r.percent, 75);
    }

    // ─── CHK-693: No spaces around semicolons ────────────────────────

    #[test]
    fn no_spaces_around_semicolons() {
        let r = DmarcRecord::parse("v=DMARC1;p=none;pct=75").unwrap();
        assert_eq!(r.policy, Policy::None);
        assert_eq!(r.percent, 75);
    }

    // ─── CHK-694: Duplicate p= → first wins ──────────────────────────

    #[test]
    fn duplicate_p_first_wins() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; p=none").unwrap();
        assert_eq!(r.policy, Policy::Reject);
    }

    // ─── CHK-695: pct > 100 → clamp ─────────────────────────────────

    #[test]
    fn pct_greater_than_100_clamped() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; pct=200").unwrap();
        assert_eq!(r.percent, 100);
    }

    // ─── CHK-696: pct < 0 → clamp ───────────────────────────────────

    #[test]
    fn pct_negative_clamped() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; pct=-5").unwrap();
        assert_eq!(r.percent, 0);
    }

    // ─── CHK-697: pct non-numeric → default ──────────────────────────

    #[test]
    fn pct_non_numeric_default() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; pct=abc").unwrap();
        assert_eq!(r.percent, 100);
    }

    // ─── CHK-698: fo= multiple options ───────────────────────────────

    #[test]
    fn fo_multiple_options() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; fo=0:1:d:s").unwrap();
        assert_eq!(r.failure_options, vec![
            FailureOption::Zero,
            FailureOption::One,
            FailureOption::D,
            FailureOption::S,
        ]);
    }

    // ─── CHK-699: fo= unknown options ignored ────────────────────────

    #[test]
    fn fo_unknown_options_ignored() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; fo=0:x:d:z").unwrap();
        assert_eq!(r.failure_options, vec![FailureOption::Zero, FailureOption::D]);
    }

    // ─── CHK-700: np= parsing (RFC 9091) ─────────────────────────────

    #[test]
    fn np_parsing() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; np=quarantine").unwrap();
        assert_eq!(r.non_existent_subdomain_policy, Some(Policy::Quarantine));
    }

    #[test]
    fn np_absent() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert!(r.non_existent_subdomain_policy.is_none());
    }

    // ─── CHK-701: sp= defaults to p= ────────────────────────────────

    #[test]
    fn sp_defaults_to_p() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert_eq!(r.subdomain_policy, Policy::Reject);
    }

    #[test]
    fn sp_overrides_default() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; sp=none").unwrap();
        assert_eq!(r.subdomain_policy, Policy::None);
    }

    // ─── CHK-702: ri= non-numeric → default ─────────────────────────

    #[test]
    fn ri_non_numeric_default() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; ri=abc").unwrap();
        assert_eq!(r.report_interval, 86400);
    }

    #[test]
    fn ri_custom_value() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; ri=7200").unwrap();
        assert_eq!(r.report_interval, 7200);
    }

    // ─── CHK-760/761: Completeness checks ────────────────────────────

    #[test]
    fn all_policy_variants() {
        assert_eq!(Policy::parse("none"), Some(Policy::None));
        assert_eq!(Policy::parse("quarantine"), Some(Policy::Quarantine));
        assert_eq!(Policy::parse("reject"), Some(Policy::Reject));
        assert_eq!(Policy::parse("NONE"), Some(Policy::None));
        assert_eq!(Policy::parse("invalid"), Option::None);
    }

    #[test]
    fn all_alignment_variants() {
        assert_eq!(AlignmentMode::parse("r"), Some(AlignmentMode::Relaxed));
        assert_eq!(AlignmentMode::parse("s"), Some(AlignmentMode::Strict));
        assert_eq!(AlignmentMode::parse("R"), Some(AlignmentMode::Relaxed));
        assert_eq!(AlignmentMode::parse("x"), Option::None);
    }

    #[test]
    fn all_failure_option_variants() {
        assert_eq!(FailureOption::parse("0"), Some(FailureOption::Zero));
        assert_eq!(FailureOption::parse("1"), Some(FailureOption::One));
        assert_eq!(FailureOption::parse("d"), Some(FailureOption::D));
        assert_eq!(FailureOption::parse("s"), Some(FailureOption::S));
        assert_eq!(FailureOption::parse("D"), Some(FailureOption::D));
        assert_eq!(FailureOption::parse("x"), Option::None);
    }

    #[test]
    fn disposition_enum_exists() {
        // Verify all variants exist and are usable
        let _pass = Disposition::Pass;
        let _quarantine = Disposition::Quarantine;
        let _reject = Disposition::Reject;
        let _none = Disposition::None;
        let _tf = Disposition::TempFail;
    }

    #[test]
    fn dmarc_result_struct() {
        let r = DmarcResult {
            disposition: Disposition::Pass,
            dkim_aligned: true,
            spf_aligned: false,
            applied_policy: Some(Policy::Reject),
            record: None,
        };
        assert_eq!(r.disposition, Disposition::Pass);
        assert!(r.dkim_aligned);
        assert!(!r.spf_aligned);
    }

    #[test]
    fn report_uri_no_size() {
        let uri = parse_report_uri("mailto:dmarc@example.com").unwrap();
        assert_eq!(uri.address, "dmarc@example.com");
        assert!(uri.max_size.is_none());
    }

    #[test]
    fn report_uri_with_size_k() {
        let uri = parse_report_uri("mailto:dmarc@example.com!100k").unwrap();
        assert_eq!(uri.address, "dmarc@example.com");
        assert_eq!(uri.max_size, Some(100 * 1024));
    }

    #[test]
    fn report_uri_with_bare_size() {
        let uri = parse_report_uri("mailto:dmarc@example.com!5000").unwrap();
        assert_eq!(uri.address, "dmarc@example.com");
        assert_eq!(uri.max_size, Some(5000));
    }

    #[test]
    fn report_uri_non_mailto() {
        let result = parse_report_uri("https://example.com");
        assert!(result.is_err());
    }

    // ─── Missing p= tag ─────────────────────────────────────────────

    #[test]
    fn missing_p_tag() {
        let result = DmarcRecord::parse("v=DMARC1; sp=none");
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("p="));
    }

    // ─── Version validation ──────────────────────────────────────────

    #[test]
    fn wrong_version() {
        let result = DmarcRecord::parse("v=DMARC2; p=none");
        assert!(result.is_err());
        assert!(result.unwrap_err().detail.contains("version"));
    }

    // ─── Empty record ───────────────────────────────────────────────

    #[test]
    fn empty_record() {
        let result = DmarcRecord::parse("");
        assert!(result.is_err());
    }

    // ─── fo= all unknown → default Zero ──────────────────────────────

    #[test]
    fn fo_all_unknown_default() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; fo=x:y:z").unwrap();
        assert_eq!(r.failure_options, vec![FailureOption::Zero]);
    }

    // ─── rf= unknown → default afrf ──────────────────────────────────

    #[test]
    fn rf_unknown_default() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; rf=iodef").unwrap();
        assert_eq!(r.report_format, ReportFormat::Afrf);
    }

    // ─── Duplicate tags: first wins (consistent) ─────────────────────

    #[test]
    fn duplicate_sp_first_wins() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; sp=none; sp=quarantine").unwrap();
        assert_eq!(r.subdomain_policy, Policy::None);
    }

    // ─── Size suffix parsing edge cases ──────────────────────────────

    #[test]
    fn size_suffix_case_insensitive() {
        assert_eq!(parse_size_suffix("10K").unwrap(), 10 * 1024);
        assert_eq!(parse_size_suffix("10M").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size_suffix("10G").unwrap(), 10 * 1024 * 1024 * 1024);
    }
}
