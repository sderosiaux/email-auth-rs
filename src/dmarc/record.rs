use super::{AlignmentMode, FailureOption, Policy, ReportFormat, ReportUri};

/// Parsed DMARC DNS record.
#[derive(Debug, Clone)]
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

impl DmarcRecord {
    /// Parse a DMARC TXT record string.
    pub fn parse(txt: &str) -> Result<Self, String> {
        let parts: Vec<&str> = txt.split(';').collect();
        if parts.is_empty() {
            return Err("empty DMARC record".to_string());
        }

        // v= must be first tag
        let first = parts[0].trim();
        let (v_name, v_value) = split_tag(first)?;
        if !v_name.eq_ignore_ascii_case("v") {
            return Err("v= must be first tag in DMARC record".to_string());
        }
        if !v_value.trim().eq_ignore_ascii_case("DMARC1") {
            return Err(format!("invalid DMARC version: {}", v_value));
        }

        // Parse remaining tags
        let mut policy: Option<Policy> = None;
        let mut sp: Option<Policy> = None;
        let mut np: Option<Policy> = None;
        let mut adkim = AlignmentMode::Relaxed;
        let mut aspf = AlignmentMode::Relaxed;
        let mut pct: u8 = 100;
        let mut fo = vec![FailureOption::Zero];
        let mut rf = ReportFormat::Afrf;
        let mut ri: u32 = 86400;
        let mut rua = Vec::new();
        let mut ruf = Vec::new();

        for part in &parts[1..] {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (name, value) = match split_tag(part) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let name_lower = name.to_ascii_lowercase();
            let value = value.trim();

            match name_lower.as_str() {
                "p" => {
                    if policy.is_none() {
                        policy = Some(parse_policy(value)?);
                    }
                    // Duplicate p= → first wins
                }
                "sp" => sp = Some(parse_policy(value)?),
                "np" => np = Some(parse_policy(value)?),
                "adkim" => adkim = parse_alignment(value)?,
                "aspf" => aspf = parse_alignment(value)?,
                "pct" => {
                    pct = match value.parse::<i32>() {
                        Ok(v) => v.clamp(0, 100) as u8,
                        Err(_) => 100, // Non-numeric → default
                    };
                }
                "fo" => {
                    fo = value
                        .split(':')
                        .filter_map(|f| match f.trim().to_ascii_lowercase().as_str() {
                            "0" => Some(FailureOption::Zero),
                            "1" => Some(FailureOption::One),
                            "d" => Some(FailureOption::D),
                            "s" => Some(FailureOption::S),
                            _ => None, // Unknown options ignored
                        })
                        .collect();
                    if fo.is_empty() {
                        fo = vec![FailureOption::Zero];
                    }
                }
                "rf" => {
                    rf = match value.to_ascii_lowercase().as_str() {
                        "afrf" => ReportFormat::Afrf,
                        _ => ReportFormat::Afrf, // Default to AFRF
                    };
                }
                "ri" => {
                    ri = value.parse().unwrap_or(86400);
                }
                "rua" => {
                    rua = parse_uris(value)?;
                }
                "ruf" => {
                    ruf = parse_uris(value)?;
                }
                _ => {
                    // Unknown tags: ignore
                }
            }
        }

        let policy = policy.ok_or("missing p= tag in DMARC record")?;
        let subdomain_policy = sp.unwrap_or(policy);

        Ok(DmarcRecord {
            policy,
            subdomain_policy,
            non_existent_subdomain_policy: np,
            dkim_alignment: adkim,
            spf_alignment: aspf,
            percent: pct,
            failure_options: fo,
            report_format: rf,
            report_interval: ri,
            rua,
            ruf,
        })
    }

    /// Filter DNS TXT records to find a valid DMARC record.
    pub fn from_txt_records(records: &[String]) -> Option<DmarcRecord> {
        let valid: Vec<DmarcRecord> = records
            .iter()
            .filter_map(|r| {
                let trimmed = r.trim();
                let lower = trimmed.to_ascii_lowercase();
                if lower.starts_with("v=dmarc1;") || lower == "v=dmarc1" {
                    DmarcRecord::parse(trimmed).ok()
                } else {
                    None
                }
            })
            .collect();

        match valid.len() {
            1 => Some(valid.into_iter().next().unwrap()),
            _ => None, // 0 or 2+ → no policy
        }
    }
}

fn split_tag(s: &str) -> Result<(&str, &str), String> {
    if let Some(eq) = s.find('=') {
        Ok((s[..eq].trim(), &s[eq + 1..]))
    } else {
        Err(format!("invalid tag: {}", s))
    }
}

fn parse_policy(s: &str) -> Result<Policy, String> {
    match s.to_ascii_lowercase().as_str() {
        "none" => Ok(Policy::None),
        "quarantine" => Ok(Policy::Quarantine),
        "reject" => Ok(Policy::Reject),
        _ => Err(format!("invalid policy: {}", s)),
    }
}

fn parse_alignment(s: &str) -> Result<AlignmentMode, String> {
    match s.to_ascii_lowercase().as_str() {
        "r" => Ok(AlignmentMode::Relaxed),
        "s" => Ok(AlignmentMode::Strict),
        _ => Err(format!("invalid alignment mode: {}", s)),
    }
}

fn parse_uris(s: &str) -> Result<Vec<ReportUri>, String> {
    let mut uris = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if !part.starts_with("mailto:") {
            return Err(format!("only mailto: URIs supported, got: {}", part));
        }
        let rest = &part[7..]; // after "mailto:"

        // Check for size suffix: !size[unit]
        if let Some(bang_pos) = rest.find('!') {
            let address = rest[..bang_pos].to_string();
            let size_str = &rest[bang_pos + 1..];
            let (num_str, multiplier) = if size_str.ends_with(|c: char| c.is_ascii_alphabetic()) {
                let unit = size_str.chars().last().unwrap().to_ascii_lowercase();
                let num = &size_str[..size_str.len() - 1];
                let mult: u64 = match unit {
                    'k' => 1024,
                    'm' => 1024 * 1024,
                    'g' => 1024 * 1024 * 1024,
                    't' => 1024 * 1024 * 1024 * 1024,
                    _ => 1,
                };
                (num, mult)
            } else {
                (size_str, 1u64)
            };
            let max_size = num_str
                .parse::<u64>()
                .ok()
                .map(|n| n * multiplier);
            uris.push(ReportUri {
                scheme: "mailto".to_string(),
                address,
                max_size,
            });
        } else {
            uris.push(ReportUri {
                scheme: "mailto".to_string(),
                address: rest.to_string(),
                max_size: None,
            });
        }
    }
    Ok(uris)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let r = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(r.policy, Policy::None);
        assert_eq!(r.dkim_alignment, AlignmentMode::Relaxed);
        assert_eq!(r.spf_alignment, AlignmentMode::Relaxed);
        assert_eq!(r.percent, 100);
    }

    #[test]
    fn test_parse_full() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=reject; sp=quarantine; np=reject; adkim=s; aspf=s; pct=75; fo=0:1:d:s; rf=afrf; ri=3600; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com"
        ).unwrap();
        assert_eq!(r.policy, Policy::Reject);
        assert_eq!(r.subdomain_policy, Policy::Quarantine);
        assert_eq!(r.non_existent_subdomain_policy, Some(Policy::Reject));
        assert_eq!(r.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(r.spf_alignment, AlignmentMode::Strict);
        assert_eq!(r.percent, 75);
        assert_eq!(r.failure_options.len(), 4);
        assert_eq!(r.report_interval, 3600);
        assert_eq!(r.rua.len(), 1);
        assert_eq!(r.ruf.len(), 1);
    }

    #[test]
    fn test_missing_v() {
        assert!(DmarcRecord::parse("p=none").is_err());
    }

    #[test]
    fn test_v_not_first() {
        assert!(DmarcRecord::parse("p=none; v=DMARC1").is_err());
    }

    #[test]
    fn test_invalid_p() {
        assert!(DmarcRecord::parse("v=DMARC1; p=invalid").is_err());
    }

    #[test]
    fn test_missing_p() {
        assert!(DmarcRecord::parse("v=DMARC1; sp=none").is_err());
    }

    #[test]
    fn test_case_insensitive() {
        let r = DmarcRecord::parse("v=dmarc1; p=Quarantine").unwrap();
        assert_eq!(r.policy, Policy::Quarantine);
    }

    #[test]
    fn test_pct_bounds() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; pct=150").unwrap();
        assert_eq!(r.percent, 100);
        let r = DmarcRecord::parse("v=DMARC1; p=none; pct=-5").unwrap();
        assert_eq!(r.percent, 0);
        let r = DmarcRecord::parse("v=DMARC1; p=none; pct=abc").unwrap();
        assert_eq!(r.percent, 100);
    }

    #[test]
    fn test_trailing_semicolons() {
        let r = DmarcRecord::parse("v=DMARC1; p=none;").unwrap();
        assert_eq!(r.policy, Policy::None);
    }

    #[test]
    fn test_unknown_tags_ignored() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; custom=value").unwrap();
        assert_eq!(r.policy, Policy::None);
    }

    #[test]
    fn test_uri_with_size() {
        let r =
            DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:d@example.com!10m").unwrap();
        assert_eq!(r.rua.len(), 1);
        assert_eq!(r.rua[0].address, "d@example.com");
        assert_eq!(r.rua[0].max_size, Some(10 * 1024 * 1024));
    }

    #[test]
    fn test_multiple_uris() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@ex.com,mailto:b@ex.com",
        )
        .unwrap();
        assert_eq!(r.rua.len(), 2);
    }

    #[test]
    fn test_sp_defaults_to_p() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert_eq!(r.subdomain_policy, Policy::Reject);
    }

    #[test]
    fn test_no_semicolons() {
        // "v=DMARC1;p=none;pct=75" — no spaces but valid
        let r = DmarcRecord::parse("v=DMARC1;p=none;pct=75").unwrap();
        assert_eq!(r.policy, Policy::None);
        assert_eq!(r.percent, 75);
    }

    #[test]
    fn test_duplicate_p_first_wins() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; p=none").unwrap();
        assert_eq!(r.policy, Policy::Reject);
    }

    #[test]
    fn test_fo_with_unknown_options() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; fo=0:1:x:d").unwrap();
        assert_eq!(r.failure_options.len(), 3); // 0, 1, d (x ignored)
    }

    #[test]
    fn test_np_parsing() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; np=reject").unwrap();
        assert_eq!(r.non_existent_subdomain_policy, Some(Policy::Reject));
    }

    #[test]
    fn test_ri_non_numeric_default() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; ri=abc").unwrap();
        assert_eq!(r.report_interval, 86400);
    }

    #[test]
    fn test_non_mailto_uri_error() {
        assert!(DmarcRecord::parse("v=DMARC1; p=none; rua=https://example.com").is_err());
    }

    #[test]
    fn test_from_txt_records() {
        let records = vec!["v=DMARC1; p=reject".to_string()];
        let r = DmarcRecord::from_txt_records(&records).unwrap();
        assert_eq!(r.policy, Policy::Reject);
    }

    #[test]
    fn test_from_txt_records_none() {
        let records = vec!["not a dmarc record".to_string()];
        assert!(DmarcRecord::from_txt_records(&records).is_none());
    }

    #[test]
    fn test_from_txt_records_ambiguous() {
        let records = vec![
            "v=DMARC1; p=reject".to_string(),
            "v=DMARC1; p=none".to_string(),
        ];
        assert!(DmarcRecord::from_txt_records(&records).is_none());
    }
}
