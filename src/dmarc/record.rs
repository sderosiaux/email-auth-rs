use super::{AlignmentMode, Policy};
use crate::dkim::signature::parse_tags;

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
pub enum FailureOption {
    Zero,
    One,
    D,
    S,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReportFormat {
    Afrf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReportUri {
    pub scheme: String,
    pub address: String,
    pub max_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DmarcParseError {
    MissingVersion,
    InvalidVersion(String),
    MissingPolicy,
    InvalidPolicy(String),
    InvalidSyntax(String),
}

impl std::fmt::Display for DmarcParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingVersion => write!(f, "missing v= tag"),
            Self::InvalidVersion(s) => write!(f, "invalid version: {s}"),
            Self::MissingPolicy => write!(f, "missing p= tag"),
            Self::InvalidPolicy(s) => write!(f, "invalid policy: {s}"),
            Self::InvalidSyntax(s) => write!(f, "invalid syntax: {s}"),
        }
    }
}

impl DmarcRecord {
    pub fn parse(input: &str) -> Result<Self, DmarcParseError> {
        let tags = parse_tags(input)
            .map_err(|e| DmarcParseError::InvalidSyntax(e.to_string()))?;

        let get = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        // v= must be first tag and must be DMARC1
        if let Some((first_name, first_val)) = tags.first() {
            if first_name != "v" || first_val.trim() != "DMARC1" {
                return Err(DmarcParseError::InvalidVersion(
                    first_val.trim().to_string(),
                ));
            }
        } else {
            return Err(DmarcParseError::MissingVersion);
        }

        // p= required
        let policy_str = get("p").ok_or(DmarcParseError::MissingPolicy)?;
        let policy = parse_policy(policy_str.trim())?;

        // sp= defaults to p=
        let subdomain_policy = get("sp")
            .map(|s| parse_policy(s.trim()))
            .transpose()?
            .unwrap_or(policy);

        // np= (RFC 9091 extension)
        let non_existent_subdomain_policy = get("np")
            .map(|s| parse_policy(s.trim()))
            .transpose()?;

        // adkim= (default relaxed)
        let dkim_alignment = match get("adkim").unwrap_or("r").trim() {
            "r" => AlignmentMode::Relaxed,
            "s" => AlignmentMode::Strict,
            other => {
                return Err(DmarcParseError::InvalidSyntax(format!(
                    "invalid adkim: {other}"
                )))
            }
        };

        // aspf= (default relaxed)
        let spf_alignment = match get("aspf").unwrap_or("r").trim() {
            "r" => AlignmentMode::Relaxed,
            "s" => AlignmentMode::Strict,
            other => {
                return Err(DmarcParseError::InvalidSyntax(format!(
                    "invalid aspf: {other}"
                )))
            }
        };

        // pct= (default 100)
        let percent = get("pct")
            .map(|s| {
                s.trim()
                    .parse::<u8>()
                    .map_err(|_| DmarcParseError::InvalidSyntax(format!("invalid pct: {s}")))
            })
            .transpose()?
            .unwrap_or(100);

        // fo= (default "0")
        let failure_options = get("fo")
            .map(|s| parse_failure_options(s.trim()))
            .unwrap_or_else(|| vec![FailureOption::Zero]);

        // rf= (default afrf)
        let report_format = ReportFormat::Afrf;

        // ri= (default 86400)
        let report_interval = get("ri")
            .map(|s| {
                s.trim()
                    .parse::<u32>()
                    .map_err(|_| DmarcParseError::InvalidSyntax(format!("invalid ri: {s}")))
            })
            .transpose()?
            .unwrap_or(86400);

        // rua=
        let rua = get("rua")
            .map(|s| parse_report_uris(s))
            .unwrap_or_default();

        // ruf=
        let ruf = get("ruf")
            .map(|s| parse_report_uris(s))
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
            rua,
            ruf,
        })
    }
}

fn parse_policy(s: &str) -> Result<Policy, DmarcParseError> {
    match s.to_ascii_lowercase().as_str() {
        "none" => Ok(Policy::None),
        "quarantine" => Ok(Policy::Quarantine),
        "reject" => Ok(Policy::Reject),
        other => Err(DmarcParseError::InvalidPolicy(other.into())),
    }
}

fn parse_failure_options(s: &str) -> Vec<FailureOption> {
    s.split(':')
        .filter_map(|f| match f.trim() {
            "0" => Some(FailureOption::Zero),
            "1" => Some(FailureOption::One),
            "d" => Some(FailureOption::D),
            "s" => Some(FailureOption::S),
            _ => None,
        })
        .collect()
}

fn parse_report_uris(s: &str) -> Vec<ReportUri> {
    s.split(',')
        .filter_map(|uri_str| {
            let uri_str = uri_str.trim();
            if uri_str.is_empty() {
                return None;
            }
            // Format: "mailto:addr!size" or "mailto:addr"
            let (uri, max_size) = if let Some((u, size)) = uri_str.split_once('!') {
                (u, parse_size(size))
            } else {
                (uri_str, None)
            };

            if let Some((scheme, address)) = uri.split_once(':') {
                Some(ReportUri {
                    scheme: scheme.to_string(),
                    address: address.to_string(),
                    max_size,
                })
            } else {
                None
            }
        })
        .collect()
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('k') {
        (n, 1024u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('g') {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('t') {
        (n, 1024u64 * 1024 * 1024 * 1024)
    } else {
        (s, 1u64)
    };
    num_str.parse::<u64>().ok().map(|n| n * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_record() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=reject; adkim=r; aspf=r; pct=100; rua=mailto:dmarc@example.com",
        )
        .unwrap();
        assert_eq!(r.policy, Policy::Reject);
        assert_eq!(r.dkim_alignment, AlignmentMode::Relaxed);
        assert_eq!(r.spf_alignment, AlignmentMode::Relaxed);
        assert_eq!(r.percent, 100);
        assert_eq!(r.rua.len(), 1);
        assert_eq!(r.rua[0].address, "dmarc@example.com");
    }

    #[test]
    fn test_subdomain_policy() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=reject; sp=quarantine; np=reject",
        )
        .unwrap();
        assert_eq!(r.subdomain_policy, Policy::Quarantine);
        assert_eq!(r.non_existent_subdomain_policy, Some(Policy::Reject));
    }

    #[test]
    fn test_sp_defaults_to_p() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert_eq!(r.subdomain_policy, Policy::Reject);
    }

    #[test]
    fn test_monitoring_policy() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; rua=mailto:dmarc@example.com").unwrap();
        assert_eq!(r.policy, Policy::None);
    }

    #[test]
    fn test_strict_alignment() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; adkim=s; aspf=s").unwrap();
        assert_eq!(r.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(r.spf_alignment, AlignmentMode::Strict);
    }

    #[test]
    fn test_pct() {
        let r = DmarcRecord::parse("v=DMARC1; p=quarantine; pct=50").unwrap();
        assert_eq!(r.percent, 50);
    }

    #[test]
    fn test_missing_version() {
        assert!(DmarcRecord::parse("p=reject").is_err());
    }

    #[test]
    fn test_missing_policy() {
        assert!(DmarcRecord::parse("v=DMARC1").is_err());
    }

    #[test]
    fn test_multiple_rua() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com",
        )
        .unwrap();
        assert_eq!(r.rua.len(), 2);
    }

    #[test]
    fn test_report_uri_with_size() {
        let r = DmarcRecord::parse(
            "v=DMARC1; p=none; rua=mailto:a@example.com!10m",
        )
        .unwrap();
        assert_eq!(r.rua[0].max_size, Some(10 * 1024 * 1024));
    }

    #[test]
    fn test_failure_options() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; fo=1:d:s").unwrap();
        assert!(r.failure_options.contains(&FailureOption::One));
        assert!(r.failure_options.contains(&FailureOption::D));
        assert!(r.failure_options.contains(&FailureOption::S));
    }
}
