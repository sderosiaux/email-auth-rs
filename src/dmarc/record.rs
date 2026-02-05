//! DMARC record parsing

use thiserror::Error;
use super::policy::{Policy, AlignmentMode};

#[derive(Debug, Error)]
pub enum DmarcParseError {
    #[error("missing v= tag")]
    MissingVersion,
    #[error("v= must be first tag")]
    VersionNotFirst,
    #[error("invalid version: {0}")]
    InvalidVersion(String),
    #[error("missing p= tag")]
    MissingPolicy,
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
}

/// Parsed DMARC record
#[derive(Debug, Clone)]
pub struct DmarcRecord {
    pub policy: Policy,
    pub subdomain_policy: Option<Policy>,
    pub np_policy: Option<Policy>,  // RFC 9091
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub pct: u8,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub fo: Vec<char>,
    pub rf: String,
    pub ri: u32,
}

impl DmarcRecord {
    pub fn parse(txt: &str) -> Result<Self, DmarcParseError> {
        let mut version_found = false;
        let mut policy = None;
        let mut subdomain_policy = None;
        let mut np_policy = None;
        let mut adkim = AlignmentMode::Relaxed;
        let mut aspf = AlignmentMode::Relaxed;
        let mut pct = 100u8;
        let mut rua = Vec::new();
        let mut ruf = Vec::new();
        let mut fo = vec!['0'];
        let mut rf = "afrf".to_string();
        let mut ri = 86400u32;

        let mut first_tag = true;

        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let eq_pos = match part.find('=') {
                Some(p) => p,
                None => continue,
            };

            let tag = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim();

            if first_tag {
                if tag != "v" {
                    return Err(DmarcParseError::VersionNotFirst);
                }
                first_tag = false;
            }

            match tag.as_str() {
                "v" => {
                    if value.to_uppercase() != "DMARC1" {
                        return Err(DmarcParseError::InvalidVersion(value.to_string()));
                    }
                    version_found = true;
                }
                "p" => {
                    policy = Some(parse_policy(value)?);
                }
                "sp" => {
                    subdomain_policy = Some(parse_policy(value)?);
                }
                "np" => {
                    np_policy = Some(parse_policy(value)?);
                }
                "adkim" => {
                    adkim = parse_alignment(value);
                }
                "aspf" => {
                    aspf = parse_alignment(value);
                }
                "pct" => {
                    pct = value.parse().unwrap_or(100).min(100);
                }
                "rua" => {
                    rua = value.split(',').map(|s| s.trim().to_string()).collect();
                }
                "ruf" => {
                    ruf = value.split(',').map(|s| s.trim().to_string()).collect();
                }
                "fo" => {
                    fo = value.split(':').filter_map(|s| s.chars().next()).collect();
                }
                "rf" => {
                    rf = value.to_string();
                }
                "ri" => {
                    ri = value.parse().unwrap_or(86400);
                }
                _ => {
                    // Unknown tags ignored
                }
            }
        }

        if !version_found {
            return Err(DmarcParseError::MissingVersion);
        }

        let policy = policy.ok_or(DmarcParseError::MissingPolicy)?;

        Ok(DmarcRecord {
            policy,
            subdomain_policy,
            np_policy,
            adkim,
            aspf,
            pct,
            rua,
            ruf,
            fo,
            rf,
            ri,
        })
    }

    /// Get effective policy for a subdomain
    pub fn get_subdomain_policy(&self) -> Policy {
        self.subdomain_policy.unwrap_or(self.policy)
    }

    /// Get effective policy for non-existent subdomain (RFC 9091)
    pub fn get_np_policy(&self) -> Policy {
        self.np_policy
            .or(self.subdomain_policy)
            .unwrap_or(self.policy)
    }
}

fn parse_policy(s: &str) -> Result<Policy, DmarcParseError> {
    match s.to_lowercase().as_str() {
        "none" => Ok(Policy::None),
        "quarantine" => Ok(Policy::Quarantine),
        "reject" => Ok(Policy::Reject),
        _ => Err(DmarcParseError::InvalidPolicy(s.to_string())),
    }
}

fn parse_alignment(s: &str) -> AlignmentMode {
    match s.to_lowercase().as_str() {
        "s" => AlignmentMode::Strict,
        _ => AlignmentMode::Relaxed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let record = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(record.policy, Policy::None);
        assert_eq!(record.pct, 100);
    }

    #[test]
    fn test_parse_full() {
        let record = DmarcRecord::parse(
            "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=50; rua=mailto:reports@example.com",
        )
        .unwrap();
        assert_eq!(record.policy, Policy::Reject);
        assert_eq!(record.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!(record.adkim, AlignmentMode::Strict);
        assert_eq!(record.aspf, AlignmentMode::Relaxed);
        assert_eq!(record.pct, 50);
    }

    #[test]
    fn test_version_must_be_first() {
        let result = DmarcRecord::parse("p=none; v=DMARC1");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_policy() {
        let result = DmarcRecord::parse("v=DMARC1; p=invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_np_policy() {
        let record = DmarcRecord::parse("v=DMARC1; p=none; sp=quarantine; np=reject").unwrap();
        assert_eq!(record.np_policy, Some(Policy::Reject));
        assert_eq!(record.get_np_policy(), Policy::Reject);
    }
}
