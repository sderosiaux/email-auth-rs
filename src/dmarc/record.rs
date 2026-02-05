use super::alignment::AlignmentMode;
use super::DmarcError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

impl Policy {
    pub fn from_str(s: &str) -> Result<Self, DmarcError> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Policy::None),
            "quarantine" => Ok(Policy::Quarantine),
            "reject" => Ok(Policy::Reject),
            _ => Err(DmarcError::Parse(format!("invalid policy: {}", s))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DmarcRecord {
    pub version: String,
    pub policy: Policy,
    pub subdomain_policy: Option<Policy>,
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub np: Option<Policy>,  // RFC 9091: non-existent subdomain policy
    pub pct: u8,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub fo: Vec<char>,
    pub ri: u32,
    pub raw: String,
}

impl DmarcRecord {
    pub fn parse(txt: &str) -> Result<Self, DmarcError> {
        let txt = txt.trim();

        // First tag must be v=DMARC1
        if !txt.to_uppercase().starts_with("V=DMARC1") {
            return Err(DmarcError::Parse("record must start with v=DMARC1".to_string()));
        }

        let mut policy = None;
        let mut subdomain_policy = None;
        let mut adkim = AlignmentMode::Relaxed;
        let mut aspf = AlignmentMode::Relaxed;
        let mut np = None;
        let mut pct = 100u8;
        let mut rua = Vec::new();
        let mut ruf = Vec::new();
        let mut fo = vec!['0'];
        let mut ri = 86400u32;

        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let eq_pos = match part.find('=') {
                Some(pos) => pos,
                None => continue,
            };

            let tag = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim();

            match tag.as_str() {
                "v" => {
                    // Already validated
                }
                "p" => {
                    policy = Some(Policy::from_str(value)?);
                }
                "sp" => {
                    subdomain_policy = Some(Policy::from_str(value)?);
                }
                "adkim" => {
                    adkim = match value.to_lowercase().as_str() {
                        "r" => AlignmentMode::Relaxed,
                        "s" => AlignmentMode::Strict,
                        _ => {
                            return Err(DmarcError::Parse(format!(
                                "invalid adkim value: {}",
                                value
                            )))
                        }
                    };
                }
                "aspf" => {
                    aspf = match value.to_lowercase().as_str() {
                        "r" => AlignmentMode::Relaxed,
                        "s" => AlignmentMode::Strict,
                        _ => {
                            return Err(DmarcError::Parse(format!(
                                "invalid aspf value: {}",
                                value
                            )))
                        }
                    };
                }
                "np" => {
                    np = Some(Policy::from_str(value)?);
                }
                "pct" => {
                    pct = value.parse::<u8>().unwrap_or(100).min(100);
                }
                "rua" => {
                    rua = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "ruf" => {
                    ruf = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "fo" => {
                    fo = value
                        .split(':')
                        .filter_map(|s| s.trim().chars().next())
                        .collect();
                    if fo.is_empty() {
                        fo = vec!['0'];
                    }
                }
                "ri" => {
                    ri = value.parse::<u32>().unwrap_or(86400);
                }
                _ => {
                    // Ignore unknown tags
                }
            }
        }

        let policy = policy.ok_or_else(|| DmarcError::Parse("missing p= tag".to_string()))?;

        Ok(DmarcRecord {
            version: "DMARC1".to_string(),
            policy,
            subdomain_policy,
            adkim,
            aspf,
            np,
            pct,
            rua,
            ruf,
            fo,
            ri,
            raw: txt.to_string(),
        })
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
        assert_eq!(record.adkim, AlignmentMode::Relaxed);
        assert_eq!(record.aspf, AlignmentMode::Relaxed);
    }

    #[test]
    fn test_parse_full() {
        let record = DmarcRecord::parse(
            "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; \
             rua=mailto:dmarc@example.com",
        )
        .unwrap();

        assert_eq!(record.policy, Policy::Reject);
        assert_eq!(record.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!(record.adkim, AlignmentMode::Strict);
        assert_eq!(record.aspf, AlignmentMode::Strict);
        assert_eq!(record.pct, 50);
        assert_eq!(record.rua, vec!["mailto:dmarc@example.com"]);
    }

    #[test]
    fn test_parse_np() {
        let record = DmarcRecord::parse("v=DMARC1; p=none; np=reject").unwrap();
        assert_eq!(record.np, Some(Policy::Reject));
    }

    #[test]
    fn test_invalid_no_version() {
        assert!(DmarcRecord::parse("p=none").is_err());
    }

    #[test]
    fn test_invalid_no_policy() {
        assert!(DmarcRecord::parse("v=DMARC1").is_err());
    }
}
