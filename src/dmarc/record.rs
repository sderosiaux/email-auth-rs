use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("not a DMARC record")]
    NotDmarc,
    #[error("missing required tag: {0}")]
    MissingTag(String),
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("v= must be first tag")]
    VersionNotFirst,
}

/// DMARC policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    #[default]
    None,
    Quarantine,
    Reject,
}

/// DMARC alignment mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlignmentMode {
    #[default]
    Relaxed,
    Strict,
}

/// Parsed DMARC record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    pub version: String,
    pub policy: Policy,
    pub subdomain_policy: Option<Policy>,
    pub np_policy: Option<Policy>,  // RFC 9091
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub pct: u8,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
}

impl DmarcRecord {
    /// Parse DMARC TXT record
    pub fn parse(txt: &str) -> Result<Self, ParseError> {
        let txt = txt.trim();

        // Check v=DMARC1 is first
        let lower = txt.to_lowercase();
        if !lower.starts_with("v=dmarc1") {
            return Err(ParseError::NotDmarc);
        }

        let mut policy = None;
        let mut subdomain_policy = None;
        let mut np_policy = None;
        let mut adkim = AlignmentMode::Relaxed;
        let mut aspf = AlignmentMode::Relaxed;
        let mut pct = 100u8;
        let mut rua = Vec::new();
        let mut ruf = Vec::new();

        for (i, part) in txt.split(';').enumerate() {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = match part.split_once('=') {
                Some((t, v)) => (t.trim().to_lowercase(), v.trim()),
                None => continue,
            };

            match tag.as_str() {
                "v" => {
                    if i != 0 {
                        return Err(ParseError::VersionNotFirst);
                    }
                    // Already validated
                }
                "p" => {
                    policy = Some(parse_policy(val)?);
                }
                "sp" => {
                    subdomain_policy = Some(parse_policy(val)?);
                }
                "np" => {
                    np_policy = Some(parse_policy(val)?);
                }
                "adkim" => {
                    adkim = match val.to_lowercase().as_str() {
                        "r" => AlignmentMode::Relaxed,
                        "s" => AlignmentMode::Strict,
                        _ => AlignmentMode::Relaxed,
                    };
                }
                "aspf" => {
                    aspf = match val.to_lowercase().as_str() {
                        "r" => AlignmentMode::Relaxed,
                        "s" => AlignmentMode::Strict,
                        _ => AlignmentMode::Relaxed,
                    };
                }
                "pct" => {
                    pct = val.parse().unwrap_or(100).min(100);
                }
                "rua" => {
                    rua = val.split(',').map(|s| s.trim().to_string()).collect();
                }
                "ruf" => {
                    ruf = val.split(',').map(|s| s.trim().to_string()).collect();
                }
                _ => {} // Ignore unknown tags
            }
        }

        Ok(DmarcRecord {
            version: "DMARC1".to_string(),
            policy: policy.ok_or_else(|| ParseError::MissingTag("p".to_string()))?,
            subdomain_policy,
            np_policy,
            adkim,
            aspf,
            pct,
            rua,
            ruf,
        })
    }

    /// Get effective policy for subdomain
    pub fn subdomain_policy(&self) -> Policy {
        self.subdomain_policy.unwrap_or(self.policy)
    }

    /// Get effective policy for non-existent subdomain (RFC 9091)
    pub fn nonexistent_policy(&self) -> Policy {
        self.np_policy
            .or(self.subdomain_policy)
            .unwrap_or(self.policy)
    }
}

fn parse_policy(s: &str) -> Result<Policy, ParseError> {
    match s.to_lowercase().as_str() {
        "none" => Ok(Policy::None),
        "quarantine" => Ok(Policy::Quarantine),
        "reject" => Ok(Policy::Reject),
        _ => Err(ParseError::InvalidPolicy(s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let record = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(record.policy, Policy::None);
        assert_eq!(record.adkim, AlignmentMode::Relaxed);
        assert_eq!(record.aspf, AlignmentMode::Relaxed);
        assert_eq!(record.pct, 100);
    }

    #[test]
    fn test_parse_full() {
        let record = DmarcRecord::parse(
            "v=DMARC1; p=reject; sp=quarantine; np=none; adkim=s; aspf=s; pct=50; \
             rua=mailto:dmarc@example.com",
        )
        .unwrap();

        assert_eq!(record.policy, Policy::Reject);
        assert_eq!(record.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!(record.np_policy, Some(Policy::None));
        assert_eq!(record.adkim, AlignmentMode::Strict);
        assert_eq!(record.aspf, AlignmentMode::Strict);
        assert_eq!(record.pct, 50);
        assert_eq!(record.rua, vec!["mailto:dmarc@example.com"]);
    }

    #[test]
    fn test_not_dmarc() {
        assert!(DmarcRecord::parse("v=spf1 -all").is_err());
    }

    #[test]
    fn test_subdomain_policy_fallback() {
        let record = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert_eq!(record.subdomain_policy(), Policy::Reject);

        let record = DmarcRecord::parse("v=DMARC1; p=reject; sp=quarantine").unwrap();
        assert_eq!(record.subdomain_policy(), Policy::Quarantine);
    }

    #[test]
    fn test_np_policy_fallback() {
        let record = DmarcRecord::parse("v=DMARC1; p=reject").unwrap();
        assert_eq!(record.nonexistent_policy(), Policy::Reject);

        let record = DmarcRecord::parse("v=DMARC1; p=reject; sp=quarantine").unwrap();
        assert_eq!(record.nonexistent_policy(), Policy::Quarantine);

        let record = DmarcRecord::parse("v=DMARC1; p=reject; sp=quarantine; np=none").unwrap();
        assert_eq!(record.nonexistent_policy(), Policy::None);
    }
}
