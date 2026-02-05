use super::{AlignmentMode, DmarcError, PolicyAction};

#[derive(Debug, Clone)]
pub struct DmarcRecord {
    pub version: String,
    pub policy: PolicyAction,
    pub sp: Option<PolicyAction>,
    pub np: Option<PolicyAction>,  // RFC 7489 extension
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub pct: u8,
    pub rua: Option<Vec<String>>,
    pub ruf: Option<Vec<String>>,
    pub fo: Option<String>,
    pub rf: Option<String>,
    pub ri: Option<u32>,
}

impl DmarcRecord {
    pub fn parse(record: &str) -> Result<Self, DmarcError> {
        let mut version = None;
        let mut policy = None;
        let mut sp = None;
        let mut np = None;
        let mut adkim = AlignmentMode::Relaxed;
        let mut aspf = AlignmentMode::Relaxed;
        let mut pct = 100;
        let mut rua = None;
        let mut ruf = None;
        let mut fo = None;
        let mut rf = None;
        let mut ri = None;

        for part in record.split(';') {
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

            match tag.as_str() {
                "v" => {
                    if value != "DMARC1" {
                        return Err(DmarcError::ParseError("invalid version".into()));
                    }
                    version = Some(value.to_string());
                }
                "p" => {
                    policy = Some(PolicyAction::parse(value));
                }
                "sp" => {
                    sp = Some(PolicyAction::parse(value));
                }
                "np" => {
                    np = Some(PolicyAction::parse(value));
                }
                "adkim" => {
                    adkim = AlignmentMode::parse(value);
                }
                "aspf" => {
                    aspf = AlignmentMode::parse(value);
                }
                "pct" => {
                    pct = value.parse().unwrap_or(100).min(100);
                }
                "rua" => {
                    rua = Some(value.split(',').map(|s| s.trim().to_string()).collect());
                }
                "ruf" => {
                    ruf = Some(value.split(',').map(|s| s.trim().to_string()).collect());
                }
                "fo" => {
                    fo = Some(value.to_string());
                }
                "rf" => {
                    rf = Some(value.to_string());
                }
                "ri" => {
                    ri = value.parse().ok();
                }
                _ => {
                    // Ignore unknown tags
                }
            }
        }

        let version = version.ok_or_else(|| DmarcError::ParseError("missing v= tag".into()))?;
        let policy = policy.ok_or_else(|| DmarcError::ParseError("missing p= tag".into()))?;

        Ok(DmarcRecord {
            version,
            policy,
            sp,
            np,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let record = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(record.version, "DMARC1");
        assert!(matches!(record.policy, PolicyAction::None));
        assert_eq!(record.pct, 100);
    }

    #[test]
    fn test_parse_full() {
        let record = DmarcRecord::parse(
            "v=DMARC1; p=reject; sp=quarantine; np=none; adkim=s; aspf=s; pct=50; rua=mailto:report@example.com"
        ).unwrap();

        assert!(matches!(record.policy, PolicyAction::Reject));
        assert!(matches!(record.sp, Some(PolicyAction::Quarantine)));
        assert!(matches!(record.np, Some(PolicyAction::None)));
        assert!(matches!(record.adkim, AlignmentMode::Strict));
        assert!(matches!(record.aspf, AlignmentMode::Strict));
        assert_eq!(record.pct, 50);
        assert!(record.rua.is_some());
    }

    #[test]
    fn test_invalid_version() {
        assert!(DmarcRecord::parse("v=DMARC2; p=none").is_err());
    }

    #[test]
    fn test_missing_policy() {
        assert!(DmarcRecord::parse("v=DMARC1").is_err());
    }
}
