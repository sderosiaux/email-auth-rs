//! DMARC record parsing.

use super::alignment::AlignmentMode;
use super::DmarcError;

/// DMARC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    #[default]
    None,
    Quarantine,
    Reject,
}

impl Policy {
    fn from_str(s: &str) -> Result<Self, DmarcError> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Policy::None),
            "quarantine" => Ok(Policy::Quarantine),
            "reject" => Ok(Policy::Reject),
            _ => Err(DmarcError::InvalidRecord(format!("invalid policy: {}", s))),
        }
    }
}

/// Parsed DMARC record.
#[derive(Debug, Clone)]
pub struct DmarcRecord {
    pub version: String,
    pub policy: Policy,
    pub subdomain_policy: Option<Policy>,
    pub np_policy: Option<Policy>, // RFC 9091: non-existent subdomain policy
    pub dkim_alignment: AlignmentMode,
    pub spf_alignment: AlignmentMode,
    pub pct: u8,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub fo: Vec<char>,
    pub ri: u32,
}

impl DmarcRecord {
    /// Parse a DMARC TXT record.
    pub fn parse(txt: &str) -> Result<Self, DmarcError> {
        let mut version = None;
        let mut policy = None;
        let mut subdomain_policy = None;
        let mut np_policy = None;
        let mut dkim_alignment = AlignmentMode::Relaxed;
        let mut spf_alignment = AlignmentMode::Relaxed;
        let mut pct = 100u8;
        let mut rua = Vec::new();
        let mut ruf = Vec::new();
        let mut fo = vec!['0'];
        let mut ri = 86400u32;

        let mut first_tag = true;

        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = match part.split_once('=') {
                Some((t, v)) => (t.trim().to_lowercase(), v.trim()),
                None => continue,
            };

            // v= must be first tag
            if first_tag {
                if tag != "v" {
                    return Err(DmarcError::InvalidRecord("v= must be first tag".into()));
                }
                first_tag = false;
            }

            match tag.as_str() {
                "v" => {
                    if val != "DMARC1" {
                        return Err(DmarcError::InvalidRecord(format!(
                            "invalid version: {}",
                            val
                        )));
                    }
                    version = Some(val.to_string());
                }
                "p" => {
                    policy = Some(Policy::from_str(val)?);
                }
                "sp" => {
                    subdomain_policy = Some(Policy::from_str(val)?);
                }
                "np" => {
                    np_policy = Some(Policy::from_str(val)?);
                }
                "adkim" => {
                    dkim_alignment = match val.to_lowercase().as_str() {
                        "r" => AlignmentMode::Relaxed,
                        "s" => AlignmentMode::Strict,
                        _ => {
                            return Err(DmarcError::InvalidRecord(format!(
                                "invalid adkim: {}",
                                val
                            )))
                        }
                    };
                }
                "aspf" => {
                    spf_alignment = match val.to_lowercase().as_str() {
                        "r" => AlignmentMode::Relaxed,
                        "s" => AlignmentMode::Strict,
                        _ => {
                            return Err(DmarcError::InvalidRecord(format!(
                                "invalid aspf: {}",
                                val
                            )))
                        }
                    };
                }
                "pct" => {
                    let p: i32 = val.parse().map_err(|_| {
                        DmarcError::InvalidRecord(format!("invalid pct: {}", val))
                    })?;
                    pct = p.clamp(0, 100) as u8;
                }
                "rua" => {
                    rua = val.split(',').map(|s| s.trim().to_string()).collect();
                }
                "ruf" => {
                    ruf = val.split(',').map(|s| s.trim().to_string()).collect();
                }
                "fo" => {
                    fo = val.split(':').filter_map(|s| s.trim().chars().next()).collect();
                }
                "ri" => {
                    ri = val.parse().unwrap_or(86400);
                }
                _ => {} // Ignore unknown tags
            }
        }

        let version =
            version.ok_or_else(|| DmarcError::InvalidRecord("missing v= tag".into()))?;
        let policy = policy.ok_or_else(|| DmarcError::InvalidRecord("missing p= tag".into()))?;

        Ok(Self {
            version,
            policy,
            subdomain_policy,
            np_policy,
            dkim_alignment,
            spf_alignment,
            pct,
            rua,
            ruf,
            fo,
            ri,
        })
    }

    /// Get the effective policy for a subdomain.
    pub fn subdomain_policy(&self) -> Policy {
        self.subdomain_policy.unwrap_or(self.policy)
    }

    /// Get the effective policy for a non-existent subdomain (RFC 9091).
    pub fn nonexistent_subdomain_policy(&self) -> Policy {
        self.np_policy
            .or(self.subdomain_policy)
            .unwrap_or(self.policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let record = DmarcRecord::parse("v=DMARC1; p=none").unwrap();
        assert_eq!(record.version, "DMARC1");
        assert_eq!(record.policy, Policy::None);
        assert_eq!(record.pct, 100);
    }

    #[test]
    fn test_parse_full() {
        let record = DmarcRecord::parse(
            "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; \
             rua=mailto:reports@example.com; ruf=mailto:forensic@example.com",
        )
        .unwrap();

        assert_eq!(record.policy, Policy::Reject);
        assert_eq!(record.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!(record.dkim_alignment, AlignmentMode::Strict);
        assert_eq!(record.spf_alignment, AlignmentMode::Strict);
        assert_eq!(record.pct, 50);
        assert_eq!(record.rua.len(), 1);
    }

    #[test]
    fn test_v_must_be_first() {
        let result = DmarcRecord::parse("p=none; v=DMARC1");
        assert!(result.is_err());
    }

    #[test]
    fn test_np_policy() {
        let record = DmarcRecord::parse("v=DMARC1; p=none; sp=quarantine; np=reject").unwrap();
        assert_eq!(record.policy, Policy::None);
        assert_eq!(record.subdomain_policy(), Policy::Quarantine);
        assert_eq!(record.nonexistent_subdomain_policy(), Policy::Reject);
    }

    #[test]
    fn test_pct_clamping() {
        let record = DmarcRecord::parse("v=DMARC1; p=none; pct=150").unwrap();
        assert_eq!(record.pct, 100);

        let record = DmarcRecord::parse("v=DMARC1; p=none; pct=-10").unwrap();
        assert_eq!(record.pct, 0);
    }
}
