use super::{AlignmentMode, DmarcError, Policy};

/// Parsed DMARC record
#[derive(Debug, Clone)]
pub struct DmarcRecord {
    /// Version (must be "DMARC1")
    pub version: String,
    /// Policy for domain
    pub policy: Policy,
    /// Subdomain policy (defaults to p)
    pub subdomain_policy: Option<Policy>,
    /// Non-existent subdomain policy (RFC 9091)
    pub nonexistent_policy: Option<Policy>,
    /// DKIM alignment mode
    pub adkim: AlignmentMode,
    /// SPF alignment mode
    pub aspf: AlignmentMode,
    /// Percentage of messages to apply policy
    pub pct: u8,
    /// Aggregate report URIs
    pub rua: Vec<String>,
    /// Failure report URIs
    pub ruf: Vec<String>,
    /// Report interval in seconds
    pub ri: u32,
    /// Failure options
    pub fo: Vec<char>,
}

impl Default for DmarcRecord {
    fn default() -> Self {
        Self {
            version: "DMARC1".to_string(),
            policy: Policy::None,
            subdomain_policy: None,
            nonexistent_policy: None,
            adkim: AlignmentMode::Relaxed,
            aspf: AlignmentMode::Relaxed,
            pct: 100,
            rua: Vec::new(),
            ruf: Vec::new(),
            ri: 86400,
            fo: vec!['0'],
        }
    }
}

impl DmarcRecord {
    /// Parse a DMARC TXT record
    pub fn parse(txt: &str) -> Result<Self, DmarcError> {
        let mut record = Self::default();
        let mut found_version = false;
        let mut found_policy = false;
        let mut is_first_tag = true;

        // Parse tag=value pairs
        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (tag, val) = part
                .split_once('=')
                .ok_or_else(|| DmarcError::Parse(format!("invalid tag-value: {}", part)))?;

            let tag = tag.trim().to_lowercase();
            let val = val.trim();

            match tag.as_str() {
                "v" => {
                    // v= must be first tag
                    if !is_first_tag {
                        return Err(DmarcError::Parse("v= must be first tag".to_string()));
                    }
                    if val != "DMARC1" {
                        return Err(DmarcError::Parse(format!("invalid version: {}", val)));
                    }
                    record.version = val.to_string();
                    found_version = true;
                }
                "p" => {
                    record.policy = Self::parse_policy(val)?;
                    found_policy = true;
                }
                "sp" => {
                    record.subdomain_policy = Some(Self::parse_policy(val)?);
                }
                "np" => {
                    // RFC 9091: non-existent subdomain policy
                    record.nonexistent_policy = Some(Self::parse_policy(val)?);
                }
                "adkim" => {
                    record.adkim = Self::parse_alignment(val)?;
                }
                "aspf" => {
                    record.aspf = Self::parse_alignment(val)?;
                }
                "pct" => {
                    let pct: i32 = val
                        .parse()
                        .map_err(|_| DmarcError::Parse("invalid pct value".to_string()))?;
                    record.pct = pct.clamp(0, 100) as u8;
                }
                "rua" => {
                    record.rua = val.split(',').map(|s| s.trim().to_string()).collect();
                }
                "ruf" => {
                    record.ruf = val.split(',').map(|s| s.trim().to_string()).collect();
                }
                "ri" => {
                    record.ri = val
                        .parse()
                        .map_err(|_| DmarcError::Parse("invalid ri value".to_string()))?;
                }
                "fo" => {
                    record.fo = val.split(':').flat_map(|s| s.trim().chars()).collect();
                }
                "rf" => {
                    // Report format - ignore (we only support AFRF)
                }
                _ => {
                    // Unknown tags are ignored for forward compatibility
                }
            }

            is_first_tag = false;
        }

        if !found_version {
            return Err(DmarcError::Parse("missing v= tag".to_string()));
        }

        if !found_policy {
            return Err(DmarcError::Parse("missing p= tag".to_string()));
        }

        Ok(record)
    }

    fn parse_policy(s: &str) -> Result<Policy, DmarcError> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Policy::None),
            "quarantine" => Ok(Policy::Quarantine),
            "reject" => Ok(Policy::Reject),
            _ => Err(DmarcError::Parse(format!("invalid policy: {}", s))),
        }
    }

    fn parse_alignment(s: &str) -> Result<AlignmentMode, DmarcError> {
        match s.to_lowercase().as_str() {
            "r" => Ok(AlignmentMode::Relaxed),
            "s" => Ok(AlignmentMode::Strict),
            _ => Err(DmarcError::Parse(format!("invalid alignment: {}", s))),
        }
    }

    /// Get the effective policy for a subdomain
    pub fn subdomain_policy_effective(&self) -> Policy {
        self.subdomain_policy.unwrap_or(self.policy)
    }

    /// Get the effective policy for a non-existent subdomain (RFC 9091)
    pub fn nonexistent_policy_effective(&self) -> Policy {
        self.nonexistent_policy
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
    }

    #[test]
    fn test_parse_full() {
        let txt = "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=50; \
                   rua=mailto:reports@example.com; ri=3600";
        let record = DmarcRecord::parse(txt).unwrap();

        assert_eq!(record.policy, Policy::Reject);
        assert_eq!(record.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!(record.adkim, AlignmentMode::Strict);
        assert_eq!(record.aspf, AlignmentMode::Relaxed);
        assert_eq!(record.pct, 50);
        assert_eq!(record.ri, 3600);
    }

    #[test]
    fn test_parse_np_tag() {
        let txt = "v=DMARC1; p=none; sp=quarantine; np=reject";
        let record = DmarcRecord::parse(txt).unwrap();

        assert_eq!(record.policy, Policy::None);
        assert_eq!(record.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!(record.nonexistent_policy, Some(Policy::Reject));
        assert_eq!(record.nonexistent_policy_effective(), Policy::Reject);
    }

    #[test]
    fn test_v_not_first() {
        let result = DmarcRecord::parse("p=none; v=DMARC1");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_policy() {
        let result = DmarcRecord::parse("v=DMARC1");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_version() {
        let result = DmarcRecord::parse("v=DMARC2; p=none");
        assert!(result.is_err());
    }

    #[test]
    fn test_pct_clamping() {
        let record = DmarcRecord::parse("v=DMARC1; p=none; pct=150").unwrap();
        assert_eq!(record.pct, 100);

        let record = DmarcRecord::parse("v=DMARC1; p=none; pct=-10").unwrap();
        assert_eq!(record.pct, 0);
    }
}
