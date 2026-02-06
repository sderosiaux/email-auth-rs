use rand::Rng;
use super::record::DmarcRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" => Some(Policy::None),
            "quarantine" => Some(Policy::Quarantine),
            "reject" => Some(Policy::Reject),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

impl From<Policy> for DmarcPolicy {
    fn from(p: Policy) -> Self {
        match p {
            Policy::None => DmarcPolicy::None,
            Policy::Quarantine => DmarcPolicy::Quarantine,
            Policy::Reject => DmarcPolicy::Reject,
        }
    }
}

pub fn get_applicable_policy(record: &DmarcRecord, from_domain: &str) -> Policy {
    let org_domain = crate::common::organizational_domain(from_domain);
    let from_lower = from_domain.to_lowercase();

    // If the From domain is the organizational domain, use p=
    if from_lower == org_domain {
        return record.policy;
    }

    // For subdomains, prefer sp= if set, otherwise fall back to p=
    record.subdomain_policy.unwrap_or(record.policy)
}

pub fn apply_pct_sampling(pct: u8) -> bool {
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }

    let mut rng = rand::rng();
    rng.random_range(1..=100) <= pct
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmarc::AlignmentMode;

    fn make_record(policy: Policy, subdomain_policy: Option<Policy>) -> DmarcRecord {
        DmarcRecord {
            version: "DMARC1".into(),
            policy,
            subdomain_policy,
            pua_policy: None,
            pct: 100,
            adkim: AlignmentMode::Relaxed,
            aspf: AlignmentMode::Relaxed,
            rua: vec![],
            ruf: vec![],
            fo: "0".into(),
            rf: "afrf".into(),
            ri: 86400,
        }
    }

    #[test]
    fn test_org_domain_uses_p() {
        let record = make_record(Policy::Reject, Some(Policy::Quarantine));
        assert_eq!(get_applicable_policy(&record, "example.com"), Policy::Reject);
    }

    #[test]
    fn test_subdomain_uses_sp() {
        let record = make_record(Policy::Reject, Some(Policy::Quarantine));
        assert_eq!(get_applicable_policy(&record, "mail.example.com"), Policy::Quarantine);
    }

    #[test]
    fn test_subdomain_falls_back_to_p() {
        let record = make_record(Policy::Reject, None);
        assert_eq!(get_applicable_policy(&record, "mail.example.com"), Policy::Reject);
    }

    #[test]
    fn test_pct_100_always_applies() {
        for _ in 0..100 {
            assert!(apply_pct_sampling(100));
        }
    }

    #[test]
    fn test_pct_0_never_applies() {
        for _ in 0..100 {
            assert!(!apply_pct_sampling(0));
        }
    }
}
