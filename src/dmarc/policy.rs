use rand::Rng;

use super::record::{DmarcRecord, Policy};
use super::Disposition;

/// Determine which policy to apply based on From domain relationship
pub fn select_policy(
    record: &DmarcRecord,
    from_domain: &str,
    record_domain: &str,
    from_domain_exists: bool,
) -> Policy {
    let from_lower = from_domain.to_lowercase();
    let record_lower = record_domain.to_lowercase();

    if from_lower == record_lower {
        // From domain matches the DMARC record domain exactly
        // Use the primary policy
        record.policy
    } else {
        // From domain is a subdomain of the DMARC record domain
        if from_domain_exists {
            // Existing subdomain - use sp= (or p= if no sp=)
            record.subdomain_policy()
        } else {
            // Non-existent subdomain - use np= (RFC 9091)
            record.nonexistent_policy()
        }
    }
}

/// Apply percentage sampling
/// Returns true if the policy should be applied, false if it should be treated as none
pub fn should_apply_policy(pct: u8) -> bool {
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }

    let mut rng = rand::rng();
    let roll: u8 = rng.random_range(1..=100);
    roll <= pct
}

/// Convert policy to disposition
pub fn policy_to_disposition(policy: Policy, sampled: bool) -> Disposition {
    if !sampled {
        return Disposition::None;
    }

    match policy {
        Policy::None => Disposition::None,
        Policy::Quarantine => Disposition::Quarantine,
        Policy::Reject => Disposition::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_record() -> DmarcRecord {
        DmarcRecord {
            version: "DMARC1".to_string(),
            policy: Policy::Reject,
            subdomain_policy: Some(Policy::Quarantine),
            np_policy: Some(Policy::None),
            adkim: super::super::record::AlignmentMode::Relaxed,
            aspf: super::super::record::AlignmentMode::Relaxed,
            pct: 100,
            rua: vec![],
            ruf: vec![],
        }
    }

    #[test]
    fn test_select_policy_exact_match() {
        let record = test_record();
        let policy = select_policy(&record, "example.com", "example.com", true);
        assert_eq!(policy, Policy::Reject);
    }

    #[test]
    fn test_select_policy_existing_subdomain() {
        let record = test_record();
        let policy = select_policy(&record, "mail.example.com", "example.com", true);
        assert_eq!(policy, Policy::Quarantine);
    }

    #[test]
    fn test_select_policy_nonexistent_subdomain() {
        let record = test_record();
        let policy = select_policy(&record, "fake.example.com", "example.com", false);
        assert_eq!(policy, Policy::None);
    }

    #[test]
    fn test_policy_to_disposition() {
        assert_eq!(
            policy_to_disposition(Policy::Reject, true),
            Disposition::Reject
        );
        assert_eq!(
            policy_to_disposition(Policy::Quarantine, true),
            Disposition::Quarantine
        );
        assert_eq!(
            policy_to_disposition(Policy::None, true),
            Disposition::None
        );
        // Not sampled - always None
        assert_eq!(
            policy_to_disposition(Policy::Reject, false),
            Disposition::None
        );
    }

    #[test]
    fn test_sampling_boundaries() {
        // 100% should always apply
        for _ in 0..10 {
            assert!(should_apply_policy(100));
        }

        // 0% should never apply
        for _ in 0..10 {
            assert!(!should_apply_policy(0));
        }
    }
}
