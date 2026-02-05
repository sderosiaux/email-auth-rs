use crate::common::organizational_domain;
use crate::dkim::DkimResult;
use crate::spf::SpfResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    Relaxed,
    Strict,
}

/// Check if any DKIM signature aligns with the From domain
pub fn check_dkim_alignment(
    from_domain: &str,
    dkim_results: &[DkimResult],
    mode: AlignmentMode,
) -> bool {
    for result in dkim_results {
        if let DkimResult::Pass { domain, .. } = result {
            if domains_aligned(from_domain, domain, mode) {
                return true;
            }
        }
    }
    false
}

/// Check if SPF result aligns with the From domain
pub fn check_spf_alignment(
    from_domain: &str,
    spf_result: &SpfResult,
    spf_domain: &str,
    mode: AlignmentMode,
) -> bool {
    // SPF must pass for alignment
    if *spf_result != SpfResult::Pass {
        return false;
    }

    domains_aligned(from_domain, spf_domain, mode)
}

/// Check if two domains align according to the given mode
fn domains_aligned(from_domain: &str, auth_domain: &str, mode: AlignmentMode) -> bool {
    let from_lower = from_domain.to_lowercase();
    let auth_lower = auth_domain.to_lowercase();

    match mode {
        AlignmentMode::Strict => from_lower == auth_lower,
        AlignmentMode::Relaxed => {
            let from_org = organizational_domain(&from_lower);
            let auth_org = organizational_domain(&auth_lower);
            from_org == auth_org
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_alignment() {
        assert!(domains_aligned(
            "example.com",
            "example.com",
            AlignmentMode::Strict
        ));
        assert!(!domains_aligned(
            "mail.example.com",
            "example.com",
            AlignmentMode::Strict
        ));
    }

    #[test]
    fn test_relaxed_alignment() {
        assert!(domains_aligned(
            "example.com",
            "example.com",
            AlignmentMode::Relaxed
        ));
        assert!(domains_aligned(
            "mail.example.com",
            "example.com",
            AlignmentMode::Relaxed
        ));
        assert!(domains_aligned(
            "mail.example.com",
            "other.example.com",
            AlignmentMode::Relaxed
        ));
        assert!(!domains_aligned(
            "example.com",
            "example.org",
            AlignmentMode::Relaxed
        ));
    }

    #[test]
    fn test_dkim_alignment() {
        let results = vec![DkimResult::Pass {
            domain: "mail.example.com".to_string(),
            selector: "s1".to_string(),
        }];

        assert!(check_dkim_alignment(
            "example.com",
            &results,
            AlignmentMode::Relaxed
        ));
        assert!(!check_dkim_alignment(
            "example.com",
            &results,
            AlignmentMode::Strict
        ));
    }

    #[test]
    fn test_spf_alignment() {
        assert!(check_spf_alignment(
            "example.com",
            &SpfResult::Pass,
            "mail.example.com",
            AlignmentMode::Relaxed
        ));
        assert!(!check_spf_alignment(
            "example.com",
            &SpfResult::Fail,
            "mail.example.com",
            AlignmentMode::Relaxed
        ));
    }
}
