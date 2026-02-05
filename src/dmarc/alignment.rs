use crate::common::psl::PublicSuffixList;

use super::record::AlignmentMode;

/// Check DKIM alignment
pub fn check_dkim_alignment(
    from_domain: &str,
    dkim_domain: &str,
    mode: AlignmentMode,
    psl: &PublicSuffixList,
) -> bool {
    let from_lower = from_domain.to_lowercase();
    let dkim_lower = dkim_domain.to_lowercase();

    match mode {
        AlignmentMode::Strict => {
            // Exact match required
            from_lower == dkim_lower
        }
        AlignmentMode::Relaxed => {
            // Organizational domain match
            let from_org = psl.organizational_domain(&from_lower);
            let dkim_org = psl.organizational_domain(&dkim_lower);
            from_org == dkim_org
        }
    }
}

/// Check SPF alignment
pub fn check_spf_alignment(
    from_domain: &str,
    spf_domain: &str,
    mode: AlignmentMode,
    psl: &PublicSuffixList,
) -> bool {
    let from_lower = from_domain.to_lowercase();
    let spf_lower = spf_domain.to_lowercase();

    match mode {
        AlignmentMode::Strict => {
            // Exact match required
            from_lower == spf_lower
        }
        AlignmentMode::Relaxed => {
            // Organizational domain match
            let from_org = psl.organizational_domain(&from_lower);
            let spf_org = psl.organizational_domain(&spf_lower);
            from_org == spf_org
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_dkim_alignment() {
        let psl = PublicSuffixList::new();

        // Exact match passes
        assert!(check_dkim_alignment(
            "example.com",
            "example.com",
            AlignmentMode::Strict,
            &psl
        ));

        // Subdomain fails
        assert!(!check_dkim_alignment(
            "mail.example.com",
            "example.com",
            AlignmentMode::Strict,
            &psl
        ));
    }

    #[test]
    fn test_relaxed_dkim_alignment() {
        let psl = PublicSuffixList::new();

        // Exact match passes
        assert!(check_dkim_alignment(
            "example.com",
            "example.com",
            AlignmentMode::Relaxed,
            &psl
        ));

        // Same org domain passes
        assert!(check_dkim_alignment(
            "mail.example.com",
            "example.com",
            AlignmentMode::Relaxed,
            &psl
        ));

        assert!(check_dkim_alignment(
            "example.com",
            "mail.example.com",
            AlignmentMode::Relaxed,
            &psl
        ));

        // Different org domain fails
        assert!(!check_dkim_alignment(
            "example.com",
            "other.com",
            AlignmentMode::Relaxed,
            &psl
        ));
    }

    #[test]
    fn test_spf_alignment() {
        let psl = PublicSuffixList::new();

        assert!(check_spf_alignment(
            "example.com",
            "example.com",
            AlignmentMode::Strict,
            &psl
        ));

        assert!(check_spf_alignment(
            "mail.example.com",
            "example.com",
            AlignmentMode::Relaxed,
            &psl
        ));
    }
}
