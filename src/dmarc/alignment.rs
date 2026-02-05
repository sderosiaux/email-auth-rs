//! DMARC identifier alignment checks.

use crate::common::psl::PublicSuffixList;

/// Alignment mode for DKIM and SPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlignmentMode {
    #[default]
    Relaxed,
    Strict,
}

/// Check if two domains are aligned according to the specified mode.
pub fn domains_aligned(d1: &str, d2: &str, mode: AlignmentMode, psl: &PublicSuffixList) -> bool {
    let d1 = crate::common::domain::normalize(d1);
    let d2 = crate::common::domain::normalize(d2);

    match mode {
        AlignmentMode::Strict => d1 == d2,
        AlignmentMode::Relaxed => {
            let org1 = psl.organizational_domain(&d1);
            let org2 = psl.organizational_domain(&d2);
            org1 == org2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_alignment() {
        let psl = PublicSuffixList::new();

        assert!(domains_aligned(
            "example.com",
            "example.com",
            AlignmentMode::Strict,
            &psl
        ));
        assert!(!domains_aligned(
            "mail.example.com",
            "example.com",
            AlignmentMode::Strict,
            &psl
        ));
    }

    #[test]
    fn test_relaxed_alignment() {
        let psl = PublicSuffixList::new();

        assert!(domains_aligned(
            "example.com",
            "example.com",
            AlignmentMode::Relaxed,
            &psl
        ));
        assert!(domains_aligned(
            "mail.example.com",
            "example.com",
            AlignmentMode::Relaxed,
            &psl
        ));
        assert!(domains_aligned(
            "mail.example.com",
            "other.example.com",
            AlignmentMode::Relaxed,
            &psl
        ));
        assert!(!domains_aligned(
            "example.com",
            "other.com",
            AlignmentMode::Relaxed,
            &psl
        ));
    }

    #[test]
    fn test_co_uk_alignment() {
        let psl = PublicSuffixList::new();

        assert!(domains_aligned(
            "mail.example.co.uk",
            "example.co.uk",
            AlignmentMode::Relaxed,
            &psl
        ));
        assert!(!domains_aligned(
            "example.co.uk",
            "other.co.uk",
            AlignmentMode::Relaxed,
            &psl
        ));
    }
}
