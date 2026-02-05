//! DMARC alignment checks

use crate::common::psl::organizational_domain;
use crate::common::domain::normalize_domain;
use super::policy::AlignmentMode;

/// Check if two domains are aligned according to DMARC rules
pub fn domains_aligned(d1: &str, d2: &str, mode: AlignmentMode) -> bool {
    let d1 = normalize_domain(d1);
    let d2 = normalize_domain(d2);

    match mode {
        AlignmentMode::Strict => d1 == d2,
        AlignmentMode::Relaxed => {
            let org1 = organizational_domain(&d1);
            let org2 = organizational_domain(&d2);
            org1 == org2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_alignment() {
        assert!(domains_aligned("example.com", "example.com", AlignmentMode::Strict));
        assert!(!domains_aligned("mail.example.com", "example.com", AlignmentMode::Strict));
    }

    #[test]
    fn test_relaxed_alignment() {
        assert!(domains_aligned("example.com", "example.com", AlignmentMode::Relaxed));
        assert!(domains_aligned("mail.example.com", "example.com", AlignmentMode::Relaxed));
        assert!(domains_aligned("mail.example.com", "other.example.com", AlignmentMode::Relaxed));
    }

    #[test]
    fn test_different_domains() {
        assert!(!domains_aligned("example.com", "other.com", AlignmentMode::Relaxed));
        assert!(!domains_aligned("example.com", "other.com", AlignmentMode::Strict));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(domains_aligned("EXAMPLE.COM", "example.com", AlignmentMode::Strict));
    }
}
