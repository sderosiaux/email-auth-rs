use crate::common::psl::{domains_aligned_relaxed, domains_aligned_strict};
use super::AlignmentMode;

/// Check if two domains are aligned according to the specified mode
pub fn domains_aligned(d1: &str, d2: &str, mode: AlignmentMode) -> bool {
    match mode {
        AlignmentMode::Strict => domains_aligned_strict(d1, d2),
        AlignmentMode::Relaxed => domains_aligned_relaxed(d1, d2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_alignment() {
        assert!(domains_aligned("example.com", "example.com", AlignmentMode::Strict));
        assert!(domains_aligned("example.com", "EXAMPLE.COM", AlignmentMode::Strict));
        assert!(!domains_aligned("mail.example.com", "example.com", AlignmentMode::Strict));
    }

    #[test]
    fn test_relaxed_alignment() {
        // These depend on PSL, but basic cases should work
        assert!(domains_aligned("example.com", "example.com", AlignmentMode::Relaxed));
    }
}
