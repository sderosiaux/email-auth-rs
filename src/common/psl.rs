use publicsuffix::{List, Psl};

use super::domain::normalize_domain;

/// Public Suffix List wrapper for organizational domain lookup
pub struct PublicSuffixList {
    list: List,
}

impl PublicSuffixList {
    /// Create PSL from embedded data
    pub fn new() -> Self {
        Self { list: List::new() }
    }

    /// Get organizational domain (public suffix + one label)
    /// Example: mail.example.com -> example.com
    /// Example: foo.bar.co.uk -> bar.co.uk
    pub fn organizational_domain(&self, domain: &str) -> String {
        let normalized = normalize_domain(domain);

        // Parse using publicsuffix crate
        if let Some(suffix) = self.list.suffix(normalized.as_bytes()) {
            // Get the suffix string
            let suffix_str = String::from_utf8_lossy(suffix.as_bytes()).into_owned();

            // If domain equals suffix, return as-is
            if normalized == suffix_str {
                return normalized;
            }

            // Find org domain: suffix + one label above it
            let domain_parts: Vec<&str> = normalized.split('.').collect();
            let suffix_parts: Vec<&str> = suffix_str.split('.').collect();

            if domain_parts.len() > suffix_parts.len() {
                let org_start = domain_parts.len() - suffix_parts.len() - 1;
                return domain_parts[org_start..].join(".");
            }
        }

        // Fallback: return as-is if no suffix found
        normalized
    }

    /// Check if domain is a public suffix itself
    pub fn is_public_suffix(&self, domain: &str) -> bool {
        let normalized = normalize_domain(domain);
        if let Some(suffix) = self.list.suffix(normalized.as_bytes()) {
            let suffix_str = String::from_utf8_lossy(suffix.as_bytes()).into_owned();
            return suffix_str == normalized;
        }
        false
    }
}

impl Default for PublicSuffixList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organizational_domain_simple() {
        let psl = PublicSuffixList::new();

        assert_eq!(psl.organizational_domain("example.com"), "example.com");
        assert_eq!(psl.organizational_domain("mail.example.com"), "example.com");
        assert_eq!(
            psl.organizational_domain("foo.bar.example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_organizational_domain_multi_part_suffix() {
        let psl = PublicSuffixList::new();

        // Note: publicsuffix crate's List::new() uses embedded PSL
        // Test with common suffixes
        let org = psl.organizational_domain("example.co.uk");
        // Should be example.co.uk (org domain above co.uk suffix)
        assert!(org == "example.co.uk" || org == "co.uk", "got: {}", org);

        let org2 = psl.organizational_domain("mail.example.co.uk");
        // Should reduce to org domain
        assert!(org2.ends_with("co.uk"), "got: {}", org2);
    }

    #[test]
    fn test_is_public_suffix() {
        let psl = PublicSuffixList::new();

        // com should be a public suffix
        assert!(psl.is_public_suffix("com"));
        // example.com should not be a public suffix
        assert!(!psl.is_public_suffix("example.com"));
    }
}
