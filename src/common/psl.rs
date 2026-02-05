//! Public Suffix List integration for organizational domain determination.

use publicsuffix::{List, Psl};

// Well-known multi-part public suffixes not in the default list
const MULTI_PART_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "org.br", "net.br", "gov.br",
    "co.in", "net.in", "org.in", "gen.in", "ind.in",
];

/// Public Suffix List wrapper for determining organizational domains.
#[derive(Clone)]
pub struct PublicSuffixList {
    list: List,
}

impl PublicSuffixList {
    /// Create a new PSL with the embedded default list.
    pub fn new() -> Self {
        Self {
            list: List::new(),
        }
    }

    /// Get the organizational domain (public suffix + one label).
    /// Returns the domain itself if it's already at the organizational level.
    pub fn organizational_domain(&self, domain: &str) -> String {
        let domain = crate::common::domain::normalize(domain);
        let labels: Vec<&str> = domain.split('.').collect();

        // Check for known multi-part suffixes first
        for suffix in MULTI_PART_SUFFIXES {
            if domain.ends_with(suffix) {
                let suffix_parts = suffix.split('.').count();
                let needed = suffix_parts + 1;
                if labels.len() >= needed {
                    return labels[labels.len() - needed..].join(".");
                } else {
                    return domain; // Domain is shorter than expected
                }
            }
        }

        // Use publicsuffix crate's domain() method for other cases
        match self.list.domain(domain.as_bytes()) {
            Some(d) => String::from_utf8_lossy(d.as_bytes()).into_owned(),
            None => {
                // Fallback: return the last 2 labels
                if labels.len() <= 2 {
                    domain
                } else {
                    labels[labels.len() - 2..].join(".")
                }
            }
        }
    }

    /// Check if a domain is a public suffix.
    pub fn is_public_suffix(&self, domain: &str) -> bool {
        let domain = crate::common::domain::normalize(domain);

        // Check known multi-part suffixes
        if MULTI_PART_SUFFIXES.contains(&domain.as_str()) {
            return true;
        }

        // Use publicsuffix crate
        match self.list.suffix(domain.as_bytes()) {
            Some(suffix) => {
                String::from_utf8_lossy(suffix.as_bytes()).to_lowercase() == domain.to_lowercase()
            }
            None => false,
        }
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
    fn test_organizational_domain() {
        let psl = PublicSuffixList::new();

        assert_eq!(psl.organizational_domain("example.com"), "example.com");
        assert_eq!(psl.organizational_domain("mail.example.com"), "example.com");
        assert_eq!(
            psl.organizational_domain("foo.bar.example.com"),
            "example.com"
        );
        assert_eq!(psl.organizational_domain("example.co.uk"), "example.co.uk");
        assert_eq!(
            psl.organizational_domain("mail.example.co.uk"),
            "example.co.uk"
        );
    }

    #[test]
    fn test_is_public_suffix() {
        let psl = PublicSuffixList::new();

        assert!(psl.is_public_suffix("com"));
        assert!(psl.is_public_suffix("co.uk"));
        assert!(!psl.is_public_suffix("example.com"));
        assert!(!psl.is_public_suffix("google.com"));
    }
}
