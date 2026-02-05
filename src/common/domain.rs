/// Normalize a domain name: lowercase and remove trailing dot
pub fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_string()
}

/// Check if two domains are equal (case-insensitive, ignoring trailing dots)
pub fn domains_equal(d1: &str, d2: &str) -> bool {
    normalize_domain(d1) == normalize_domain(d2)
}

/// Extract domain from an email address
pub fn domain_from_email(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(_, domain)| domain)
}

/// Extract local part from an email address
pub fn local_part_from_email(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(local, _)| local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("EXAMPLE.COM"), "example.com");
        assert_eq!(normalize_domain("example.com."), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM."), "example.com");
    }

    #[test]
    fn test_domains_equal() {
        assert!(domains_equal("example.com", "EXAMPLE.COM"));
        assert!(domains_equal("example.com.", "example.com"));
        assert!(!domains_equal("example.com", "example.org"));
    }

    #[test]
    fn test_domain_from_email() {
        assert_eq!(domain_from_email("user@example.com"), Some("example.com"));
        assert_eq!(domain_from_email("user@sub.example.com"), Some("sub.example.com"));
        assert_eq!(domain_from_email("noatsign"), None);
    }

    #[test]
    fn test_local_part_from_email() {
        assert_eq!(local_part_from_email("user@example.com"), Some("user"));
        assert_eq!(local_part_from_email("complex+tag@example.com"), Some("complex+tag"));
    }
}
