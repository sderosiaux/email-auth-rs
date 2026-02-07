/// Normalize a domain: lowercase, strip trailing dot.
pub fn normalize_domain(domain: &str) -> String {
    domain.to_ascii_lowercase().trim_end_matches('.').to_string()
}

/// Extract the domain from an email address. Returns None if no '@' present.
pub fn domain_from_email(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(_, d)| d)
}

/// Check if `child` is a subdomain of (or equal to) `parent`.
/// Both inputs should be normalized (lowercase, no trailing dot).
pub fn is_subdomain_of(child: &str, parent: &str) -> bool {
    if child == parent {
        return true;
    }
    child.ends_with(&format!(".{}", parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize() {
        assert_eq!(normalize_domain("Example.COM."), "example.com");
        assert_eq!(normalize_domain("test"), "test");
    }

    #[test]
    fn email_domain() {
        assert_eq!(domain_from_email("user@example.com"), Some("example.com"));
        assert_eq!(domain_from_email("noat"), None);
        assert_eq!(domain_from_email("a@b@c"), Some("c"));
    }

    #[test]
    fn subdomain_check() {
        assert!(is_subdomain_of("sub.example.com", "example.com"));
        assert!(is_subdomain_of("example.com", "example.com"));
        assert!(!is_subdomain_of("notexample.com", "example.com"));
        assert!(!is_subdomain_of("fakeexample.com", "example.com"));
    }
}
