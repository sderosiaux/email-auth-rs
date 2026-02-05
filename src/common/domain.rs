/// Normalize domain name: lowercase and strip trailing dot
pub fn normalize_domain(domain: &str) -> String {
    strip_trailing_dot(domain).to_lowercase()
}

/// Strip trailing dot from domain name
pub fn strip_trailing_dot(domain: &str) -> &str {
    domain.strip_suffix('.').unwrap_or(domain)
}

/// Check if child is a subdomain of parent (or equal)
pub fn is_subdomain_of(child: &str, parent: &str) -> bool {
    let child = normalize_domain(child);
    let parent = normalize_domain(parent);

    if child == parent {
        return true;
    }

    child.ends_with(&format!(".{}", parent))
}

/// Extract domain from email address
pub fn domain_from_email(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(_, domain)| domain)
}

/// Extract local part from email address
pub fn local_part_from_email(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(local, _)| local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("Example.COM"), "example.com");
        assert_eq!(normalize_domain("example.com."), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM."), "example.com");
    }

    #[test]
    fn test_strip_trailing_dot() {
        assert_eq!(strip_trailing_dot("example.com."), "example.com");
        assert_eq!(strip_trailing_dot("example.com"), "example.com");
    }

    #[test]
    fn test_is_subdomain_of() {
        assert!(is_subdomain_of("mail.example.com", "example.com"));
        assert!(is_subdomain_of("example.com", "example.com"));
        assert!(is_subdomain_of("deep.mail.example.com", "example.com"));
        assert!(!is_subdomain_of("example.com", "mail.example.com"));
        assert!(!is_subdomain_of("notexample.com", "example.com"));
        assert!(!is_subdomain_of("fakeexample.com", "example.com"));
    }

    #[test]
    fn test_domain_from_email() {
        assert_eq!(domain_from_email("user@example.com"), Some("example.com"));
        assert_eq!(domain_from_email("user"), None);
        assert_eq!(
            domain_from_email("user@sub.example.com"),
            Some("sub.example.com")
        );
    }

    #[test]
    fn test_local_part_from_email() {
        assert_eq!(local_part_from_email("user@example.com"), Some("user"));
        assert_eq!(local_part_from_email("user"), None);
    }
}
