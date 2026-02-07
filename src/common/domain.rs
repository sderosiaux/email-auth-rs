/// Normalize a domain: lowercase, strip trailing dot.
pub fn normalize(domain: &str) -> String {
    let d = domain.to_ascii_lowercase();
    d.strip_suffix('.').unwrap_or(&d).to_string()
}

/// Case-insensitive domain comparison after normalization.
pub fn domains_equal(a: &str, b: &str) -> bool {
    normalize(a) == normalize(b)
}

/// Check if `child` is a subdomain of `parent` (or equal).
pub fn is_subdomain_of(child: &str, parent: &str) -> bool {
    let c = normalize(child);
    let p = normalize(parent);
    if c == p {
        return true;
    }
    c.ends_with(&format!(".{p}"))
}

/// Extract domain part after @ from an email address.
pub fn domain_from_email(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(_, d)| d)
}

/// Extract local-part before @ from an email address.
pub fn local_part_from_email(email: &str) -> &str {
    email.rsplit_once('@').map_or(email, |(l, _)| l)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("Example.COM."), "example.com");
        assert_eq!(normalize("example.com"), "example.com");
    }

    #[test]
    fn test_domains_equal() {
        assert!(domains_equal("Example.COM", "example.com"));
        assert!(domains_equal("a.com.", "a.com"));
        assert!(!domains_equal("a.com", "b.com"));
    }

    #[test]
    fn test_is_subdomain_of() {
        assert!(is_subdomain_of("mail.example.com", "example.com"));
        assert!(is_subdomain_of("example.com", "example.com"));
        assert!(is_subdomain_of("a.b.example.com", "example.com"));
        assert!(!is_subdomain_of("example.com", "mail.example.com"));
        assert!(!is_subdomain_of("notexample.com", "example.com"));
    }

    #[test]
    fn test_domain_from_email() {
        assert_eq!(domain_from_email("user@example.com"), Some("example.com"));
        assert_eq!(domain_from_email("noat"), None);
    }

    #[test]
    fn test_local_part_from_email() {
        assert_eq!(local_part_from_email("user@example.com"), "user");
        assert_eq!(local_part_from_email("noat"), "noat");
    }
}
