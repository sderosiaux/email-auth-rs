/// Normalize a domain name: lowercase + strip trailing dot.
pub fn normalize(domain: &str) -> String {
    let s = domain.to_ascii_lowercase();
    s.strip_suffix('.').unwrap_or(&s).to_string()
}

/// Case-insensitive domain equality, ignoring trailing dots.
pub fn domains_equal(a: &str, b: &str) -> bool {
    normalize(a) == normalize(b)
}

/// Check if `child` is a subdomain of (or equal to) `parent`.
/// Both are normalized before comparison.
pub fn is_subdomain_of(child: &str, parent: &str) -> bool {
    let c = normalize(child);
    let p = normalize(parent);
    if c == p {
        return true;
    }
    c.ends_with(&format!(".{p}"))
}

/// Extract the domain part from an email address.
/// Returns None if no @ is present.
pub fn domain_from_email(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(_, domain)| domain)
}

/// Extract the local part from an email address.
/// Returns the full string if no @ is present.
pub fn local_part_from_email(email: &str) -> &str {
    email.rsplit_once('@').map_or(email, |(local, _)| local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("Example.COM."), "example.com");
        assert_eq!(normalize("example.com"), "example.com");
        assert_eq!(normalize("A.B.C."), "a.b.c");
    }

    #[test]
    fn test_domains_equal() {
        assert!(domains_equal("EXAMPLE.COM", "example.com"));
        assert!(domains_equal("example.com.", "example.com"));
        assert!(!domains_equal("a.example.com", "example.com"));
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
        assert_eq!(domain_from_email("noatsign"), None);
        assert_eq!(domain_from_email("a@b@c.com"), Some("c.com"));
    }

    #[test]
    fn test_local_part_from_email() {
        assert_eq!(local_part_from_email("user@example.com"), "user");
        assert_eq!(local_part_from_email("noatsign"), "noatsign");
    }
}
