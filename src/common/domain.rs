/// Normalize a domain: lowercase + strip trailing dot.
pub fn normalize(domain: &str) -> String {
    domain.to_ascii_lowercase().trim_end_matches('.').to_string()
}

/// Case-insensitive domain comparison with trailing dot normalization.
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
    c.ends_with(&format!(".{}", p))
}

/// Extract domain from an email address (part after @).
pub fn domain_from_email(email: &str) -> Option<&str> {
    let at = email.rfind('@')?;
    let domain = &email[at + 1..];
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// Extract local-part from an email address (part before @).
pub fn local_part_from_email(email: &str) -> &str {
    match email.rfind('@') {
        Some(at) => &email[..at],
        None => email,
    }
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
        assert!(domains_equal("example.com.", "example.com"));
        assert!(!domains_equal("other.com", "example.com"));
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
        assert_eq!(domain_from_email("user"), None);
        assert_eq!(domain_from_email("user@"), None);
    }

    #[test]
    fn test_local_part_from_email() {
        assert_eq!(local_part_from_email("user@example.com"), "user");
        assert_eq!(local_part_from_email("natsign"), "natsign");
    }
}
