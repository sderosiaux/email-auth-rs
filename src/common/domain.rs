//! Domain utilities: normalization, trailing dot handling

/// Normalize a domain name: lowercase, remove trailing dot
pub fn normalize_domain(domain: &str) -> String {
    let domain = domain.to_lowercase();
    domain.trim_end_matches('.').to_string()
}

/// Check if domain1 is a subdomain of or equal to domain2
pub fn is_subdomain_of(domain1: &str, domain2: &str) -> bool {
    let d1 = normalize_domain(domain1);
    let d2 = normalize_domain(domain2);

    if d1 == d2 {
        return true;
    }

    // d1 must end with .d2
    d1.ends_with(&format!(".{}", d2))
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
    fn test_is_subdomain_of() {
        assert!(is_subdomain_of("example.com", "example.com"));
        assert!(is_subdomain_of("mail.example.com", "example.com"));
        assert!(is_subdomain_of("a.b.example.com", "example.com"));
        assert!(!is_subdomain_of("example.com", "mail.example.com"));
        assert!(!is_subdomain_of("notexample.com", "example.com"));
        assert!(!is_subdomain_of("fakeexample.com", "example.com"));
    }
}
