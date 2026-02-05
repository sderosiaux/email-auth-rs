//! Domain parsing and normalization utilities.

/// Normalize a domain name: lowercase and remove trailing dot.
pub fn normalize(domain: &str) -> String {
    let domain = domain.to_lowercase();
    domain.strip_suffix('.').unwrap_or(&domain).to_string()
}

/// Check if `subdomain` is a subdomain of `parent` (or equal).
pub fn is_subdomain_of(subdomain: &str, parent: &str) -> bool {
    let sub = normalize(subdomain);
    let par = normalize(parent);

    if sub == par {
        return true;
    }

    sub.ends_with(&format!(".{}", par))
}

/// Extract the local-part and domain from an email address.
pub fn parse_email(email: &str) -> Option<(&str, &str)> {
    let email = email.trim();
    let email = email.strip_prefix('<').unwrap_or(email);
    let email = email.strip_suffix('>').unwrap_or(email);

    if email.is_empty() {
        return None;
    }

    match email.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => Some((local, domain)),
        None if !email.is_empty() => Some(("postmaster", email)), // bare domain
        _ => None,
    }
}

/// Extract the domain from an email address.
pub fn email_domain(email: &str) -> Option<&str> {
    parse_email(email).map(|(_, domain)| domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("Example.COM."), "example.com");
        assert_eq!(normalize("example.com"), "example.com");
        assert_eq!(normalize("EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn test_is_subdomain_of() {
        assert!(is_subdomain_of("mail.example.com", "example.com"));
        assert!(is_subdomain_of("example.com", "example.com"));
        assert!(is_subdomain_of("a.b.example.com", "example.com"));
        assert!(!is_subdomain_of("example.com", "mail.example.com"));
        assert!(!is_subdomain_of("notexample.com", "example.com"));
        assert!(!is_subdomain_of("fakeexample.com", "example.com"));
    }

    #[test]
    fn test_parse_email() {
        assert_eq!(parse_email("user@example.com"), Some(("user", "example.com")));
        assert_eq!(parse_email("<user@example.com>"), Some(("user", "example.com")));
        assert_eq!(parse_email("example.com"), Some(("postmaster", "example.com")));
        assert_eq!(parse_email(""), None);
    }
}
