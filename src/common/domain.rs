/// Normalize a domain name: lowercase and remove trailing dot
pub fn normalize_domain(domain: &str) -> String {
    let d = domain.to_lowercase();
    d.strip_suffix('.').unwrap_or(&d).to_string()
}

/// Extract domain from email address
pub fn parse_email_domain(email: &str) -> Option<&str> {
    let at_pos = email.rfind('@')?;
    Some(&email[at_pos + 1..])
}

/// Extract local part from email address
pub fn parse_email_local(email: &str) -> Option<&str> {
    let at_pos = email.rfind('@')?;
    Some(&email[..at_pos])
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
    fn test_parse_email_domain() {
        assert_eq!(parse_email_domain("user@example.com"), Some("example.com"));
        assert_eq!(parse_email_domain("user"), None);
        assert_eq!(
            parse_email_domain("user@sub.example.com"),
            Some("sub.example.com")
        );
    }

    #[test]
    fn test_parse_email_local() {
        assert_eq!(parse_email_local("user@example.com"), Some("user"));
        assert_eq!(parse_email_local("user.name@example.com"), Some("user.name"));
        assert_eq!(parse_email_local("noat"), None);
    }
}
