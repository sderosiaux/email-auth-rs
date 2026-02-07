use super::domain;

/// Determine the organizational domain (registrable domain) using PSL.
pub fn organizational_domain(input: &str) -> String {
    let normalized = domain::normalize(input);
    psl::domain_str(&normalized)
        .unwrap_or(&normalized)
        .to_string()
}

/// Check if two domains share the same organizational domain (relaxed alignment).
pub fn relaxed_match(a: &str, b: &str) -> bool {
    organizational_domain(a) == organizational_domain(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organizational_domain() {
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("a.b.c.example.com"), "example.com");
        assert_eq!(organizational_domain("example.co.uk"), "example.co.uk");
        assert_eq!(organizational_domain("mail.example.co.uk"), "example.co.uk");
        assert_eq!(organizational_domain("foo.bar.co.uk"), "bar.co.uk");
    }

    #[test]
    fn test_relaxed_match() {
        assert!(relaxed_match("mail.example.com", "example.com"));
        assert!(relaxed_match("a.example.com", "b.example.com"));
        assert!(!relaxed_match("example.com", "other.com"));
    }
}
