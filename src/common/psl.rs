use super::domain;

/// Determine the organizational domain (registrable domain) using the Public Suffix List.
/// Returns the input domain normalized if PSL lookup fails.
pub fn organizational_domain(input: &str) -> String {
    let normalized = domain::normalize(input);
    psl::domain_str(&normalized)
        .unwrap_or(&normalized)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_org_domain() {
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("a.b.c.example.com"), "example.com");
    }

    #[test]
    fn test_org_domain_co_uk() {
        assert_eq!(organizational_domain("example.co.uk"), "example.co.uk");
        assert_eq!(organizational_domain("mail.example.co.uk"), "example.co.uk");
        assert_eq!(organizational_domain("foo.bar.co.uk"), "bar.co.uk");
    }

    #[test]
    fn test_org_domain_normalized() {
        assert_eq!(organizational_domain("Example.COM."), "example.com");
    }
}
