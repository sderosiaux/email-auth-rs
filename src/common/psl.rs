use crate::common::domain;

/// Compute the organizational domain for a given domain using the Public Suffix List.
/// Example: "mail.example.com" -> "example.com", "foo.bar.co.uk" -> "bar.co.uk"
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
    fn test_org_domain_simple() {
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("example.com"), "example.com");
    }

    #[test]
    fn test_org_domain_multi_level_tld() {
        assert_eq!(organizational_domain("mail.example.co.uk"), "example.co.uk");
        assert_eq!(organizational_domain("foo.bar.co.uk"), "bar.co.uk");
    }

    #[test]
    fn test_org_domain_already_org() {
        assert_eq!(organizational_domain("example.com"), "example.com");
    }

    #[test]
    fn test_org_domain_deep_subdomain() {
        assert_eq!(
            organizational_domain("a.b.c.example.com"),
            "example.com"
        );
    }
}
