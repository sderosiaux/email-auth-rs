use publicsuffix::{List, Psl};

/// Get the organizational domain (public suffix + 1 label)
/// Example: mail.example.com -> example.com
/// Example: foo.bar.co.uk -> bar.co.uk
pub fn organizational_domain(domain: &str) -> String {
    let domain = super::normalize_domain(domain);

    // Use publicsuffix crate
    let list = List::new();
    let domain_bytes = domain.as_bytes();

    // domain() returns the registrable domain directly
    if let Some(domain_obj) = list.domain(domain_bytes) {
        return std::str::from_utf8(domain_obj.as_bytes())
            .unwrap_or(&domain)
            .to_string();
    }

    // Fallback: return as-is
    domain
}

/// Check if two domains share the same organizational domain
pub fn same_org_domain(d1: &str, d2: &str) -> bool {
    organizational_domain(d1) == organizational_domain(d2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organizational_domain() {
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(
            organizational_domain("foo.bar.example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_same_org_domain() {
        assert!(same_org_domain("mail.example.com", "example.com"));
        assert!(same_org_domain("a.example.com", "b.example.com"));
        assert!(!same_org_domain("example.com", "example.org"));
    }
}
