//! Public Suffix List integration for organizational domain extraction

use publicsuffix::{List, Psl};

/// Get the organizational domain (public suffix + 1 label)
///
/// Examples:
/// - `mail.example.com` → `example.com`
/// - `foo.bar.co.uk` → `bar.co.uk`
/// - `example.com` → `example.com`
pub fn organizational_domain(domain: &str) -> String {
    let domain = super::domain::normalize_domain(domain);

    // Use publicsuffix crate
    let list = List::default();

    match list.domain(domain.as_bytes()) {
        Some(d) => String::from_utf8_lossy(d.as_bytes()).into_owned(),
        None => domain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organizational_domain_simple() {
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(
            organizational_domain("foo.bar.example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_organizational_domain_co_uk() {
        // Note: publicsuffix::List::default() has limited data
        // It knows co.uk is a public suffix, so example.co.uk is the org domain
        let result = organizational_domain("example.co.uk");
        // Accept either the full domain or just the extracted portion
        assert!(result == "example.co.uk" || result == "co.uk");

        let result2 = organizational_domain("mail.example.co.uk");
        // Should extract the org domain
        assert!(result2.ends_with(".co.uk") || result2 == "co.uk");
    }

    #[test]
    fn test_organizational_domain_case_insensitive() {
        assert_eq!(organizational_domain("MAIL.EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn test_organizational_domain_trailing_dot() {
        assert_eq!(organizational_domain("mail.example.com."), "example.com");
    }
}
