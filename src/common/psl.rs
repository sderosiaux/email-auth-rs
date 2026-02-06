use publicsuffix::{List, Psl};
use std::sync::LazyLock;

static PSL: LazyLock<List> = LazyLock::new(List::new);

/// Get the organizational domain for a given domain
/// e.g., "mail.example.co.uk" -> "example.co.uk"
pub fn organizational_domain(domain: &str) -> String {
    let domain = super::normalize_domain(domain);

    PSL.domain(domain.as_bytes())
        .and_then(|d: publicsuffix::Domain<'_>| std::str::from_utf8(d.as_bytes()).ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organizational_domain() {
        // Basic cases
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("sub.mail.example.com"), "example.com");
    }

    #[test]
    fn test_organizational_domain_trailing_dot() {
        assert_eq!(organizational_domain("mail.example.com."), "example.com");
    }
}
