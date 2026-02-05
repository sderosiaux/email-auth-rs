/// Normalize domain: lowercase and strip trailing dot
pub fn normalize_domain(domain: &str) -> String {
    strip_trailing_dot(domain).to_lowercase()
}

/// Strip trailing dot from domain if present
pub fn strip_trailing_dot(domain: &str) -> &str {
    domain.strip_suffix('.').unwrap_or(domain)
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
    fn test_strip_trailing_dot() {
        assert_eq!(strip_trailing_dot("example.com."), "example.com");
        assert_eq!(strip_trailing_dot("example.com"), "example.com");
    }
}
