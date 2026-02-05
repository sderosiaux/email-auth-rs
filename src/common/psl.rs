use publicsuffix::{List, Psl};

/// Get the organizational domain using the Public Suffix List
pub fn organizational_domain(domain: &str) -> Option<String> {
    let list = List::new();
    let domain = domain.trim_end_matches('.');
    list.domain(domain.as_bytes())
        .and_then(|d| std::str::from_utf8(d.as_bytes()).ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organizational_domain() {
        if let Some(org) = organizational_domain("mail.example.com") {
            assert_eq!(org, "example.com");
        }
    }
}
