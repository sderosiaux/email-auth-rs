use super::domain::normalize_domain;

/// Get the organizational domain using the Public Suffix List.
/// Returns the registrable domain (eTLD+1).
/// If the domain itself IS a public suffix or lookup fails, returns the domain unchanged.
pub fn org_domain(domain: &str) -> String {
    let normalized = normalize_domain(domain);
    let bytes = normalized.as_bytes();
    match psl::domain(bytes) {
        Some(d) => {
            // psl::domain returns the registrable domain as bytes
            std::str::from_utf8(d.as_bytes())
                .unwrap_or(&normalized)
                .to_string()
        }
        None => normalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_org_domain() {
        assert_eq!(org_domain("sub.example.com"), "example.com");
        assert_eq!(org_domain("example.com"), "example.com");
        assert_eq!(org_domain("deep.sub.example.com"), "example.com");
    }

    #[test]
    fn uk_domain() {
        assert_eq!(org_domain("sub.example.co.uk"), "example.co.uk");
        assert_eq!(org_domain("example.co.uk"), "example.co.uk");
    }

    #[test]
    fn normalized_input() {
        assert_eq!(org_domain("SUB.EXAMPLE.COM."), "example.com");
    }
}
