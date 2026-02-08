/// Normalize a domain: lowercase + strip trailing dot.
pub fn normalize(domain: &str) -> String {
    let d = domain.to_ascii_lowercase();
    d.strip_suffix('.').unwrap_or(&d).to_string()
}

/// Compare two domains after normalization.
pub fn domains_equal(a: &str, b: &str) -> bool {
    normalize(a) == normalize(b)
}

/// Check if `child` is a subdomain of `parent` (after normalization).
/// A domain is NOT a subdomain of itself.
pub fn is_subdomain_of(child: &str, parent: &str) -> bool {
    let nc = normalize(child);
    let np = normalize(parent);
    if nc == np {
        return false;
    }
    nc.ends_with(&format!(".{}", np))
}

/// Extract domain part from an email address (after `@`).
/// Returns None if no `@` is present.
pub fn domain_from_email(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(_, domain)| domain)
}

/// Extract local part from an email address (before `@`).
/// Returns the entire string if no `@` is present.
pub fn local_part_from_email(email: &str) -> &str {
    match email.rsplit_once('@') {
        Some((local, _)) => local,
        None => email,
    }
}

/// Determine the organizational domain using the Public Suffix List.
///
/// The organizational domain is the public suffix plus one label.
/// For example: `mail.example.com` → `example.com`, `foo.bar.co.uk` → `bar.co.uk`.
///
/// Uses the `psl` crate v2 with an embedded PSL snapshot.
pub fn organizational_domain(domain: &str) -> String {
    let normalized = normalize(domain);
    match psl::domain_str(&normalized) {
        Some(org) => org.to_string(),
        None => normalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Normalize tests ---

    #[test]
    fn normalize_lowercase() {
        assert_eq!(normalize("EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn normalize_strip_trailing_dot() {
        assert_eq!(normalize("example.com."), "example.com");
    }

    #[test]
    fn normalize_combined() {
        assert_eq!(normalize("Mail.EXAMPLE.COM."), "mail.example.com");
    }

    #[test]
    fn normalize_already_normal() {
        assert_eq!(normalize("example.com"), "example.com");
    }

    // --- domains_equal tests ---

    #[test]
    fn domains_equal_same() {
        assert!(domains_equal("example.com", "example.com"));
    }

    #[test]
    fn domains_equal_case_insensitive() {
        assert!(domains_equal("Example.COM", "example.com"));
    }

    #[test]
    fn domains_equal_trailing_dot() {
        assert!(domains_equal("example.com.", "example.com"));
    }

    #[test]
    fn domains_not_equal() {
        assert!(!domains_equal("example.com", "example.org"));
    }

    // --- is_subdomain_of tests ---

    #[test]
    fn subdomain_true() {
        assert!(is_subdomain_of("mail.example.com", "example.com"));
    }

    #[test]
    fn subdomain_deep() {
        assert!(is_subdomain_of("a.b.c.example.com", "example.com"));
    }

    #[test]
    fn subdomain_self_is_not_subdomain() {
        assert!(!is_subdomain_of("example.com", "example.com"));
    }

    #[test]
    fn subdomain_different_domain() {
        assert!(!is_subdomain_of("mail.other.com", "example.com"));
    }

    #[test]
    fn subdomain_case_insensitive() {
        assert!(is_subdomain_of("MAIL.Example.COM", "example.com"));
    }

    #[test]
    fn subdomain_partial_label_no_match() {
        // "notexample.com" is NOT a subdomain of "example.com"
        assert!(!is_subdomain_of("notexample.com", "example.com"));
    }

    // --- domain_from_email tests ---

    #[test]
    fn domain_from_email_normal() {
        assert_eq!(domain_from_email("user@example.com"), Some("example.com"));
    }

    #[test]
    fn domain_from_email_no_at() {
        assert_eq!(domain_from_email("example.com"), None);
    }

    #[test]
    fn domain_from_email_multiple_at() {
        // rsplit_once takes the last @
        assert_eq!(domain_from_email("user@host@example.com"), Some("example.com"));
    }

    // --- local_part_from_email tests ---

    #[test]
    fn local_part_normal() {
        assert_eq!(local_part_from_email("user@example.com"), "user");
    }

    #[test]
    fn local_part_no_at() {
        assert_eq!(local_part_from_email("noatsign"), "noatsign");
    }

    // --- organizational_domain tests ---

    // CHK-726: example.com → example.com
    #[test]
    fn org_domain_apex() {
        assert_eq!(organizational_domain("example.com"), "example.com");
    }

    // CHK-727: mail.example.com → example.com
    #[test]
    fn org_domain_subdomain() {
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
    }

    // CHK-728: foo.bar.example.com → example.com
    #[test]
    fn org_domain_deep_subdomain() {
        assert_eq!(organizational_domain("foo.bar.example.com"), "example.com");
    }

    // CHK-729: example.co.uk → example.co.uk
    #[test]
    fn org_domain_cctld() {
        assert_eq!(organizational_domain("example.co.uk"), "example.co.uk");
    }

    // CHK-730: mail.example.co.uk → example.co.uk
    #[test]
    fn org_domain_cctld_subdomain() {
        assert_eq!(organizational_domain("mail.example.co.uk"), "example.co.uk");
    }

    // CHK-731: foo.bar.co.uk → bar.co.uk
    #[test]
    fn org_domain_cctld_deep() {
        assert_eq!(organizational_domain("foo.bar.co.uk"), "bar.co.uk");
    }

    // CHK-732: a.b.c.example.com → example.com
    #[test]
    fn org_domain_very_deep() {
        assert_eq!(organizational_domain("a.b.c.example.com"), "example.com");
    }

    // CHK-680: Normalize before PSL lookup
    #[test]
    fn org_domain_normalizes_input() {
        assert_eq!(organizational_domain("MAIL.EXAMPLE.COM."), "example.com");
    }

    // Edge: PSL returns None for TLD-only input
    #[test]
    fn org_domain_tld_only_fallback() {
        // "com" alone — PSL returns None, fallback to normalized input
        assert_eq!(organizational_domain("com"), "com");
    }
}
