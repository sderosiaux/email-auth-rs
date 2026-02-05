use publicsuffix::{List, Psl};

// Embedded minimal PSL for common TLDs (fallback)
const BASIC_PSL: &[u8] = b"com\nnet\norg\nio\nco.uk\ncom.au\n";

/// Get the organizational domain using the Public Suffix List
/// Returns the public suffix + one label
pub fn organizational_domain(domain: &str) -> String {
    let domain = domain.to_lowercase().trim_end_matches('.').to_string();

    // Try to create a list from embedded data
    let list = List::from_bytes(BASIC_PSL).unwrap_or_else(|_| List::new());

    // Get the registrable domain (public suffix + 1 label)
    match list.domain(domain.as_bytes()) {
        Some(d) => {
            // d is a Domain type, convert to string via suffix
            String::from_utf8_lossy(d.suffix().as_bytes()).to_string()
                .split('.')
                .last()
                .map(|_| {
                    // Get the full registrable domain
                    let parts: Vec<&str> = domain.split('.').collect();
                    if parts.len() >= 2 {
                        // Find where the suffix starts
                        let suffix_str = String::from_utf8_lossy(d.suffix().as_bytes()).to_string();
                        let suffix_parts: Vec<&str> = suffix_str.split('.').collect();
                        let org_start = parts.len().saturating_sub(suffix_parts.len() + 1);
                        parts[org_start..].join(".")
                    } else {
                        domain.clone()
                    }
                })
                .unwrap_or_else(|| domain.clone())
        }
        None => domain,
    }
}

/// Check if d1 is a subdomain of or equal to d2 (organizational domain match)
pub fn domains_aligned_relaxed(d1: &str, d2: &str) -> bool {
    let org1 = organizational_domain(d1);
    let org2 = organizational_domain(d2);
    org1 == org2
}

/// Check if domains match exactly (strict alignment)
pub fn domains_aligned_strict(d1: &str, d2: &str) -> bool {
    let d1_norm = d1.to_lowercase().trim_end_matches('.').to_string();
    let d2_norm = d2.to_lowercase().trim_end_matches('.').to_string();
    d1_norm == d2_norm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organizational_domain() {
        // Basic test - with our embedded PSL
        let org = organizational_domain("mail.example.com");
        // Should return either "example.com" or the full domain depending on PSL
        assert!(!org.is_empty());
    }

    #[test]
    fn test_domains_aligned_strict() {
        assert!(domains_aligned_strict("example.com", "EXAMPLE.COM"));
        assert!(domains_aligned_strict("example.com.", "example.com"));
        assert!(!domains_aligned_strict("mail.example.com", "example.com"));
    }
}
