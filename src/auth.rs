//! Combined email authentication (SPF + DKIM + DMARC)

use std::net::IpAddr;

use crate::common::dns::DnsResolver;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{Disposition, DmarcResult, DmarcVerifier};
use crate::spf::{SpfResult, SpfVerifier};

/// Combined authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub disposition: Disposition,
}

/// Combined email authenticator
#[derive(Clone)]
pub struct EmailAuthenticator<R: DnsResolver> {
    spf_verifier: SpfVerifier<R>,
    dkim_verifier: DkimVerifier<R>,
    dmarc_verifier: DmarcVerifier<R>,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            spf_verifier: SpfVerifier::new(resolver.clone()),
            dkim_verifier: DkimVerifier::new(resolver.clone()),
            dmarc_verifier: DmarcVerifier::new(resolver),
        }
    }

    /// Authenticate an email message
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // Extract From header domain
        let from_domain = extract_from_domain(message).unwrap_or_else(|| {
            // Fallback to mail_from domain
            mail_from.split('@').last().unwrap_or("").to_string()
        });

        // Get SPF domain from mail_from
        let spf_domain = if mail_from.is_empty() {
            helo.to_string()
        } else {
            mail_from.split('@').last().unwrap_or(helo).to_string()
        };

        // Run SPF check
        let spf = self
            .spf_verifier
            .check_host(client_ip, &spf_domain, mail_from, helo)
            .await;

        // Run DKIM verification
        let dkim = self.dkim_verifier.verify(message).await;

        // Run DMARC verification
        let dmarc = self
            .dmarc_verifier
            .verify(&from_domain, &spf, &spf_domain, &dkim)
            .await;

        let disposition = dmarc.disposition;

        AuthenticationResult {
            spf,
            dkim,
            dmarc,
            disposition,
        }
    }
}

fn extract_from_domain(message: &[u8]) -> Option<String> {
    let message_str = String::from_utf8_lossy(message);

    // Find From: header
    for line in message_str.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("from:") {
            let value = &line[5..]; // Skip "From:"
            return extract_domain_from_address(value);
        }
    }

    None
}

fn extract_domain_from_address(addr: &str) -> Option<String> {
    // Handle formats like:
    // - user@example.com
    // - <user@example.com>
    // - "Name" <user@example.com>

    let addr = addr.trim();

    // Try to find <...> first
    if let Some(start) = addr.find('<') {
        if let Some(end) = addr.find('>') {
            let inner = &addr[start + 1..end];
            if let Some(at_pos) = inner.find('@') {
                return Some(inner[at_pos + 1..].to_lowercase());
            }
        }
    }

    // Otherwise try simple user@domain
    if let Some(at_pos) = addr.find('@') {
        let domain = addr[at_pos + 1..].trim();
        let domain = domain.trim_end_matches('>');
        return Some(domain.to_lowercase());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_simple() {
        assert_eq!(
            extract_domain_from_address("user@example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_angle_brackets() {
        assert_eq!(
            extract_domain_from_address("<user@example.com>"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_with_name() {
        assert_eq!(
            extract_domain_from_address("\"John Doe\" <user@example.com>"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_from_domain() {
        let message = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody";
        assert_eq!(extract_from_domain(message), Some("example.com".to_string()));
    }
}
