use std::net::IpAddr;

use crate::common::DnsResolver;
use crate::spf::{SpfVerifier, SpfResult};
use crate::dkim::{DkimVerifier, DkimResult};
use crate::dmarc::{DmarcVerifier, DmarcResult};

#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub from_domain: Option<String>,
}

pub struct EmailAuthenticator<R: DnsResolver> {
    spf_verifier: SpfVerifier<R>,
    dkim_verifier: DkimVerifier<R>,
    dmarc_verifier: DmarcVerifier<R>,
}

impl<R: DnsResolver + Clone> EmailAuthenticator<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            spf_verifier: SpfVerifier::new(resolver.clone()),
            dkim_verifier: DkimVerifier::new(resolver.clone()),
            dmarc_verifier: DmarcVerifier::new(resolver),
        }
    }

    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // Extract From domain from message
        let from_domain = extract_from_domain(message);

        // Run SPF check
        let spf_domain = extract_domain(mail_from).unwrap_or_else(|| helo.to_string());
        let spf_result = self.spf_verifier.check_host(client_ip, &spf_domain, mail_from).await;

        // Run DKIM verification
        let dkim_results = self.dkim_verifier.verify(message).await;

        // Run DMARC check
        let effective_from_domain = from_domain.clone().unwrap_or_else(|| spf_domain.clone());
        let dmarc_result = self.dmarc_verifier.verify(
            &effective_from_domain,
            &spf_result,
            &spf_domain,
            &dkim_results,
        ).await;

        AuthenticationResult {
            spf: spf_result,
            dkim: dkim_results,
            dmarc: dmarc_result,
            from_domain,
        }
    }
}

fn extract_from_domain(message: &[u8]) -> Option<String> {
    let message_str = String::from_utf8_lossy(message);

    // Find the headers section
    let headers = if let Some(pos) = message_str.find("\r\n\r\n") {
        &message_str[..pos]
    } else if let Some(pos) = message_str.find("\n\n") {
        &message_str[..pos]
    } else {
        &message_str[..]
    };

    // Look for From: header
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("from:") {
            let value = &line[5..];
            return extract_domain_from_address(value);
        }
    }

    None
}

fn extract_domain_from_address(address: &str) -> Option<String> {
    // Handle formats like:
    // "Name <email@domain.com>"
    // "email@domain.com"
    // "<email@domain.com>"

    let address = address.trim();

    // Look for angle brackets
    if let Some(start) = address.find('<') {
        if let Some(end) = address.find('>') {
            let email = &address[start + 1..end];
            return extract_domain(email);
        }
    }

    // No angle brackets, assume bare address
    extract_domain(address)
}

fn extract_domain(address: &str) -> Option<String> {
    address
        .split('@')
        .nth(1)
        .map(|d| d.trim().to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_from_domain() {
        let msg = b"From: sender@example.com\r\nTo: recipient@other.com\r\n\r\nBody";
        assert_eq!(extract_from_domain(msg), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_from_domain_with_name() {
        let msg = b"From: Sender Name <sender@example.com>\r\n\r\nBody";
        assert_eq!(extract_from_domain(msg), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("user@example.com"), Some("example.com".to_string()));
        assert_eq!(extract_domain("user"), None);
    }

    #[test]
    fn test_extract_domain_from_address() {
        assert_eq!(
            extract_domain_from_address("Name <user@example.com>"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain_from_address("<user@example.com>"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain_from_address("user@example.com"),
            Some("example.com".to_string())
        );
    }
}
