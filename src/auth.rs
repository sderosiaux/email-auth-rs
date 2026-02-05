use std::net::IpAddr;
use std::sync::Arc;

use crate::common::dns::DnsResolver;
use crate::common::domain::domain_from_email;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{DmarcResult, DmarcVerifier, Disposition};
use crate::spf::{SpfResult, SpfVerifier};

/// Combined email authentication result
#[derive(Debug)]
pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub disposition: Disposition,
}

impl AuthenticationResult {
    /// Check if all authentication passed
    pub fn is_authenticated(&self) -> bool {
        self.dmarc.is_pass()
    }
}

/// Combined email authenticator (SPF + DKIM + DMARC)
pub struct EmailAuthenticator<R: DnsResolver> {
    spf: SpfVerifier<R>,
    dkim: DkimVerifier<R>,
    dmarc: DmarcVerifier<R>,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            spf: SpfVerifier::new(resolver.clone()),
            dkim: DkimVerifier::new(resolver.clone()),
            dmarc: DmarcVerifier::new(resolver),
        }
    }

    /// Authenticate an email message
    ///
    /// # Arguments
    /// * `message` - Raw email message (headers + body)
    /// * `client_ip` - IP address of the sending SMTP client
    /// * `helo` - HELO/EHLO domain from SMTP session
    /// * `mail_from` - MAIL FROM address from SMTP envelope
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        _helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // Extract domain from MAIL FROM for SPF
        let spf_domain = domain_from_email(mail_from).unwrap_or(mail_from);

        // Extract From header domain for DMARC
        let from_domain = extract_from_domain(message).unwrap_or_else(|| spf_domain.to_string());

        // Run SPF check
        let spf = self.spf.check_host(client_ip, spf_domain, mail_from).await;

        // Run DKIM verification
        let dkim = self.dkim.verify(message).await;

        // Run DMARC verification
        let dmarc = self
            .dmarc
            .verify(&from_domain, &spf, spf_domain, &dkim)
            .await;

        let disposition = dmarc.disposition;

        AuthenticationResult {
            spf,
            dkim,
            dmarc,
            disposition,
        }
    }

    /// Get the SPF verifier for direct use
    pub fn spf(&self) -> &SpfVerifier<R> {
        &self.spf
    }

    /// Get the DKIM verifier for direct use
    pub fn dkim(&self) -> &DkimVerifier<R> {
        &self.dkim
    }

    /// Get the DMARC verifier for direct use
    pub fn dmarc(&self) -> &DmarcVerifier<R> {
        &self.dmarc
    }
}

/// Extract From header domain from message
fn extract_from_domain(message: &[u8]) -> Option<String> {
    let message_str = String::from_utf8_lossy(message);

    // Find headers section (before first blank line)
    let headers = message_str.split("\r\n\r\n").next()?;

    // Find From header
    for line in headers.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("from:") {
            let value = &line[5..].trim();
            return extract_domain_from_address(value);
        }
    }

    // Handle folded headers
    let mut current_header = String::new();
    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            current_header.push_str(line);
        } else {
            if current_header.to_lowercase().starts_with("from:") {
                let value = &current_header[5..].trim();
                return extract_domain_from_address(value);
            }
            current_header = line.to_string();
        }
    }

    // Check last header
    if current_header.to_lowercase().starts_with("from:") {
        let value = &current_header[5..].trim();
        return extract_domain_from_address(value);
    }

    None
}

/// Extract domain from email address (handles "Name <email>" format)
fn extract_domain_from_address(addr: &str) -> Option<String> {
    // Handle "Name <email@domain>" format
    if let Some(start) = addr.find('<') {
        if let Some(end) = addr.find('>') {
            let email = &addr[start + 1..end];
            return domain_from_email(email).map(|s| s.to_string());
        }
    }

    // Simple email@domain format
    domain_from_email(addr).map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_from_domain() {
        let message = b"From: user@example.com\r\nTo: other@example.com\r\n\r\nBody";
        assert_eq!(
            extract_from_domain(message),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_from_domain_with_name() {
        let message = b"From: John Doe <john@example.com>\r\n\r\nBody";
        assert_eq!(
            extract_from_domain(message),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_from_address() {
        assert_eq!(
            extract_domain_from_address("user@example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain_from_address("John Doe <john@example.com>"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain_from_address("<user@example.com>"),
            Some("example.com".to_string())
        );
    }
}
