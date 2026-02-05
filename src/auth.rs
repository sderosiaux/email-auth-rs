use std::net::IpAddr;

use crate::common::dns::DnsResolver;
use crate::common::domain::domain_from_email;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{DmarcResult, DmarcVerifier, Disposition};
use crate::spf::{SpfResult, SpfVerifier};

/// Combined authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    /// SPF result
    pub spf: SpfResult,
    /// SPF domain that was checked
    pub spf_domain: String,
    /// DKIM results (one per signature)
    pub dkim: Vec<DkimResult>,
    /// DMARC result
    pub dmarc: DmarcResult,
    /// Final disposition
    pub disposition: Disposition,
}

/// Combined email authenticator
#[derive(Clone)]
pub struct EmailAuthenticator<R: DnsResolver> {
    spf: SpfVerifier<R>,
    dkim: DkimVerifier<R>,
    dmarc: DmarcVerifier<R>,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub fn new(resolver: R) -> Self {
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
    /// * `client_ip` - IP address of the sending server
    /// * `helo` - HELO/EHLO domain from SMTP session
    /// * `mail_from` - MAIL FROM address (envelope sender)
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // Extract From header domain for DMARC
        let from_domain = self.extract_from_domain(message);

        // Determine SPF domain (MAIL FROM domain, or HELO if MAIL FROM is empty)
        let spf_domain = if mail_from.is_empty() || mail_from == "<>" {
            helo.to_string()
        } else {
            domain_from_email(mail_from)
                .unwrap_or(helo)
                .to_string()
        };

        // Run SPF check
        let sender = if mail_from.is_empty() || mail_from == "<>" {
            format!("postmaster@{}", helo)
        } else {
            mail_from.to_string()
        };
        let spf_result = self.spf.check_host(client_ip, &spf_domain, &sender).await;

        // Run DKIM verification
        let dkim_results = self.dkim.verify(message).await;

        // Get From domain for DMARC, fallback to SPF domain
        let from_domain = from_domain.unwrap_or_else(|| spf_domain.clone());

        // Run DMARC verification
        let dmarc_result = self
            .dmarc
            .verify(&from_domain, &spf_result, &spf_domain, &dkim_results)
            .await;

        let disposition = dmarc_result.disposition;

        AuthenticationResult {
            spf: spf_result,
            spf_domain,
            dkim: dkim_results,
            dmarc: dmarc_result,
            disposition,
        }
    }

    fn extract_from_domain(&self, message: &[u8]) -> Option<String> {
        let message_str = std::str::from_utf8(message).ok()?;

        // Find the From header
        for line in message_str.lines() {
            if line.to_lowercase().starts_with("from:") {
                let value = line[5..].trim();
                // Extract email address from value (may be in angle brackets or bare)
                return self.extract_domain_from_header(value);
            }
        }

        None
    }

    fn extract_domain_from_header(&self, value: &str) -> Option<String> {
        // Handle formats like:
        // - user@example.com
        // - <user@example.com>
        // - "Display Name" <user@example.com>
        // - Display Name <user@example.com>

        // Look for angle brackets first
        if let Some(start) = value.find('<') {
            if let Some(end) = value.find('>') {
                let email = &value[start + 1..end];
                return domain_from_email(email).map(|d| d.to_lowercase());
            }
        }

        // No angle brackets, try to find @ directly
        domain_from_email(value).map(|d| d.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[tokio::test]
    async fn test_basic_authentication() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.1 -all".to_string()]);
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=none".to_string()]);

        let auth = EmailAuthenticator::new(resolver);

        let message = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody";
        let result = auth
            .authenticate(
                message,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                "mail.example.com",
                "user@example.com",
            )
            .await;

        assert_eq!(result.spf, SpfResult::Pass);
        assert_eq!(result.disposition, Disposition::Pass);
    }

    #[tokio::test]
    async fn test_from_header_extraction() {
        let resolver = MockResolver::new();
        let auth = EmailAuthenticator::new(resolver);

        let message = b"From: \"Test User\" <test@example.com>\r\nSubject: Test\r\n\r\nBody";
        let domain = auth.extract_from_domain(message);
        assert_eq!(domain, Some("example.com".to_string()));

        let message = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody";
        let domain = auth.extract_from_domain(message);
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[tokio::test]
    async fn test_empty_mail_from() {
        let resolver = MockResolver::new();
        resolver.add_txt("mail.example.com", vec!["v=spf1 ip4:192.0.2.1 -all".to_string()]);

        let auth = EmailAuthenticator::new(resolver);

        let message = b"From: user@example.com\r\n\r\nBody";
        let result = auth
            .authenticate(
                message,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                "mail.example.com",
                "<>", // Empty MAIL FROM (bounce message)
            )
            .await;

        // Should use HELO domain for SPF
        assert_eq!(result.spf_domain, "mail.example.com");
    }
}
