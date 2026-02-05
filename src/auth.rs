//! Combined email authentication API.

use crate::common::dns::DnsResolver;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{DmarcResult, DmarcVerifier, Disposition};
use crate::spf::{SpfResult, SpfVerifier};
use std::net::IpAddr;

/// Combined authentication result.
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub disposition: Disposition,
}

impl AuthenticationResult {
    /// Check if the message passed all authentication checks.
    pub fn is_pass(&self) -> bool {
        self.dmarc.is_pass()
    }
}

/// Combined email authenticator.
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

    /// Authenticate an email message.
    ///
    /// # Arguments
    /// * `message` - The raw email message (headers + body)
    /// * `client_ip` - The IP address of the sending server
    /// * `helo` - The HELO/EHLO domain from the SMTP session
    /// * `mail_from` - The MAIL FROM address (envelope sender)
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // Extract From header domain
        let message_str = String::from_utf8_lossy(message);
        let from_domain = extract_from_domain(&message_str).unwrap_or_else(|| {
            // Fallback to SPF domain
            crate::common::domain::email_domain(mail_from)
                .unwrap_or(helo)
                .to_string()
        });

        // Determine SPF domain
        let spf_domain = crate::common::domain::email_domain(mail_from).unwrap_or(helo);

        // Run SPF check
        let spf = self.spf.check_host(client_ip, spf_domain, mail_from).await;

        // Run DKIM verification
        let dkim = self.dkim.verify(message).await;

        // Run DMARC evaluation
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
}

/// Extract the domain from the RFC5322 From header.
fn extract_from_domain(message: &str) -> Option<String> {
    // Find the From header
    let headers = message.split("\r\n\r\n").next().or_else(|| message.split("\n\n").next())?;

    let mut from_value = String::new();
    let mut in_from = false;

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation
            if in_from {
                from_value.push_str(line);
            }
        } else if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("from") {
                from_value = value.to_string();
                in_from = true;
            } else {
                in_from = false;
            }
        }
    }

    if from_value.is_empty() {
        return None;
    }

    // Parse email address from From value
    // Handle formats like:
    // - user@example.com
    // - <user@example.com>
    // - "User Name" <user@example.com>
    // - User Name <user@example.com>

    let from_value = from_value.trim();

    // Look for angle brackets
    if let Some(start) = from_value.rfind('<') {
        if let Some(end) = from_value.rfind('>') {
            let email = &from_value[start + 1..end];
            return crate::common::domain::email_domain(email).map(|s| s.to_string());
        }
    }

    // No angle brackets - try to parse as bare email
    crate::common::domain::email_domain(from_value).map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;
    use std::net::Ipv4Addr;

    #[test]
    fn test_extract_from_domain() {
        assert_eq!(
            extract_from_domain("From: user@example.com\r\n\r\nBody"),
            Some("example.com".to_string())
        );

        assert_eq!(
            extract_from_domain("From: <user@example.com>\r\n\r\nBody"),
            Some("example.com".to_string())
        );

        assert_eq!(
            extract_from_domain("From: \"User Name\" <user@example.com>\r\n\r\nBody"),
            Some("example.com".to_string())
        );

        assert_eq!(
            extract_from_domain("Subject: Test\r\nFrom: user@example.com\r\n\r\nBody"),
            Some("example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_full_authentication() {
        let resolver = MockResolver::new()
            .with_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()])
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject".into()]);

        let auth = EmailAuthenticator::new(resolver);

        let message = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody";

        let result = auth
            .authenticate(
                message,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "mail.example.com",
                "user@example.com",
            )
            .await;

        assert!(result.spf.is_pass());
        // DKIM won't pass (no signature), but SPF alignment should work
        assert!(matches!(result.disposition, Disposition::Pass));
    }

    #[tokio::test]
    async fn test_authentication_fail() {
        let resolver = MockResolver::new()
            .with_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()])
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject; pct=100".into()]);

        let auth = EmailAuthenticator::new(resolver);

        let message = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody";

        let result = auth
            .authenticate(
                message,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Different IP
                "mail.example.com",
                "user@example.com",
            )
            .await;

        assert!(result.spf.is_fail());
        assert!(matches!(result.disposition, Disposition::Reject));
    }
}
