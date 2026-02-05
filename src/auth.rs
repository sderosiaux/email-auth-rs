use crate::common::DnsResolver;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{DmarcResult, DmarcVerifier, Disposition};
use crate::spf::{SpfResult, SpfVerifier};
use std::net::IpAddr;

/// Combined email authenticator
pub struct EmailAuthenticator<R: DnsResolver> {
    spf: SpfVerifier<R>,
    dkim: DkimVerifier<R>,
    dmarc: DmarcVerifier<R>,
}

impl<R: DnsResolver + Clone> EmailAuthenticator<R> {
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
    /// * `message` - The raw email message (headers + body)
    /// * `client_ip` - The IP address of the sending mail server
    /// * `helo` - The HELO/EHLO identity
    /// * `mail_from` - The MAIL FROM envelope sender
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
            mail_from
                .rfind('@')
                .map(|pos| &mail_from[pos + 1..])
                .unwrap_or(helo)
                .to_string()
        });

        // Determine SPF domain (MAIL FROM domain or HELO)
        let spf_domain = if mail_from.is_empty() || mail_from == "<>" {
            helo.to_string()
        } else {
            mail_from
                .rfind('@')
                .map(|pos| mail_from[pos + 1..].to_string())
                .unwrap_or_else(|| helo.to_string())
        };

        // Run SPF and DKIM in parallel conceptually
        // (In practice they run sequentially due to async)
        let spf_result = self
            .spf
            .check_host(client_ip, &spf_domain, mail_from, helo)
            .await;

        let dkim_results = self.dkim.verify(message).await;

        // Run DMARC
        let dmarc_result = self
            .dmarc
            .verify(&from_domain, &spf_result, &spf_domain, &dkim_results)
            .await;

        // Determine final disposition
        let disposition = dmarc_result.disposition.clone();

        AuthenticationResult {
            spf: spf_result,
            spf_domain,
            dkim: dkim_results,
            dmarc: dmarc_result,
            disposition,
            from_domain,
        }
    }
}

/// Result of email authentication
#[derive(Debug)]
pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub spf_domain: String,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub disposition: Disposition,
    pub from_domain: String,
}

impl AuthenticationResult {
    /// Check if the message passed authentication
    pub fn passed(&self) -> bool {
        self.disposition == Disposition::Pass
    }

    /// Get a summary header suitable for Authentication-Results
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!("spf={}", self.spf));

        for (i, dkim) in self.dkim.iter().enumerate() {
            let dkim_str = match dkim {
                DkimResult::Pass { domain, .. } => format!("pass (domain={})", domain),
                DkimResult::Fail { reason } => format!("fail ({})", reason),
                DkimResult::TempFail { reason } => format!("temperror ({})", reason),
                DkimResult::PermFail { reason } => format!("permerror ({})", reason),
                DkimResult::None => "none".to_string(),
            };
            if i == 0 {
                parts.push(format!("dkim={}", dkim_str));
            }
        }

        parts.push(format!("dmarc={}", self.dmarc.disposition));

        parts.join("; ")
    }
}

/// Extract the From header domain from a raw message
fn extract_from_domain(message: &[u8]) -> Option<String> {
    let message_str = String::from_utf8_lossy(message);

    // Find headers section
    let headers = if let Some(pos) = message_str.find("\r\n\r\n") {
        &message_str[..pos]
    } else if let Some(pos) = message_str.find("\n\n") {
        &message_str[..pos]
    } else {
        &message_str[..]
    };

    // Find From header (handle folded headers)
    let mut in_from = false;
    let mut from_value = String::new();

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if in_from {
                from_value.push_str(line.trim());
            }
        } else {
            if in_from {
                break;
            }
            if line.to_lowercase().starts_with("from:") {
                in_from = true;
                from_value = line[5..].trim().to_string();
            }
        }
    }

    if from_value.is_empty() {
        return None;
    }

    // Extract domain from From value
    // Handle formats like: "Name <email@domain>" or "email@domain"
    let from_value = from_value.trim();

    if let Some(start) = from_value.find('<') {
        if let Some(end) = from_value.find('>') {
            let email = &from_value[start + 1..end];
            if let Some(at_pos) = email.rfind('@') {
                return Some(email[at_pos + 1..].to_lowercase());
            }
        }
    } else if let Some(at_pos) = from_value.rfind('@') {
        // Simple email address
        let domain = from_value[at_pos + 1..].trim();
        // Remove any trailing characters
        let domain = domain.split_whitespace().next().unwrap_or(domain);
        return Some(domain.to_lowercase());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_from_domain_simple() {
        let message = b"From: user@example.com\r\nTo: other@example.org\r\n\r\nBody";
        assert_eq!(
            extract_from_domain(message),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_from_domain_with_name() {
        let message = b"From: John Doe <john@example.com>\r\nTo: other@example.org\r\n\r\nBody";
        assert_eq!(
            extract_from_domain(message),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_from_domain_folded() {
        let message = b"From: Very Long Name\r\n <user@example.com>\r\nTo: other@example.org\r\n\r\nBody";
        assert_eq!(
            extract_from_domain(message),
            Some("example.com".to_string())
        );
    }
}
