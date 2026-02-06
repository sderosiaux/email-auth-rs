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
    pub from_domain: String,
}

pub struct EmailAuthenticator<R: DnsResolver + Clone> {
    resolver: R,
}

impl<R: DnsResolver + Clone> EmailAuthenticator<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        let from_domain = extract_from_domain(message)
            .unwrap_or_else(|| extract_domain_from_email(mail_from).unwrap_or_default());

        let spf_domain = extract_domain_from_email(mail_from)
            .unwrap_or_else(|| helo.to_string());

        let spf_verifier = SpfVerifier::new(self.resolver.clone());
        let spf_result = spf_verifier.check_host(client_ip, &spf_domain, mail_from).await;

        let dkim_verifier = DkimVerifier::new(self.resolver.clone());
        let dkim_results = dkim_verifier.verify(message).await;

        let dmarc_verifier = DmarcVerifier::new(self.resolver.clone());
        let dmarc_result = dmarc_verifier.verify(
            &from_domain,
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
    let msg = std::str::from_utf8(message).ok()?;
    let headers_end = msg.find("\r\n\r\n").or_else(|| msg.find("\n\n"))?;
    let headers = &msg[..headers_end];

    let mut current_header = String::new();
    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            current_header.push(' ');
            current_header.push_str(line.trim());
        } else {
            if let Some(domain) = parse_from_header(&current_header) {
                return Some(domain);
            }
            current_header = line.to_string();
        }
    }
    parse_from_header(&current_header)
}

fn parse_from_header(header: &str) -> Option<String> {
    let lower = header.to_lowercase();
    if !lower.starts_with("from:") {
        return None;
    }
    let value = header[5..].trim();
    extract_domain_from_email(value)
}

fn extract_domain_from_email(email: &str) -> Option<String> {
    let email = email.trim();
    let email = if let Some(start) = email.find('<') {
        if let Some(end) = email.find('>') {
            &email[start + 1..end]
        } else {
            email
        }
    } else {
        email
    };

    email.split('@').nth(1).map(|d| d.to_lowercase())
}
