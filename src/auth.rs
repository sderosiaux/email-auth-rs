use std::net::IpAddr;
use std::sync::Arc;

use crate::common::dns::DnsResolver;
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
    pub async fn authenticate(
        &self,
        _message: &[u8],
        client_ip: IpAddr,
        _helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // Extract domain from MAIL FROM
        let spf_domain = mail_from
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or(mail_from);

        // Run SPF check
        let spf = self.spf.check_host(client_ip, spf_domain, mail_from).await;

        // Run DKIM verification (TODO: implement in M3)
        let dkim = vec![DkimResult::None];

        // TODO: Extract From header from message for DMARC
        let from_domain = spf_domain; // Placeholder

        // Run DMARC verification
        let dmarc = self.dmarc.verify(from_domain, &spf, spf_domain, &dkim).await;

        let disposition = dmarc.disposition;

        AuthenticationResult {
            spf,
            dkim,
            dmarc,
            disposition,
        }
    }
}
