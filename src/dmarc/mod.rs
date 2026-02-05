mod alignment;
mod policy;
mod record;

pub use alignment::{check_dkim_alignment, check_spf_alignment, AlignmentMode};
pub use policy::{DmarcResult, Disposition};
pub use record::{DmarcRecord, Policy};

use crate::common::{organizational_domain, DnsError, DnsResolver};
use crate::dkim::DkimResult;
use crate::spf::SpfResult;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DmarcError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("DNS error: {0}")]
    Dns(String),
}

pub struct DmarcVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> DmarcVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Verify DMARC for a message
    pub async fn verify(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult {
        let from_domain = crate::common::normalize_domain(from_domain);

        // Fetch DMARC record
        let record = match self.fetch_dmarc_record(&from_domain).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                return DmarcResult {
                    disposition: Disposition::None,
                    dkim_aligned: false,
                    spf_aligned: false,
                    policy: None,
                    record: None,
                }
            }
            Err(_) => {
                return DmarcResult {
                    disposition: Disposition::None,
                    dkim_aligned: false,
                    spf_aligned: false,
                    policy: None,
                    record: None,
                }
            }
        };

        // Check DKIM alignment
        let dkim_aligned = check_dkim_alignment(&from_domain, dkim_results, record.adkim);

        // Check SPF alignment
        let spf_aligned = check_spf_alignment(&from_domain, spf_result, spf_domain, record.aspf);

        // Determine disposition
        if dkim_aligned || spf_aligned {
            return DmarcResult {
                disposition: Disposition::Pass,
                dkim_aligned,
                spf_aligned,
                policy: Some(record.policy),
                record: Some(record),
            };
        }

        // DMARC failed - apply policy
        let applicable_policy = self.get_applicable_policy(&from_domain, &record).await;

        // Apply pct sampling
        let disposition = if should_apply_policy(record.pct) {
            match applicable_policy {
                Policy::None => Disposition::None,
                Policy::Quarantine => Disposition::Quarantine,
                Policy::Reject => Disposition::Reject,
            }
        } else {
            // Not sampled - treat as none
            Disposition::None
        };

        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            policy: Some(applicable_policy),
            record: Some(record),
        }
    }

    async fn fetch_dmarc_record(&self, from_domain: &str) -> Result<Option<DmarcRecord>, DmarcError> {
        // Try exact domain first
        let dmarc_domain = format!("_dmarc.{}", from_domain);

        match self.resolver.query_txt(&dmarc_domain).await {
            Ok(records) => {
                for txt in records {
                    if let Ok(record) = DmarcRecord::parse(&txt) {
                        return Ok(Some(record));
                    }
                }
            }
            Err(DnsError::NxDomain) => {
                // Try organizational domain
                let org_domain = organizational_domain(from_domain);
                if org_domain != from_domain {
                    let dmarc_org = format!("_dmarc.{}", org_domain);
                    if let Ok(records) = self.resolver.query_txt(&dmarc_org).await {
                        for txt in records {
                            if let Ok(record) = DmarcRecord::parse(&txt) {
                                return Ok(Some(record));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                return Err(DmarcError::Dns(e.to_string()));
            }
        }

        Ok(None)
    }

    async fn get_applicable_policy(&self, from_domain: &str, record: &DmarcRecord) -> Policy {
        let org_domain = organizational_domain(from_domain);

        if from_domain == org_domain {
            // This is the organizational domain itself - use p=
            return record.policy;
        }

        // This is a subdomain - check if it exists
        if let Some(np) = record.np {
            // Check if domain exists (RFC 9091)
            let exists = self.domain_exists(from_domain).await;
            if !exists {
                return np;
            }
        }

        // Use sp= or fall back to p=
        record.subdomain_policy.unwrap_or(record.policy)
    }

    async fn domain_exists(&self, domain: &str) -> bool {
        // Domain exists if ANY of A, AAAA, MX queries succeed with data
        let a_exists = self
            .resolver
            .query_a(domain)
            .await
            .map(|r| !r.is_empty())
            .unwrap_or(false);

        if a_exists {
            return true;
        }

        let aaaa_exists = self
            .resolver
            .query_aaaa(domain)
            .await
            .map(|r| !r.is_empty())
            .unwrap_or(false);

        if aaaa_exists {
            return true;
        }

        let mx_exists = self
            .resolver
            .query_mx(domain)
            .await
            .map(|r| !r.is_empty())
            .unwrap_or(false);

        mx_exists
    }
}

fn should_apply_policy(pct: u8) -> bool {
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }

    use rand::Rng;
    let mut rng = rand::rng();
    let random: u8 = rng.random_range(1..=100);
    random <= pct
}
