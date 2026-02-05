//! DMARC policy evaluation.

use super::alignment::domains_aligned;
use super::record::{DmarcRecord, Policy};
use super::{DmarcError, DmarcResult};
use crate::common::dns::{DnsError, DnsResolver};
use crate::common::psl::PublicSuffixList;
use crate::dkim::DkimResult;
use crate::spf::SpfResult;
use rand::Rng;

/// DMARC disposition (what to do with the message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Pass,
    Quarantine,
    Reject,
    None,
}

/// DMARC verifier.
#[derive(Clone)]
pub struct DmarcVerifier<R: DnsResolver> {
    resolver: R,
    psl: PublicSuffixList,
}

impl<R: DnsResolver> DmarcVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            psl: PublicSuffixList::new(),
        }
    }

    /// Verify DMARC for a message.
    pub async fn verify(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult {
        // Lookup DMARC record
        let (record, queried_domain) = match self.lookup_record(from_domain).await {
            Ok(Some((r, d))) => (r, d),
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
        let dkim_aligned = dkim_results.iter().any(|r| {
            if let DkimResult::Pass { domain, .. } = r {
                domains_aligned(domain, from_domain, record.dkim_alignment, &self.psl)
            } else {
                false
            }
        });

        // Check SPF alignment
        let spf_aligned = spf_result.is_pass()
            && domains_aligned(spf_domain, from_domain, record.spf_alignment, &self.psl);

        // DMARC passes if DKIM OR SPF aligns
        if dkim_aligned || spf_aligned {
            return DmarcResult {
                disposition: Disposition::Pass,
                dkim_aligned,
                spf_aligned,
                policy: Some(record.policy),
                record: Some(record),
            };
        }

        // DMARC fails - determine policy
        let from_domain_lower = from_domain.to_lowercase();
        let queried_domain_lower = queried_domain.to_lowercase();

        let applicable_policy = if from_domain_lower == queried_domain_lower {
            // From domain is the org domain itself
            record.policy
        } else {
            // From domain is a subdomain
            record.subdomain_policy()
        };

        // Apply pct sampling
        let disposition = if record.pct < 100 {
            let mut rng = rand::rng();
            let sample: u8 = rng.random_range(1..=100);
            if sample > record.pct {
                // Not sampled - treat as policy=none
                Disposition::None
            } else {
                policy_to_disposition(applicable_policy)
            }
        } else {
            policy_to_disposition(applicable_policy)
        };

        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            policy: Some(applicable_policy),
            record: Some(record),
        }
    }

    async fn lookup_record(
        &self,
        from_domain: &str,
    ) -> Result<Option<(DmarcRecord, String)>, DmarcError> {
        let from_domain = crate::common::domain::normalize(from_domain);

        // First try _dmarc.<from-domain>
        let dmarc_domain = format!("_dmarc.{}", from_domain);
        match self.query_dmarc(&dmarc_domain).await {
            Ok(Some(record)) => return Ok(Some((record, from_domain))),
            Ok(None) => {}
            Err(DmarcError::DnsError(DnsError::NxDomain | DnsError::NoRecords)) => {}
            Err(e) => return Err(e),
        }

        // Fall back to organizational domain
        let org_domain = self.psl.organizational_domain(&from_domain);
        if org_domain != from_domain {
            let dmarc_domain = format!("_dmarc.{}", org_domain);
            match self.query_dmarc(&dmarc_domain).await {
                Ok(Some(record)) => return Ok(Some((record, org_domain))),
                Ok(None) => {}
                Err(DmarcError::DnsError(DnsError::NxDomain | DnsError::NoRecords)) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(None)
    }

    async fn query_dmarc(&self, domain: &str) -> Result<Option<DmarcRecord>, DmarcError> {
        let txt_records = match self.resolver.query_txt(domain).await {
            Ok(r) => r,
            Err(DnsError::NxDomain | DnsError::NoRecords) => return Ok(None),
            Err(e) => return Err(DmarcError::DnsError(e)),
        };

        // Find DMARC records (start with v=DMARC1)
        let dmarc_records: Vec<_> = txt_records
            .iter()
            .filter(|r| r.to_uppercase().starts_with("V=DMARC1"))
            .collect();

        match dmarc_records.first() {
            Some(record) => Ok(Some(DmarcRecord::parse(record)?)),
            None => Ok(None),
        }
    }
}

fn policy_to_disposition(policy: Policy) -> Disposition {
    match policy {
        Policy::None => Disposition::None,
        Policy::Quarantine => Disposition::Quarantine,
        Policy::Reject => Disposition::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[tokio::test]
    async fn test_dmarc_pass_dkim() {
        let resolver = MockResolver::new()
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject".into()]);

        let verifier = DmarcVerifier::new(resolver);

        let dkim_results = vec![DkimResult::Pass {
            domain: "example.com".into(),
            selector: "selector".into(),
        }];

        let result = verifier
            .verify(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &dkim_results,
            )
            .await;

        assert!(matches!(result.disposition, Disposition::Pass));
        assert!(result.dkim_aligned);
        assert!(!result.spf_aligned);
    }

    #[tokio::test]
    async fn test_dmarc_pass_spf() {
        let resolver = MockResolver::new()
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject".into()]);

        let verifier = DmarcVerifier::new(resolver);

        let result = verifier
            .verify("example.com", &SpfResult::Pass, "example.com", &[])
            .await;

        assert!(matches!(result.disposition, Disposition::Pass));
        assert!(!result.dkim_aligned);
        assert!(result.spf_aligned);
    }

    #[tokio::test]
    async fn test_dmarc_fail_reject() {
        let resolver = MockResolver::new()
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject; pct=100".into()]);

        let verifier = DmarcVerifier::new(resolver);

        let result = verifier
            .verify(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
            )
            .await;

        assert!(matches!(result.disposition, Disposition::Reject));
    }

    #[tokio::test]
    async fn test_dmarc_no_record() {
        let resolver = MockResolver::new();

        let verifier = DmarcVerifier::new(resolver);

        let result = verifier
            .verify("example.com", &SpfResult::Pass, "example.com", &[])
            .await;

        assert!(matches!(result.disposition, Disposition::None));
        assert!(result.record.is_none());
    }

    #[tokio::test]
    async fn test_dmarc_org_domain_fallback() {
        let resolver = MockResolver::new()
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject".into()]);

        let verifier = DmarcVerifier::new(resolver);

        // Query for subdomain, falls back to org domain
        let result = verifier
            .verify(
                "mail.example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
            )
            .await;

        // Should find the policy at org domain level
        assert!(result.record.is_some());
    }

    #[tokio::test]
    async fn test_relaxed_dkim_alignment() {
        let resolver = MockResolver::new()
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject; adkim=r".into()]);

        let verifier = DmarcVerifier::new(resolver);

        // DKIM domain is subdomain of From domain
        let dkim_results = vec![DkimResult::Pass {
            domain: "mail.example.com".into(),
            selector: "selector".into(),
        }];

        let result = verifier
            .verify(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &dkim_results,
            )
            .await;

        assert!(matches!(result.disposition, Disposition::Pass));
        assert!(result.dkim_aligned);
    }
}
