//! DMARC policy evaluation

use rand::Rng;

use crate::common::dns::{DnsError, DnsResolver};
use crate::common::psl::organizational_domain;
use crate::dkim::DkimResult;
use crate::spf::SpfResult;
use super::alignment::domains_aligned;
use super::record::DmarcRecord;

/// DMARC policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

/// DMARC alignment mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlignmentMode {
    #[default]
    Relaxed,
    Strict,
}

/// Final disposition after DMARC evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Pass,
    Quarantine,
    Reject,
    None,
}

/// DMARC verification result
#[derive(Debug, Clone)]
pub struct DmarcResult {
    pub disposition: Disposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub policy: Option<Policy>,
    pub record: Option<DmarcRecord>,
}

/// DMARC verifier
#[derive(Clone)]
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
        // Query DMARC record
        let (record, queried_domain) = match self.lookup_dmarc_record(from_domain).await {
            Some(r) => r,
            None => {
                return DmarcResult {
                    disposition: Disposition::None,
                    dkim_aligned: false,
                    spf_aligned: false,
                    policy: None,
                    record: None,
                };
            }
        };

        // Check DKIM alignment
        let dkim_aligned = dkim_results.iter().any(|r| {
            if let DkimResult::Pass { domain, .. } = r {
                domains_aligned(domain, from_domain, record.adkim)
            } else {
                false
            }
        });

        // Check SPF alignment
        let spf_aligned = matches!(spf_result, SpfResult::Pass)
            && domains_aligned(spf_domain, from_domain, record.aspf);

        // DMARC passes if either aligns
        if dkim_aligned || spf_aligned {
            return DmarcResult {
                disposition: Disposition::Pass,
                dkim_aligned,
                spf_aligned,
                policy: Some(record.policy),
                record: Some(record),
            };
        }

        // Determine which policy to apply
        let effective_policy = self.get_effective_policy(&record, from_domain, &queried_domain).await;

        // Apply pct sampling
        let disposition = if record.pct < 100 {
            let mut rng = rand::rng();
            let sample: u8 = rng.random_range(1..=100);
            if sample <= record.pct {
                policy_to_disposition(effective_policy)
            } else {
                Disposition::None
            }
        } else {
            policy_to_disposition(effective_policy)
        };

        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            policy: Some(effective_policy),
            record: Some(record),
        }
    }

    async fn lookup_dmarc_record(&self, domain: &str) -> Option<(DmarcRecord, String)> {
        // Try _dmarc.<domain>
        let dmarc_domain = format!("_dmarc.{}", domain);
        if let Ok(records) = self.resolver.query_txt(&dmarc_domain).await {
            for txt in &records {
                if txt.to_lowercase().starts_with("v=dmarc1") {
                    if let Ok(record) = DmarcRecord::parse(txt) {
                        return Some((record, domain.to_string()));
                    }
                }
            }
        }

        // Try organizational domain fallback
        let org_domain = organizational_domain(domain);
        if org_domain != domain {
            let dmarc_org_domain = format!("_dmarc.{}", org_domain);
            if let Ok(records) = self.resolver.query_txt(&dmarc_org_domain).await {
                for txt in &records {
                    if txt.to_lowercase().starts_with("v=dmarc1") {
                        if let Ok(record) = DmarcRecord::parse(txt) {
                            return Some((record, org_domain));
                        }
                    }
                }
            }
        }

        None
    }

    async fn get_effective_policy(
        &self,
        record: &DmarcRecord,
        from_domain: &str,
        queried_domain: &str,
    ) -> Policy {
        // If from_domain == queried_domain, use p=
        if from_domain.to_lowercase() == queried_domain.to_lowercase() {
            return record.policy;
        }

        // Check if from_domain is non-existent (RFC 9091)
        if record.np_policy.is_some() {
            let exists = self.domain_exists(from_domain).await;
            if !exists {
                return record.get_np_policy();
            }
        }

        // Otherwise it's a subdomain, use sp= (or p= if no sp=)
        record.get_subdomain_policy()
    }

    async fn domain_exists(&self, domain: &str) -> bool {
        // Check A, AAAA, and MX records
        let a_exists = self.resolver.query_a(domain).await.is_ok();
        let aaaa_exists = self.resolver.query_aaaa(domain).await.is_ok();
        let mx_exists = self.resolver.query_mx(domain).await.is_ok();

        a_exists || aaaa_exists || mx_exists
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
    async fn test_no_dmarc_record() {
        let resolver = MockResolver::new();
        let verifier = DmarcVerifier::new(resolver);

        let result = verifier
            .verify("example.com", &SpfResult::Pass, "example.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::None);
        assert!(result.record.is_none());
    }

    #[tokio::test]
    async fn test_dmarc_pass_spf_aligned() {
        let resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject".to_string()]);

        let verifier = DmarcVerifier::new(resolver);
        let result = verifier
            .verify("example.com", &SpfResult::Pass, "example.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.spf_aligned);
    }

    #[tokio::test]
    async fn test_dmarc_pass_dkim_aligned() {
        let resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject".to_string()]);

        let verifier = DmarcVerifier::new(resolver);
        let dkim_results = vec![DkimResult::Pass {
            domain: "example.com".to_string(),
            selector: "s1".to_string(),
        }];

        let result = verifier
            .verify("example.com", &SpfResult::Fail, "example.com", &dkim_results)
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
    }

    #[tokio::test]
    async fn test_dmarc_fail_reject() {
        let resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject".to_string()]);

        let verifier = DmarcVerifier::new(resolver);
        let result = verifier
            .verify("example.com", &SpfResult::Fail, "other.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn test_subdomain_policy() {
        let resolver = MockResolver::new();
        resolver.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; sp=quarantine".to_string()],
        );

        let verifier = DmarcVerifier::new(resolver);
        let result = verifier
            .verify("mail.example.com", &SpfResult::Fail, "other.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::Quarantine);
    }

    #[tokio::test]
    async fn test_relaxed_alignment() {
        let resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject; aspf=r".to_string()]);

        let verifier = DmarcVerifier::new(resolver);
        let result = verifier
            .verify("example.com", &SpfResult::Pass, "mail.example.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.spf_aligned);
    }
}
