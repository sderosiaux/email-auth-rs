mod alignment;
mod policy;
mod record;

use std::sync::Arc;

use crate::common::dns::{DnsError, DnsResolver};
use crate::common::psl::PublicSuffixList;
use crate::dkim::DkimResult;
use crate::spf::SpfResult;

pub use record::{AlignmentMode, DmarcRecord, ParseError, Policy};

/// DMARC evaluation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcResult {
    pub disposition: Disposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub policy: Option<Policy>,
    pub record: Option<DmarcRecord>,
}

impl DmarcResult {
    pub fn is_pass(&self) -> bool {
        matches!(self.disposition, Disposition::Pass)
    }

    /// No DMARC record found
    pub fn none() -> Self {
        Self {
            disposition: Disposition::None,
            dkim_aligned: false,
            spf_aligned: false,
            policy: None,
            record: None,
        }
    }
}

/// DMARC disposition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Pass,
    Quarantine,
    Reject,
    None,
}

/// DMARC verifier
pub struct DmarcVerifier<R: DnsResolver> {
    resolver: Arc<R>,
    psl: PublicSuffixList,
}

impl<R: DnsResolver> DmarcVerifier<R> {
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            psl: PublicSuffixList::new(),
        }
    }

    /// Verify DMARC for given SPF and DKIM results
    pub async fn verify(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult {
        // Lookup DMARC record
        let (record, record_domain) = match self.lookup_dmarc(from_domain).await {
            Some((r, d)) => (r, d),
            None => return DmarcResult::none(),
        };

        // Check DKIM alignment
        let dkim_aligned = self.check_dkim_alignment(from_domain, dkim_results, &record);

        // Check SPF alignment
        let spf_aligned = self.check_spf_alignment(from_domain, spf_result, spf_domain, &record);

        // DMARC passes if either DKIM or SPF aligns
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
        // Check if From domain exists (for np= policy)
        let from_exists = self.resolver.domain_exists(from_domain).await.unwrap_or(true);

        let selected_policy = policy::select_policy(&record, from_domain, &record_domain, from_exists);

        // Apply percentage sampling
        let sampled = policy::should_apply_policy(record.pct);
        let disposition = policy::policy_to_disposition(selected_policy, sampled);

        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            policy: Some(selected_policy),
            record: Some(record),
        }
    }

    async fn lookup_dmarc(&self, from_domain: &str) -> Option<(DmarcRecord, String)> {
        // Try _dmarc.<from-domain> first
        let query = format!("_dmarc.{}", from_domain);
        if let Some(record) = self.query_dmarc(&query).await {
            return Some((record, from_domain.to_string()));
        }

        // Try organizational domain
        let org_domain = self.psl.organizational_domain(from_domain);
        if org_domain != from_domain.to_lowercase() {
            let query = format!("_dmarc.{}", org_domain);
            if let Some(record) = self.query_dmarc(&query).await {
                return Some((record, org_domain));
            }
        }

        None
    }

    async fn query_dmarc(&self, query: &str) -> Option<DmarcRecord> {
        match self.resolver.query_txt(query).await {
            Ok(records) => {
                for txt in records {
                    if let Ok(record) = DmarcRecord::parse(&txt) {
                        return Some(record);
                    }
                }
                None
            }
            Err(_) => None,
        }
    }

    fn check_dkim_alignment(
        &self,
        from_domain: &str,
        dkim_results: &[DkimResult],
        record: &DmarcRecord,
    ) -> bool {
        for result in dkim_results {
            if let DkimResult::Pass { domain, .. } = result {
                if alignment::check_dkim_alignment(from_domain, domain, record.adkim, &self.psl) {
                    return true;
                }
            }
        }
        false
    }

    fn check_spf_alignment(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        record: &DmarcRecord,
    ) -> bool {
        // SPF must pass AND align
        if !spf_result.is_pass() {
            return false;
        }

        alignment::check_spf_alignment(from_domain, spf_domain, record.aspf, &self.psl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[tokio::test]
    async fn test_dmarc_no_record() {
        let resolver = MockResolver::new();
        let verifier = DmarcVerifier::new(Arc::new(resolver));

        let result = verifier
            .verify("example.com", &SpfResult::Pass, "example.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::None);
        assert!(result.record.is_none());
    }

    #[tokio::test]
    async fn test_dmarc_pass_spf() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject"]);

        let verifier = DmarcVerifier::new(Arc::new(resolver));

        let result = verifier
            .verify("example.com", &SpfResult::Pass, "example.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.spf_aligned);
        assert!(!result.dkim_aligned);
    }

    #[tokio::test]
    async fn test_dmarc_pass_dkim() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject"]);

        let verifier = DmarcVerifier::new(Arc::new(resolver));

        let dkim_results = vec![DkimResult::Pass {
            domain: "example.com".to_string(),
            selector: "sel".to_string(),
        }];

        let result = verifier
            .verify("example.com", &SpfResult::Fail, "other.com", &dkim_results)
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(!result.spf_aligned);
        assert!(result.dkim_aligned);
    }

    #[tokio::test]
    async fn test_dmarc_fail_applies_policy() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject; pct=100"]);
        // Add A record so domain is considered to exist
        resolver.add_a("example.com", vec!["1.2.3.4".parse().unwrap()]);

        let verifier = DmarcVerifier::new(Arc::new(resolver));

        let result = verifier
            .verify("example.com", &SpfResult::Fail, "other.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.policy, Some(Policy::Reject));
    }

    #[tokio::test]
    async fn test_dmarc_org_domain_fallback() {
        let mut resolver = MockResolver::new();
        // No DMARC at subdomain
        // DMARC at org domain
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject; sp=quarantine"]);
        resolver.add_a("mail.example.com", vec!["1.2.3.4".parse().unwrap()]);

        let verifier = DmarcVerifier::new(Arc::new(resolver));

        let result = verifier
            .verify("mail.example.com", &SpfResult::Fail, "other.com", &[])
            .await;

        // Should use sp= policy for existing subdomain
        assert_eq!(result.policy, Some(Policy::Quarantine));
    }

    #[tokio::test]
    async fn test_dmarc_relaxed_alignment() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject; adkim=r; aspf=r"]);

        let verifier = DmarcVerifier::new(Arc::new(resolver));

        // DKIM from subdomain should align with From at org domain
        let dkim_results = vec![DkimResult::Pass {
            domain: "mail.example.com".to_string(),
            selector: "sel".to_string(),
        }];

        let result = verifier
            .verify("example.com", &SpfResult::Fail, "other.com", &dkim_results)
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
    }
}
