use crate::common::dns::{DnsError, DnsResolver};
use crate::common::{domain, psl};
use crate::dkim::DkimResult;
use crate::spf::SpfResult;

use super::record::DmarcRecord;
use super::{AlignmentMode, Disposition, DmarcResult, Policy};

/// DMARC policy evaluator.
pub struct DmarcEvaluator<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> DmarcEvaluator<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Evaluate DMARC for a message.
    pub async fn evaluate(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult {
        self.evaluate_with_roll(from_domain, spf_result, spf_domain, dkim_results, None)
            .await
    }

    /// Internal evaluation with optional deterministic roll for pct sampling.
    pub(crate) async fn evaluate_with_roll(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
        pct_roll: Option<u8>,
    ) -> DmarcResult {
        let org_domain = psl::organizational_domain(from_domain);

        // Discover DMARC record
        let record = match self.discover_record(from_domain, &org_domain).await {
            DiscoveryResult::Found(r) => r,
            DiscoveryResult::None => return DmarcResult::default(),
            DiscoveryResult::TempFail(_msg) => {
                return DmarcResult {
                    disposition: Disposition::TempFail,
                    dkim_aligned: false,
                    spf_aligned: false,
                    applied_policy: None,
                    record: None,
                }
            }
        };

        // Check DKIM alignment
        let dkim_aligned = dkim_results.iter().any(|r| {
            if let DkimResult::Pass {
                domain: dkim_domain,
                ..
            } = r
            {
                domains_aligned(dkim_domain, from_domain, record.dkim_alignment)
            } else {
                false
            }
        });

        // Check SPF alignment
        let spf_aligned = matches!(spf_result, SpfResult::Pass)
            && domains_aligned(spf_domain, from_domain, record.spf_alignment);

        // DMARC passes if either alignment passes
        if dkim_aligned || spf_aligned {
            return DmarcResult {
                disposition: Disposition::Pass,
                dkim_aligned,
                spf_aligned,
                applied_policy: None,
                record: Some(record),
            };
        }

        // DMARC fails — select applicable policy
        let from_norm = domain::normalize(from_domain);
        let org_norm = domain::normalize(&org_domain);

        let applicable_policy = if domain::domains_equal(&from_norm, &org_norm) {
            // From domain is the organizational domain
            record.policy
        } else {
            // From domain is a subdomain — check if non-existent
            let is_nonexistent = self.check_nonexistent_subdomain(from_domain).await;
            if is_nonexistent {
                // np= → sp= → p= fallback chain
                record
                    .non_existent_subdomain_policy
                    .unwrap_or(record.subdomain_policy)
            } else {
                record.subdomain_policy
            }
        };

        // Apply pct sampling
        let roll = pct_roll.unwrap_or_else(|| rand::random_range(0u8..100));
        let apply_policy = roll < record.percent;

        let disposition = if !apply_policy {
            Disposition::None // Monitoring mode (not sampled)
        } else {
            match applicable_policy {
                Policy::None => Disposition::None,
                Policy::Quarantine => Disposition::Quarantine,
                Policy::Reject => Disposition::Reject,
            }
        };

        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            applied_policy: Some(applicable_policy),
            record: Some(record),
        }
    }

    async fn discover_record(
        &self,
        from_domain: &str,
        org_domain: &str,
    ) -> DiscoveryResult {
        let dmarc_domain = format!("_dmarc.{}", from_domain);
        match self.resolver.query_txt(&dmarc_domain).await {
            Ok(records) => {
                if let Some(record) = DmarcRecord::from_txt_records(&records) {
                    return DiscoveryResult::Found(record);
                }
                // Valid response but no DMARC record — fall through to org domain
            }
            Err(DnsError::NxDomain | DnsError::NoRecords) => {
                // No record at from_domain, try org domain
            }
            Err(DnsError::TempFail(msg)) => {
                return DiscoveryResult::TempFail(msg);
            }
        }

        // Fallback to organizational domain
        if !domain::domains_equal(from_domain, org_domain) {
            let org_dmarc = format!("_dmarc.{}", org_domain);
            match self.resolver.query_txt(&org_dmarc).await {
                Ok(records) => {
                    if let Some(record) = DmarcRecord::from_txt_records(&records) {
                        return DiscoveryResult::Found(record);
                    }
                }
                Err(DnsError::NxDomain | DnsError::NoRecords) => {}
                Err(DnsError::TempFail(msg)) => {
                    return DiscoveryResult::TempFail(msg);
                }
            }
        }

        DiscoveryResult::None
    }

    /// Check if subdomain is non-existent (all of A, AAAA, MX return NxDomain).
    async fn check_nonexistent_subdomain(&self, domain_name: &str) -> bool {
        let (a_result, aaaa_result, mx_result) = tokio::join!(
            self.resolver.query_a(domain_name),
            self.resolver.query_aaaa(domain_name),
            self.resolver.query_mx(domain_name),
        );
        matches!(
            (&a_result, &aaaa_result, &mx_result),
            (
                Err(DnsError::NxDomain),
                Err(DnsError::NxDomain),
                Err(DnsError::NxDomain)
            )
        )
    }
}

enum DiscoveryResult {
    Found(DmarcRecord),
    None,
    TempFail(String),
}

fn domains_aligned(d1: &str, d2: &str, mode: AlignmentMode) -> bool {
    match mode {
        AlignmentMode::Strict => domain::domains_equal(d1, d2),
        AlignmentMode::Relaxed => {
            psl::organizational_domain(d1) == psl::organizational_domain(d2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    fn setup_resolver() -> MockResolver {
        let mut r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; adkim=r; aspf=r".to_string()],
        );
        r
    }

    #[tokio::test]
    async fn test_dkim_aligned_pass() {
        let r = setup_resolver();
        let eval = DmarcEvaluator::new(r);
        let dkim = vec![DkimResult::Pass {
            domain: "example.com".to_string(),
            selector: "sel1".to_string(),
            testing: false,
        }];
        let result = eval
            .evaluate("example.com", &SpfResult::Fail { explanation: None }, "", &dkim)
            .await;
        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
    }

    #[tokio::test]
    async fn test_spf_aligned_pass() {
        let r = setup_resolver();
        let eval = DmarcEvaluator::new(r);
        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Pass,
                "example.com",
                &[],
            )
            .await;
        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.spf_aligned);
    }

    #[tokio::test]
    async fn test_spf_softfail_not_aligned() {
        let r = setup_resolver();
        let eval = DmarcEvaluator::new(r);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::SoftFail,
                "example.com",
                &[],
                Some(0),
            )
            .await;
        assert!(!result.spf_aligned);
        assert_eq!(result.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn test_no_record() {
        let r = MockResolver::new();
        let eval = DmarcEvaluator::new(r);
        let result = eval
            .evaluate("norecord.example.com", &SpfResult::Pass, "norecord.example.com", &[])
            .await;
        assert_eq!(result.disposition, Disposition::None);
    }

    #[tokio::test]
    async fn test_dns_tempfail() {
        let mut r = MockResolver::new();
        r.add_txt_tempfail("_dmarc.example.com", "timeout");
        let eval = DmarcEvaluator::new(r);
        let result = eval
            .evaluate("example.com", &SpfResult::Pass, "example.com", &[])
            .await;
        assert_eq!(result.disposition, Disposition::TempFail);
    }

    #[tokio::test]
    async fn test_subdomain_policy() {
        let mut r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; sp=quarantine".to_string()],
        );
        // sub.example.com has no _dmarc record, falls back to org domain
        // sub.example.com exists (has A records)
        r.add_a("sub.example.com", vec!["192.0.2.1".parse().unwrap()]);
        let eval = DmarcEvaluator::new(r);
        let result = eval
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: None },
                "sub.example.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Quarantine);
    }

    #[tokio::test]
    async fn test_np_policy_nonexistent_subdomain() {
        let mut r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=none; sp=quarantine; np=reject".to_string()],
        );
        // nx.example.com is non-existent (A, AAAA, MX all NxDomain)
        r.add_a_nxdomain("nx.example.com");
        r.add_aaaa_nxdomain("nx.example.com");
        r.add_mx_nxdomain("nx.example.com");
        let eval = DmarcEvaluator::new(r);
        let result = eval
            .evaluate_with_roll(
                "nx.example.com",
                &SpfResult::Fail { explanation: None },
                "nx.example.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    #[tokio::test]
    async fn test_pct_sampling_applied() {
        let mut r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=quarantine; pct=50".to_string()],
        );
        let eval = DmarcEvaluator::new(r);

        // Roll 25 < pct 50 → apply policy
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "example.com",
                &[],
                Some(25),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Quarantine);
    }

    #[tokio::test]
    async fn test_pct_sampling_not_applied() {
        let mut r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=quarantine; pct=50".to_string()],
        );
        let eval = DmarcEvaluator::new(r);

        // Roll 75 >= pct 50 → monitoring mode
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "example.com",
                &[],
                Some(75),
            )
            .await;
        assert_eq!(result.disposition, Disposition::None);
    }

    #[tokio::test]
    async fn test_pct_zero_always_monitoring() {
        let mut r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; pct=0".to_string()],
        );
        let eval = DmarcEvaluator::new(r);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "example.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::None);
    }

    #[tokio::test]
    async fn test_relaxed_dkim_alignment_subdomain() {
        let mut r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; adkim=r".to_string()],
        );
        let eval = DmarcEvaluator::new(r);
        let dkim = vec![DkimResult::Pass {
            domain: "sub.example.com".to_string(),
            selector: "sel1".to_string(),
            testing: false,
        }];
        let result = eval
            .evaluate("example.com", &SpfResult::Fail { explanation: None }, "", &dkim)
            .await;
        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
    }

    #[tokio::test]
    async fn test_strict_dkim_alignment_subdomain_fails() {
        let mut r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; adkim=s".to_string()],
        );
        let eval = DmarcEvaluator::new(r);
        let dkim = vec![DkimResult::Pass {
            domain: "sub.example.com".to_string(),
            selector: "sel1".to_string(),
            testing: false,
        }];
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "",
                &dkim,
                Some(0),
            )
            .await;
        assert!(!result.dkim_aligned);
        assert_eq!(result.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn test_org_domain_fallback() {
        let mut r = MockResolver::new();
        // No DMARC at sub.example.com, falls back to _dmarc.example.com
        r.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject".to_string()],
        );
        r.add_a("sub.example.com", vec!["192.0.2.1".parse().unwrap()]);
        let eval = DmarcEvaluator::new(r);
        let result = eval
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: None },
                "sub.example.com",
                &[],
                Some(0),
            )
            .await;
        // Should find the org domain record and apply sp= (which defaults to p=reject)
        assert_eq!(result.disposition, Disposition::Reject);
    }
}
