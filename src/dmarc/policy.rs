use rand::Rng;

use crate::common::dns::{DnsError, DnsResolver};
use crate::common::psl::organizational_domain;
use crate::dkim::DkimResult;
use crate::spf::SpfResult;

use super::alignment::domains_aligned;
use super::record::DmarcRecord;
use super::{AlignmentMode, DmarcError, Policy};

/// DMARC verification result
#[derive(Debug, Clone)]
pub struct DmarcResult {
    /// What to do with the message
    pub disposition: Disposition,
    /// Whether DKIM alignment passed
    pub dkim_aligned: bool,
    /// Whether SPF alignment passed
    pub spf_aligned: bool,
    /// The policy that was applied
    pub policy: Policy,
    /// The DMARC record found (if any)
    pub record: Option<DmarcRecord>,
    /// The domain that was queried
    pub domain: String,
}

/// Disposition for the message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Message passed DMARC
    Pass,
    /// Quarantine per policy
    Quarantine,
    /// Reject per policy
    Reject,
    /// No policy (monitoring mode or no record)
    None,
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
        let from_domain_lower = from_domain.to_lowercase();

        // Lookup DMARC record
        let (record, queried_domain) = match self.lookup_record(&from_domain_lower).await {
            Ok(Some((r, d))) => (r, d),
            Ok(None) => {
                return DmarcResult {
                    disposition: Disposition::None,
                    dkim_aligned: false,
                    spf_aligned: false,
                    policy: Policy::None,
                    record: None,
                    domain: from_domain_lower,
                };
            }
            Err(_) => {
                // DNS error - treat as no record for now
                return DmarcResult {
                    disposition: Disposition::None,
                    dkim_aligned: false,
                    spf_aligned: false,
                    policy: Policy::None,
                    record: None,
                    domain: from_domain_lower,
                };
            }
        };

        // Check DKIM alignment
        let dkim_aligned = self.check_dkim_alignment(&from_domain_lower, dkim_results, record.adkim);

        // Check SPF alignment
        let spf_aligned = self.check_spf_alignment(&from_domain_lower, spf_result, spf_domain, record.aspf);

        // Determine pass/fail
        if dkim_aligned || spf_aligned {
            return DmarcResult {
                disposition: Disposition::Pass,
                dkim_aligned,
                spf_aligned,
                policy: record.policy,
                record: Some(record),
                domain: queried_domain,
            };
        }

        // DMARC failed - determine which policy to apply
        let effective_policy = self.determine_policy(&from_domain_lower, &queried_domain, &record).await;

        // Apply pct sampling
        let disposition = if record.pct < 100 {
            let mut rng = rand::rng();
            let sample: u8 = rng.random_range(1..=100);
            if sample <= record.pct {
                self.policy_to_disposition(effective_policy)
            } else {
                // Not sampled, treat as monitoring mode
                Disposition::None
            }
        } else {
            self.policy_to_disposition(effective_policy)
        };

        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            policy: effective_policy,
            record: Some(record),
            domain: queried_domain,
        }
    }

    async fn lookup_record(&self, domain: &str) -> Result<Option<(DmarcRecord, String)>, DmarcError> {
        // First try _dmarc.<domain>
        let query = format!("_dmarc.{}", domain);
        if let Some(record) = self.query_dmarc(&query).await? {
            return Ok(Some((record, domain.to_string())));
        }

        // If not found and domain is not org domain, try org domain
        let org_domain = organizational_domain(domain);
        if org_domain != domain {
            let query = format!("_dmarc.{}", org_domain);
            if let Some(record) = self.query_dmarc(&query).await? {
                return Ok(Some((record, org_domain)));
            }
        }

        Ok(None)
    }

    async fn query_dmarc(&self, query: &str) -> Result<Option<DmarcRecord>, DmarcError> {
        let records = match self.resolver.query_txt(query).await {
            Ok(r) => r,
            Err(DnsError::NxDomain) => return Ok(None),
            Err(e) => return Err(DmarcError::Dns(e.to_string())),
        };

        // Find first valid DMARC record
        for txt in records {
            if txt.trim().to_lowercase().starts_with("v=dmarc1") {
                match DmarcRecord::parse(&txt) {
                    Ok(record) => return Ok(Some(record)),
                    Err(_) => continue, // Try next record
                }
            }
        }

        Ok(None)
    }

    fn check_dkim_alignment(
        &self,
        from_domain: &str,
        dkim_results: &[DkimResult],
        mode: AlignmentMode,
    ) -> bool {
        for result in dkim_results {
            if let DkimResult::Pass { domain, .. } = result {
                if domains_aligned(domain, from_domain, mode) {
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
        mode: AlignmentMode,
    ) -> bool {
        // SPF must pass AND be aligned
        if *spf_result != SpfResult::Pass {
            return false;
        }
        domains_aligned(spf_domain, from_domain, mode)
    }

    async fn determine_policy(
        &self,
        from_domain: &str,
        queried_domain: &str,
        record: &DmarcRecord,
    ) -> Policy {
        // If from_domain == queried_domain, use p=
        if from_domain == queried_domain {
            return record.policy;
        }

        // from_domain is a subdomain of queried_domain
        // Check if it's a non-existent subdomain (RFC 9091)
        if record.nonexistent_policy.is_some() {
            if self.is_nonexistent_subdomain(from_domain).await {
                return record.nonexistent_policy_effective();
            }
        }

        // Use sp= (or p= if no sp=)
        record.subdomain_policy_effective()
    }

    async fn is_nonexistent_subdomain(&self, domain: &str) -> bool {
        // RFC 9091: domain is non-existent if A, AAAA, and MX all return NXDOMAIN or NODATA
        let a_result = self.resolver.query_a(domain).await;
        let aaaa_result = self.resolver.query_aaaa(domain).await;
        let mx_result = self.resolver.query_mx(domain).await;

        let a_empty = matches!(a_result, Ok(ref v) if v.is_empty()) || matches!(a_result, Err(DnsError::NxDomain));
        let aaaa_empty = matches!(aaaa_result, Ok(ref v) if v.is_empty()) || matches!(aaaa_result, Err(DnsError::NxDomain));
        let mx_empty = matches!(mx_result, Ok(ref v) if v.is_empty()) || matches!(mx_result, Err(DnsError::NxDomain));

        a_empty && aaaa_empty && mx_empty
    }

    fn policy_to_disposition(&self, policy: Policy) -> Disposition {
        match policy {
            Policy::None => Disposition::None,
            Policy::Quarantine => Disposition::Quarantine,
            Policy::Reject => Disposition::Reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[tokio::test]
    async fn test_no_dmarc_record() {
        let resolver = MockResolver::new();
        resolver.set_nxdomain("_dmarc.example.com");

        let verifier = DmarcVerifier::new(resolver);
        let result = verifier
            .verify("example.com", &SpfResult::Pass, "example.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::None);
        assert!(result.record.is_none());
    }

    #[tokio::test]
    async fn test_dmarc_pass_spf() {
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
    async fn test_dmarc_pass_dkim() {
        let resolver = MockResolver::new();
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject".to_string()]);

        let dkim_results = vec![DkimResult::Pass {
            domain: "example.com".to_string(),
            selector: "selector".to_string(),
        }];

        let verifier = DmarcVerifier::new(resolver);
        let result = verifier
            .verify("example.com", &SpfResult::Fail, "other.com", &dkim_results)
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
        assert!(!result.spf_aligned);
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
        assert_eq!(result.policy, Policy::Reject);
    }

    #[tokio::test]
    async fn test_org_domain_fallback() {
        let resolver = MockResolver::new();
        resolver.set_nxdomain("_dmarc.mail.example.com");
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=quarantine".to_string()]);

        let verifier = DmarcVerifier::new(resolver);
        let result = verifier
            .verify("mail.example.com", &SpfResult::Fail, "other.com", &[])
            .await;

        // Should find the org domain record
        assert!(result.record.is_some());
    }
}
