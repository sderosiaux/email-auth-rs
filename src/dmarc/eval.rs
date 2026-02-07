use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain::normalize_domain;
use crate::common::psl::org_domain;
use crate::dkim::signature::DkimResult;
use crate::dmarc::record::{AlignmentMode, DmarcRecord, Policy};
use crate::spf::record::SpfResult;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Pass,
    Quarantine,
    Reject,
    None,
    TempFail,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DmarcResult {
    pub disposition: Disposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub applied_policy: Option<Policy>,
    pub record: Option<DmarcRecord>,
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

pub struct DmarcEvaluator<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> DmarcEvaluator<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub async fn evaluate(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult {
        self.evaluate_with_roll(from_domain, spf_result, spf_domain, dkim_results, Option::None)
            .await
    }

    async fn evaluate_with_roll(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
        roll: Option<u8>,
    ) -> DmarcResult {
        let from_domain = normalize_domain(from_domain);
        let org = org_domain(&from_domain);

        // -- Step 3: Discover DMARC record ------------------------------------
        let record = match self.discover_record(&from_domain, &org).await {
            Discovery::Found(r) => r,
            Discovery::TempFail => {
                return DmarcResult {
                    disposition: Disposition::TempFail,
                    dkim_aligned: false,
                    spf_aligned: false,
                    applied_policy: Option::None,
                    record: Option::None,
                };
            }
            Discovery::NotFound => {
                return DmarcResult {
                    disposition: Disposition::None,
                    dkim_aligned: false,
                    spf_aligned: false,
                    applied_policy: Option::None,
                    record: Option::None,
                };
            }
        };

        // -- Step 4: DKIM alignment -------------------------------------------
        let dkim_aligned = dkim_results.iter().any(|dr| {
            if let DkimResult::Pass { domain, .. } = dr {
                domains_aligned(domain, &from_domain, &record.dkim_alignment)
            } else {
                false
            }
        });

        // -- Step 5: SPF alignment --------------------------------------------
        let spf_aligned = matches!(spf_result, SpfResult::Pass)
            && domains_aligned(spf_domain, &from_domain, &record.spf_alignment);

        // -- Step 6: Pass if either aligned -----------------------------------
        if dkim_aligned || spf_aligned {
            return DmarcResult {
                disposition: Disposition::Pass,
                dkim_aligned,
                spf_aligned,
                applied_policy: Option::None,
                record: Some(record),
            };
        }

        // -- Step 7: DMARC failure — select and apply policy ------------------
        let policy = self.select_policy(&from_domain, &org, &record).await;
        let disposition = apply_pct(&policy, record.percent, roll);

        DmarcResult {
            disposition,
            dkim_aligned: false,
            spf_aligned: false,
            applied_policy: Some(policy),
            record: Some(record),
        }
    }

    // -- Record discovery -----------------------------------------------------

    async fn discover_record(&self, from_domain: &str, org: &str) -> Discovery {
        // Try _dmarc.<from_domain> first.
        match self.try_parse_dmarc(&format!("_dmarc.{}", from_domain)).await {
            Discovery::Found(r) => return Discovery::Found(r),
            Discovery::TempFail => return Discovery::TempFail,
            Discovery::NotFound => {}
        }

        // Fallback to org domain only if from_domain != org.
        if from_domain != org {
            return self.try_parse_dmarc(&format!("_dmarc.{}", org)).await;
        }

        Discovery::NotFound
    }

    async fn try_parse_dmarc(&self, query_domain: &str) -> Discovery {
        let txts = match self.resolver.query_txt(query_domain).await {
            Ok(v) => v,
            Err(DnsError::TempFail) => return Discovery::TempFail,
            Err(_) => return Discovery::NotFound,
        };

        for txt in &txts {
            if let Ok(record) = DmarcRecord::parse(txt) {
                return Discovery::Found(record);
            }
        }

        Discovery::NotFound
    }

    // -- Policy selection -----------------------------------------------------

    async fn select_policy(&self, from_domain: &str, org: &str, record: &DmarcRecord) -> Policy {
        if from_domain == org {
            return record.policy.clone();
        }

        // Subdomain: check np= for non-existent subdomains.
        if record.non_existent_subdomain_policy.is_some()
            && self.is_non_existent(from_domain).await
        {
            return record.non_existent_subdomain_policy.clone().unwrap();
        }

        record.subdomain_policy.clone()
    }

    async fn is_non_existent(&self, domain: &str) -> bool {
        let (a, aaaa, mx) = tokio::join!(
            self.resolver.query_a(domain),
            self.resolver.query_aaaa(domain),
            self.resolver.query_mx(domain),
        );
        matches!(a, Err(DnsError::NxDomain))
            && matches!(aaaa, Err(DnsError::NxDomain))
            && matches!(mx, Err(DnsError::NxDomain))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

enum Discovery {
    Found(DmarcRecord),
    TempFail,
    NotFound,
}

fn domains_aligned(d1: &str, d2: &str, mode: &AlignmentMode) -> bool {
    let n1 = normalize_domain(d1);
    let n2 = normalize_domain(d2);
    match mode {
        AlignmentMode::Strict => n1 == n2,
        AlignmentMode::Relaxed => org_domain(&n1) == org_domain(&n2),
    }
}

fn apply_pct(policy: &Policy, percent: u8, roll: Option<u8>) -> Disposition {
    match policy {
        Policy::None => Disposition::None,
        Policy::Quarantine | Policy::Reject => {
            let r = roll.unwrap_or_else(|| rand::random_range(0u8..100));
            if r < percent {
                match policy {
                    Policy::Quarantine => Disposition::Quarantine,
                    Policy::Reject => Disposition::Reject,
                    _ => unreachable!(),
                }
            } else {
                Disposition::None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;
    use crate::common::dns::DnsError;
    use crate::dkim::signature::DkimResult;
    use crate::dmarc::record::Policy;
    use crate::spf::record::SpfResult;

    // -- Helpers --------------------------------------------------------------

    fn add_dmarc(resolver: &MockResolver, domain: &str, txt: &str) {
        resolver.add_txt(&format!("_dmarc.{}", domain), vec![txt.to_string()]);
    }

    fn dkim_pass(domain: &str) -> DkimResult {
        DkimResult::Pass {
            domain: domain.to_string(),
            selector: "sel".to_string(),
            testing: false,
        }
    }

    fn dkim_fail() -> DkimResult {
        DkimResult::Fail {
            kind: crate::dkim::signature::FailureKind::SignatureVerificationFailed,
            detail: "test".to_string(),
        }
    }

    fn eval(resolver: MockResolver) -> DmarcEvaluator<MockResolver> {
        DmarcEvaluator::new(resolver)
    }

    // =========================================================================
    // Record discovery tests
    // =========================================================================

    #[tokio::test]
    async fn no_dmarc_record_returns_none() {
        let r = MockResolver::new();
        let e = eval(r);
        let res = e.evaluate("example.com", &SpfResult::Pass, "example.com", &[]).await;
        assert_eq!(res.disposition, Disposition::None);
        assert!(!res.dkim_aligned);
        assert!(!res.spf_aligned);
        assert!(res.applied_policy.is_none());
        assert!(res.record.is_none());
    }

    #[tokio::test]
    async fn dns_tempfail_returns_tempfail() {
        let r = MockResolver::new();
        r.add_txt_err("_dmarc.example.com", DnsError::TempFail);
        let e = eval(r);
        let res = e.evaluate("example.com", &SpfResult::Pass, "example.com", &[]).await;
        assert_eq!(res.disposition, Disposition::TempFail);
    }

    #[tokio::test]
    async fn fallback_to_org_domain() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=none;");
        let e = eval(r);
        let res = e
            .evaluate(
                "sub.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
            )
            .await;
        assert_eq!(res.disposition, Disposition::None);
        assert!(res.record.is_some());
    }

    #[tokio::test]
    async fn multiple_txt_records_first_valid_wins() {
        let r = MockResolver::new();
        r.add_txt(
            "_dmarc.example.com",
            vec![
                "not a dmarc record".to_string(),
                "v=DMARC1; p=quarantine;".to_string(),
                "v=DMARC1; p=reject;".to_string(),
            ],
        );
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Quarantine);
        assert_eq!(res.applied_policy, Some(Policy::Quarantine));
    }

    #[tokio::test]
    async fn dns_tempfail_on_org_domain_fallback() {
        let r = MockResolver::new();
        // sub.example.com -> NxDomain (default).
        r.add_txt_err("_dmarc.example.com", DnsError::TempFail);
        let e = eval(r);
        let res = e
            .evaluate("sub.example.com", &SpfResult::Pass, "sub.example.com", &[])
            .await;
        assert_eq!(res.disposition, Disposition::TempFail);
    }

    // =========================================================================
    // Alignment tests
    // =========================================================================

    #[tokio::test]
    async fn dkim_strict_exact_match_passes() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; adkim=s;");
        let e = eval(r);
        let res = e
            .evaluate(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[dkim_pass("example.com")],
            )
            .await;
        assert_eq!(res.disposition, Disposition::Pass);
        assert!(res.dkim_aligned);
        assert!(!res.spf_aligned);
    }

    #[tokio::test]
    async fn dkim_strict_subdomain_fails() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; adkim=s;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[dkim_pass("sub.example.com")],
                Some(0),
            )
            .await;
        assert!(!res.dkim_aligned);
        assert_eq!(res.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn dkim_relaxed_subdomain_passes() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; adkim=r;");
        let e = eval(r);
        let res = e
            .evaluate(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[dkim_pass("sub.example.com")],
            )
            .await;
        assert_eq!(res.disposition, Disposition::Pass);
        assert!(res.dkim_aligned);
    }

    #[tokio::test]
    async fn dkim_relaxed_different_org_fails() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; adkim=r;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[dkim_pass("different.org")],
                Some(0),
            )
            .await;
        assert!(!res.dkim_aligned);
        assert_eq!(res.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn spf_pass_aligned_strict() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; aspf=s;");
        let e = eval(r);
        let res = e
            .evaluate("example.com", &SpfResult::Pass, "example.com", &[])
            .await;
        assert_eq!(res.disposition, Disposition::Pass);
        assert!(res.spf_aligned);
    }

    #[tokio::test]
    async fn spf_pass_aligned_relaxed() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; aspf=r;");
        let e = eval(r);
        let res = e
            .evaluate("example.com", &SpfResult::Pass, "sub.example.com", &[])
            .await;
        assert_eq!(res.disposition, Disposition::Pass);
        assert!(res.spf_aligned);
    }

    #[tokio::test]
    async fn spf_softfail_not_aligned() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; aspf=r;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::SoftFail,
                "example.com",
                &[],
                Some(0),
            )
            .await;
        assert!(!res.spf_aligned);
        assert_eq!(res.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn spf_fail_not_aligned() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; aspf=r;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "example.com",
                &[],
                Some(0),
            )
            .await;
        assert!(!res.spf_aligned);
        assert_eq!(res.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn both_aligned_passes() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject;");
        let e = eval(r);
        let res = e
            .evaluate(
                "example.com",
                &SpfResult::Pass,
                "example.com",
                &[dkim_pass("example.com")],
            )
            .await;
        assert_eq!(res.disposition, Disposition::Pass);
        assert!(res.dkim_aligned);
        assert!(res.spf_aligned);
    }

    #[tokio::test]
    async fn dkim_only_aligned_passes() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject;");
        let e = eval(r);
        let res = e
            .evaluate(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[dkim_pass("example.com")],
            )
            .await;
        assert_eq!(res.disposition, Disposition::Pass);
        assert!(res.dkim_aligned);
        assert!(!res.spf_aligned);
    }

    #[tokio::test]
    async fn spf_only_aligned_passes() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject;");
        let e = eval(r);
        let res = e
            .evaluate("example.com", &SpfResult::Pass, "example.com", &[dkim_fail()])
            .await;
        assert_eq!(res.disposition, Disposition::Pass);
        assert!(!res.dkim_aligned);
        assert!(res.spf_aligned);
    }

    #[tokio::test]
    async fn neither_aligned_fails() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[dkim_fail()],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Reject);
        assert!(!res.dkim_aligned);
        assert!(!res.spf_aligned);
        assert_eq!(res.applied_policy, Some(Policy::Reject));
    }

    // =========================================================================
    // Policy evaluation tests
    // =========================================================================

    #[tokio::test]
    async fn policy_none_monitoring() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=none;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::None);
        assert_eq!(res.applied_policy, Some(Policy::None));
    }

    #[tokio::test]
    async fn policy_quarantine() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=quarantine;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Quarantine);
        assert_eq!(res.applied_policy, Some(Policy::Quarantine));
    }

    #[tokio::test]
    async fn policy_reject() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Reject);
        assert_eq!(res.applied_policy, Some(Policy::Reject));
    }

    #[tokio::test]
    async fn subdomain_policy_sp() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=none; sp=quarantine;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Quarantine);
        assert_eq!(res.applied_policy, Some(Policy::Quarantine));
    }

    #[tokio::test]
    async fn np_tag_non_existent_subdomain() {
        let r = MockResolver::new();
        add_dmarc(
            &r,
            "example.com",
            "v=DMARC1; p=none; sp=quarantine; np=reject;",
        );
        // sub.example.com is non-existent: all queries return NxDomain (MockResolver default).
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Reject);
        assert_eq!(res.applied_policy, Some(Policy::Reject));
    }

    #[tokio::test]
    async fn np_absent_falls_back_to_sp() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=none; sp=quarantine;");
        // sub.example.com non-existent but no np= -> falls back to sp=.
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Quarantine);
        assert_eq!(res.applied_policy, Some(Policy::Quarantine));
    }

    #[tokio::test]
    async fn pct_below_enforces() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=quarantine; pct=50;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(25),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Quarantine);
    }

    #[tokio::test]
    async fn pct_above_monitoring() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=quarantine; pct=50;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(75),
            )
            .await;
        assert_eq!(res.disposition, Disposition::None);
    }

    #[tokio::test]
    async fn pct_zero_always_monitoring() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; pct=0;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::None);
        assert_eq!(res.applied_policy, Some(Policy::Reject));
    }

    #[tokio::test]
    async fn pct_100_always_enforces() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; pct=100;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(99),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn pct_applies_to_reject() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; pct=50;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(75),
            )
            .await;
        assert_eq!(res.disposition, Disposition::None);
        assert_eq!(res.applied_policy, Some(Policy::Reject));
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[tokio::test]
    async fn org_domain_exact_uses_p_not_sp() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; sp=none;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(res.disposition, Disposition::Reject);
        assert_eq!(res.applied_policy, Some(Policy::Reject));
    }

    #[tokio::test]
    async fn multiple_dkim_one_aligns() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject;");
        let e = eval(r);
        let res = e
            .evaluate(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[
                    dkim_fail(),
                    dkim_pass("different.org"),
                    dkim_pass("example.com"),
                ],
            )
            .await;
        assert_eq!(res.disposition, Disposition::Pass);
        assert!(res.dkim_aligned);
    }

    #[tokio::test]
    async fn dkim_pass_not_aligned_plus_spf_fail() {
        let r = MockResolver::new();
        add_dmarc(&r, "example.com", "v=DMARC1; p=reject; adkim=s;");
        let e = eval(r);
        let res = e
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "example.com",
                &[dkim_pass("sub.example.com")],
                Some(0),
            )
            .await;
        assert!(!res.dkim_aligned);
        assert!(!res.spf_aligned);
        assert_eq!(res.disposition, Disposition::Reject);
    }
}
