//! DMARC evaluation engine — RFC 7489 + RFC 9091 (np=).
//!
//! Consumes SPF and DKIM results, discovers the DMARC record via DNS,
//! checks identifier alignment, selects the applicable policy, and
//! applies pct= sampling.

use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain;
use crate::common::psl;
use crate::dkim::DkimResult;
use crate::dmarc::record::{AlignmentMode, DmarcRecord, Policy};
use crate::spf::SpfResult;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Final DMARC disposition applied to a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Message passes DMARC.
    Pass,
    /// Policy says quarantine.
    Quarantine,
    /// Policy says reject.
    Reject,
    /// No policy found, or monitoring mode (pct sampling excluded).
    None,
}

/// Structured DMARC evaluation result.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Full DMARC evaluation per RFC 7489 Section 6.6.2.
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

    /// Internal evaluation with optional deterministic pct roll for testing.
    /// `roll` is in 0..100. When `None`, a random value is generated.
    async fn evaluate_with_roll(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
        roll: Option<u8>,
    ) -> DmarcResult {
        let from_norm = domain::normalize(from_domain);
        let org_domain = psl::organizational_domain(&from_norm);

        // Step 1: Discover DMARC record
        let record = match self.discover_record(&from_norm, &org_domain).await {
            Some(r) => r,
            None => {
                return DmarcResult {
                    disposition: Disposition::None,
                    dkim_aligned: false,
                    spf_aligned: false,
                    applied_policy: None,
                    record: None,
                };
            }
        };

        // Step 2: Check alignment
        let dkim_aligned =
            check_dkim_alignment(dkim_results, &from_norm, record.dkim_alignment);
        let spf_aligned =
            check_spf_alignment(spf_result, spf_domain, &from_norm, record.spf_alignment);

        // Step 3: If either alignment passes -> DMARC pass
        if dkim_aligned || spf_aligned {
            return DmarcResult {
                disposition: Disposition::Pass,
                dkim_aligned,
                spf_aligned,
                applied_policy: Some(record.policy),
                record: Some(record),
            };
        }

        // Step 4: DMARC fails — select applicable policy
        let policy = self
            .select_policy(&from_norm, &org_domain, &record)
            .await;

        // Step 5: Apply pct= sampling
        let disposition = apply_pct(policy, record.percent, roll);

        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            applied_policy: Some(policy),
            record: Some(record),
        }
    }

    // -- DNS discovery --------------------------------------------------

    /// Discover the DMARC record for `from_domain`, with org-domain fallback.
    async fn discover_record(
        &self,
        from_domain: &str,
        org_domain: &str,
    ) -> Option<DmarcRecord> {
        // Try _dmarc.<from_domain> first
        if let Some(rec) = self.query_dmarc(from_domain).await {
            return Some(rec);
        }

        // Fallback to org domain if different
        if !domain::domains_equal(from_domain, org_domain) {
            if let Some(rec) = self.query_dmarc(org_domain).await {
                return Some(rec);
            }
        }

        None
    }

    /// Query `_dmarc.<domain>` TXT, parse each record, return first valid.
    async fn query_dmarc(&self, base_domain: &str) -> Option<DmarcRecord> {
        let qname = format!("_dmarc.{base_domain}");
        let txts = match self.resolver.query_txt(&qname).await {
            Ok(v) => v,
            Err(_) => return None,
        };

        txts.iter()
            .filter_map(|txt| DmarcRecord::parse(txt).ok())
            .next()
    }

    // -- Policy selection -----------------------------------------------

    /// Select the applicable policy for a failing message.
    ///
    /// - from_domain == org_domain -> p=
    /// - from_domain is a subdomain:
    ///   - non-existent (NxDomain on A/AAAA/MX) -> np= (fallback sp=, then p=)
    ///   - existing subdomain -> sp= (already defaults to p= in DmarcRecord)
    async fn select_policy(
        &self,
        from_domain: &str,
        org_domain: &str,
        record: &DmarcRecord,
    ) -> Policy {
        if domain::domains_equal(from_domain, org_domain) {
            return record.policy;
        }

        // Subdomain — check if non-existent per RFC 9091
        if self.is_nonexistent_domain(from_domain).await {
            if let Some(np) = record.non_existent_subdomain_policy {
                return np;
            }
            // np absent -> fall back to sp (which already defaults to p in DmarcRecord)
            return record.subdomain_policy;
        }

        // Existing subdomain -> sp=
        record.subdomain_policy
    }

    /// RFC 9091: a domain is "non-existent" if A, AAAA, and MX all return NxDomain.
    async fn is_nonexistent_domain(&self, domain: &str) -> bool {
        let a_nx = matches!(self.resolver.query_a(domain).await, Err(DnsError::NxDomain));
        let aaaa_nx = matches!(
            self.resolver.query_aaaa(domain).await,
            Err(DnsError::NxDomain)
        );
        let mx_nx = matches!(
            self.resolver.query_mx(domain).await,
            Err(DnsError::NxDomain)
        );

        a_nx && aaaa_nx && mx_nx
    }
}

// ---------------------------------------------------------------------------
// Alignment checks (pure functions)
// ---------------------------------------------------------------------------

/// Check DKIM identifier alignment.
/// ANY DkimResult::Pass whose d= domain aligns with the From domain -> aligned.
fn check_dkim_alignment(
    dkim_results: &[DkimResult],
    from_domain: &str,
    mode: AlignmentMode,
) -> bool {
    dkim_results.iter().any(|r| {
        if let DkimResult::Pass { domain, .. } = r {
            is_aligned(domain, from_domain, mode)
        } else {
            false
        }
    })
}

/// Check SPF identifier alignment.
/// SPF must have passed AND spf_domain must align with the From domain.
fn check_spf_alignment(
    spf_result: &SpfResult,
    spf_domain: &str,
    from_domain: &str,
    mode: AlignmentMode,
) -> bool {
    if !matches!(spf_result, SpfResult::Pass) {
        return false;
    }
    is_aligned(spf_domain, from_domain, mode)
}

/// Domain alignment check.
/// - Strict: exact case-insensitive match.
/// - Relaxed: organizational domains match.
fn is_aligned(domain_a: &str, domain_b: &str, mode: AlignmentMode) -> bool {
    match mode {
        AlignmentMode::Strict => domain::domains_equal(domain_a, domain_b),
        AlignmentMode::Relaxed => {
            let org_a = psl::organizational_domain(domain_a);
            let org_b = psl::organizational_domain(domain_b);
            domain::domains_equal(&org_a, &org_b)
        }
    }
}

// ---------------------------------------------------------------------------
// pct= sampling
// ---------------------------------------------------------------------------

/// Apply pct= sampling to the selected policy.
/// Returns `Disposition::None` (monitoring mode) if the message is not sampled.
fn apply_pct(policy: Policy, pct: u8, roll: Option<u8>) -> Disposition {
    let disposition = match policy {
        Policy::None => Disposition::None,
        Policy::Quarantine => Disposition::Quarantine,
        Policy::Reject => Disposition::Reject,
    };

    // Policy::None always results in Disposition::None regardless of pct
    if matches!(policy, Policy::None) {
        return Disposition::None;
    }

    if pct >= 100 {
        return disposition;
    }

    let r = roll.unwrap_or_else(|| {
        use rand::Rng;
        rand::rng().random_range(0u8..100)
    });

    if r < pct {
        disposition
    } else {
        Disposition::None // monitoring mode
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::{MockDnsResponse, MockResolver};

    /// Helper: build a MockResolver with a DMARC record at `_dmarc.<domain>`.
    fn resolver_with_dmarc(domain: &str, record_txt: &str) -> MockResolver {
        let mut r = MockResolver::new();
        r.txt.insert(
            format!("_dmarc.{domain}"),
            MockDnsResponse::Records(vec![record_txt.to_string()]),
        );
        r
    }

    /// Helper: default DKIM pass result for a domain.
    fn dkim_pass(domain: &str) -> DkimResult {
        DkimResult::Pass {
            domain: domain.to_string(),
            selector: "sel".to_string(),
            testing: false,
        }
    }

    // -- Test 1: Pass via DKIM alignment (relaxed) --------------------------

    #[tokio::test]
    async fn pass_via_dkim_alignment_relaxed() {
        // DKIM d=sub.example.com, from=example.com, relaxed -> org domains match
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::None,
                "",
                &[dkim_pass("sub.example.com")],
            )
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
        assert!(!result.spf_aligned);
        assert!(result.record.is_some());
    }

    // -- Test 2: Pass via SPF alignment (strict) ----------------------------

    #[tokio::test]
    async fn pass_via_spf_alignment_strict() {
        let resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=reject; aspf=s");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Pass,
                "example.com",
                &[],
            )
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(!result.dkim_aligned);
        assert!(result.spf_aligned);
    }

    // -- Test 3: Fail -> reject ---------------------------------------------

    #[tokio::test]
    async fn fail_policy_reject() {
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[DkimResult::Fail {
                    reason: "bad".into(),
                }],
                Some(0),
            )
            .await;

        assert_eq!(result.disposition, Disposition::Reject);
        assert!(!result.dkim_aligned);
        assert!(!result.spf_aligned);
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    // -- Test 4: Fail -> quarantine -----------------------------------------

    #[tokio::test]
    async fn fail_policy_quarantine() {
        let resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=quarantine");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(0),
            )
            .await;

        assert_eq!(result.disposition, Disposition::Quarantine);
        assert_eq!(result.applied_policy, Some(Policy::Quarantine));
    }

    // -- Test 5: Fail -> policy none ----------------------------------------

    #[tokio::test]
    async fn fail_policy_none() {
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=none");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(0),
            )
            .await;

        assert_eq!(result.disposition, Disposition::None);
        assert_eq!(result.applied_policy, Some(Policy::None));
    }

    // -- Test 6: Subdomain policy (sp=) -------------------------------------

    #[tokio::test]
    async fn subdomain_policy_sp() {
        // from=sub.example.com, record at _dmarc.example.com with sp=reject
        // sub.example.com must exist (not NxDomain) to use sp=
        let mut resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=none; sp=reject");
        // Make sub.example.com "exist" by returning A records
        resolver.a.insert(
            "sub.example.com".into(),
            MockDnsResponse::Records(vec![std::net::Ipv4Addr::new(1, 2, 3, 4)]),
        );
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(0),
            )
            .await;

        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    // -- Test 7: np= for non-existent subdomain ----------------------------

    #[tokio::test]
    async fn np_policy_nonexistent_subdomain() {
        // from=nx.example.com, all DNS queries -> NxDomain, np=reject
        let resolver = resolver_with_dmarc(
            "example.com",
            "v=DMARC1; p=none; sp=quarantine; np=reject",
        );
        // nx.example.com has no A/AAAA/MX entries in mock -> defaults to NxDomain
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "nx.example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(0),
            )
            .await;

        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    // -- Test 8: np= absent -> fallback to sp= then p= ---------------------

    #[tokio::test]
    async fn np_absent_falls_back_to_sp() {
        // np absent, sp=quarantine, p=none. Non-existent subdomain should use sp.
        let resolver = resolver_with_dmarc(
            "example.com",
            "v=DMARC1; p=none; sp=quarantine",
        );
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "nx.example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(0),
            )
            .await;

        assert_eq!(result.disposition, Disposition::Quarantine);
        assert_eq!(result.applied_policy, Some(Policy::Quarantine));
    }

    #[tokio::test]
    async fn np_and_sp_absent_falls_back_to_p() {
        // Both np and sp absent (sp defaults to p in DmarcRecord).
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "nx.example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(0),
            )
            .await;

        // sp defaults to p=reject when not specified
        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    // -- Test 9: No DMARC record -> None ------------------------------------

    #[tokio::test]
    async fn no_dmarc_record() {
        let resolver = MockResolver::new(); // no records at all
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate("example.com", &SpfResult::Pass, "example.com", &[])
            .await;

        assert_eq!(result.disposition, Disposition::None);
        assert!(!result.dkim_aligned);
        assert!(!result.spf_aligned);
        assert_eq!(result.applied_policy, None);
        assert!(result.record.is_none());
    }

    // -- Test 10: Fallback to org domain ------------------------------------

    #[tokio::test]
    async fn fallback_to_org_domain() {
        // No _dmarc.mail.example.com, but has _dmarc.example.com
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        // SPF pass + aligned so we get Pass disposition
        let result = eval
            .evaluate(
                "mail.example.com",
                &SpfResult::Pass,
                "mail.example.com",
                &[],
            )
            .await;

        assert!(result.record.is_some());
        // SPF relaxed alignment: org(mail.example.com) == org(mail.example.com) -> pass
        assert_eq!(result.disposition, Disposition::Pass);
    }

    // -- Test 11: pct=0 -> monitoring mode ----------------------------------

    #[tokio::test]
    async fn pct_zero_monitoring_mode() {
        let resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=reject; pct=0");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
            )
            .await;

        // pct=0 means no messages sampled -> monitoring mode
        assert_eq!(result.disposition, Disposition::None);
        // The policy is still reject, just not enforced
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    // -- Test 12: Strict vs relaxed alignment difference --------------------

    #[tokio::test]
    async fn strict_alignment_fails_where_relaxed_passes() {
        // Strict DKIM alignment: sub.example.com != example.com
        let resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=reject; adkim=s");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::None,
                "",
                &[dkim_pass("sub.example.com")],
                Some(0),
            )
            .await;

        // Strict: sub.example.com != example.com -> no alignment -> reject
        assert_eq!(result.disposition, Disposition::Reject);
        assert!(!result.dkim_aligned);
    }

    #[tokio::test]
    async fn relaxed_alignment_passes_for_subdomain() {
        // Relaxed (default): org(sub.example.com) == org(example.com) -> aligned
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::None,
                "",
                &[dkim_pass("sub.example.com")],
            )
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
    }

    // -- Test 13: Multiple DKIM signatures, one aligned ---------------------

    #[tokio::test]
    async fn multiple_dkim_one_aligned() {
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        let dkim_results = vec![
            DkimResult::Fail {
                reason: "bad".into(),
            },
            dkim_pass("unrelated.org"),
            dkim_pass("mail.example.com"), // this one aligns (relaxed)
            DkimResult::TempFail {
                reason: "dns".into(),
            },
        ];

        let result = eval
            .evaluate("example.com", &SpfResult::None, "", &dkim_results)
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
    }

    // -- Additional edge cases ----------------------------------------------

    #[tokio::test]
    async fn spf_strict_subdomain_fails() {
        // SPF strict: spf_domain=sub.example.com, from=example.com -> no alignment
        let resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=reject; aspf=s");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Pass,
                "sub.example.com",
                &[],
                Some(0),
            )
            .await;

        assert_eq!(result.disposition, Disposition::Reject);
        assert!(!result.spf_aligned);
    }

    #[tokio::test]
    async fn spf_relaxed_subdomain_passes() {
        // SPF relaxed (default): org(sub.example.com) == org(example.com)
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Pass,
                "sub.example.com",
                &[],
            )
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.spf_aligned);
    }

    #[tokio::test]
    async fn spf_fail_no_alignment_even_if_domain_matches() {
        // SPF must be Pass for alignment — SoftFail doesn't count
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

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
    async fn pct_100_enforces_policy() {
        let resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=quarantine; pct=100");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(99), // even worst roll, pct=100 always enforces
            )
            .await;

        assert_eq!(result.disposition, Disposition::Quarantine);
    }

    #[tokio::test]
    async fn pct_sampling_below_threshold_enforces() {
        // pct=50, roll=30 -> 30 < 50 -> enforced
        let resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=reject; pct=50");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(30),
            )
            .await;

        assert_eq!(result.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn pct_sampling_above_threshold_monitoring() {
        // pct=50, roll=70 -> 70 >= 50 -> monitoring
        let resolver =
            resolver_with_dmarc("example.com", "v=DMARC1; p=reject; pct=50");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: None },
                "other.com",
                &[],
                Some(70),
            )
            .await;

        assert_eq!(result.disposition, Disposition::None);
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    #[tokio::test]
    async fn invalid_dmarc_txt_record_ignored() {
        // First TXT record is garbage, second is valid
        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec![
                "not a dmarc record".to_string(),
                "v=DMARC1; p=reject".to_string(),
            ]),
        );
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Pass,
                "example.com",
                &[],
            )
            .await;

        assert!(result.record.is_some());
        assert_eq!(result.disposition, Disposition::Pass);
    }

    #[tokio::test]
    async fn both_dkim_and_spf_aligned() {
        let resolver = resolver_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Pass,
                "example.com",
                &[dkim_pass("example.com")],
            )
            .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
        assert!(result.spf_aligned);
    }
}
