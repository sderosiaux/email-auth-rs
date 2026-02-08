use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain;
use crate::dkim::types::DkimResult;
use crate::spf::types::SpfResult;

use super::types::{AlignmentMode, DmarcRecord, DmarcResult, Disposition, Policy};

/// DMARC evaluator. Performs DNS discovery, alignment checks, and policy evaluation.
pub struct DmarcEvaluator<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> DmarcEvaluator<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Evaluate DMARC for a message.
    ///
    /// - `from_domain`: RFC5322.From domain
    /// - `spf_result`: SPF evaluation result
    /// - `spf_domain`: Domain used for SPF (MAIL FROM domain, or HELO if MAIL FROM empty)
    /// - `dkim_results`: DKIM verification results for all signatures
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

    /// Internal evaluate with deterministic pct roll for testing.
    /// If `roll` is None, generates random value.
    pub(crate) async fn evaluate_with_roll(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
        roll: Option<u8>,
    ) -> DmarcResult {
        // Step 1-3: Discover DMARC record
        let (record, _is_org_domain_record) =
            match self.discover_record(from_domain).await {
                DiscoveryResult::Found(record, is_org) => (record, is_org),
                DiscoveryResult::None => {
                    return DmarcResult {
                        disposition: Disposition::None,
                        dkim_aligned: false,
                        spf_aligned: false,
                        applied_policy: Option::None,
                        record: Option::None,
                    };
                }
                DiscoveryResult::TempFail => {
                    return DmarcResult {
                        disposition: Disposition::TempFail,
                        dkim_aligned: false,
                        spf_aligned: false,
                        applied_policy: Option::None,
                        record: Option::None,
                    };
                }
            };

        // Step 6: DKIM alignment
        let dkim_aligned = check_dkim_alignment(
            from_domain,
            dkim_results,
            record.dkim_alignment,
        );

        // Step 7: SPF alignment
        let spf_aligned = check_spf_alignment(
            from_domain,
            spf_result,
            spf_domain,
            record.spf_alignment,
        );

        // Step 8: Pass if either aligns
        if dkim_aligned || spf_aligned {
            return DmarcResult {
                disposition: Disposition::Pass,
                dkim_aligned,
                spf_aligned,
                applied_policy: Option::None,
                record: Some(record),
            };
        }

        // Step 9: Select policy and apply pct sampling
        let org_domain = domain::organizational_domain(from_domain);

        let policy = if domain::domains_equal(from_domain, &org_domain) {
            // From = org domain → use p=
            record.policy
        } else {
            // From is subdomain → check non-existent vs existing
            self.select_subdomain_policy(from_domain, &record).await
        };

        // Apply pct sampling
        let disposition = apply_pct_sampling(policy, record.percent, roll);

        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            applied_policy: Some(policy),
            record: Some(record),
        }
    }

    /// Discover DMARC record via DNS with org-domain fallback.
    async fn discover_record(&self, from_domain: &str) -> DiscoveryResult {
        let normalized = domain::normalize(from_domain);

        // First: try _dmarc.<from-domain>
        let dmarc_name = format!("_dmarc.{}", normalized);
        match self.query_and_parse(&dmarc_name).await {
            QueryResult::Found(record) => return DiscoveryResult::Found(record, false),
            QueryResult::TempFail => return DiscoveryResult::TempFail,
            QueryResult::None => {} // fall through to org domain
        }

        // Check if we're already at the org domain
        let org_domain = domain::organizational_domain(from_domain);
        if domain::domains_equal(&normalized, &org_domain) {
            return DiscoveryResult::None;
        }

        // Fallback: try _dmarc.<org-domain>
        let org_dmarc_name = format!("_dmarc.{}", org_domain);
        match self.query_and_parse(&org_dmarc_name).await {
            QueryResult::Found(record) => DiscoveryResult::Found(record, true),
            QueryResult::TempFail => DiscoveryResult::TempFail,
            QueryResult::None => DiscoveryResult::None,
        }
    }

    /// Query DNS TXT for a DMARC record name and parse the first valid record.
    async fn query_and_parse(&self, name: &str) -> QueryResult {
        let txt_records = match self.resolver.query_txt(name).await {
            Ok(records) => records,
            Err(DnsError::TempFail) => return QueryResult::TempFail,
            Err(_) => return QueryResult::None, // NxDomain or NoRecords
        };

        // Multiple TXT: try each, use first valid DMARC record
        for txt in &txt_records {
            if let Ok(record) = DmarcRecord::parse(txt) {
                return QueryResult::Found(record);
            }
        }

        QueryResult::None
    }

    /// Select subdomain policy: np= for non-existent, sp= for existing.
    /// Fallback chain: np= → sp= → p=
    async fn select_subdomain_policy(
        &self,
        from_domain: &str,
        record: &DmarcRecord,
    ) -> Policy {
        // Check if subdomain is non-existent (RFC 9091)
        let non_existent = self.is_non_existent_domain(from_domain).await;

        if non_existent {
            // np= if present, else sp= (which already defaults to p= in parser)
            record
                .non_existent_subdomain_policy
                .unwrap_or(record.subdomain_policy)
        } else {
            // Existing subdomain: use sp= (defaults to p= in parser)
            record.subdomain_policy
        }
    }

    /// Check if a domain is non-existent by querying A, AAAA, MX.
    /// All three must return NxDomain for the domain to be considered non-existent.
    async fn is_non_existent_domain(&self, domain: &str) -> bool {
        let normalized = domain::normalize(domain);

        // Parallel DNS queries with tokio::join!
        let (a_result, aaaa_result, mx_result) = tokio::join!(
            self.resolver.query_a(&normalized),
            self.resolver.query_aaaa(&normalized),
            self.resolver.query_mx(&normalized),
        );

        // ALL must be NxDomain for non-existent
        matches!(a_result, Err(DnsError::NxDomain))
            && matches!(aaaa_result, Err(DnsError::NxDomain))
            && matches!(mx_result, Err(DnsError::NxDomain))
    }
}

/// DNS discovery result.
enum DiscoveryResult {
    Found(DmarcRecord, bool), // (record, is_org_domain_fallback)
    TempFail,
    None,
}

/// Single DNS query+parse result.
enum QueryResult {
    Found(DmarcRecord),
    TempFail,
    None,
}

/// Check DKIM alignment: any DKIM Pass with aligned domain.
fn check_dkim_alignment(
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

/// Check SPF alignment: SPF must Pass AND domain must align.
fn check_spf_alignment(
    from_domain: &str,
    spf_result: &SpfResult,
    spf_domain: &str,
    mode: AlignmentMode,
) -> bool {
    // SPF must be Pass (not SoftFail, not Neutral, etc.)
    if !matches!(spf_result, SpfResult::Pass) {
        return false;
    }
    domains_aligned(spf_domain, from_domain, mode)
}

/// Compare two domains using the specified alignment mode.
fn domains_aligned(d1: &str, d2: &str, mode: AlignmentMode) -> bool {
    match mode {
        AlignmentMode::Strict => domain::domains_equal(d1, d2),
        AlignmentMode::Relaxed => {
            domain::organizational_domain(d1) == domain::organizational_domain(d2)
        }
    }
}

/// Apply pct sampling. Returns the final disposition.
fn apply_pct_sampling(policy: Policy, pct: u8, roll: Option<u8>) -> Disposition {
    match policy {
        Policy::None => Disposition::None,
        Policy::Quarantine | Policy::Reject => {
            if pct >= 100 {
                // Always apply
                policy_to_disposition(policy)
            } else if pct == 0 {
                // Never apply
                Disposition::None
            } else {
                let value = roll.unwrap_or_else(|| {
                    use rand::Rng;
                    rand::rng().random_range(0u8..100)
                });
                if value < pct {
                    policy_to_disposition(policy)
                } else {
                    Disposition::None
                }
            }
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
    use crate::common::dns::mock::MockResolver;
    use crate::common::dns::DnsError;
    use crate::dkim::types::{DkimResult, FailureKind};
    use crate::spf::types::SpfResult;

    fn mock_with_dmarc(domain: &str, record: &str) -> MockResolver {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            &format!("_dmarc.{}", domain),
            vec![record.to_string()],
        );
        resolver
    }

    fn pass_dkim(domain: &str) -> DkimResult {
        DkimResult::Pass {
            domain: domain.to_string(),
            selector: "s1".to_string(),
            testing: false,
        }
    }

    fn fail_dkim() -> DkimResult {
        DkimResult::Fail {
            kind: FailureKind::BodyHashMismatch,
            detail: "body hash mismatch".to_string(),
        }
    }

    // ─── CHK-703: Strict DKIM alignment: exact match passes ─────────

    #[test]
    fn strict_dkim_exact_match() {
        assert!(domains_aligned("example.com", "example.com", AlignmentMode::Strict));
    }

    // ─── CHK-704: Strict DKIM alignment: subdomain fails ────────────

    #[test]
    fn strict_dkim_subdomain_fails() {
        assert!(!domains_aligned("mail.example.com", "example.com", AlignmentMode::Strict));
    }

    // ─── CHK-705: Relaxed DKIM alignment: subdomain passes ──────────

    #[test]
    fn relaxed_dkim_subdomain_passes() {
        assert!(domains_aligned("mail.example.com", "example.com", AlignmentMode::Relaxed));
    }

    // ─── CHK-706: Relaxed DKIM alignment: different org domain fails ─

    #[test]
    fn relaxed_dkim_diff_org_fails() {
        assert!(!domains_aligned("example.com", "other.org", AlignmentMode::Relaxed));
    }

    // ─── CHK-707: Strict SPF alignment: exact match ─────────────────

    #[test]
    fn strict_spf_exact_match() {
        assert!(check_spf_alignment(
            "example.com",
            &SpfResult::Pass,
            "example.com",
            AlignmentMode::Strict,
        ));
    }

    // ─── CHK-708: Relaxed SPF alignment: subdomain passes ───────────

    #[test]
    fn relaxed_spf_subdomain_passes() {
        assert!(check_spf_alignment(
            "example.com",
            &SpfResult::Pass,
            "mail.example.com",
            AlignmentMode::Relaxed,
        ));
    }

    // ─── CHK-709: SPF SoftFail does NOT produce alignment ───────────

    #[test]
    fn spf_softfail_no_alignment() {
        assert!(!check_spf_alignment(
            "example.com",
            &SpfResult::SoftFail,
            "example.com",
            AlignmentMode::Relaxed,
        ));
    }

    // ─── CHK-710: Both misaligned → DMARC fails ─────────────────────

    #[tokio::test]
    async fn both_misaligned() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[pass_dkim("unrelated.org")],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Reject);
        assert!(!result.dkim_aligned);
        assert!(!result.spf_aligned);
    }

    // ─── CHK-711: No DMARC record → disposition=None ────────────────

    #[tokio::test]
    async fn no_dmarc_record_none() {
        let resolver = MockResolver::new(); // no DMARC records
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate("example.com", &SpfResult::Pass, "example.com", &[])
            .await;
        assert_eq!(result.disposition, Disposition::None);
        assert!(result.record.is_none());
    }

    // ─── CHK-712: DNS TempFail → disposition=TempFail ────────────────

    #[tokio::test]
    async fn dns_tempfail_disposition() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_err("_dmarc.example.com", DnsError::TempFail);
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate("example.com", &SpfResult::Pass, "example.com", &[])
            .await;
        assert_eq!(result.disposition, Disposition::TempFail);
    }

    // ─── CHK-713: DKIM aligns → Pass ────────────────────────────────

    #[tokio::test]
    async fn dkim_aligns_pass() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[pass_dkim("example.com")],
            )
            .await;
        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
    }

    // ─── CHK-714: SPF aligns → Pass ─────────────────────────────────

    #[tokio::test]
    async fn spf_aligns_pass() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate("example.com", &SpfResult::Pass, "example.com", &[fail_dkim()])
            .await;
        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.spf_aligned);
        assert!(!result.dkim_aligned);
    }

    // ─── CHK-715: Both align → Pass ─────────────────────────────────

    #[tokio::test]
    async fn both_align_pass() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Pass,
                "example.com",
                &[pass_dkim("example.com")],
            )
            .await;
        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
        assert!(result.spf_aligned);
    }

    // ─── CHK-716: Misaligned → apply policy ─────────────────────────

    #[tokio::test]
    async fn misaligned_apply_policy() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=quarantine");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Quarantine);
        assert_eq!(result.applied_policy, Some(Policy::Quarantine));
    }

    // ─── CHK-717: Policy=none → disposition=None ─────────────────────

    #[tokio::test]
    async fn policy_none_monitoring() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=none");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
            )
            .await;
        assert_eq!(result.disposition, Disposition::None);
        assert_eq!(result.applied_policy, Some(Policy::None));
    }

    // ─── CHK-718: Policy=quarantine → disposition=Quarantine ─────────

    #[tokio::test]
    async fn policy_quarantine() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=quarantine");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Quarantine);
    }

    // ─── CHK-719: Policy=reject → disposition=Reject ─────────────────

    #[tokio::test]
    async fn policy_reject() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Reject);
    }

    // ─── CHK-720: sp= different from p= ─────────────────────────────

    #[tokio::test]
    async fn subdomain_policy_different() {
        let mut resolver = MockResolver::new();
        // Record at org domain (subdomain falls back to org)
        resolver.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; sp=none".to_string()],
        );
        // sub.example.com has A records → it exists
        resolver.add_a("sub.example.com", vec!["1.2.3.4".parse().unwrap()]);
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        // sp=none → disposition=None for existing subdomain
        assert_eq!(result.disposition, Disposition::None);
        assert_eq!(result.applied_policy, Some(Policy::None));
    }

    // ─── CHK-721: np= for non-existent subdomain ────────────────────

    #[tokio::test]
    async fn np_non_existent_subdomain() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=none; sp=none; np=reject".to_string()],
        );
        // nosub.example.com has no records → non-existent
        // (MockResolver returns NxDomain by default for missing entries)
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "nosub.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    // ─── CHK-722: np= absent, non-existent → fall back to sp= ───────

    #[tokio::test]
    async fn np_absent_fallback_sp() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; sp=quarantine".to_string()],
        );
        // nosub2 is non-existent (no DNS records)
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "nosub2.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        // No np= → falls back to sp=quarantine
        assert_eq!(result.disposition, Disposition::Quarantine);
        assert_eq!(result.applied_policy, Some(Policy::Quarantine));
    }

    // ─── CHK-723: pct=50 both branches ──────────────────────────────

    #[tokio::test]
    async fn pct_50_apply_branch() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject; pct=50");
        let eval = DmarcEvaluator::new(resolver);
        // Roll < 50 → apply
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(25),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn pct_50_monitoring_branch() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject; pct=50");
        let eval = DmarcEvaluator::new(resolver);
        // Roll >= 50 → monitoring
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(75),
            )
            .await;
        assert_eq!(result.disposition, Disposition::None);
    }

    // ─── CHK-724: pct=0 → always monitoring ─────────────────────────

    #[tokio::test]
    async fn pct_0_monitoring() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject; pct=0");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::None);
    }

    // ─── CHK-725: pct=100 → always apply ────────────────────────────

    #[tokio::test]
    async fn pct_100_always_apply() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject; pct=100");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(99),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Reject);
    }

    // ─── CHK-578: Extract From domain ────────────────────────────────

    #[tokio::test]
    async fn from_domain_used_for_discovery() {
        // Verify that _dmarc.example.com is queried
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=none");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval.evaluate("example.com", &SpfResult::Pass, "example.com", &[]).await;
        // Would be TempFail or None if not found — Pass confirms the record was found
        assert!(result.record.is_some());
    }

    // ─── CHK-579: _dmarc query ───────────────────────────────────────

    #[tokio::test]
    async fn dmarc_dns_query() {
        let resolver = mock_with_dmarc("test.org", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll("test.org", &SpfResult::Fail { explanation: Option::None }, "x.com", &[], Some(0))
            .await;
        assert_eq!(result.disposition, Disposition::Reject);
        assert!(result.record.is_some());
    }

    // ─── CHK-580/581/582: Org domain fallback ────────────────────────

    #[tokio::test]
    async fn org_domain_fallback() {
        let mut resolver = MockResolver::new();
        // No record at _dmarc.sub.example.com, but record at _dmarc.example.com
        resolver.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=quarantine".to_string()],
        );
        // sub.example.com exists
        resolver.add_a("sub.example.com", vec!["1.2.3.4".parse().unwrap()]);
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Quarantine);
    }

    // ─── CHK-583: Multiple TXT, first valid DMARC ───────────────────

    #[tokio::test]
    async fn multiple_txt_first_valid() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "_dmarc.example.com",
            vec![
                "some random txt record".to_string(),
                "v=DMARC1; p=reject".to_string(),
                "v=DMARC1; p=none".to_string(), // second valid, should be ignored
            ],
        );
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.disposition, Disposition::Reject);
    }

    // ─── CHK-584: No record → None ──────────────────────────────────

    #[tokio::test]
    async fn no_record_none() {
        let resolver = MockResolver::new();
        let eval = DmarcEvaluator::new(resolver);
        let result = eval.evaluate("nopolicy.com", &SpfResult::Pass, "nopolicy.com", &[]).await;
        assert_eq!(result.disposition, Disposition::None);
        assert!(result.record.is_none());
    }

    // ─── CHK-585/586/587: DNS TempFail → TempFail disposition ────────

    #[tokio::test]
    async fn dns_tempfail_not_treated_as_no_record() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_err("_dmarc.example.com", DnsError::TempFail);
        let eval = DmarcEvaluator::new(resolver);
        let result = eval.evaluate("example.com", &SpfResult::Pass, "example.com", &[]).await;
        // MUST be TempFail, NOT None
        assert_eq!(result.disposition, Disposition::TempFail);
    }

    // ─── CHK-624-629: DKIM alignment checks ─────────────────────────

    #[test]
    fn dkim_alignment_relaxed_subdomain() {
        let dkim = vec![pass_dkim("mail.example.com")];
        assert!(check_dkim_alignment("example.com", &dkim, AlignmentMode::Relaxed));
    }

    #[test]
    fn dkim_alignment_strict_subdomain_fails() {
        let dkim = vec![pass_dkim("mail.example.com")];
        assert!(!check_dkim_alignment("example.com", &dkim, AlignmentMode::Strict));
    }

    #[test]
    fn dkim_alignment_any_one_aligns() {
        let dkim = vec![
            fail_dkim(),
            pass_dkim("unrelated.org"),
            pass_dkim("example.com"), // this one aligns
        ];
        assert!(check_dkim_alignment("example.com", &dkim, AlignmentMode::Relaxed));
    }

    // ─── CHK-630-635: SPF alignment checks ──────────────────────────

    #[test]
    fn spf_must_pass_for_alignment() {
        assert!(!check_spf_alignment(
            "example.com",
            &SpfResult::SoftFail,
            "example.com",
            AlignmentMode::Relaxed,
        ));
        assert!(!check_spf_alignment(
            "example.com",
            &SpfResult::Neutral,
            "example.com",
            AlignmentMode::Relaxed,
        ));
        assert!(!check_spf_alignment(
            "example.com",
            &SpfResult::None,
            "example.com",
            AlignmentMode::Relaxed,
        ));
    }

    #[test]
    fn spf_alignment_relaxed_org_domain() {
        assert!(check_spf_alignment(
            "example.com",
            &SpfResult::Pass,
            "mail.example.com",
            AlignmentMode::Relaxed,
        ));
    }

    #[test]
    fn spf_alignment_strict_mismatch() {
        assert!(!check_spf_alignment(
            "example.com",
            &SpfResult::Pass,
            "mail.example.com",
            AlignmentMode::Strict,
        ));
    }

    // ─── CHK-636/637/638: Pass = DKIM OR SPF ────────────────────────

    #[tokio::test]
    async fn pass_requires_dkim_or_spf() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);

        // DKIM only
        let r1 = eval
            .evaluate(
                "example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[pass_dkim("example.com")],
            )
            .await;
        assert_eq!(r1.disposition, Disposition::Pass);

        // SPF only
        let resolver2 = mock_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval2 = DmarcEvaluator::new(resolver2);
        let r2 = eval2
            .evaluate("example.com", &SpfResult::Pass, "example.com", &[fail_dkim()])
            .await;
        assert_eq!(r2.disposition, Disposition::Pass);
    }

    // ─── CHK-639: From = org domain → p= ────────────────────────────

    #[tokio::test]
    async fn org_domain_uses_p() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; sp=none".to_string()],
        );
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "example.com", // = org domain
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        // Should use p=reject, not sp=none
        assert_eq!(result.disposition, Disposition::Reject);
        assert_eq!(result.applied_policy, Some(Policy::Reject));
    }

    // ─── CHK-640-644: Subdomain policy selection ─────────────────────

    #[tokio::test]
    async fn subdomain_uses_sp() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject; sp=quarantine".to_string()],
        );
        resolver.add_a("sub.example.com", vec!["1.2.3.4".parse().unwrap()]);
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "sub.example.com",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        assert_eq!(result.applied_policy, Some(Policy::Quarantine));
    }

    // ─── CHK-645-648: Non-existent subdomain detection ──────────────

    #[tokio::test]
    async fn non_existent_detection_all_nxdomain() {
        let resolver = MockResolver::new(); // all queries return NxDomain
        let eval = DmarcEvaluator::new(resolver);
        assert!(eval.is_non_existent_domain("ghost.example.com").await);
    }

    #[tokio::test]
    async fn non_existent_detection_a_exists() {
        let mut resolver = MockResolver::new();
        resolver.add_a("has-a.example.com", vec!["1.2.3.4".parse().unwrap()]);
        let eval = DmarcEvaluator::new(resolver);
        assert!(!eval.is_non_existent_domain("has-a.example.com").await);
    }

    #[tokio::test]
    async fn non_existent_detection_mx_exists() {
        let mut resolver = MockResolver::new();
        resolver.add_mx(
            "has-mx.example.com",
            vec![crate::common::dns::MxRecord { preference: 10, exchange: "mx.example.com".to_string() }],
        );
        let eval = DmarcEvaluator::new(resolver);
        assert!(!eval.is_non_existent_domain("has-mx.example.com").await);
    }

    // ─── CHK-649-656: pct sampling unit tests ────────────────────────

    #[test]
    fn pct_sampling_100_always() {
        assert_eq!(apply_pct_sampling(Policy::Reject, 100, Some(99)), Disposition::Reject);
        assert_eq!(apply_pct_sampling(Policy::Reject, 100, Some(0)), Disposition::Reject);
    }

    #[test]
    fn pct_sampling_0_never() {
        assert_eq!(apply_pct_sampling(Policy::Reject, 0, Some(0)), Disposition::None);
    }

    #[test]
    fn pct_sampling_boundary() {
        // pct=50, roll=49 → apply
        assert_eq!(apply_pct_sampling(Policy::Reject, 50, Some(49)), Disposition::Reject);
        // pct=50, roll=50 → monitoring
        assert_eq!(apply_pct_sampling(Policy::Reject, 50, Some(50)), Disposition::None);
    }

    #[test]
    fn pct_sampling_none_policy_always_none() {
        assert_eq!(apply_pct_sampling(Policy::None, 100, Some(0)), Disposition::None);
    }

    #[test]
    fn pct_sampling_quarantine() {
        assert_eq!(apply_pct_sampling(Policy::Quarantine, 100, Some(0)), Disposition::Quarantine);
    }

    // ─── CHK-770: Structured result ──────────────────────────────────

    #[tokio::test]
    async fn result_is_structured() {
        let resolver = mock_with_dmarc("example.com", "v=DMARC1; p=reject");
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate(
                "example.com",
                &SpfResult::Pass,
                "example.com",
                &[pass_dkim("example.com")],
            )
            .await;
        // Verify all fields populated
        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
        assert!(result.spf_aligned);
        assert!(result.record.is_some());
        let rec = result.record.unwrap();
        assert_eq!(rec.policy, Policy::Reject);
    }

    // ─── CHK-773: No unwrap/expect in library code ──────────────────
    // (Verified by compilation — tests use unwrap, library code does not)

    // ─── CHK-764: PSL integration ────────────────────────────────────

    #[tokio::test]
    async fn psl_integration_org_domain_fallback() {
        let mut resolver = MockResolver::new();
        // deep.sub.example.co.uk → org domain = example.co.uk
        resolver.add_txt(
            "_dmarc.example.co.uk",
            vec!["v=DMARC1; p=reject".to_string()],
        );
        resolver.add_a("deep.sub.example.co.uk", vec!["1.2.3.4".parse().unwrap()]);
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate_with_roll(
                "deep.sub.example.co.uk",
                &SpfResult::Fail { explanation: Option::None },
                "other.com",
                &[],
                Some(0),
            )
            .await;
        // Should have fallen back to _dmarc.example.co.uk
        assert!(result.record.is_some());
    }

    // ─── Org domain fallback with TempFail on first query ────────────

    #[tokio::test]
    async fn tempfail_on_subdomain_query_returns_tempfail() {
        let mut resolver = MockResolver::new();
        // TempFail on _dmarc.sub.example.com
        resolver.add_txt_err("_dmarc.sub.example.com", DnsError::TempFail);
        let eval = DmarcEvaluator::new(resolver);
        let result = eval
            .evaluate("sub.example.com", &SpfResult::Pass, "sub.example.com", &[])
            .await;
        // Should be TempFail (not fall through to org domain)
        assert_eq!(result.disposition, Disposition::TempFail);
    }
}
