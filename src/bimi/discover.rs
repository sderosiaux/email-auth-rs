use crate::bimi::record::BimiRecord;
use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain::normalize_domain;
use crate::common::psl::org_domain;
use crate::dmarc::eval::{DmarcResult, Disposition};
use crate::dmarc::record::Policy;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BimiResult {
    /// BIMI record found and validated.
    Pass,
    /// No BIMI record found.
    None,
    /// Validation failure with reason.
    Fail(String),
    /// DNS transient error.
    TempError,
    /// DMARC not eligible for BIMI.
    Skipped,
    /// Domain published a declination record (empty l=).
    Declined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BimiDiscoveryResult {
    pub result: BimiResult,
    pub domain: String,
    pub selector: String,
    pub logo_uri: Option<String>,
    pub authority_uri: Option<String>,
}

// ---------------------------------------------------------------------------
// DMARC eligibility
// ---------------------------------------------------------------------------

/// Check whether a DMARC result meets BIMI requirements.
///
/// BIMI requires:
/// 1. DMARC disposition is Pass
/// 2. A DMARC record exists
/// 3. The published policy is Quarantine or Reject (not None)
/// 4. pct=100 (full enforcement)
pub fn check_dmarc_eligibility(dmarc_result: &DmarcResult) -> bool {
    if dmarc_result.disposition != Disposition::Pass {
        return false;
    }

    let record = match &dmarc_result.record {
        Some(r) => r,
        None => return false,
    };

    if record.percent != 100 {
        return false;
    }

    matches!(record.policy, Policy::Quarantine | Policy::Reject)
}

// ---------------------------------------------------------------------------
// BimiVerifier
// ---------------------------------------------------------------------------

pub struct BimiVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> BimiVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Discover a BIMI record for the given author domain.
    ///
    /// Algorithm:
    /// 1. Check DMARC eligibility
    /// 2. Query `<selector>._bimi.<author_domain>` TXT
    /// 3. If not found and author_domain != org_domain, fallback to org domain
    /// 4. Return discovery result
    pub async fn discover(
        &self,
        author_domain: &str,
        selector: Option<&str>,
        dmarc_result: &DmarcResult,
    ) -> BimiDiscoveryResult {
        let domain = normalize_domain(author_domain);
        let sel = selector.unwrap_or("default").to_string();

        // Step 1: DMARC eligibility gate.
        if !check_dmarc_eligibility(dmarc_result) {
            return BimiDiscoveryResult {
                result: BimiResult::Skipped,
                domain,
                selector: sel,
                logo_uri: None,
                authority_uri: None,
            };
        }

        // Step 2: Query at author domain.
        let query = format!("{}._bimi.{}", sel, domain);
        match self.try_bimi_lookup(&query).await {
            LookupOutcome::Found(record) => {
                return self.make_pass(&domain, &sel, &record);
            }
            LookupOutcome::Declined => {
                return BimiDiscoveryResult {
                    result: BimiResult::Declined,
                    domain,
                    selector: sel,
                    logo_uri: None,
                    authority_uri: None,
                };
            }
            LookupOutcome::TempFail => {
                return BimiDiscoveryResult {
                    result: BimiResult::TempError,
                    domain,
                    selector: sel,
                    logo_uri: None,
                    authority_uri: None,
                };
            }
            LookupOutcome::NotFound => {}
        }

        // Step 3: Fallback to org domain if different.
        let org = org_domain(&domain);
        if domain != org {
            let query = format!("{}._bimi.{}", sel, org);
            match self.try_bimi_lookup(&query).await {
                LookupOutcome::Found(record) => {
                    return self.make_pass(&domain, &sel, &record);
                }
                LookupOutcome::Declined => {
                    return BimiDiscoveryResult {
                        result: BimiResult::Declined,
                        domain,
                        selector: sel,
                        logo_uri: None,
                        authority_uri: None,
                    };
                }
                LookupOutcome::TempFail => {
                    return BimiDiscoveryResult {
                        result: BimiResult::TempError,
                        domain,
                        selector: sel,
                        logo_uri: None,
                        authority_uri: None,
                    };
                }
                LookupOutcome::NotFound => {}
            }
        }

        // Step 4: No record found anywhere.
        BimiDiscoveryResult {
            result: BimiResult::None,
            domain,
            selector: sel,
            logo_uri: None,
            authority_uri: None,
        }
    }

    // -- Internal helpers -----------------------------------------------------

    async fn try_bimi_lookup(&self, query_domain: &str) -> LookupOutcome {
        let txts = match self.resolver.query_txt(query_domain).await {
            Ok(v) => v,
            Err(DnsError::TempFail) => return LookupOutcome::TempFail,
            Err(_) => return LookupOutcome::NotFound,
        };

        for txt in &txts {
            match BimiRecord::parse(txt) {
                Ok(Some(record)) => return LookupOutcome::Found(record),
                Ok(None) => return LookupOutcome::Declined,
                Err(_) => continue,
            }
        }

        LookupOutcome::NotFound
    }

    fn make_pass(
        &self,
        domain: &str,
        selector: &str,
        record: &BimiRecord,
    ) -> BimiDiscoveryResult {
        BimiDiscoveryResult {
            result: BimiResult::Pass,
            domain: domain.to_string(),
            selector: selector.to_string(),
            logo_uri: record.logo_uris.first().cloned(),
            authority_uri: record.authority_uri.clone(),
        }
    }
}

enum LookupOutcome {
    Found(BimiRecord),
    Declined,
    TempFail,
    NotFound,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;
    use crate::dmarc::eval::DmarcResult;
    use crate::dmarc::record::{
        AlignmentMode, DmarcRecord, FailureOption, Policy, ReportFormat,
    };

    // -- Test helpers ---------------------------------------------------------

    fn default_dmarc_record(policy: Policy, percent: u8) -> DmarcRecord {
        DmarcRecord {
            policy,
            subdomain_policy: policy.clone(),
            non_existent_subdomain_policy: None,
            dkim_alignment: AlignmentMode::Relaxed,
            spf_alignment: AlignmentMode::Relaxed,
            percent,
            failure_options: vec![FailureOption::Zero],
            report_format: ReportFormat::Afrf,
            report_interval: 86400,
            rua: vec![],
            ruf: vec![],
        }
    }

    fn passing_dmarc(policy: Policy, percent: u8) -> DmarcResult {
        DmarcResult {
            disposition: Disposition::Pass,
            dkim_aligned: true,
            spf_aligned: false,
            applied_policy: None,
            record: Some(default_dmarc_record(policy, percent)),
        }
    }

    fn add_bimi(resolver: &MockResolver, domain: &str, selector: &str, txt: &str) {
        resolver.add_txt(
            &format!("{}._bimi.{}", selector, domain),
            vec![txt.to_string()],
        );
    }

    fn verifier(resolver: MockResolver) -> BimiVerifier<MockResolver> {
        BimiVerifier::new(resolver)
    }

    // =========================================================================
    // DMARC eligibility tests
    // =========================================================================

    #[tokio::test]
    async fn eligible_pass_quarantine() {
        let dmarc = passing_dmarc(Policy::Quarantine, 100);
        assert!(check_dmarc_eligibility(&dmarc));
    }

    #[tokio::test]
    async fn eligible_pass_reject() {
        let dmarc = passing_dmarc(Policy::Reject, 100);
        assert!(check_dmarc_eligibility(&dmarc));
    }

    #[tokio::test]
    async fn not_eligible_pass_none() {
        let dmarc = passing_dmarc(Policy::None, 100);
        assert!(!check_dmarc_eligibility(&dmarc));
    }

    #[tokio::test]
    async fn not_eligible_fail() {
        let dmarc = DmarcResult {
            disposition: Disposition::Reject,
            dkim_aligned: false,
            spf_aligned: false,
            applied_policy: Some(Policy::Reject),
            record: Some(default_dmarc_record(Policy::Reject, 100)),
        };
        assert!(!check_dmarc_eligibility(&dmarc));
    }

    #[tokio::test]
    async fn not_eligible_pct_not_100() {
        let dmarc = passing_dmarc(Policy::Reject, 50);
        assert!(!check_dmarc_eligibility(&dmarc));
    }

    #[tokio::test]
    async fn not_eligible_no_record() {
        let dmarc = DmarcResult {
            disposition: Disposition::Pass,
            dkim_aligned: true,
            spf_aligned: false,
            applied_policy: None,
            record: None,
        };
        assert!(!check_dmarc_eligibility(&dmarc));
    }

    // =========================================================================
    // Discovery tests
    // =========================================================================

    #[tokio::test]
    async fn discover_at_author_domain() {
        let r = MockResolver::new();
        add_bimi(&r, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg;");
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Pass);
        assert_eq!(res.domain, "example.com");
        assert_eq!(res.selector, "default");
        assert_eq!(
            res.logo_uri,
            Some("https://example.com/logo.svg".to_string())
        );
        assert_eq!(res.authority_uri, None);
    }

    #[tokio::test]
    async fn discover_fallback_to_org_domain() {
        let r = MockResolver::new();
        // No record at sub.example.com, but found at org domain.
        add_bimi(
            &r,
            "example.com",
            "default",
            "v=BIMI1; l=https://example.com/logo.svg;",
        );
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("sub.example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Pass);
        assert_eq!(res.domain, "sub.example.com");
        assert_eq!(
            res.logo_uri,
            Some("https://example.com/logo.svg".to_string())
        );
    }

    #[tokio::test]
    async fn discover_no_record() {
        let r = MockResolver::new();
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::None);
        assert_eq!(res.domain, "example.com");
        assert_eq!(res.logo_uri, None);
    }

    #[tokio::test]
    async fn discover_dns_tempfail() {
        let r = MockResolver::new();
        r.add_txt_err("default._bimi.example.com", DnsError::TempFail);
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::TempError);
    }

    #[tokio::test]
    async fn discover_dmarc_not_eligible() {
        let r = MockResolver::new();
        add_bimi(&r, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg;");
        let v = verifier(r);
        // p=none -> not eligible
        let dmarc = passing_dmarc(Policy::None, 100);

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Skipped);
        assert_eq!(res.logo_uri, None);
    }

    #[tokio::test]
    async fn discover_declination_record() {
        let r = MockResolver::new();
        add_bimi(&r, "example.com", "default", "v=BIMI1; l=;");
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Declined);
        assert_eq!(res.logo_uri, None);
    }

    #[tokio::test]
    async fn discover_custom_selector() {
        let r = MockResolver::new();
        add_bimi(
            &r,
            "example.com",
            "brand",
            "v=BIMI1; l=https://example.com/brand-logo.svg;",
        );
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("example.com", Some("brand"), &dmarc).await;
        assert_eq!(res.result, BimiResult::Pass);
        assert_eq!(res.selector, "brand");
        assert_eq!(
            res.logo_uri,
            Some("https://example.com/brand-logo.svg".to_string())
        );
    }

    #[tokio::test]
    async fn discover_default_selector() {
        let r = MockResolver::new();
        add_bimi(&r, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg;");
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        // None selector -> "default"
        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.selector, "default");
        assert_eq!(res.result, BimiResult::Pass);
    }

    #[tokio::test]
    async fn discover_with_authority_uri() {
        let r = MockResolver::new();
        add_bimi(
            &r,
            "example.com",
            "default",
            "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem;",
        );
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Pass);
        assert_eq!(
            res.logo_uri,
            Some("https://example.com/logo.svg".to_string())
        );
        assert_eq!(
            res.authority_uri,
            Some("https://example.com/vmc.pem".to_string())
        );
    }

    #[tokio::test]
    async fn discover_first_valid_record() {
        let r = MockResolver::new();
        // Multiple TXT records: first is garbage, second is valid BIMI.
        r.add_txt(
            "default._bimi.example.com",
            vec![
                "not a bimi record at all".to_string(),
                "v=BIMI1; l=https://example.com/first.svg;".to_string(),
                "v=BIMI1; l=https://example.com/second.svg;".to_string(),
            ],
        );
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Pass);
        // First valid record wins.
        assert_eq!(
            res.logo_uri,
            Some("https://example.com/first.svg".to_string())
        );
    }

    // =========================================================================
    // Additional edge-case tests
    // =========================================================================

    #[tokio::test]
    async fn discover_tempfail_on_org_fallback() {
        let r = MockResolver::new();
        // Author domain: NxDomain (default). Org domain: TempFail.
        r.add_txt_err("default._bimi.example.com", DnsError::TempFail);
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("sub.example.com", None, &dmarc).await;
        // sub.example.com -> NxDomain (not found), fall through.
        // But wait: the TempFail is on "default._bimi.example.com" which is the
        // org domain fallback query. The author domain query is
        // "default._bimi.sub.example.com" which returns NxDomain (not found).
        // So it falls through to org domain lookup which is TempFail.
        assert_eq!(res.result, BimiResult::TempError);
    }

    #[tokio::test]
    async fn discover_domain_normalization() {
        let r = MockResolver::new();
        add_bimi(&r, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg;");
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        // Uppercase + trailing dot should normalize.
        let res = v.discover("Example.COM.", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Pass);
        assert_eq!(res.domain, "example.com");
    }

    #[tokio::test]
    async fn discover_no_fallback_when_author_is_org() {
        let r = MockResolver::new();
        // No record at all. Since author == org, no fallback happens.
        let v = verifier(r);
        let dmarc = passing_dmarc(Policy::Reject, 100);

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::None);
    }

    #[tokio::test]
    async fn discover_disposition_quarantine_not_eligible() {
        let r = MockResolver::new();
        add_bimi(&r, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg;");
        let v = verifier(r);
        let dmarc = DmarcResult {
            disposition: Disposition::Quarantine,
            dkim_aligned: false,
            spf_aligned: false,
            applied_policy: Some(Policy::Quarantine),
            record: Some(default_dmarc_record(Policy::Quarantine, 100)),
        };

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Skipped);
    }

    #[tokio::test]
    async fn discover_disposition_tempfail_not_eligible() {
        let r = MockResolver::new();
        add_bimi(&r, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg;");
        let v = verifier(r);
        let dmarc = DmarcResult {
            disposition: Disposition::TempFail,
            dkim_aligned: false,
            spf_aligned: false,
            applied_policy: None,
            record: None,
        };

        let res = v.discover("example.com", None, &dmarc).await;
        assert_eq!(res.result, BimiResult::Skipped);
    }
}
