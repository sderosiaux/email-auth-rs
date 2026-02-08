use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain::organizational_domain;
use crate::dmarc::types::{DmarcResult, Disposition, Policy};

use super::parser::{is_declination, parse_bimi_record};
use super::types::{BimiRecord, BimiResult, BimiValidationResult};

/// BIMI record discovery and validation.
pub struct BimiVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> BimiVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Discover and parse BIMI record. Does NOT fetch logo or VMC.
    pub async fn discover(
        &self,
        author_domain: &str,
        selector: Option<&str>,
        dmarc_result: &DmarcResult,
    ) -> BimiValidationResult {
        let sel = selector.unwrap_or("default");

        // Step 1: Check DMARC eligibility
        if check_dmarc_ineligible(dmarc_result).is_some() {
            return BimiValidationResult {
                result: BimiResult::Skipped,
                domain: author_domain.to_string(),
                selector: sel.to_string(),
                record: Option::None,
            };
        }

        // Step 2: DNS lookup at author domain
        let query = format!("{}._bimi.{}", sel, author_domain);
        match self.lookup_bimi_record(&query).await {
            Ok(record) => {
                if is_declination(&record) {
                    return BimiValidationResult {
                        result: BimiResult::Declined,
                        domain: author_domain.to_string(),
                        selector: sel.to_string(),
                        record: Some(record),
                    };
                }
                return BimiValidationResult {
                    result: BimiResult::Pass,
                    domain: author_domain.to_string(),
                    selector: sel.to_string(),
                    record: Some(record),
                };
            }
            Err(LookupError::NotFound) => {
                // Fallback to org domain
            }
            Err(LookupError::TempFail) => {
                return BimiValidationResult {
                    result: BimiResult::TempError,
                    domain: author_domain.to_string(),
                    selector: sel.to_string(),
                    record: Option::None,
                };
            }
            Err(LookupError::Fail(reason)) => {
                return BimiValidationResult {
                    result: BimiResult::Fail { reason },
                    domain: author_domain.to_string(),
                    selector: sel.to_string(),
                    record: Option::None,
                };
            }
        }

        // Step 3: Fallback to organizational domain
        let org_domain = organizational_domain(author_domain);
        if org_domain == author_domain {
            // Already at org domain, no fallback
            return BimiValidationResult {
                result: BimiResult::None,
                domain: author_domain.to_string(),
                selector: sel.to_string(),
                record: Option::None,
            };
        }

        let fallback_query = format!("{}._bimi.{}", sel, org_domain);
        match self.lookup_bimi_record(&fallback_query).await {
            Ok(record) => {
                if is_declination(&record) {
                    return BimiValidationResult {
                        result: BimiResult::Declined,
                        domain: org_domain,
                        selector: sel.to_string(),
                        record: Some(record),
                    };
                }
                BimiValidationResult {
                    result: BimiResult::Pass,
                    domain: org_domain,
                    selector: sel.to_string(),
                    record: Some(record),
                }
            }
            Err(LookupError::NotFound) => BimiValidationResult {
                result: BimiResult::None,
                domain: author_domain.to_string(),
                selector: sel.to_string(),
                record: Option::None,
            },
            Err(LookupError::TempFail) => BimiValidationResult {
                result: BimiResult::TempError,
                domain: author_domain.to_string(),
                selector: sel.to_string(),
                record: Option::None,
            },
            Err(LookupError::Fail(reason)) => BimiValidationResult {
                result: BimiResult::Fail { reason },
                domain: author_domain.to_string(),
                selector: sel.to_string(),
                record: Option::None,
            },
        }
    }

    /// Lookup and parse BIMI record from DNS.
    /// Returns exactly one valid record, or error.
    async fn lookup_bimi_record(&self, query: &str) -> Result<BimiRecord, LookupError> {
        let txt_records = match self.resolver.query_txt(query).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                return Err(LookupError::NotFound);
            }
            Err(DnsError::TempFail) => {
                return Err(LookupError::TempFail);
            }
        };

        // Filter records starting with v= and try to parse as BIMI
        let mut valid_records: Vec<BimiRecord> = Vec::new();

        for txt in &txt_records {
            let trimmed = txt.trim();
            // Only consider records that look like BIMI (start with v=)
            if !trimmed.starts_with("v=") && !trimmed.starts_with("V=") {
                continue;
            }

            match parse_bimi_record(trimmed) {
                Ok(record) => valid_records.push(record),
                Err(_) => {
                    // Invalid record silently skipped
                }
            }
        }

        match valid_records.len() {
            0 => Err(LookupError::NotFound),
            1 => Ok(valid_records.into_iter().next().unwrap()),
            n => Err(LookupError::Fail(format!(
                "multiple valid BIMI records ({}) at {}",
                n, query
            ))),
        }
    }
}

enum LookupError {
    NotFound,
    TempFail,
    Fail(String),
}

/// Check if DMARC result makes the message eligible for BIMI.
/// Returns None if eligible, Some(reason) if not.
pub fn check_dmarc_ineligible(result: &DmarcResult) -> Option<String> {
    // Disposition must be Pass
    if result.disposition != Disposition::Pass {
        return Some(format!("DMARC disposition is {:?}, not Pass", result.disposition));
    }

    // Must have alignment
    if !result.dkim_aligned && !result.spf_aligned {
        return Some("neither DKIM nor SPF aligned".into());
    }

    // Check policy from record
    if let Some(ref record) = result.record {
        // Policy must be quarantine or reject
        if record.policy == Policy::None {
            return Some("DMARC policy is none, must be quarantine or reject".into());
        }

        // pct must be 100
        if record.percent != 100 {
            return Some(format!("DMARC pct={}, must be 100", record.percent));
        }
    } else {
        // No DMARC record → not eligible
        return Some("no DMARC record".into());
    }

    Option::None
}

/// Strip sender-inserted BIMI-Location and BIMI-Indicator headers.
/// Returns filtered headers (without BIMI-Location/BIMI-Indicator).
pub fn strip_bimi_headers<'a>(headers: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower != "bimi-location" && lower != "bimi-indicator"
        })
        .copied()
        .collect()
}

/// Generate BIMI-Location header value from validation result.
pub fn format_bimi_location(result: &BimiValidationResult) -> Option<String> {
    if result.result != BimiResult::Pass {
        return Option::None;
    }

    result.record.as_ref().and_then(|r| {
        r.logo_uris.first().map(|uri| uri.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;
    use crate::common::dns::DnsError;
    use crate::dmarc::types::{
        AlignmentMode, DmarcRecord, FailureOption, ReportFormat,
    };

    fn make_dmarc_result(
        disposition: Disposition,
        policy: Policy,
        pct: u8,
        dkim_aligned: bool,
        spf_aligned: bool,
    ) -> DmarcResult {
        DmarcResult {
            disposition,
            dkim_aligned,
            spf_aligned,
            applied_policy: Some(policy),
            record: Some(DmarcRecord {
                policy,
                subdomain_policy: policy,
                non_existent_subdomain_policy: Option::None,
                dkim_alignment: AlignmentMode::Relaxed,
                spf_alignment: AlignmentMode::Relaxed,
                percent: pct,
                failure_options: vec![FailureOption::Zero],
                report_format: ReportFormat::Afrf,
                report_interval: 86400,
                rua: vec![],
                ruf: vec![],
            }),
        }
    }

    fn eligible_dmarc() -> DmarcResult {
        make_dmarc_result(Disposition::Pass, Policy::Quarantine, 100, true, true)
    }

    // ─── CHK-993: DMARC pass + quarantine → eligible ─────────────────

    #[test]
    fn dmarc_quarantine_eligible() {
        let r = make_dmarc_result(Disposition::Pass, Policy::Quarantine, 100, true, false);
        assert!(check_dmarc_ineligible(&r).is_none());
    }

    // ─── CHK-994: DMARC pass + reject → eligible ────────────────────

    #[test]
    fn dmarc_reject_eligible() {
        let r = make_dmarc_result(Disposition::Pass, Policy::Reject, 100, true, false);
        assert!(check_dmarc_ineligible(&r).is_none());
    }

    // ─── CHK-995: DMARC pass + none → NOT eligible ──────────────────

    #[test]
    fn dmarc_none_not_eligible() {
        let r = make_dmarc_result(Disposition::Pass, Policy::None, 100, true, false);
        assert!(check_dmarc_ineligible(&r).is_some());
    }

    // ─── CHK-996: DMARC fail → NOT eligible ──────────────────────────

    #[test]
    fn dmarc_fail_not_eligible() {
        let r = make_dmarc_result(Disposition::Reject, Policy::Reject, 100, false, false);
        assert!(check_dmarc_ineligible(&r).is_some());
    }

    // ─── CHK-997: pct < 100 → NOT eligible ──────────────────────────

    #[test]
    fn dmarc_pct_50_not_eligible() {
        let r = make_dmarc_result(Disposition::Pass, Policy::Quarantine, 50, true, false);
        assert!(check_dmarc_ineligible(&r).is_some());
        assert!(check_dmarc_ineligible(&r).unwrap().contains("pct=50"));
    }

    // ─── CHK-998: pct=100 → eligible ────────────────────────────────

    #[test]
    fn dmarc_pct_100_eligible() {
        let r = make_dmarc_result(Disposition::Pass, Policy::Reject, 100, false, true);
        assert!(check_dmarc_ineligible(&r).is_none());
    }

    // ─── CHK-999: dkim_aligned=true → eligible ──────────────────────

    #[test]
    fn dmarc_dkim_aligned_eligible() {
        let r = make_dmarc_result(Disposition::Pass, Policy::Quarantine, 100, true, false);
        assert!(check_dmarc_ineligible(&r).is_none());
    }

    // ─── CHK-1000: both false → NOT eligible ────────────────────────

    #[test]
    fn dmarc_no_alignment_not_eligible() {
        let r = make_dmarc_result(Disposition::Pass, Policy::Reject, 100, false, false);
        assert!(check_dmarc_ineligible(&r).is_some());
    }

    // ─── CHK-1001: Record at author domain → use it ─────────────────

    #[tokio::test]
    async fn discover_author_domain() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "default._bimi.example.com",
            vec!["v=BIMI1; l=https://example.com/logo.svg;".into()],
        );
        let verifier = BimiVerifier::new(resolver);
        let dmarc = eligible_dmarc();

        let result = verifier.discover("example.com", Option::None, &dmarc).await;
        assert_eq!(result.result, BimiResult::Pass);
        assert_eq!(result.domain, "example.com");
        assert!(result.record.is_some());
        assert_eq!(
            result.record.unwrap().logo_uris,
            vec!["https://example.com/logo.svg"]
        );
    }

    // ─── CHK-1002: Fallback to org domain ────────────────────────────

    #[tokio::test]
    async fn discover_fallback_org_domain() {
        let mut resolver = MockResolver::new();
        // No record at author domain, but at org domain
        resolver.add_txt(
            "default._bimi.example.com",
            vec!["v=BIMI1; l=https://example.com/logo.svg;".into()],
        );
        let verifier = BimiVerifier::new(resolver);
        let dmarc = eligible_dmarc();

        let result = verifier
            .discover("mail.example.com", Option::None, &dmarc)
            .await;
        assert_eq!(result.result, BimiResult::Pass);
        assert_eq!(result.domain, "example.com");
    }

    // ─── CHK-1003: No record anywhere → None ────────────────────────

    #[tokio::test]
    async fn discover_no_record_none() {
        let resolver = MockResolver::new();
        let verifier = BimiVerifier::new(resolver);
        let dmarc = eligible_dmarc();

        let result = verifier.discover("example.com", Option::None, &dmarc).await;
        assert_eq!(result.result, BimiResult::None);
    }

    // ─── CHK-1004: DNS TempFail → TempError ─────────────────────────

    #[tokio::test]
    async fn discover_dns_tempfail() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_err("default._bimi.example.com", DnsError::TempFail);
        let verifier = BimiVerifier::new(resolver);
        let dmarc = eligible_dmarc();

        let result = verifier.discover("example.com", Option::None, &dmarc).await;
        assert_eq!(result.result, BimiResult::TempError);
    }

    // ─── CHK-1005: Custom selector ──────────────────────────────────

    #[tokio::test]
    async fn discover_custom_selector() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "brand._bimi.example.com",
            vec!["v=BIMI1; l=https://example.com/brand.svg;".into()],
        );
        let verifier = BimiVerifier::new(resolver);
        let dmarc = eligible_dmarc();

        let result = verifier
            .discover("example.com", Some("brand"), &dmarc)
            .await;
        assert_eq!(result.result, BimiResult::Pass);
        assert_eq!(result.selector, "brand");
    }

    // ─── CHK-1006: Multiple valid records → Fail ────────────────────

    #[tokio::test]
    async fn discover_multiple_valid_fail() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "default._bimi.example.com",
            vec![
                "v=BIMI1; l=https://example.com/logo1.svg;".into(),
                "v=BIMI1; l=https://example.com/logo2.svg;".into(),
            ],
        );
        let verifier = BimiVerifier::new(resolver);
        let dmarc = eligible_dmarc();

        let result = verifier.discover("example.com", Option::None, &dmarc).await;
        assert!(matches!(result.result, BimiResult::Fail { .. }));
    }

    // ─── CHK-1007: One valid + one invalid → use valid ──────────────

    #[tokio::test]
    async fn discover_one_valid_one_invalid() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "default._bimi.example.com",
            vec![
                "v=BIMI1; l=https://example.com/logo.svg;".into(),
                "v=BIMI1; l=http://invalid.com/bad;".into(), // invalid: non-HTTPS
            ],
        );
        let verifier = BimiVerifier::new(resolver);
        let dmarc = eligible_dmarc();

        let result = verifier.discover("example.com", Option::None, &dmarc).await;
        assert_eq!(result.result, BimiResult::Pass);
    }

    // ─── CHK-951/952: Declination record ────────────────────────────

    #[tokio::test]
    async fn discover_declination() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "default._bimi.example.com",
            vec!["v=BIMI1;".into()],
        );
        let verifier = BimiVerifier::new(resolver);
        let dmarc = eligible_dmarc();

        let result = verifier.discover("example.com", Option::None, &dmarc).await;
        assert_eq!(result.result, BimiResult::Declined);
    }

    // ─── CHK-1036/1037/1038: Header removal ─────────────────────────

    #[test]
    fn strip_bimi_location() {
        let headers = vec![
            ("From", "user@example.com"),
            ("BIMI-Location", "https://evil.com/fake.svg"),
            ("Subject", "test"),
        ];
        let filtered = strip_bimi_headers(&headers);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|(n, _)| !n.eq_ignore_ascii_case("bimi-location")));
    }

    #[test]
    fn strip_bimi_indicator() {
        let headers = vec![
            ("From", "user@example.com"),
            ("BIMI-Indicator", "base64data"),
            ("Subject", "test"),
        ];
        let filtered = strip_bimi_headers(&headers);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn strip_no_bimi_noop() {
        let headers = vec![
            ("From", "user@example.com"),
            ("Subject", "test"),
        ];
        let filtered = strip_bimi_headers(&headers);
        assert_eq!(filtered.len(), 2);
    }

    // ─── DMARC eligibility: DMARC not eligible → Skipped ────────────

    #[tokio::test]
    async fn discover_dmarc_not_eligible_skipped() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "default._bimi.example.com",
            vec!["v=BIMI1; l=https://example.com/logo.svg;".into()],
        );
        let verifier = BimiVerifier::new(resolver);
        // Policy=none → not eligible
        let dmarc = make_dmarc_result(Disposition::Pass, Policy::None, 100, true, false);

        let result = verifier.discover("example.com", Option::None, &dmarc).await;
        assert_eq!(result.result, BimiResult::Skipped);
    }

    // ─── format_bimi_location ────────────────────────────────────────

    #[test]
    fn format_location_on_pass() {
        let result = BimiValidationResult {
            result: BimiResult::Pass,
            domain: "example.com".into(),
            selector: "default".into(),
            record: Some(BimiRecord {
                version: "BIMI1".into(),
                logo_uris: vec!["https://example.com/logo.svg".into()],
                authority_uri: Option::None,
            }),
        };
        assert_eq!(
            format_bimi_location(&result),
            Some("https://example.com/logo.svg".into())
        );
    }

    #[test]
    fn format_location_on_fail() {
        let result = BimiValidationResult {
            result: BimiResult::Fail { reason: "test".into() },
            domain: "example.com".into(),
            selector: "default".into(),
            record: Option::None,
        };
        assert_eq!(format_bimi_location(&result), Option::None);
    }
}
