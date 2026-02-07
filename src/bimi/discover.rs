use super::record::BimiRecord;
use super::{BimiResult, BimiValidationResult};
use crate::common::dns::{DnsError, DnsResolver};
use crate::common::{domain, psl};
use crate::dmarc::DmarcResult;

pub struct BimiVerifier<R: DnsResolver> {
    pub resolver: R,
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
        let selector = selector.unwrap_or("default");
        let base = BimiValidationResult {
            result: BimiResult::None,
            domain: author_domain.to_string(),
            selector: selector.to_string(),
            logo_uri: None,
            authority_uri: None,
        };

        // Check DMARC eligibility first
        if !super::check_dmarc_eligibility(dmarc_result) {
            return BimiValidationResult {
                result: BimiResult::Skipped {
                    reason: "DMARC not eligible for BIMI".into(),
                },
                ..base
            };
        }

        // Try author domain
        let bimi_name = format!("{selector}._bimi.{author_domain}");
        match self.query_and_parse(&bimi_name).await {
            Ok(record) => return self.to_result(record, base),
            Err(BimiDiscoveryError::TempFail) => {
                return BimiValidationResult {
                    result: BimiResult::TempError {
                        detail: format!("DNS TempFail for {bimi_name}"),
                    },
                    ..base
                }
            }
            Err(BimiDiscoveryError::NotFound) => {}
            Err(BimiDiscoveryError::ParseError(e)) => {
                return BimiValidationResult {
                    result: BimiResult::Fail {
                        detail: format!("parse error: {e}"),
                    },
                    ..base
                }
            }
        }

        // Fallback to org domain
        let org_domain = psl::organizational_domain(author_domain);
        if domain::domains_equal(author_domain, &org_domain) {
            return base; // Already at org domain
        }

        let org_bimi_name = format!("{selector}._bimi.{org_domain}");
        match self.query_and_parse(&org_bimi_name).await {
            Ok(record) => self.to_result(record, base),
            Err(BimiDiscoveryError::TempFail) => BimiValidationResult {
                result: BimiResult::TempError {
                    detail: format!("DNS TempFail for {org_bimi_name}"),
                },
                ..base
            },
            Err(BimiDiscoveryError::NotFound) => base,
            Err(BimiDiscoveryError::ParseError(e)) => BimiValidationResult {
                result: BimiResult::Fail {
                    detail: format!("parse error: {e}"),
                },
                ..base
            },
        }
    }

    fn to_result(&self, record: BimiRecord, base: BimiValidationResult) -> BimiValidationResult {
        if record.is_declination {
            return BimiValidationResult {
                result: BimiResult::Declined,
                ..base
            };
        }

        BimiValidationResult {
            result: BimiResult::Pass,
            logo_uri: record.logo_uris.first().cloned(),
            authority_uri: record.authority_uri,
            ..base
        }
    }

    async fn query_and_parse(&self, name: &str) -> Result<BimiRecord, BimiDiscoveryError> {
        let txt_records = match self.resolver.query_txt(name).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                return Err(BimiDiscoveryError::NotFound)
            }
            Err(DnsError::TempFail) => return Err(BimiDiscoveryError::TempFail),
        };

        // Filter BIMI records (starting with v=)
        let bimi_records: Vec<&String> = txt_records
            .iter()
            .filter(|r| {
                let lower = r.to_ascii_lowercase();
                lower.starts_with("v=bimi1")
            })
            .collect();

        match bimi_records.len() {
            0 => Err(BimiDiscoveryError::NotFound),
            1 => BimiRecord::parse(bimi_records[0])
                .map_err(|e| BimiDiscoveryError::ParseError(e.to_string())),
            _ => Err(BimiDiscoveryError::ParseError(
                "multiple BIMI records found".into(),
            )),
        }
    }
}

enum BimiDiscoveryError {
    NotFound,
    TempFail,
    ParseError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;
    use crate::dmarc::{AlignmentMode, Disposition, Policy};

    fn eligible_dmarc() -> DmarcResult {
        DmarcResult {
            disposition: Disposition::Pass,
            dkim_aligned: true,
            spf_aligned: true,
            applied_policy: Some(Policy::Reject),
            record: Some(crate::dmarc::DmarcRecord {
                policy: Policy::Reject,
                subdomain_policy: Policy::Reject,
                non_existent_subdomain_policy: None,
                dkim_alignment: AlignmentMode::Relaxed,
                spf_alignment: AlignmentMode::Relaxed,
                percent: 100,
                failure_options: vec![],
                report_format: crate::dmarc::record::ReportFormat::Afrf,
                report_interval: 86400,
                rua: vec![],
                ruf: vec![],
            }),
        }
    }

    #[tokio::test]
    async fn test_discover_record() {
        let resolver = MockResolver::new().with_txt(
            "default._bimi.example.com",
            vec!["v=BIMI1; l=https://example.com/logo.svg"],
        );
        let verifier = BimiVerifier::new(resolver);
        let result = verifier
            .discover("example.com", None, &eligible_dmarc())
            .await;
        assert_eq!(result.result, BimiResult::Pass);
        assert_eq!(result.logo_uri, Some("https://example.com/logo.svg".into()));
    }

    #[tokio::test]
    async fn test_discover_custom_selector() {
        let resolver = MockResolver::new().with_txt(
            "brand._bimi.example.com",
            vec!["v=BIMI1; l=https://example.com/brand.svg"],
        );
        let verifier = BimiVerifier::new(resolver);
        let result = verifier
            .discover("example.com", Some("brand"), &eligible_dmarc())
            .await;
        assert_eq!(result.result, BimiResult::Pass);
        assert_eq!(result.selector, "brand");
    }

    #[tokio::test]
    async fn test_discover_org_domain_fallback() {
        let resolver = MockResolver::new().with_txt(
            "default._bimi.example.com",
            vec!["v=BIMI1; l=https://example.com/logo.svg"],
        );
        let verifier = BimiVerifier::new(resolver);
        let result = verifier
            .discover("sub.example.com", None, &eligible_dmarc())
            .await;
        assert_eq!(result.result, BimiResult::Pass);
    }

    #[tokio::test]
    async fn test_discover_no_record() {
        let resolver = MockResolver::new();
        let verifier = BimiVerifier::new(resolver);
        let result = verifier
            .discover("nodmarc.com", None, &eligible_dmarc())
            .await;
        assert_eq!(result.result, BimiResult::None);
    }

    #[tokio::test]
    async fn test_discover_declination() {
        let resolver = MockResolver::new().with_txt(
            "default._bimi.example.com",
            vec!["v=BIMI1;"],
        );
        let verifier = BimiVerifier::new(resolver);
        let result = verifier
            .discover("example.com", None, &eligible_dmarc())
            .await;
        assert_eq!(result.result, BimiResult::Declined);
    }

    #[tokio::test]
    async fn test_discover_dmarc_not_eligible() {
        let resolver = MockResolver::new().with_txt(
            "default._bimi.example.com",
            vec!["v=BIMI1; l=https://example.com/logo.svg"],
        );
        let verifier = BimiVerifier::new(resolver);
        let dmarc = DmarcResult {
            disposition: Disposition::Pass,
            dkim_aligned: true,
            spf_aligned: true,
            applied_policy: Some(Policy::None), // p=none → not eligible
            record: None,
        };
        let result = verifier.discover("example.com", None, &dmarc).await;
        assert!(matches!(result.result, BimiResult::Skipped { .. }));
    }

    #[tokio::test]
    async fn test_discover_dns_tempfail() {
        let resolver = MockResolver::new()
            .with_txt_err("default._bimi.example.com", DnsError::TempFail);
        let verifier = BimiVerifier::new(resolver);
        let result = verifier
            .discover("example.com", None, &eligible_dmarc())
            .await;
        assert!(matches!(result.result, BimiResult::TempError { .. }));
    }
}
