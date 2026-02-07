use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain;
use crate::common::psl;
use crate::dkim::DkimResult;
use crate::spf::SpfResult;
use super::{AlignmentMode, Disposition, DmarcRecord, DmarcResult, Policy};

/// Evaluate DMARC for a message.
///
/// - `from_domain`: RFC 5322 From domain
/// - `spf_result`: SPF result for MAIL FROM domain
/// - `spf_domain`: MAIL FROM domain (or HELO if no MAIL FROM)
/// - `dkim_results`: All DKIM verification results
pub async fn evaluate<R: DnsResolver>(
    resolver: &R,
    from_domain: &str,
    spf_result: &SpfResult,
    spf_domain: &str,
    dkim_results: &[DkimResult],
) -> DmarcResult {
    // Step 1: Discover DMARC record
    let (record, is_subdomain) = match discover_dmarc(resolver, from_domain).await {
        Ok(r) => r,
        Err(DmarcDiscoveryError::None) => {
            return DmarcResult {
                disposition: Disposition::None,
                dkim_aligned: false,
                spf_aligned: false,
                applied_policy: None,
                record: None,
            };
        }
        Err(DmarcDiscoveryError::TempFail) => {
            return DmarcResult {
                disposition: Disposition::TempFail,
                dkim_aligned: false,
                spf_aligned: false,
                applied_policy: None,
                record: None,
            };
        }
    };

    // Step 2: Check DKIM alignment
    let dkim_aligned = dkim_results.iter().any(|r| {
        if let DkimResult::Pass { domain, .. } = r {
            check_alignment(domain, from_domain, record.dkim_alignment)
        } else {
            false
        }
    });

    // Step 3: Check SPF alignment
    let spf_aligned = matches!(spf_result, SpfResult::Pass)
        && check_alignment(spf_domain, from_domain, record.spf_alignment);

    // Step 4: Determine disposition
    let disposition = if dkim_aligned || spf_aligned {
        Disposition::Pass
    } else {
        // Select applicable policy
        let policy = select_policy(&record, is_subdomain, from_domain, resolver).await;

        // Apply pct sampling
        if record.percent < 100 && policy == Policy::Quarantine {
            let sample: u8 = rand::random::<u8>() % 100;
            if sample >= record.percent {
                // Outside sample: treat as p=none
                Disposition::None
            } else {
                Disposition::Quarantine
            }
        } else {
            match policy {
                Policy::None => Disposition::None,
                Policy::Quarantine => Disposition::Quarantine,
                Policy::Reject => Disposition::Reject,
            }
        }
    };

    let applied_policy = Some(if dkim_aligned || spf_aligned {
        // Pass — report applied policy as the record policy
        record.policy
    } else {
        select_policy_sync(&record, is_subdomain)
    });

    DmarcResult {
        disposition,
        dkim_aligned,
        spf_aligned,
        applied_policy,
        record: Some(record),
    }
}

/// Check if `identifier_domain` aligns with `from_domain` per alignment mode.
fn check_alignment(identifier_domain: &str, from_domain: &str, mode: AlignmentMode) -> bool {
    match mode {
        AlignmentMode::Strict => domain::domains_equal(identifier_domain, from_domain),
        AlignmentMode::Relaxed => psl::relaxed_match(identifier_domain, from_domain),
    }
}

/// Select applicable DMARC policy based on subdomain status.
fn select_policy_sync(record: &DmarcRecord, is_subdomain: bool) -> Policy {
    if is_subdomain {
        record.subdomain_policy
    } else {
        record.policy
    }
}

/// Async version that also checks np= for non-existent subdomains.
async fn select_policy<R: DnsResolver>(
    record: &DmarcRecord,
    is_subdomain: bool,
    from_domain: &str,
    resolver: &R,
) -> Policy {
    if !is_subdomain {
        return record.policy;
    }

    // Check np= for non-existent subdomains
    if let Some(np) = record.non_existent_subdomain_policy {
        // Check if the from_domain has any DNS records
        let exists = match resolver.query_a(from_domain).await {
            Ok(addrs) if !addrs.is_empty() => true,
            _ => match resolver.query_mx(from_domain).await {
                Ok(recs) if !recs.is_empty() => true,
                _ => false,
            },
        };
        if !exists {
            return np;
        }
    }

    record.subdomain_policy
}

enum DmarcDiscoveryError {
    None,
    TempFail,
}

/// DMARC record discovery with org-domain fallback.
/// Returns (record, is_subdomain) where is_subdomain indicates if we fell back.
async fn discover_dmarc<R: DnsResolver>(
    resolver: &R,
    from_domain: &str,
) -> Result<(DmarcRecord, bool), DmarcDiscoveryError> {
    let dmarc_name = format!("_dmarc.{from_domain}");

    // Try exact domain first
    match query_and_parse(resolver, &dmarc_name).await {
        Ok(record) => return Ok((record, false)),
        Err(DiscoveryStep::TempFail) => return Err(DmarcDiscoveryError::TempFail),
        Err(DiscoveryStep::NotFound) => {}
    }

    // Fallback to org domain
    let org_domain = psl::organizational_domain(from_domain);
    if domain::domains_equal(from_domain, &org_domain) {
        // Already at org domain — no fallback possible
        return Err(DmarcDiscoveryError::None);
    }

    let org_dmarc = format!("_dmarc.{org_domain}");
    match query_and_parse(resolver, &org_dmarc).await {
        Ok(record) => Ok((record, true)),
        Err(DiscoveryStep::TempFail) => Err(DmarcDiscoveryError::TempFail),
        Err(DiscoveryStep::NotFound) => Err(DmarcDiscoveryError::None),
    }
}

enum DiscoveryStep {
    NotFound,
    TempFail,
}

async fn query_and_parse<R: DnsResolver>(
    resolver: &R,
    name: &str,
) -> Result<DmarcRecord, DiscoveryStep> {
    let txt_records = match resolver.query_txt(name).await {
        Ok(records) => records,
        Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
            return Err(DiscoveryStep::NotFound)
        }
        Err(DnsError::TempFail) => return Err(DiscoveryStep::TempFail),
    };

    // Filter DMARC records
    let dmarc_records: Vec<&String> = txt_records
        .iter()
        .filter(|r| {
            let lower = r.to_ascii_lowercase();
            lower.starts_with("v=dmarc1")
        })
        .collect();

    match dmarc_records.len() {
        0 => Err(DiscoveryStep::NotFound),
        1 => DmarcRecord::parse(dmarc_records[0])
            .map_err(|_| DiscoveryStep::NotFound),
        _ => Err(DiscoveryStep::NotFound), // Multiple DMARC records → ignore
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    fn fixture_resolver() -> MockResolver {
        MockResolver::new()
            .with_txt(
                "_dmarc.example.com",
                vec!["v=DMARC1; p=reject; adkim=r; aspf=r; pct=100; rua=mailto:dmarc@example.com"],
            )
            .with_txt(
                "_dmarc.monitoring.example.com",
                vec!["v=DMARC1; p=none; rua=mailto:dmarc@example.com"],
            )
            .with_txt(
                "_dmarc.subdomain-policy.example.com",
                vec!["v=DMARC1; p=reject; sp=quarantine; np=reject"],
            )
            .with_txt(
                "_dmarc.pct-test.example.com",
                vec!["v=DMARC1; p=quarantine; pct=50"],
            )
    }

    #[tokio::test]
    async fn test_dkim_pass_alignment() {
        let r = fixture_resolver();
        let dkim_results = vec![DkimResult::Pass {
            domain: "example.com".into(),
            selector: "sel1".into(),
            testing: false,
        }];

        let result = evaluate(
            &r,
            "example.com",
            &SpfResult::Fail { explanation: None },
            "other.com",
            &dkim_results,
        )
        .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.dkim_aligned);
        assert!(!result.spf_aligned);
    }

    #[tokio::test]
    async fn test_spf_pass_alignment() {
        let r = fixture_resolver();
        let result = evaluate(
            &r,
            "example.com",
            &SpfResult::Pass,
            "example.com",
            &[DkimResult::None],
        )
        .await;

        assert_eq!(result.disposition, Disposition::Pass);
        assert!(result.spf_aligned);
    }

    #[tokio::test]
    async fn test_both_fail_reject() {
        let r = fixture_resolver();
        let result = evaluate(
            &r,
            "example.com",
            &SpfResult::Fail { explanation: None },
            "other.com",
            &[DkimResult::None],
        )
        .await;

        assert_eq!(result.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn test_monitoring_mode() {
        let r = fixture_resolver();
        let result = evaluate(
            &r,
            "monitoring.example.com",
            &SpfResult::Fail { explanation: None },
            "other.com",
            &[DkimResult::None],
        )
        .await;

        assert_eq!(result.disposition, Disposition::None);
    }

    #[tokio::test]
    async fn test_org_domain_fallback() {
        let r = fixture_resolver();
        // sub.example.com has no DMARC record → falls back to _dmarc.example.com
        let result = evaluate(
            &r,
            "sub.example.com",
            &SpfResult::Fail { explanation: None },
            "other.com",
            &[DkimResult::None],
        )
        .await;

        // Should use org domain's record (p=reject)
        assert!(result.record.is_some());
        assert_eq!(result.record.unwrap().policy, Policy::Reject);
    }

    #[tokio::test]
    async fn test_no_dmarc_record() {
        let r = MockResolver::new();
        let result = evaluate(
            &r,
            "nodmarc.com",
            &SpfResult::Pass,
            "nodmarc.com",
            &[DkimResult::None],
        )
        .await;

        assert_eq!(result.disposition, Disposition::None);
        assert!(result.record.is_none());
    }

    #[tokio::test]
    async fn test_dns_tempfail() {
        let r = MockResolver::new()
            .with_txt_err("_dmarc.tempfail.com", DnsError::TempFail);
        let result = evaluate(
            &r,
            "tempfail.com",
            &SpfResult::Pass,
            "tempfail.com",
            &[DkimResult::None],
        )
        .await;

        assert_eq!(result.disposition, Disposition::TempFail);
    }

    #[tokio::test]
    async fn test_relaxed_dkim_alignment() {
        let r = fixture_resolver();
        let dkim_results = vec![DkimResult::Pass {
            domain: "mail.example.com".into(),
            selector: "sel1".into(),
            testing: false,
        }];

        let result = evaluate(
            &r,
            "example.com",
            &SpfResult::Fail { explanation: None },
            "other.com",
            &dkim_results,
        )
        .await;

        // Relaxed: mail.example.com aligns with example.com
        assert!(result.dkim_aligned);
        assert_eq!(result.disposition, Disposition::Pass);
    }

    #[tokio::test]
    async fn test_strict_dkim_alignment_fails() {
        let r = MockResolver::new().with_txt(
            "_dmarc.strict.com",
            vec!["v=DMARC1; p=reject; adkim=s"],
        );
        let dkim_results = vec![DkimResult::Pass {
            domain: "mail.strict.com".into(),
            selector: "sel1".into(),
            testing: false,
        }];

        let result = evaluate(
            &r,
            "strict.com",
            &SpfResult::Fail { explanation: None },
            "other.com",
            &dkim_results,
        )
        .await;

        // Strict: mail.strict.com does NOT align with strict.com
        assert!(!result.dkim_aligned);
        assert_eq!(result.disposition, Disposition::Reject);
    }

    #[tokio::test]
    async fn test_spf_pass_but_no_alignment() {
        let r = fixture_resolver();
        let result = evaluate(
            &r,
            "example.com",
            &SpfResult::Pass,
            "other.com", // SPF passes but for different domain
            &[DkimResult::None],
        )
        .await;

        assert!(!result.spf_aligned);
        assert_eq!(result.disposition, Disposition::Reject);
    }
}
