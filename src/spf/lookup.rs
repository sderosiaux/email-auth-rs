use crate::common::dns::{DnsError, DnsResolver};
use super::types::{SpfRecord, SpfResult};

/// Query DNS TXT records for a domain, filter for SPF, enforce single-record
/// constraint, and parse. Returns the parsed record or an SpfResult error.
///
/// - No TXT record matching `v=spf1` → `Err(SpfResult::None)`
/// - Multiple TXT records matching `v=spf1` → `Err(SpfResult::PermError)`
/// - DNS TempFail → `Err(SpfResult::TempError)`
/// - Parse failure → `Err(SpfResult::PermError)`
pub async fn lookup_spf<R: DnsResolver>(
    resolver: &R,
    domain: &str,
) -> Result<SpfRecord, SpfResult> {
    let txt_records = match resolver.query_txt(domain).await {
        Ok(records) => records,
        Err(DnsError::NxDomain) => return Err(SpfResult::None),
        Err(DnsError::NoRecords) => return Err(SpfResult::None),
        Err(DnsError::TempFail) => return Err(SpfResult::TempError),
    };

    // Filter for SPF records: starts with "v=spf1" followed by space or end-of-string
    let spf_records: Vec<&str> = txt_records
        .iter()
        .map(|s| s.as_str())
        .filter(|s| is_spf_record(s))
        .collect();

    match spf_records.len() {
        0 => Err(SpfResult::None),
        1 => SpfRecord::parse(spf_records[0]).map_err(|_| SpfResult::PermError),
        _ => Err(SpfResult::PermError), // Multiple SPF records
    }
}

/// Check if a TXT record is an SPF record (case-insensitive v=spf1 prefix).
fn is_spf_record(txt: &str) -> bool {
    let lower = txt.to_ascii_lowercase();
    lower == "v=spf1" || lower.starts_with("v=spf1 ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;

    // CHK-038: Query DNS TXT records for domain
    #[tokio::test]
    async fn lookup_spf_queries_txt_and_parses() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 -all".into()]);
        let record = lookup_spf(&resolver, "example.com").await.unwrap();
        assert_eq!(record.directives.len(), 1);
    }

    // CHK-039: Filter v=spf1 records from TXT results
    #[tokio::test]
    async fn lookup_spf_filters_non_spf_records() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec![
            "google-site-verification=abc123".into(),
            "v=spf1 -all".into(),
            "some other txt record".into(),
        ]);
        let record = lookup_spf(&resolver, "example.com").await.unwrap();
        assert_eq!(record.directives.len(), 1);
    }

    // CHK-040: Multiple TXT records matching v=spf1 → PermError
    #[tokio::test]
    async fn lookup_spf_multiple_spf_records_permerror() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec![
            "v=spf1 +all".into(),
            "v=spf1 -all".into(),
        ]);
        let err = lookup_spf(&resolver, "example.com").await.unwrap_err();
        assert_eq!(err, SpfResult::PermError);
    }

    // CHK-041: No SPF record → None
    #[tokio::test]
    async fn lookup_spf_no_spf_record_none() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["not-spf".into()]);
        let err = lookup_spf(&resolver, "example.com").await.unwrap_err();
        assert_eq!(err, SpfResult::None);
    }

    #[tokio::test]
    async fn lookup_spf_nxdomain_none() {
        let resolver = MockResolver::new();
        let err = lookup_spf(&resolver, "nonexistent.example.com").await.unwrap_err();
        assert_eq!(err, SpfResult::None);
    }

    // CHK-042: DNS TempFail → TempError
    #[tokio::test]
    async fn lookup_spf_tempfail_temperror() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_err("example.com", DnsError::TempFail);
        let err = lookup_spf(&resolver, "example.com").await.unwrap_err();
        assert_eq!(err, SpfResult::TempError);
    }

    // Additional: parse failure → PermError
    #[tokio::test]
    async fn lookup_spf_parse_failure_permerror() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 badmech:foo -all".into()]);
        let err = lookup_spf(&resolver, "example.com").await.unwrap_err();
        assert_eq!(err, SpfResult::PermError);
    }

    // Additional: case-insensitive v=spf1 filtering
    #[tokio::test]
    async fn lookup_spf_case_insensitive_filter() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["V=SPF1 -all".into()]);
        let record = lookup_spf(&resolver, "example.com").await.unwrap();
        assert_eq!(record.directives.len(), 1);
    }

    // Additional: empty TXT records → None
    #[tokio::test]
    async fn lookup_spf_empty_txt_none() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec![]);
        let err = lookup_spf(&resolver, "example.com").await.unwrap_err();
        assert_eq!(err, SpfResult::None);
    }

    // Additional: NoRecords → None
    #[tokio::test]
    async fn lookup_spf_no_records_none() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_err("example.com", DnsError::NoRecords);
        let err = lookup_spf(&resolver, "example.com").await.unwrap_err();
        assert_eq!(err, SpfResult::None);
    }
}
