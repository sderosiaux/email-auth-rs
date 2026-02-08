use std::fmt::Write as FmtWrite;
use std::net::IpAddr;

use crate::common::dns::DnsResolver;
use crate::common::domain;
use crate::dmarc::types::{
    AlignmentMode, FailureOption, Policy,
};

// ─── Aggregate Report Types ─────────────────────────────────────────

/// DMARC aggregate report per RFC 7489 Appendix C.
#[derive(Debug, Clone)]
pub struct AggregateReport {
    /// Reporting organization name.
    pub org_name: String,
    /// Contact email for the reporting organization.
    pub email: String,
    /// Unique report identifier.
    pub report_id: String,
    /// Date range begin (UNIX timestamp).
    pub date_range_begin: u64,
    /// Date range end (UNIX timestamp).
    pub date_range_end: u64,
    /// Published policy details.
    pub policy: PublishedPolicy,
    /// Individual authentication result records.
    pub records: Vec<ReportRecord>,
}

/// Policy published by the domain owner (as discovered).
#[derive(Debug, Clone)]
pub struct PublishedPolicy {
    pub domain: String,
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub policy: Policy,
    pub subdomain_policy: Policy,
    pub percent: u8,
}

/// A single row in the aggregate report.
#[derive(Debug, Clone)]
pub struct ReportRecord {
    pub source_ip: IpAddr,
    pub count: u32,
    pub disposition: ReportDisposition,
    pub dkim_result: ReportAuthResult,
    pub spf_result: ReportAuthResult,
    /// DKIM auth domain (d= from signature).
    pub dkim_domain: Option<String>,
    /// SPF auth domain (MAIL FROM domain).
    pub spf_domain: Option<String>,
    /// Envelope From (MAIL FROM).
    pub envelope_from: Option<String>,
    /// RFC5322.From header domain.
    pub header_from: String,
}

/// Disposition reported in aggregate report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportDisposition {
    None,
    Quarantine,
    Reject,
}

/// Auth result for a single mechanism in reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportAuthResult {
    Pass,
    Fail,
    None,
}

impl AggregateReport {
    /// Serialize to XML matching RFC 7489 Appendix C schema.
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<feedback>\n");

        // Report metadata
        xml.push_str("  <report_metadata>\n");
        write_xml_element(&mut xml, "    ", "org_name", &self.org_name);
        write_xml_element(&mut xml, "    ", "email", &self.email);
        write_xml_element(&mut xml, "    ", "report_id", &self.report_id);
        xml.push_str("    <date_range>\n");
        write_xml_element(&mut xml, "      ", "begin", &self.date_range_begin.to_string());
        write_xml_element(&mut xml, "      ", "end", &self.date_range_end.to_string());
        xml.push_str("    </date_range>\n");
        xml.push_str("  </report_metadata>\n");

        // Policy published
        xml.push_str("  <policy_published>\n");
        write_xml_element(&mut xml, "    ", "domain", &self.policy.domain);
        write_xml_element(&mut xml, "    ", "adkim", alignment_str(self.policy.adkim));
        write_xml_element(&mut xml, "    ", "aspf", alignment_str(self.policy.aspf));
        write_xml_element(&mut xml, "    ", "p", policy_str(self.policy.policy));
        write_xml_element(&mut xml, "    ", "sp", policy_str(self.policy.subdomain_policy));
        write_xml_element(&mut xml, "    ", "pct", &self.policy.percent.to_string());
        xml.push_str("  </policy_published>\n");

        // Records
        for record in &self.records {
            xml.push_str("  <record>\n");
            xml.push_str("    <row>\n");
            write_xml_element(&mut xml, "      ", "source_ip", &record.source_ip.to_string());
            write_xml_element(&mut xml, "      ", "count", &record.count.to_string());
            xml.push_str("      <policy_evaluated>\n");
            write_xml_element(&mut xml, "        ", "disposition", disposition_str(record.disposition));
            xml.push_str("        <dkim>"); xml.push_str(auth_result_str(record.dkim_result)); xml.push_str("</dkim>\n");
            xml.push_str("        <spf>"); xml.push_str(auth_result_str(record.spf_result)); xml.push_str("</spf>\n");
            xml.push_str("      </policy_evaluated>\n");
            xml.push_str("    </row>\n");
            xml.push_str("    <identifiers>\n");
            if let Some(ref ef) = record.envelope_from {
                write_xml_element(&mut xml, "      ", "envelope_from", ef);
            }
            write_xml_element(&mut xml, "      ", "header_from", &record.header_from);
            xml.push_str("    </identifiers>\n");
            xml.push_str("    <auth_results>\n");
            if let Some(ref dd) = record.dkim_domain {
                xml.push_str("      <dkim>\n");
                write_xml_element(&mut xml, "        ", "domain", dd);
                write_xml_element(&mut xml, "        ", "result", auth_result_str(record.dkim_result));
                xml.push_str("      </dkim>\n");
            }
            if let Some(ref sd) = record.spf_domain {
                xml.push_str("      <spf>\n");
                write_xml_element(&mut xml, "        ", "domain", sd);
                write_xml_element(&mut xml, "        ", "result", auth_result_str(record.spf_result));
                xml.push_str("      </spf>\n");
            }
            xml.push_str("    </auth_results>\n");
            xml.push_str("  </record>\n");
        }

        xml.push_str("</feedback>\n");
        xml
    }
}

// ─── AggregateReportBuilder ─────────────────────────────────────────

/// Builder that accumulates auth results and produces an AggregateReport.
pub struct AggregateReportBuilder {
    org_name: String,
    email: String,
    report_id: String,
    date_range_begin: u64,
    date_range_end: u64,
    policy: PublishedPolicy,
    records: Vec<ReportRecord>,
}

impl AggregateReportBuilder {
    pub fn new(
        org_name: impl Into<String>,
        email: impl Into<String>,
        report_id: impl Into<String>,
        date_range_begin: u64,
        date_range_end: u64,
        policy: PublishedPolicy,
    ) -> Self {
        Self {
            org_name: org_name.into(),
            email: email.into(),
            report_id: report_id.into(),
            date_range_begin,
            date_range_end,
            policy,
            records: Vec::new(),
        }
    }

    pub fn add_record(&mut self, record: ReportRecord) {
        self.records.push(record);
    }

    pub fn build(self) -> AggregateReport {
        AggregateReport {
            org_name: self.org_name,
            email: self.email,
            report_id: self.report_id,
            date_range_begin: self.date_range_begin,
            date_range_end: self.date_range_end,
            policy: self.policy,
            records: self.records,
        }
    }
}

// ─── External Report URI Verification ────────────────────────────────

/// Verify that a cross-domain report URI is authorized.
/// If sender domain and target domain differ, queries
/// `<sender-domain>._report._dmarc.<target-domain>` for a TXT record containing "v=DMARC1".
pub async fn verify_external_report_uri<R: DnsResolver>(
    resolver: &R,
    sender_domain: &str,
    report_address: &str,
) -> bool {
    let target_domain = match domain::domain_from_email(report_address) {
        Some(d) => d,
        None => return false,
    };

    let sender_norm = domain::normalize(sender_domain);
    let target_norm = domain::normalize(target_domain);

    // Same domain → no verification needed
    if domain::domains_equal(&sender_norm, &target_norm) {
        return true;
    }

    // Cross-domain → query _report._dmarc
    let query_name = format!("{}._report._dmarc.{}", sender_norm, target_norm);
    let txt_records = match resolver.query_txt(&query_name).await {
        Ok(records) => records,
        Err(_) => return false, // TempFail or NxDomain → drop URI
    };

    // Look for any record starting with "v=DMARC1"
    txt_records.iter().any(|r| {
        let trimmed = r.trim();
        trimmed.eq_ignore_ascii_case("v=DMARC1")
            || trimmed.to_ascii_lowercase().starts_with("v=dmarc1;")
            || trimmed.to_ascii_lowercase().starts_with("v=dmarc1 ")
    })
}

// ─── Failure Report Types ────────────────────────────────────────────

/// DMARC failure report per RFC 6591 (AFRF format).
#[derive(Debug, Clone)]
pub struct FailureReport {
    /// Original message headers (or relevant subset).
    pub original_headers: String,
    /// Authentication failure details.
    pub auth_failure: String,
    /// RFC5322.From domain.
    pub from_domain: String,
    /// Source IP of the message.
    pub source_ip: Option<IpAddr>,
    /// Reporting domain.
    pub reporting_domain: String,
}

impl FailureReport {
    /// Generate AFRF-formatted failure report.
    /// Returns a MIME multipart/report message body.
    pub fn to_afrf(&self) -> String {
        let boundary = "----=_DMARC_AFRF_Boundary";
        let mut out = String::new();
        // MIME headers
        let _ = writeln!(out, "MIME-Version: 1.0");
        let _ = writeln!(out, "Content-Type: multipart/report; report-type=feedback-report; boundary=\"{}\"", boundary);
        let _ = writeln!(out);

        // Part 1: Human-readable description
        let _ = writeln!(out, "--{}", boundary);
        let _ = writeln!(out, "Content-Type: text/plain");
        let _ = writeln!(out);
        let _ = writeln!(out, "DMARC authentication failure report for domain {}", self.from_domain);
        let _ = writeln!(out);

        // Part 2: Machine-readable feedback report
        let _ = writeln!(out, "--{}", boundary);
        let _ = writeln!(out, "Content-Type: message/feedback-report");
        let _ = writeln!(out);
        let _ = writeln!(out, "Feedback-Type: auth-failure");
        let _ = writeln!(out, "User-Agent: email-auth/0.1.0");
        let _ = writeln!(out, "Version: 1");
        let _ = writeln!(out, "Auth-Failure: dmarc");
        let _ = writeln!(out, "Authentication-Results: {}; dmarc=fail", self.reporting_domain);
        let _ = writeln!(out, "Reported-Domain: {}", self.from_domain);
        if let Some(ip) = &self.source_ip {
            let _ = writeln!(out, "Source-IP: {}", ip);
        }
        let _ = writeln!(out);

        // Part 3: Original headers
        let _ = writeln!(out, "--{}", boundary);
        let _ = writeln!(out, "Content-Type: text/rfc822-headers");
        let _ = writeln!(out);
        let _ = write!(out, "{}", self.original_headers);
        if !self.original_headers.ends_with('\n') {
            let _ = writeln!(out);
        }
        let _ = writeln!(out);

        // Closing boundary
        let _ = writeln!(out, "--{}--", boundary);

        out
    }
}

// ─── Failure Option Filtering ────────────────────────────────────────

/// Determine whether a failure report should be generated based on fo= options.
pub fn should_generate_failure_report(
    failure_options: &[FailureOption],
    dkim_aligned: bool,
    spf_aligned: bool,
) -> bool {
    for opt in failure_options {
        match opt {
            FailureOption::Zero => {
                // Report when ALL mechanisms fail (neither DKIM nor SPF aligned)
                if !dkim_aligned && !spf_aligned {
                    return true;
                }
            }
            FailureOption::One => {
                // Report when ANY mechanism fails
                if !dkim_aligned || !spf_aligned {
                    return true;
                }
            }
            FailureOption::D => {
                // Report when DKIM fails
                if !dkim_aligned {
                    return true;
                }
            }
            FailureOption::S => {
                // Report when SPF fails
                if !spf_aligned {
                    return true;
                }
            }
        }
    }
    false
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn write_xml_element(xml: &mut String, indent: &str, tag: &str, value: &str) {
    let _ = write!(xml, "{}<{}>{}</{}>\n", indent, tag, escape_xml(value), tag);
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn alignment_str(mode: AlignmentMode) -> &'static str {
    match mode {
        AlignmentMode::Relaxed => "r",
        AlignmentMode::Strict => "s",
    }
}

fn policy_str(policy: Policy) -> &'static str {
    match policy {
        Policy::None => "none",
        Policy::Quarantine => "quarantine",
        Policy::Reject => "reject",
    }
}

fn disposition_str(d: ReportDisposition) -> &'static str {
    match d {
        ReportDisposition::None => "none",
        ReportDisposition::Quarantine => "quarantine",
        ReportDisposition::Reject => "reject",
    }
}

fn auth_result_str(r: ReportAuthResult) -> &'static str {
    match r {
        ReportAuthResult::Pass => "pass",
        ReportAuthResult::Fail => "fail",
        ReportAuthResult::None => "none",
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;
    use crate::common::dns::DnsError;
    use crate::dmarc::types::FailureOption;

    fn sample_policy() -> PublishedPolicy {
        PublishedPolicy {
            domain: "example.com".to_string(),
            adkim: AlignmentMode::Relaxed,
            aspf: AlignmentMode::Relaxed,
            policy: Policy::Reject,
            subdomain_policy: Policy::Quarantine,
            percent: 100,
        }
    }

    fn sample_record(ip: &str, header_from: &str) -> ReportRecord {
        ReportRecord {
            source_ip: ip.parse().unwrap(),
            count: 1,
            disposition: ReportDisposition::Reject,
            dkim_result: ReportAuthResult::Fail,
            spf_result: ReportAuthResult::Pass,
            dkim_domain: Some("example.com".to_string()),
            spf_domain: Some("example.com".to_string()),
            envelope_from: Some("sender@example.com".to_string()),
            header_from: header_from.to_string(),
        }
    }

    // ─── CHK-733: Build → XML → verify structure ─────────────────────

    #[test]
    fn aggregate_report_xml_structure() {
        let mut builder = AggregateReportBuilder::new(
            "Test Org", "dmarc@test.org", "report-001",
            1700000000, 1700086400, sample_policy(),
        );
        builder.add_record(sample_record("192.0.2.1", "example.com"));
        let report = builder.build();
        let xml = report.to_xml();

        assert!(xml.starts_with("<?xml version=\"1.0\""));
        assert!(xml.contains("<feedback>"));
        assert!(xml.contains("</feedback>"));
        assert!(xml.contains("<report_metadata>"));
        assert!(xml.contains("<policy_published>"));
        assert!(xml.contains("<record>"));
    }

    // ─── CHK-734: Report metadata present ────────────────────────────

    #[test]
    fn aggregate_report_metadata() {
        let builder = AggregateReportBuilder::new(
            "My Org", "admin@org.com", "rpt-42",
            1700000000, 1700086400, sample_policy(),
        );
        let xml = builder.build().to_xml();

        assert!(xml.contains("<org_name>My Org</org_name>"));
        assert!(xml.contains("<email>admin@org.com</email>"));
        assert!(xml.contains("<report_id>rpt-42</report_id>"));
        assert!(xml.contains("<begin>1700000000</begin>"));
        assert!(xml.contains("<end>1700086400</end>"));
    }

    // ─── CHK-735: Policy published fields ────────────────────────────

    #[test]
    fn aggregate_report_policy_published() {
        let builder = AggregateReportBuilder::new(
            "Org", "e@o.com", "r1", 0, 0, sample_policy(),
        );
        let xml = builder.build().to_xml();

        assert!(xml.contains("<domain>example.com</domain>"));
        assert!(xml.contains("<adkim>r</adkim>"));
        assert!(xml.contains("<aspf>r</aspf>"));
        assert!(xml.contains("<p>reject</p>"));
        assert!(xml.contains("<sp>quarantine</sp>"));
        assert!(xml.contains("<pct>100</pct>"));
    }

    // ─── CHK-736: Multiple records ───────────────────────────────────

    #[test]
    fn aggregate_report_multiple_records() {
        let mut builder = AggregateReportBuilder::new(
            "Org", "e@o.com", "r1", 0, 0, sample_policy(),
        );
        builder.add_record(sample_record("192.0.2.1", "a.com"));
        builder.add_record(sample_record("192.0.2.2", "b.com"));
        builder.add_record(sample_record("192.0.2.3", "c.com"));
        let xml = builder.build().to_xml();

        let record_count = xml.matches("<record>").count();
        assert_eq!(record_count, 3);
    }

    // ─── CHK-737: Empty report ───────────────────────────────────────

    #[test]
    fn aggregate_report_empty() {
        let builder = AggregateReportBuilder::new(
            "Org", "e@o.com", "r1", 0, 0, sample_policy(),
        );
        let xml = builder.build().to_xml();

        assert!(xml.contains("<feedback>"));
        assert!(xml.contains("</feedback>"));
        assert!(!xml.contains("<record>"));
    }

    // ─── CHK-738: Same domain, no _report._dmarc query ──────────────

    #[tokio::test]
    async fn external_uri_same_domain() {
        let resolver = MockResolver::new(); // no DNS entries needed
        let result = verify_external_report_uri(
            &resolver, "example.com", "dmarc@example.com",
        ).await;
        assert!(result);
    }

    // ─── CHK-739: Cross-domain authorized ────────────────────────────

    #[tokio::test]
    async fn external_uri_cross_domain_authorized() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "example.com._report._dmarc.thirdparty.com",
            vec!["v=DMARC1".to_string()],
        );
        let result = verify_external_report_uri(
            &resolver, "example.com", "reports@thirdparty.com",
        ).await;
        assert!(result);
    }

    // ─── CHK-740: Cross-domain unauthorized ──────────────────────────

    #[tokio::test]
    async fn external_uri_cross_domain_unauthorized() {
        let resolver = MockResolver::new(); // no authorization record
        let result = verify_external_report_uri(
            &resolver, "example.com", "reports@thirdparty.com",
        ).await;
        assert!(!result);
    }

    // ─── CHK-741: Cross-domain TempFail ──────────────────────────────

    #[tokio::test]
    async fn external_uri_cross_domain_tempfail() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_err(
            "example.com._report._dmarc.thirdparty.com",
            DnsError::TempFail,
        );
        let result = verify_external_report_uri(
            &resolver, "example.com", "reports@thirdparty.com",
        ).await;
        assert!(!result); // Safe default: drop URI
    }

    // ─── CHK-742: AFRF format ────────────────────────────────────────

    #[test]
    fn failure_report_afrf_format() {
        let report = FailureReport {
            original_headers: "From: bad@example.com\r\nSubject: test\r\n".to_string(),
            auth_failure: "dmarc=fail".to_string(),
            from_domain: "example.com".to_string(),
            source_ip: Some("192.0.2.1".parse().unwrap()),
            reporting_domain: "receiver.org".to_string(),
        };
        let afrf = report.to_afrf();

        assert!(afrf.contains("Feedback-Type: auth-failure"));
        assert!(afrf.contains("multipart/report"));
        assert!(afrf.contains("feedback-report"));
        assert!(afrf.contains("Auth-Failure: dmarc"));
        assert!(afrf.contains("Reported-Domain: example.com"));
        assert!(afrf.contains("Source-IP: 192.0.2.1"));
        assert!(afrf.contains("text/rfc822-headers"));
        assert!(afrf.contains("From: bad@example.com"));
    }

    // ─── CHK-743: fo=0 both fail → report ───────────────────────────

    #[test]
    fn fo_0_both_fail_generate() {
        assert!(should_generate_failure_report(
            &[FailureOption::Zero],
            false, false,
        ));
    }

    // ─── CHK-744: fo=0 dkim aligns, spf fails → NO report ───────────

    #[test]
    fn fo_0_dkim_aligns_no_report() {
        assert!(!should_generate_failure_report(
            &[FailureOption::Zero],
            true, false,
        ));
    }

    // ─── CHK-745: fo=1 any fails → report ───────────────────────────

    #[test]
    fn fo_1_any_fails_generate() {
        // DKIM aligns, SPF fails → report (any failed)
        assert!(should_generate_failure_report(
            &[FailureOption::One],
            true, false,
        ));
        // SPF aligns, DKIM fails → report
        assert!(should_generate_failure_report(
            &[FailureOption::One],
            false, true,
        ));
    }

    // ─── CHK-746: fo=d dkim fails → report ──────────────────────────

    #[test]
    fn fo_d_dkim_fails_generate() {
        assert!(should_generate_failure_report(
            &[FailureOption::D],
            false, true, // DKIM fails, SPF aligns
        ));
    }

    // ─── CHK-747: fo=d dkim passes → NO report ──────────────────────

    #[test]
    fn fo_d_dkim_passes_no_report() {
        assert!(!should_generate_failure_report(
            &[FailureOption::D],
            true, false, // DKIM passes, SPF fails
        ));
    }

    // ─── CHK-748: fo=s spf fails → report ───────────────────────────

    #[test]
    fn fo_s_spf_fails_generate() {
        assert!(should_generate_failure_report(
            &[FailureOption::S],
            true, false, // DKIM passes, SPF fails
        ));
    }

    // ─── CHK-749: fo=s spf passes → NO report ───────────────────────

    #[test]
    fn fo_s_spf_passes_no_report() {
        assert!(!should_generate_failure_report(
            &[FailureOption::S],
            false, true, // DKIM fails, SPF passes
        ));
    }

    // ─── Additional: XML escaping ────────────────────────────────────

    #[test]
    fn xml_escaping() {
        let builder = AggregateReportBuilder::new(
            "Org <&>", "e@o.com", "r1", 0, 0, sample_policy(),
        );
        let xml = builder.build().to_xml();
        assert!(xml.contains("<org_name>Org &lt;&amp;&gt;</org_name>"));
    }

    // ─── Additional: fo=0 both align → NO report ─────────────────────

    #[test]
    fn fo_0_both_align_no_report() {
        assert!(!should_generate_failure_report(
            &[FailureOption::Zero],
            true, true,
        ));
    }

    // ─── Additional: fo=1 both align → NO report ─────────────────────

    #[test]
    fn fo_1_both_align_no_report() {
        assert!(!should_generate_failure_report(
            &[FailureOption::One],
            true, true,
        ));
    }

    // ─── Additional: multiple fo options ──────────────────────────────

    #[test]
    fn multiple_fo_options_any_triggers() {
        // fo=0:d — DKIM fails, SPF passes → fo=0 doesn't trigger but fo=d does
        assert!(should_generate_failure_report(
            &[FailureOption::Zero, FailureOption::D],
            false, true,
        ));
    }

    // ─── Additional: verify_external auth record with tags ───────────

    #[tokio::test]
    async fn external_uri_auth_record_with_tags() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "example.com._report._dmarc.thirdparty.com",
            vec!["v=DMARC1; rua=mailto:reports@thirdparty.com".to_string()],
        );
        let result = verify_external_report_uri(
            &resolver, "example.com", "reports@thirdparty.com",
        ).await;
        assert!(result); // v=DMARC1; ... is valid
    }

    // ─── Additional: report record with IPv6 ─────────────────────────

    #[test]
    fn aggregate_report_ipv6_source() {
        let mut builder = AggregateReportBuilder::new(
            "Org", "e@o.com", "r1", 0, 0, sample_policy(),
        );
        builder.add_record(ReportRecord {
            source_ip: "2001:db8::1".parse().unwrap(),
            count: 5,
            disposition: ReportDisposition::None,
            dkim_result: ReportAuthResult::Pass,
            spf_result: ReportAuthResult::Pass,
            dkim_domain: Some("example.com".to_string()),
            spf_domain: Some("example.com".to_string()),
            envelope_from: None,
            header_from: "example.com".to_string(),
        });
        let xml = builder.build().to_xml();
        assert!(xml.contains("<source_ip>2001:db8::1</source_ip>"));
        assert!(xml.contains("<count>5</count>"));
        assert!(xml.contains("<disposition>none</disposition>"));
    }
}
