//! DMARC aggregate and failure reporting (RFC 7489 Appendix C, RFC 6591).
//!
//! Provides structs for building DMARC aggregate reports and AFRF failure
//! reports, plus serialization to XML and MIME feedback-report format.
//! Actual delivery (gzip, email transport) is the caller's responsibility.

use std::io::Cursor;
use std::net::IpAddr;

use quick_xml::events::{BytesDecl, BytesText, Event};
use quick_xml::Writer;

use crate::dmarc::eval::Disposition;
use crate::dmarc::record::{AlignmentMode, Policy};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a DKIM or SPF check expressed in DMARC terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcAuthResult {
    Pass,
    Fail,
    None,
}

/// Metadata block of a DMARC aggregate report.
#[derive(Debug, Clone)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: String,
    pub report_id: String,
    /// Unix timestamp — start of the reporting window.
    pub date_range_begin: u64,
    /// Unix timestamp — end of the reporting window.
    pub date_range_end: u64,
}

/// The policy that was published in DNS during the reporting period.
#[derive(Debug, Clone)]
pub struct PolicyPublished {
    pub domain: String,
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub policy: Policy,
    pub subdomain_policy: Policy,
    pub percent: u8,
}

/// A single row inside the aggregate report — one (source_ip, disposition)
/// tuple with associated authentication results.
#[derive(Debug, Clone)]
pub struct ReportRecord {
    pub source_ip: IpAddr,
    pub count: u32,
    pub disposition: Disposition,
    pub dkim_result: DmarcAuthResult,
    pub spf_result: DmarcAuthResult,
}

/// DMARC aggregate report (RFC 7489 Appendix C).
#[derive(Debug, Clone)]
pub struct AggregateReport {
    pub metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    pub records: Vec<ReportRecord>,
}

/// DMARC failure report in AFRF format (RFC 6591).
#[derive(Debug, Clone)]
pub struct FailureReport {
    pub original_mail_from: String,
    pub arrival_date: String,
    pub source_ip: IpAddr,
    pub reported_domain: String,
    pub authentication_results: String,
    pub original_headers: String,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Incremental builder for [`AggregateReport`].
pub struct AggregateReportBuilder {
    metadata: ReportMetadata,
    policy_published: PolicyPublished,
    records: Vec<ReportRecord>,
}

impl AggregateReportBuilder {
    pub fn new(metadata: ReportMetadata, policy_published: PolicyPublished) -> Self {
        Self {
            metadata,
            policy_published,
            records: Vec::new(),
        }
    }

    pub fn add_record(&mut self, record: ReportRecord) {
        self.records.push(record);
    }

    pub fn build(self) -> AggregateReport {
        AggregateReport {
            metadata: self.metadata,
            policy_published: self.policy_published,
            records: self.records,
        }
    }
}

// ---------------------------------------------------------------------------
// XML helpers
// ---------------------------------------------------------------------------

fn policy_xml(p: &Policy) -> &'static str {
    match p {
        Policy::None => "none",
        Policy::Quarantine => "quarantine",
        Policy::Reject => "reject",
    }
}

fn alignment_xml(a: &AlignmentMode) -> &'static str {
    match a {
        AlignmentMode::Relaxed => "r",
        AlignmentMode::Strict => "s",
    }
}

fn disposition_xml(d: &Disposition) -> &'static str {
    match d {
        Disposition::Quarantine => "quarantine",
        Disposition::Reject => "reject",
        // Pass, None, TempFail all map to "none" (no action).
        Disposition::Pass | Disposition::None | Disposition::TempFail => "none",
    }
}

fn auth_result_xml(r: &DmarcAuthResult) -> &'static str {
    match r {
        DmarcAuthResult::Pass => "pass",
        DmarcAuthResult::Fail => "fail",
        DmarcAuthResult::None => "none",
    }
}

/// Write a simple `<tag>text</tag>` element via the high-level API.
fn write_text_element<W: std::io::Write>(
    writer: &mut Writer<W>,
    tag: &str,
    text: &str,
) -> std::io::Result<()> {
    writer
        .create_element(tag)
        .write_text_content(BytesText::new(text))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// XML serialization
// ---------------------------------------------------------------------------

impl AggregateReport {
    /// Serialize the report to DMARC aggregate XML (RFC 7489 Appendix C).
    pub fn to_xml(&self) -> Result<String, String> {
        let buf = Cursor::new(Vec::new());
        let mut writer = Writer::new_with_indent(buf, b' ', 2);

        // XML declaration
        writer
            .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
            .map_err(|e| e.to_string())?;

        // <feedback>
        writer
            .create_element("feedback")
            .write_inner_content(|w| {
                // <report_metadata>
                w.create_element("report_metadata")
                    .write_inner_content(|w| {
                        write_text_element(w, "org_name", &self.metadata.org_name)?;
                        write_text_element(w, "email", &self.metadata.email)?;
                        write_text_element(w, "report_id", &self.metadata.report_id)?;
                        w.create_element("date_range").write_inner_content(|w| {
                            write_text_element(
                                w,
                                "begin",
                                &self.metadata.date_range_begin.to_string(),
                            )?;
                            write_text_element(
                                w,
                                "end",
                                &self.metadata.date_range_end.to_string(),
                            )?;
                            Ok(())
                        })?;
                        Ok(())
                    })?;

                // <policy_published>
                w.create_element("policy_published")
                    .write_inner_content(|w| {
                        write_text_element(w, "domain", &self.policy_published.domain)?;
                        write_text_element(
                            w,
                            "adkim",
                            alignment_xml(&self.policy_published.adkim),
                        )?;
                        write_text_element(
                            w,
                            "aspf",
                            alignment_xml(&self.policy_published.aspf),
                        )?;
                        write_text_element(w, "p", policy_xml(&self.policy_published.policy))?;
                        write_text_element(
                            w,
                            "sp",
                            policy_xml(&self.policy_published.subdomain_policy),
                        )?;
                        write_text_element(
                            w,
                            "pct",
                            &self.policy_published.percent.to_string(),
                        )?;
                        Ok(())
                    })?;

                // <record> per row
                for rec in &self.records {
                    w.create_element("record").write_inner_content(|w| {
                        w.create_element("row").write_inner_content(|w| {
                            write_text_element(w, "source_ip", &rec.source_ip.to_string())?;
                            write_text_element(w, "count", &rec.count.to_string())?;
                            w.create_element("policy_evaluated")
                                .write_inner_content(|w| {
                                    write_text_element(
                                        w,
                                        "disposition",
                                        disposition_xml(&rec.disposition),
                                    )?;
                                    write_text_element(
                                        w,
                                        "dkim",
                                        auth_result_xml(&rec.dkim_result),
                                    )?;
                                    write_text_element(
                                        w,
                                        "spf",
                                        auth_result_xml(&rec.spf_result),
                                    )?;
                                    Ok(())
                                })?;
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                }

                Ok(())
            })
            .map_err(|e| e.to_string())?;

        let bytes = writer.into_inner().into_inner();
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// AFRF serialization
// ---------------------------------------------------------------------------

impl FailureReport {
    /// Serialize to AFRF format (RFC 6591 message/feedback-report).
    pub fn to_afrf(&self) -> String {
        format!(
            "Feedback-Type: auth-failure\r\n\
             User-Agent: email-auth/0.1.0\r\n\
             Version: 1\r\n\
             Original-Mail-From: {}\r\n\
             Arrival-Date: {}\r\n\
             Source-IP: {}\r\n\
             Reported-Domain: {}\r\n\
             Authentication-Results: {}\r\n\
             \r\n\
             {}",
            self.original_mail_from,
            self.arrival_date,
            self.source_ip,
            self.reported_domain,
            self.authentication_results,
            self.original_headers,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample_metadata() -> ReportMetadata {
        ReportMetadata {
            org_name: "Test Org".into(),
            email: "admin@example.com".into(),
            report_id: "report-123".into(),
            date_range_begin: 1704067200,
            date_range_end: 1704153600,
        }
    }

    fn sample_policy() -> PolicyPublished {
        PolicyPublished {
            domain: "example.com".into(),
            adkim: AlignmentMode::Relaxed,
            aspf: AlignmentMode::Relaxed,
            policy: Policy::None,
            subdomain_policy: Policy::None,
            percent: 100,
        }
    }

    fn sample_record() -> ReportRecord {
        ReportRecord {
            source_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            count: 5,
            disposition: Disposition::None,
            dkim_result: DmarcAuthResult::Pass,
            spf_result: DmarcAuthResult::Pass,
        }
    }

    // 1. Build report, verify record count.
    #[test]
    fn aggregate_report_builder() {
        let mut builder = AggregateReportBuilder::new(sample_metadata(), sample_policy());
        builder.add_record(sample_record());
        builder.add_record(sample_record());
        let report = builder.build();
        assert_eq!(report.records.len(), 2);
        assert_eq!(report.metadata.org_name, "Test Org");
    }

    // 2. One record, verify XML structure.
    #[test]
    fn aggregate_report_to_xml_minimal() {
        let mut builder = AggregateReportBuilder::new(sample_metadata(), sample_policy());
        builder.add_record(sample_record());
        let report = builder.build();
        let xml = report.to_xml().expect("XML serialization failed");

        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<feedback>"));
        assert!(xml.contains("</feedback>"));
        assert!(xml.contains("<org_name>Test Org</org_name>"));
        assert!(xml.contains("<email>admin@example.com</email>"));
        assert!(xml.contains("<report_id>report-123</report_id>"));
        assert!(xml.contains("<begin>1704067200</begin>"));
        assert!(xml.contains("<end>1704153600</end>"));
        assert!(xml.contains("<source_ip>1.2.3.4</source_ip>"));
        assert!(xml.contains("<count>5</count>"));
    }

    // 3. Multiple records, check all fields.
    #[test]
    fn aggregate_report_to_xml_full() {
        let mut builder = AggregateReportBuilder::new(sample_metadata(), sample_policy());
        builder.add_record(sample_record());
        builder.add_record(ReportRecord {
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            count: 12,
            disposition: Disposition::Quarantine,
            dkim_result: DmarcAuthResult::Fail,
            spf_result: DmarcAuthResult::Pass,
        });
        let report = builder.build();
        let xml = report.to_xml().expect("XML serialization failed");

        // Both records present
        assert!(xml.contains("<source_ip>1.2.3.4</source_ip>"));
        assert!(xml.contains("<source_ip>10.0.0.1</source_ip>"));
        assert!(xml.contains("<count>12</count>"));
        assert!(xml.contains("<disposition>quarantine</disposition>"));
        assert!(xml.contains("<dkim>fail</dkim>"));

        // Policy published
        assert!(xml.contains("<domain>example.com</domain>"));
        assert!(xml.contains("<pct>100</pct>"));
    }

    // 4. Verify none/quarantine/reject map correctly.
    #[test]
    fn xml_policy_values() {
        let policies = [
            (Policy::None, "none"),
            (Policy::Quarantine, "quarantine"),
            (Policy::Reject, "reject"),
        ];
        for (p, expected) in &policies {
            let pp = PolicyPublished {
                domain: "d.example".into(),
                adkim: AlignmentMode::Relaxed,
                aspf: AlignmentMode::Relaxed,
                policy: *p,
                subdomain_policy: *p,
                percent: 100,
            };
            let report = AggregateReport {
                metadata: sample_metadata(),
                policy_published: pp,
                records: vec![],
            };
            let xml = report.to_xml().unwrap();
            let p_tag = format!("<p>{}</p>", expected);
            let sp_tag = format!("<sp>{}</sp>", expected);
            assert!(xml.contains(&p_tag), "missing {} in XML", p_tag);
            assert!(xml.contains(&sp_tag), "missing {} in XML", sp_tag);
        }
    }

    // 5. Verify r/s mapping.
    #[test]
    fn xml_alignment_values() {
        for (mode, expected) in [
            (AlignmentMode::Relaxed, "r"),
            (AlignmentMode::Strict, "s"),
        ] {
            let pp = PolicyPublished {
                domain: "d.example".into(),
                adkim: mode,
                aspf: mode,
                policy: Policy::None,
                subdomain_policy: Policy::None,
                percent: 100,
            };
            let report = AggregateReport {
                metadata: sample_metadata(),
                policy_published: pp,
                records: vec![],
            };
            let xml = report.to_xml().unwrap();
            assert!(
                xml.contains(&format!("<adkim>{}</adkim>", expected)),
                "adkim mismatch for {:?}",
                mode
            );
            assert!(
                xml.contains(&format!("<aspf>{}</aspf>", expected)),
                "aspf mismatch for {:?}",
                mode
            );
        }
    }

    // 6. Verify disposition mapping.
    #[test]
    fn xml_disposition_values() {
        let cases = [
            (Disposition::Pass, "none"),
            (Disposition::Quarantine, "quarantine"),
            (Disposition::Reject, "reject"),
            (Disposition::None, "none"),
            (Disposition::TempFail, "none"),
        ];
        for (disp, expected) in &cases {
            let rec = ReportRecord {
                source_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                count: 1,
                disposition: *disp,
                dkim_result: DmarcAuthResult::None,
                spf_result: DmarcAuthResult::None,
            };
            let report = AggregateReport {
                metadata: sample_metadata(),
                policy_published: sample_policy(),
                records: vec![rec],
            };
            let xml = report.to_xml().unwrap();
            let tag = format!("<disposition>{}</disposition>", expected);
            assert!(
                xml.contains(&tag),
                "expected {:?} -> {} but XML was:\n{}",
                disp,
                expected,
                xml
            );
        }
    }

    // 7. AFRF output contains required fields.
    #[test]
    fn failure_report_afrf_format() {
        let fr = FailureReport {
            original_mail_from: "sender@evil.example".into(),
            arrival_date: "Fri, 01 Jan 2024 00:00:00 +0000".into(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            reported_domain: "example.com".into(),
            authentication_results: "dmarc=fail header.from=example.com".into(),
            original_headers: "From: spoof@example.com\r\nTo: victim@example.com".into(),
        };
        let afrf = fr.to_afrf();

        assert!(afrf.contains("Feedback-Type: auth-failure"));
        assert!(afrf.contains("User-Agent: email-auth/0.1.0"));
        assert!(afrf.contains("Version: 1"));
        assert!(afrf.contains("Original-Mail-From: sender@evil.example"));
        assert!(afrf.contains("Source-IP: 192.168.1.1"));
        assert!(afrf.contains("Reported-Domain: example.com"));
        assert!(afrf.contains("Authentication-Results: dmarc=fail header.from=example.com"));
        assert!(afrf.contains("From: spoof@example.com"));
    }

    // 8. Empty report still valid XML.
    #[test]
    fn builder_no_records() {
        let builder = AggregateReportBuilder::new(sample_metadata(), sample_policy());
        let report = builder.build();
        assert!(report.records.is_empty());
        let xml = report.to_xml().expect("empty report must serialize");
        assert!(xml.contains("<feedback>"));
        assert!(xml.contains("</feedback>"));
        // No <record> element expected
        assert!(!xml.contains("<record>"));
    }

    // 9. IPv6 address in XML.
    #[test]
    fn ipv6_source_ip() {
        let rec = ReportRecord {
            source_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            count: 3,
            disposition: Disposition::Reject,
            dkim_result: DmarcAuthResult::Fail,
            spf_result: DmarcAuthResult::Fail,
        };
        let report = AggregateReport {
            metadata: sample_metadata(),
            policy_published: sample_policy(),
            records: vec![rec],
        };
        let xml = report.to_xml().unwrap();
        assert!(xml.contains("<source_ip>2001:db8::1</source_ip>"));
        assert!(xml.contains("<disposition>reject</disposition>"));
    }
}
