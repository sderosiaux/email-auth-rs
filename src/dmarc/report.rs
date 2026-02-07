use super::{AlignmentMode, Disposition, Policy};
use std::net::IpAddr;

/// DMARC Aggregate Report (RFC 7489 Appendix C).
#[derive(Debug, Clone)]
pub struct AggregateReport {
    pub metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    pub records: Vec<ReportRecord>,
}

/// Report metadata.
#[derive(Debug, Clone)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: String,
    pub extra_contact_info: Option<String>,
    pub report_id: String,
    pub date_range_begin: u64,
    pub date_range_end: u64,
}

/// Published DMARC policy.
#[derive(Debug, Clone)]
pub struct PolicyPublished {
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
    pub disposition: Disposition,
    pub dkim: PolicyOverrideType,
    pub spf: PolicyOverrideType,
    pub header_from: String,
    pub dkim_results: Vec<DkimAuthResult>,
    pub spf_results: Vec<SpfAuthResult>,
}

/// Policy evaluation result for a single check.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyOverrideType {
    Pass,
    Fail,
}

/// DKIM authentication result in report.
#[derive(Debug, Clone)]
pub struct DkimAuthResult {
    pub domain: String,
    pub selector: Option<String>,
    pub result: DkimReportResult,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DkimReportResult {
    Pass,
    Fail,
    None,
    TempError,
    PermError,
}

/// SPF authentication result in report.
#[derive(Debug, Clone)]
pub struct SpfAuthResult {
    pub domain: String,
    pub scope: SpfScope,
    pub result: SpfReportResult,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpfScope {
    Helo,
    MailFrom,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpfReportResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl AggregateReport {
    /// Serialize to XML per RFC 7489 Appendix C schema.
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<feedback>\n");

        // Report metadata
        xml.push_str("  <report_metadata>\n");
        xml.push_str(&format!(
            "    <org_name>{}</org_name>\n",
            escape_xml(&self.metadata.org_name)
        ));
        xml.push_str(&format!(
            "    <email>{}</email>\n",
            escape_xml(&self.metadata.email)
        ));
        if let Some(ref info) = self.metadata.extra_contact_info {
            xml.push_str(&format!(
                "    <extra_contact_info>{}</extra_contact_info>\n",
                escape_xml(info)
            ));
        }
        xml.push_str(&format!(
            "    <report_id>{}</report_id>\n",
            escape_xml(&self.metadata.report_id)
        ));
        xml.push_str("    <date_range>\n");
        xml.push_str(&format!(
            "      <begin>{}</begin>\n",
            self.metadata.date_range_begin
        ));
        xml.push_str(&format!(
            "      <end>{}</end>\n",
            self.metadata.date_range_end
        ));
        xml.push_str("    </date_range>\n");
        xml.push_str("  </report_metadata>\n");

        // Policy published
        xml.push_str("  <policy_published>\n");
        xml.push_str(&format!(
            "    <domain>{}</domain>\n",
            escape_xml(&self.policy_published.domain)
        ));
        xml.push_str(&format!(
            "    <adkim>{}</adkim>\n",
            alignment_str(self.policy_published.adkim)
        ));
        xml.push_str(&format!(
            "    <aspf>{}</aspf>\n",
            alignment_str(self.policy_published.aspf)
        ));
        xml.push_str(&format!(
            "    <p>{}</p>\n",
            policy_str(self.policy_published.policy)
        ));
        xml.push_str(&format!(
            "    <sp>{}</sp>\n",
            policy_str(self.policy_published.subdomain_policy)
        ));
        xml.push_str(&format!(
            "    <pct>{}</pct>\n",
            self.policy_published.percent
        ));
        xml.push_str("  </policy_published>\n");

        // Records
        for record in &self.records {
            xml.push_str("  <record>\n");
            xml.push_str("    <row>\n");
            xml.push_str(&format!(
                "      <source_ip>{}</source_ip>\n",
                record.source_ip
            ));
            xml.push_str(&format!("      <count>{}</count>\n", record.count));
            xml.push_str("      <policy_evaluated>\n");
            xml.push_str(&format!(
                "        <disposition>{}</disposition>\n",
                disposition_str(&record.disposition)
            ));
            xml.push_str(&format!(
                "        <dkim>{}</dkim>\n",
                override_str(&record.dkim)
            ));
            xml.push_str(&format!(
                "        <spf>{}</spf>\n",
                override_str(&record.spf)
            ));
            xml.push_str("      </policy_evaluated>\n");
            xml.push_str("    </row>\n");

            xml.push_str("    <identifiers>\n");
            xml.push_str(&format!(
                "      <header_from>{}</header_from>\n",
                escape_xml(&record.header_from)
            ));
            xml.push_str("    </identifiers>\n");

            xml.push_str("    <auth_results>\n");
            for dkim in &record.dkim_results {
                xml.push_str("      <dkim>\n");
                xml.push_str(&format!(
                    "        <domain>{}</domain>\n",
                    escape_xml(&dkim.domain)
                ));
                if let Some(ref sel) = dkim.selector {
                    xml.push_str(&format!(
                        "        <selector>{}</selector>\n",
                        escape_xml(sel)
                    ));
                }
                xml.push_str(&format!(
                    "        <result>{}</result>\n",
                    dkim_result_str(&dkim.result)
                ));
                xml.push_str("      </dkim>\n");
            }
            for spf in &record.spf_results {
                xml.push_str("      <spf>\n");
                xml.push_str(&format!(
                    "        <domain>{}</domain>\n",
                    escape_xml(&spf.domain)
                ));
                xml.push_str(&format!(
                    "        <scope>{}</scope>\n",
                    spf_scope_str(&spf.scope)
                ));
                xml.push_str(&format!(
                    "        <result>{}</result>\n",
                    spf_result_str(&spf.result)
                ));
                xml.push_str("      </spf>\n");
            }
            xml.push_str("    </auth_results>\n");
            xml.push_str("  </record>\n");
        }

        xml.push_str("</feedback>\n");
        xml
    }
}

/// Builder for accumulating authentication results into an aggregate report.
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

/// DMARC failure report (AFRF / RFC 6591 feedback report).
#[derive(Debug, Clone)]
pub struct FailureReport {
    pub feedback_type: String, // "auth-failure"
    pub user_agent: String,
    pub version: String, // "1"
    pub original_mail_from: String,
    pub arrival_date: String,
    pub source_ip: IpAddr,
    pub reported_domain: String,
    pub authentication_results: String,
    pub original_headers: String,
    pub delivery_result: String,
    pub auth_failure: AuthFailureType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthFailureType {
    Dkim,
    Spf,
    Dmarc,
}

impl FailureReport {
    /// Generate AFRF message body (message/feedback-report part).
    pub fn to_feedback_report(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("Feedback-Type: {}\r\n", self.feedback_type));
        report.push_str(&format!("User-Agent: {}\r\n", self.user_agent));
        report.push_str(&format!("Version: {}\r\n", self.version));
        report.push_str(&format!(
            "Original-Mail-From: {}\r\n",
            self.original_mail_from
        ));
        report.push_str(&format!("Arrival-Date: {}\r\n", self.arrival_date));
        report.push_str(&format!("Source-IP: {}\r\n", self.source_ip));
        report.push_str(&format!("Reported-Domain: {}\r\n", self.reported_domain));
        report.push_str(&format!(
            "Authentication-Results: {}\r\n",
            self.authentication_results
        ));
        report.push_str(&format!("Delivery-Result: {}\r\n", self.delivery_result));
        report.push_str(&format!(
            "Auth-Failure: {}\r\n",
            auth_failure_str(&self.auth_failure)
        ));
        report
    }

    /// Generate full MIME multipart/report message body.
    pub fn to_mime_report(&self, boundary: &str) -> String {
        let feedback = self.to_feedback_report();
        let mut mime = String::new();
        mime.push_str(&format!("--{boundary}\r\n"));
        mime.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
        mime.push_str("This is a DMARC failure report.\r\n");
        mime.push_str(&format!("\r\n--{boundary}\r\n"));
        mime.push_str("Content-Type: message/feedback-report\r\n\r\n");
        mime.push_str(&feedback);
        mime.push_str(&format!("\r\n--{boundary}\r\n"));
        mime.push_str("Content-Type: text/rfc822-headers\r\n\r\n");
        mime.push_str(&self.original_headers);
        mime.push_str(&format!("\r\n--{boundary}--\r\n"));
        mime
    }
}

/// Check whether a failure report should be generated based on fo= tags.
pub fn should_generate_failure_report(
    failure_options: &[super::record::FailureOption],
    dkim_failed: bool,
    spf_failed: bool,
    all_failed: bool,
) -> bool {
    use super::record::FailureOption;

    for opt in failure_options {
        match opt {
            FailureOption::Zero => {
                if all_failed {
                    return true;
                }
            }
            FailureOption::One => {
                if dkim_failed || spf_failed {
                    return true;
                }
            }
            FailureOption::D => {
                if dkim_failed {
                    return true;
                }
            }
            FailureOption::S => {
                if spf_failed {
                    return true;
                }
            }
        }
    }
    false
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn alignment_str(a: AlignmentMode) -> &'static str {
    match a {
        AlignmentMode::Relaxed => "r",
        AlignmentMode::Strict => "s",
    }
}

fn policy_str(p: Policy) -> &'static str {
    match p {
        Policy::None => "none",
        Policy::Quarantine => "quarantine",
        Policy::Reject => "reject",
    }
}

fn disposition_str(d: &Disposition) -> &'static str {
    match d {
        Disposition::None => "none",
        Disposition::Quarantine => "quarantine",
        Disposition::Reject => "reject",
        Disposition::Pass => "none",
        Disposition::TempFail => "none",
    }
}

fn override_str(o: &PolicyOverrideType) -> &'static str {
    match o {
        PolicyOverrideType::Pass => "pass",
        PolicyOverrideType::Fail => "fail",
    }
}

fn dkim_result_str(r: &DkimReportResult) -> &'static str {
    match r {
        DkimReportResult::Pass => "pass",
        DkimReportResult::Fail => "fail",
        DkimReportResult::None => "none",
        DkimReportResult::TempError => "temperror",
        DkimReportResult::PermError => "permerror",
    }
}

fn spf_scope_str(s: &SpfScope) -> &'static str {
    match s {
        SpfScope::Helo => "helo",
        SpfScope::MailFrom => "mfrom",
    }
}

fn spf_result_str(r: &SpfReportResult) -> &'static str {
    match r {
        SpfReportResult::Pass => "pass",
        SpfReportResult::Fail => "fail",
        SpfReportResult::SoftFail => "softfail",
        SpfReportResult::Neutral => "neutral",
        SpfReportResult::None => "none",
        SpfReportResult::TempError => "temperror",
        SpfReportResult::PermError => "permerror",
    }
}

fn auth_failure_str(a: &AuthFailureType) -> &'static str {
    match a {
        AuthFailureType::Dkim => "dkim",
        AuthFailureType::Spf => "spf",
        AuthFailureType::Dmarc => "dmarc",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> AggregateReport {
        AggregateReport {
            metadata: ReportMetadata {
                org_name: "Example Corp".into(),
                email: "postmaster@example.com".into(),
                extra_contact_info: None,
                report_id: "report-001".into(),
                date_range_begin: 1704067200,
                date_range_end: 1704153600,
            },
            policy_published: PolicyPublished {
                domain: "example.com".into(),
                adkim: AlignmentMode::Relaxed,
                aspf: AlignmentMode::Relaxed,
                policy: Policy::Reject,
                subdomain_policy: Policy::Reject,
                percent: 100,
            },
            records: vec![ReportRecord {
                source_ip: "192.0.2.1".parse().unwrap(),
                count: 10,
                disposition: Disposition::None,
                dkim: PolicyOverrideType::Pass,
                spf: PolicyOverrideType::Pass,
                header_from: "example.com".into(),
                dkim_results: vec![DkimAuthResult {
                    domain: "example.com".into(),
                    selector: Some("sel1".into()),
                    result: DkimReportResult::Pass,
                }],
                spf_results: vec![SpfAuthResult {
                    domain: "example.com".into(),
                    scope: SpfScope::MailFrom,
                    result: SpfReportResult::Pass,
                }],
            }],
        }
    }

    #[test]
    fn test_aggregate_xml_generation() {
        let report = sample_report();
        let xml = report.to_xml();

        assert!(xml.contains("<feedback>"));
        assert!(xml.contains("<org_name>Example Corp</org_name>"));
        assert!(xml.contains("<report_id>report-001</report_id>"));
        assert!(xml.contains("<domain>example.com</domain>"));
        assert!(xml.contains("<p>reject</p>"));
        assert!(xml.contains("<source_ip>192.0.2.1</source_ip>"));
        assert!(xml.contains("<count>10</count>"));
        assert!(xml.contains("<dkim>pass</dkim>"));
        assert!(xml.contains("<spf>pass</spf>"));
        assert!(xml.contains("<selector>sel1</selector>"));
        assert!(xml.contains("<scope>mfrom</scope>"));
        assert!(xml.contains("</feedback>"));
    }

    #[test]
    fn test_xml_escaping() {
        let mut report = sample_report();
        report.metadata.org_name = "Test & <Corp>".into();
        let xml = report.to_xml();
        assert!(xml.contains("Test &amp; &lt;Corp&gt;"));
    }

    #[test]
    fn test_builder() {
        let meta = ReportMetadata {
            org_name: "Test".into(),
            email: "test@example.com".into(),
            extra_contact_info: None,
            report_id: "r1".into(),
            date_range_begin: 0,
            date_range_end: 86400,
        };
        let policy = PolicyPublished {
            domain: "example.com".into(),
            adkim: AlignmentMode::Relaxed,
            aspf: AlignmentMode::Relaxed,
            policy: Policy::None,
            subdomain_policy: Policy::None,
            percent: 100,
        };
        let mut builder = AggregateReportBuilder::new(meta, policy);
        builder.add_record(ReportRecord {
            source_ip: "10.0.0.1".parse().unwrap(),
            count: 1,
            disposition: Disposition::None,
            dkim: PolicyOverrideType::Fail,
            spf: PolicyOverrideType::Pass,
            header_from: "example.com".into(),
            dkim_results: vec![],
            spf_results: vec![],
        });
        let report = builder.build();
        assert_eq!(report.records.len(), 1);
    }

    #[test]
    fn test_failure_report_afrf() {
        let report = FailureReport {
            feedback_type: "auth-failure".into(),
            user_agent: "email-auth/0.1.0".into(),
            version: "1".into(),
            original_mail_from: "sender@example.com".into(),
            arrival_date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
            source_ip: "192.0.2.1".parse().unwrap(),
            reported_domain: "example.com".into(),
            authentication_results: "dkim=fail; spf=pass".into(),
            original_headers: "From: user@example.com\r\nTo: other@test.com\r\n".into(),
            delivery_result: "delivered".into(),
            auth_failure: AuthFailureType::Dkim,
        };

        let feedback = report.to_feedback_report();
        assert!(feedback.contains("Feedback-Type: auth-failure"));
        assert!(feedback.contains("Auth-Failure: dkim"));
        assert!(feedback.contains("Source-IP: 192.0.2.1"));
    }

    #[test]
    fn test_failure_report_mime() {
        let report = FailureReport {
            feedback_type: "auth-failure".into(),
            user_agent: "email-auth/0.1.0".into(),
            version: "1".into(),
            original_mail_from: "sender@example.com".into(),
            arrival_date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
            source_ip: "192.0.2.1".parse().unwrap(),
            reported_domain: "example.com".into(),
            authentication_results: "spf=fail".into(),
            original_headers: "From: user@example.com\r\n".into(),
            delivery_result: "reject".into(),
            auth_failure: AuthFailureType::Spf,
        };

        let mime = report.to_mime_report("boundary123");
        assert!(mime.contains("--boundary123"));
        assert!(mime.contains("message/feedback-report"));
        assert!(mime.contains("text/rfc822-headers"));
        assert!(mime.contains("--boundary123--"));
    }

    #[test]
    fn test_failure_option_filtering() {
        use super::super::record::FailureOption;

        // fo=0: only when all fail
        assert!(should_generate_failure_report(
            &[FailureOption::Zero],
            true,
            true,
            true
        ));
        assert!(!should_generate_failure_report(
            &[FailureOption::Zero],
            true,
            false,
            false
        ));

        // fo=1: when any fail
        assert!(should_generate_failure_report(
            &[FailureOption::One],
            true,
            false,
            false
        ));
        assert!(should_generate_failure_report(
            &[FailureOption::One],
            false,
            true,
            false
        ));

        // fo=d: only dkim
        assert!(should_generate_failure_report(
            &[FailureOption::D],
            true,
            false,
            false
        ));
        assert!(!should_generate_failure_report(
            &[FailureOption::D],
            false,
            true,
            false
        ));

        // fo=s: only spf
        assert!(should_generate_failure_report(
            &[FailureOption::S],
            false,
            true,
            false
        ));
        assert!(!should_generate_failure_report(
            &[FailureOption::S],
            true,
            false,
            false
        ));
    }
}
