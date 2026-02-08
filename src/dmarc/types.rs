/// DMARC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// No action, monitoring only.
    None,
    /// Treat as suspicious (spam folder).
    Quarantine,
    /// Reject the message.
    Reject,
}

impl Policy {
    /// Parse policy string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Some(Policy::None),
            "quarantine" => Some(Policy::Quarantine),
            "reject" => Some(Policy::Reject),
            _ => Option::None,
        }
    }
}

/// Alignment mode for DKIM/SPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    /// Organizational domain match.
    Relaxed,
    /// Exact domain match.
    Strict,
}

impl AlignmentMode {
    /// Parse alignment mode: "r" → Relaxed, "s" → Strict.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "r" => Some(AlignmentMode::Relaxed),
            "s" => Some(AlignmentMode::Strict),
            _ => Option::None,
        }
    }
}

/// Failure reporting option (fo= tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOption {
    /// Generate report if all mechanisms fail.
    Zero,
    /// Generate report if any mechanism fails.
    One,
    /// Generate report if DKIM fails.
    D,
    /// Generate report if SPF fails.
    S,
}

impl FailureOption {
    /// Parse a single failure option character (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "0" => Some(FailureOption::Zero),
            "1" => Some(FailureOption::One),
            "d" => Some(FailureOption::D),
            "s" => Some(FailureOption::S),
            _ => Option::None,
        }
    }
}

/// Report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Authentication Failure Reporting Format (RFC 6591).
    Afrf,
}

impl ReportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "afrf" => Some(ReportFormat::Afrf),
            _ => Option::None,
        }
    }
}

/// Report URI (mailto: address with optional size limit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportUri {
    /// Email address (after stripping mailto: prefix).
    pub address: String,
    /// Maximum report size in bytes.
    pub max_size: Option<u64>,
}

/// Parsed DMARC record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    /// Policy for organizational domain (p= tag).
    pub policy: Policy,
    /// Subdomain policy (sp= tag, defaults to p=).
    pub subdomain_policy: Policy,
    /// Non-existent subdomain policy (np= tag, RFC 9091).
    pub non_existent_subdomain_policy: Option<Policy>,
    /// DKIM alignment mode (adkim= tag, default: Relaxed).
    pub dkim_alignment: AlignmentMode,
    /// SPF alignment mode (aspf= tag, default: Relaxed).
    pub spf_alignment: AlignmentMode,
    /// Percentage of messages to apply policy (pct= tag, default: 100).
    pub percent: u8,
    /// Failure reporting options (fo= tag).
    pub failure_options: Vec<FailureOption>,
    /// Report format (rf= tag, default: AFRF).
    pub report_format: ReportFormat,
    /// Aggregate report interval in seconds (ri= tag, default: 86400).
    pub report_interval: u32,
    /// Aggregate report URIs (rua= tag).
    pub rua: Vec<ReportUri>,
    /// Failure report URIs (ruf= tag).
    pub ruf: Vec<ReportUri>,
}

/// DMARC evaluation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcResult {
    /// What to do with the message.
    pub disposition: Disposition,
    /// Whether any DKIM signature aligned.
    pub dkim_aligned: bool,
    /// Whether SPF passed and aligned.
    pub spf_aligned: bool,
    /// The policy that was applied.
    pub applied_policy: Option<Policy>,
    /// The DMARC record found (if any).
    pub record: Option<DmarcRecord>,
}

/// DMARC disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Message passed DMARC.
    Pass,
    /// Quarantine per policy.
    Quarantine,
    /// Reject per policy.
    Reject,
    /// No policy (monitoring, pct sampling excluded, or no record).
    None,
    /// DNS temporary failure during record discovery.
    TempFail,
}
