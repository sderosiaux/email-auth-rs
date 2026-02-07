pub mod eval;
pub mod record;

pub use eval::DmarcEvaluator;
pub use record::DmarcRecord;

/// DMARC policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

/// DKIM/SPF alignment mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlignmentMode {
    Relaxed,
    Strict,
}

/// Failure reporting option.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FailureOption {
    Zero,
    One,
    D,
    S,
}

/// Report format.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReportFormat {
    Afrf,
}

/// Report URI.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportUri {
    pub scheme: String,
    pub address: String,
    pub max_size: Option<u64>,
}

/// DMARC evaluation result.
#[derive(Debug, Clone)]
pub struct DmarcResult {
    pub disposition: Disposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub applied_policy: Option<Policy>,
    pub record: Option<DmarcRecord>,
}

/// DMARC disposition.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Disposition {
    Pass,
    Quarantine,
    Reject,
    None,
    TempFail,
}

impl Default for DmarcResult {
    fn default() -> Self {
        Self {
            disposition: Disposition::None,
            dkim_aligned: false,
            spf_aligned: false,
            applied_policy: None,
            record: None,
        }
    }
}
