pub mod eval;
pub mod record;
pub mod report;

pub use record::DmarcRecord;

/// DMARC policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

/// DMARC alignment mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlignmentMode {
    Relaxed,
    Strict,
}

/// DMARC disposition.
#[derive(Debug, Clone, PartialEq)]
pub enum Disposition {
    Pass,
    Quarantine,
    Reject,
    None,
    TempFail,
}

/// Structured DMARC result.
#[derive(Debug, Clone, PartialEq)]
pub struct DmarcResult {
    pub disposition: Disposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub applied_policy: Option<Policy>,
    pub record: Option<DmarcRecord>,
}
