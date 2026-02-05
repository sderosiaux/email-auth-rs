//! DMARC (Domain-based Message Authentication, Reporting, and Conformance) per RFC 7489.

mod alignment;
mod policy;
mod record;

pub use alignment::AlignmentMode;
pub use policy::{DmarcVerifier, Disposition};
pub use record::{DmarcRecord, Policy};

use thiserror::Error;

/// DMARC verification result.
#[derive(Debug, Clone)]
pub struct DmarcResult {
    pub disposition: Disposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub policy: Option<Policy>,
    pub record: Option<DmarcRecord>,
}

impl DmarcResult {
    pub fn is_pass(&self) -> bool {
        matches!(self.disposition, Disposition::Pass)
    }
}

#[derive(Debug, Error)]
pub enum DmarcError {
    #[error("invalid record: {0}")]
    InvalidRecord(String),
    #[error("DNS error: {0}")]
    DnsError(#[from] crate::common::dns::DnsError),
}
