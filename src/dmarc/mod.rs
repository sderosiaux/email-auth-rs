mod record;
mod alignment;
mod policy;

pub use record::DmarcRecord;
pub use policy::{DmarcVerifier, DmarcResult, Disposition};

use thiserror::Error;

/// DMARC policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// No action, monitoring only
    #[default]
    None,
    /// Treat as suspicious
    Quarantine,
    /// Reject the message
    Reject,
}

/// Alignment mode for DKIM/SPF
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlignmentMode {
    /// Organizational domain match
    #[default]
    Relaxed,
    /// Exact domain match
    Strict,
}

#[derive(Debug, Error)]
pub enum DmarcError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("DNS error: {0}")]
    Dns(String),
}
