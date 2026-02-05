//! SPF (Sender Policy Framework) implementation per RFC 7208.

mod eval;
mod macro_exp;
mod mechanism;
mod record;

pub use eval::SpfVerifier;
pub use mechanism::{Directive, Mechanism, Modifier, Qualifier};
pub use record::SpfRecord;

use thiserror::Error;

/// SPF evaluation result (RFC 7208 Section 2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfResult {
    /// Sender is authorized.
    Pass,
    /// Sender is NOT authorized.
    Fail { explanation: Option<String> },
    /// Weak authorization failure.
    SoftFail,
    /// No assertion made.
    Neutral,
    /// No SPF record found.
    None,
    /// Transient DNS error.
    TempError,
    /// Permanent error (syntax, etc.).
    PermError,
}

impl SpfResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, SpfResult::Pass)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, SpfResult::Fail { .. })
    }
}

#[derive(Debug, Error)]
pub enum SpfError {
    #[error("invalid SPF record: {0}")]
    InvalidRecord(String),
    #[error("DNS lookup limit exceeded")]
    LookupLimitExceeded,
    #[error("void lookup limit exceeded")]
    VoidLookupLimitExceeded,
    #[error("DNS error: {0}")]
    DnsError(#[from] crate::common::dns::DnsError),
}
