mod record;
mod mechanism;
mod macro_exp;
mod eval;

pub use record::SpfRecord;
pub use mechanism::{Directive, Mechanism, Modifier, Qualifier};
pub use eval::SpfVerifier;

use thiserror::Error;

/// SPF evaluation result (RFC 7208 Section 2.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfResult {
    /// Sender is authorized
    Pass,
    /// Sender is NOT authorized
    Fail,
    /// Weak authorization failure
    SoftFail,
    /// No assertion made
    Neutral,
    /// No SPF record found
    None,
    /// Transient DNS error
    TempError,
    /// Permanent error (syntax, lookup limit, etc.)
    PermError,
}

#[derive(Debug, Error)]
pub enum SpfError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("lookup limit exceeded")]
    LookupLimitExceeded,
    #[error("void lookup limit exceeded")]
    VoidLookupLimitExceeded,
}
