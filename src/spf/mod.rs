mod eval;
mod macro_exp;
mod mechanism;
mod record;

pub use eval::SpfVerifier;
pub use mechanism::{Directive, Mechanism, Modifier, Qualifier};
pub use record::SpfRecord;

use thiserror::Error;

/// SPF result codes (RFC 7208 Section 2.6)
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
    /// Permanent error (syntax, etc.)
    PermError,
}

impl std::fmt::Display for SpfResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfResult::Pass => write!(f, "pass"),
            SpfResult::Fail => write!(f, "fail"),
            SpfResult::SoftFail => write!(f, "softfail"),
            SpfResult::Neutral => write!(f, "neutral"),
            SpfResult::None => write!(f, "none"),
            SpfResult::TempError => write!(f, "temperror"),
            SpfResult::PermError => write!(f, "permerror"),
        }
    }
}

#[derive(Debug, Error)]
pub enum SpfError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("DNS lookup limit exceeded")]
    LookupLimitExceeded,
    #[error("void lookup limit exceeded")]
    VoidLookupLimitExceeded,
}
