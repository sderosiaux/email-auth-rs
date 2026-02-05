mod eval;
mod macro_exp;
mod mechanism;
mod record;

pub use eval::SpfVerifier;
pub use record::{ParseError, SpfRecord};

/// SPF evaluation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfResult {
    /// Explicit authorization
    Pass,
    /// Explicit rejection
    Fail,
    /// Weak rejection (between neutral and fail)
    SoftFail,
    /// No assertion made
    Neutral,
    /// No SPF record found
    None,
    /// Transient error (DNS timeout, etc.)
    TempError,
    /// Permanent error (syntax error, too many lookups)
    PermError,
}

impl SpfResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, SpfResult::Pass)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, SpfResult::Fail | SpfResult::SoftFail)
    }
}
