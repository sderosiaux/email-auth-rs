pub mod eval;
pub mod macro_exp;
pub mod mechanism;
pub mod record;

pub use eval::check_host;
pub use mechanism::{Directive, Mechanism, Qualifier};
pub use record::SpfRecord;

/// SPF evaluation result per RFC 7208 Section 2.6.
#[derive(Debug, Clone, PartialEq)]
pub enum SpfResult {
    Pass,
    Fail { explanation: Option<String> },
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}
