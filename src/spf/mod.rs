mod record;
mod mechanism;
mod macro_exp;
mod eval;

pub use record::SpfRecord;
pub use mechanism::{Mechanism, Qualifier};
pub use eval::SpfVerifier;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum SpfResult {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

#[derive(Debug, Error)]
pub enum SpfError {
    #[error("invalid SPF record: {0}")]
    InvalidRecord(String),
    #[error("DNS error: {0}")]
    DnsError(String),
    #[error("too many DNS lookups")]
    TooManyLookups,
}
