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
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("Too many DNS lookups")]
    TooManyLookups,
    #[error("Too many void lookups")]
    TooManyVoidLookups,
    #[error("Invalid record: {0}")]
    InvalidRecord(String),
}
