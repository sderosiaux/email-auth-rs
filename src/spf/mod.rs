//! SPF (Sender Policy Framework) implementation - RFC 7208

mod record;
mod mechanism;
mod macro_exp;
mod eval;

pub use record::SpfRecord;
pub use mechanism::{Directive, Mechanism, Modifier, Qualifier};
pub use eval::{SpfResult, SpfVerifier};
