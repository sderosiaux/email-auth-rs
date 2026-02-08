pub mod types;
pub(crate) mod parser;
pub mod lookup;

pub use types::{Directive, Mechanism, Qualifier, SpfRecord, SpfResult};
pub use lookup::lookup_spf;
