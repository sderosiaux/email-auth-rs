pub mod types;
pub(crate) mod parser;
pub mod lookup;
pub mod macros;
pub mod eval;

pub use types::{Directive, Mechanism, Qualifier, SpfRecord, SpfResult};
pub use lookup::lookup_spf;
pub use macros::MacroContext;
pub use eval::check_host;
