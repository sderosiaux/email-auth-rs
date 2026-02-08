pub mod types;
pub(crate) mod parser;
pub mod discovery;

pub use types::{BimiRecord, BimiResult, BimiSelectorHeader, BimiValidationResult};
pub use parser::{parse_bimi_record, parse_bimi_selector, is_declination, BimiParseError};
pub use discovery::{BimiVerifier, check_dmarc_ineligible, strip_bimi_headers, format_bimi_location};
