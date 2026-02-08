pub mod types;
pub(crate) mod parser;
pub mod discovery;
pub mod svg;
pub mod vmc;

pub use types::{BimiRecord, BimiResult, BimiSelectorHeader, BimiValidationResult};
pub use parser::{parse_bimi_record, parse_bimi_selector, is_declination, BimiParseError};
pub use discovery::{BimiVerifier, BimiHeaders, check_dmarc_ineligible, strip_bimi_headers, format_bimi_location, format_bimi_headers};
pub use svg::{validate_svg_tiny_ps, SvgError};
pub use vmc::{validate_vmc, VmcError, VmcValidationResult};
