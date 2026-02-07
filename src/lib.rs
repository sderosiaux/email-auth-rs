pub mod common;
pub mod spf;
pub mod dkim;
pub mod dmarc;
pub mod arc;
pub mod bimi;
pub mod auth;

pub use common::{DnsError, DnsResolver, MockResolver, MxRecord};
pub use spf::SpfResult;
pub use dkim::{DkimResult, DkimVerifier, DkimSigner};
pub use dmarc::{DmarcResult, DmarcRecord, Policy, Disposition, AlignmentMode};
pub use auth::{authenticate, AuthResult, AuthParams, parse_message};
pub use arc::{ArcVerifier, ArcSealer, ArcResult, ArcValidationResult, ArcSet, ChainValidationStatus, SealError};
pub use bimi::{BimiVerifier, BimiRecord, BimiResult, BimiValidationResult, BimiSelectorHeader, check_dmarc_eligibility};
