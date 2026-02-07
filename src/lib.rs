pub mod auth;
pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod spf;

// Public API re-exports
pub use auth::{AuthenticationResult, EmailAuthenticator};
pub use common::{DnsError, DnsResolver, HickoryResolver, MockResolver};
pub use dkim::{DkimResult, DkimSigner, DkimVerifier, FailureKind, PermFailKind};
pub use dmarc::{Disposition, DmarcEvaluator, DmarcResult};
pub use spf::SpfResult;
