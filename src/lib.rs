pub mod auth;
pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod spf;

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

// Combined API
pub use auth::{AuthenticationResult, EmailAuthenticator};

// SPF
pub use spf::{SpfResult, SpfVerifier};

// DKIM
pub use dkim::{DkimResult, DkimSigner, DkimVerifier};

// DMARC
pub use dmarc::{Disposition, DmarcEvaluator, DmarcResult};

// DNS
pub use common::dns::{DnsResolver, HickoryResolver};
