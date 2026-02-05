pub mod common;
pub mod spf;
pub mod dkim;
pub mod dmarc;
pub mod auth;

pub use common::{DnsResolver, HickoryResolver, MockResolver};
pub use spf::{SpfVerifier, SpfResult};
pub use dkim::{DkimVerifier, DkimSigner, DkimResult, SigningConfig};
pub use dmarc::{DmarcVerifier, DmarcResult};
pub use auth::{EmailAuthenticator, AuthenticationResult};
