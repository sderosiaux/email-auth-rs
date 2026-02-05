pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod spf;

mod auth;

pub use auth::{AuthenticationResult, EmailAuthenticator};
pub use common::dns::{DnsError, DnsResolver};
pub use dkim::{DkimResult, DkimSigner, DkimVerifier, SigningConfig};
pub use dmarc::{DmarcResult, DmarcVerifier};
pub use spf::{SpfResult, SpfVerifier};
