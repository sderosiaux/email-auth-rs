pub mod common;
pub mod spf;
pub mod dkim;
pub mod dmarc;
pub mod auth;

pub use common::{DnsResolver, HickoryResolver, MockResolver};
pub use spf::{SpfVerifier, SpfResult, SpfRecord};
pub use dkim::{DkimVerifier, DkimSigner, DkimResult, DkimSignature};
pub use dmarc::{DmarcVerifier, DmarcResult, DmarcRecord};
pub use auth::{EmailAuthenticator, AuthenticationResult};
