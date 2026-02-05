//! Email authentication library: SPF, DKIM, DMARC
//!
//! Implements RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC).

pub mod common;
pub mod spf;
pub mod dkim;
pub mod dmarc;
mod auth;

pub use auth::{AuthenticationResult, EmailAuthenticator};
pub use common::dns::{DnsError, DnsResolver, HickoryResolver, MockResolver};
pub use common::domain;
pub use common::psl::PublicSuffixList;
pub use dkim::{DkimResult, DkimSigner, DkimVerifier};
pub use dmarc::{DmarcResult, DmarcVerifier, Disposition, Policy};
pub use spf::{SpfResult, SpfVerifier};
