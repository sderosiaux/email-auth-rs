//! Email authentication library: SPF, DKIM, DMARC

pub mod common;
pub mod spf;
pub mod dkim;
pub mod dmarc;
mod auth;

pub use common::dns::{DnsError, DnsResolver};
pub use common::domain::normalize_domain;
pub use common::psl::organizational_domain;

pub use spf::{SpfResult, SpfVerifier};
pub use dkim::{DkimResult, DkimVerifier};
pub use dmarc::{DmarcResult, DmarcVerifier, Policy, Disposition};
pub use auth::{AuthenticationResult, EmailAuthenticator};
