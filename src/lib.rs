//! Email authentication library: SPF, DKIM, DMARC, ARC, BIMI.
//!
//! DNS caching is the caller's responsibility. This library provides
//! a `DnsResolver` trait — implement it with caching at the resolver layer.

pub mod arc;
pub mod auth;
pub mod bimi;
pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod spf;

pub use auth::{AuthenticationResult, AuthError, EmailAuthenticator};
