//! Email authentication library implementing SPF, DKIM, and DMARC.
//!
//! This crate provides a complete implementation of email authentication
//! protocols as defined in RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC).
//!
//! # Example
//!
//! ```no_run
//! use email_auth::{EmailAuthenticator, HickoryResolver};
//! use std::net::IpAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let resolver = HickoryResolver::new().unwrap();
//!     let auth = EmailAuthenticator::new(resolver);
//!
//!     let message = b"From: sender@example.com\r\nTo: recipient@example.org\r\n\r\nHello!";
//!     let client_ip: IpAddr = "192.0.2.1".parse().unwrap();
//!
//!     let result = auth.authenticate(
//!         message,
//!         client_ip,
//!         "mail.example.com",
//!         "sender@example.com",
//!     ).await;
//!
//!     println!("Authentication result: {}", result.summary());
//!     println!("Passed: {}", result.passed());
//! }
//! ```

pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod spf;

mod auth;

// Re-exports for convenient access
pub use auth::{AuthenticationResult, EmailAuthenticator};
pub use common::{DnsError, DnsResolver, HickoryResolver, MockResolver};
pub use dkim::{DkimResult, DkimSignature, DkimVerifier, FailureReason as DkimFailureReason};
pub use dmarc::{AlignmentMode, DmarcRecord, DmarcResult, DmarcVerifier, Disposition, Policy};
pub use spf::{SpfResult, SpfVerifier};
