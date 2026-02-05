//! DKIM (DomainKeys Identified Mail) implementation - RFC 6376

mod signature;
mod key;
mod canon;
mod hash;
mod crypto;

pub use signature::DkimSignature;
pub use key::DkimPublicKey;
pub use crypto::{DkimResult, DkimVerifier};
