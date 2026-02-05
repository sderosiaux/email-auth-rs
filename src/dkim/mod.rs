mod canon;
mod crypto;
mod hash;
mod key;
mod signature;

use std::sync::Arc;

use crate::common::dns::DnsResolver;

pub use signature::{DkimSignature, ParseError};

/// DKIM verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimResult {
    /// Valid signature
    Pass { domain: String, selector: String },
    /// Invalid signature
    Fail { reason: FailureReason },
    /// Transient error
    TempFail { reason: String },
    /// Permanent error
    PermFail { reason: String },
    /// No signature present
    None,
}

impl DkimResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, DkimResult::Pass { .. })
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            DkimResult::Pass { domain, .. } => Some(domain),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    SignatureMismatch,
    BodyHashMismatch,
    KeyRevoked,
    KeyNotFound,
    ExpiredSignature,
    FutureSignature,
    AlgorithmMismatch,
    DomainMismatch,
}

/// DKIM verifier
pub struct DkimVerifier<R: DnsResolver> {
    resolver: Arc<R>,
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: Arc<R>) -> Self {
        Self { resolver }
    }

    /// Verify all DKIM signatures in message
    pub async fn verify(&self, _message: &[u8]) -> Vec<DkimResult> {
        // TODO: Implement in M3
        vec![DkimResult::None]
    }
}

/// DKIM signer configuration
#[derive(Debug, Clone)]
pub struct SigningConfig {
    pub domain: String,
    pub selector: String,
    pub headers: Vec<String>,
}

/// DKIM signer
pub struct DkimSigner {
    // TODO: Implement in M4
}

impl DkimSigner {
    pub fn sign(&self, _message: &[u8]) -> Result<String, SignError> {
        // TODO: Implement in M4
        Err(SignError::NotImplemented)
    }
}

#[derive(Debug)]
pub enum SignError {
    NotImplemented,
}
