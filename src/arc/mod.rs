pub mod parse;
pub mod validate;
pub mod seal;

pub use validate::ArcVerifier;
pub use seal::ArcSealer;

use crate::dkim::Algorithm;

/// ARC chain validation result.
#[derive(Debug, Clone, PartialEq)]
pub enum ArcResult {
    /// No ARC Sets present.
    None,
    /// All validation steps passed.
    Pass,
    /// Validation failed.
    Fail { detail: String },
}

/// Full ARC validation result with oldest-pass info.
#[derive(Debug, Clone, PartialEq)]
pub struct ArcValidationResult {
    pub status: ArcResult,
    /// Lowest AMS instance that validated (0 if all pass, None if fail/none).
    pub oldest_pass: Option<u32>,
}

/// Chain validation status from cv= tag.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChainValidationStatus {
    None,
    Pass,
    Fail,
}

/// An ARC Set: AAR + AMS + AS sharing the same instance.
#[derive(Debug, Clone)]
pub struct ArcSet {
    pub instance: u32,
    pub aar: ArcAuthenticationResults,
    pub ams: ArcMessageSignature,
    pub seal: ArcSeal,
}

/// ARC-Authentication-Results header.
#[derive(Debug, Clone)]
pub struct ArcAuthenticationResults {
    pub instance: u32,
    pub payload: String,
    /// Raw header value for seal validation.
    pub raw_value: String,
}

/// ARC-Message-Signature header (DKIM-like).
#[derive(Debug, Clone)]
pub struct ArcMessageSignature {
    pub instance: u32,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub domain: String,
    pub selector: String,
    pub signed_headers: Vec<String>,
    pub header_canonicalization: crate::dkim::CanonicalizationMethod,
    pub body_canonicalization: crate::dkim::CanonicalizationMethod,
    pub timestamp: Option<u64>,
    pub body_length: Option<u64>,
    /// Raw header value for seal validation.
    pub raw_value: String,
}

/// ARC-Seal header.
#[derive(Debug, Clone)]
pub struct ArcSeal {
    pub instance: u32,
    pub cv: ChainValidationStatus,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub domain: String,
    pub selector: String,
    pub timestamp: Option<u64>,
    /// Raw header value for seal validation.
    pub raw_value: String,
}

/// Error during ARC sealing.
#[derive(Debug, Clone, PartialEq)]
pub enum SealError {
    /// Incoming chain has cv=fail, cannot seal.
    ChainFailed,
    /// Instance would exceed 50.
    InstanceLimitExceeded,
    /// Signing error.
    SigningError(String),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainFailed => write!(f, "incoming chain cv=fail"),
            Self::InstanceLimitExceeded => write!(f, "instance limit 50 exceeded"),
            Self::SigningError(s) => write!(f, "signing error: {s}"),
        }
    }
}
