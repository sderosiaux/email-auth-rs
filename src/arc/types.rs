use crate::dkim::types::{Algorithm, CanonicalizationMethod};

/// ARC Set — three headers sharing the same instance number.
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
    pub raw_header: String,
}

/// ARC-Message-Signature — DKIM-like signature over message headers+body.
#[derive(Debug, Clone)]
pub struct ArcMessageSignature {
    pub instance: u32,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub domain: String,
    pub selector: String,
    pub signed_headers: Vec<String>,
    pub header_canonicalization: CanonicalizationMethod,
    pub body_canonicalization: CanonicalizationMethod,
    pub timestamp: Option<u64>,
    pub body_length: Option<u64>,
    pub raw_header: String,
}

/// ARC-Seal — signature over ARC headers only.
#[derive(Debug, Clone)]
pub struct ArcSeal {
    pub instance: u32,
    pub cv: ChainValidationStatus,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub domain: String,
    pub selector: String,
    pub timestamp: Option<u64>,
    pub raw_header: String,
}

/// Chain validation status (cv= tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainValidationStatus {
    None,
    Pass,
    Fail,
}

/// ARC validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcResult {
    None,
    Pass,
    Fail { reason: String },
}

/// Full ARC validation result with oldest-pass info.
#[derive(Debug, Clone)]
pub struct ArcValidationResult {
    pub status: ArcResult,
    /// Lowest AMS instance that validated. 0 if all pass, None if not computed.
    pub oldest_pass: Option<u32>,
}
