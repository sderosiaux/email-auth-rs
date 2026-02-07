pub mod canon;
pub mod key;
pub mod sign;
pub mod signature;
pub mod verify;

pub use signature::DkimSignature;
pub use verify::DkimVerifier;
pub use sign::DkimSigner;

/// DKIM signing/verification algorithm.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

/// Canonicalization method.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CanonicalizationMethod {
    Simple,
    Relaxed,
}

/// DKIM verification result.
#[derive(Debug, Clone, PartialEq)]
pub enum DkimResult {
    Pass {
        domain: String,
        selector: String,
        testing: bool,
    },
    Fail {
        kind: FailureKind,
        detail: String,
    },
    PermFail {
        kind: PermFailKind,
        detail: String,
    },
    TempFail {
        reason: String,
    },
    None,
}

impl DkimResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }

    pub fn pass_domain(&self) -> Option<&str> {
        match self {
            Self::Pass { domain, .. } => Some(domain),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FailureKind {
    BodyHashMismatch,
    SignatureVerificationFailed,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PermFailKind {
    MalformedSignature,
    KeyRevoked,
    KeyNotFound,
    ExpiredSignature,
    AlgorithmMismatch,
    HashNotPermitted,
    ServiceTypeMismatch,
    StrictModeViolation,
    DomainMismatch,
}
