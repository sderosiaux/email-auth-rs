pub mod canon;
pub mod key;
pub mod sign;
pub mod signature;
pub mod verify;

pub use key::DkimPublicKey;
pub use sign::DkimSigner;
pub use signature::DkimSignature;
pub use verify::DkimVerifier;

/// DKIM signing/verification algorithm.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

impl Algorithm {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "rsa-sha1" => Ok(Algorithm::RsaSha1),
            "rsa-sha256" => Ok(Algorithm::RsaSha256),
            "ed25519-sha256" => Ok(Algorithm::Ed25519Sha256),
            _ => Err(format!("unknown DKIM algorithm: {}", s)),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::RsaSha1 => "rsa-sha1",
            Algorithm::RsaSha256 => "rsa-sha256",
            Algorithm::Ed25519Sha256 => "ed25519-sha256",
        }
    }
}

/// Canonicalization method.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CanonicalizationMethod {
    Simple,
    Relaxed,
}

/// DKIM verification result.
#[derive(Debug, Clone)]
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

/// Cryptographic verification failure kinds.
#[derive(Debug, Clone, PartialEq)]
pub enum FailureKind {
    BodyHashMismatch,
    SignatureVerificationFailed,
}

/// Permanent structural/configuration failure kinds.
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

/// Key type (RSA or Ed25519).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

/// Hash algorithm constraint in DNS key record.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

/// Key flag from DNS key record.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyFlag {
    Testing,
    Strict,
}
