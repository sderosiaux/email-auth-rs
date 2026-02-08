/// DKIM signing/verification algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// RSA with SHA-1 (verify only, MUST NOT sign)
    RsaSha1,
    /// RSA with SHA-256 (preferred)
    RsaSha256,
    /// Ed25519 with SHA-256 (RFC 8463)
    Ed25519Sha256,
}

impl Algorithm {
    /// Parse algorithm string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rsa-sha1" => Some(Algorithm::RsaSha1),
            "rsa-sha256" => Some(Algorithm::RsaSha256),
            "ed25519-sha256" => Some(Algorithm::Ed25519Sha256),
            _ => None,
        }
    }

    /// Returns the hash algorithm used by this signing algorithm.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Algorithm::RsaSha1 => HashAlgorithm::Sha1,
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => HashAlgorithm::Sha256,
        }
    }
}

/// Canonicalization method for headers or body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizationMethod {
    Simple,
    Relaxed,
}

impl CanonicalizationMethod {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "simple" => Some(CanonicalizationMethod::Simple),
            "relaxed" => Some(CanonicalizationMethod::Relaxed),
            _ => None,
        }
    }
}

/// Parsed DKIM-Signature header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSignature {
    pub version: u8,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub header_canonicalization: CanonicalizationMethod,
    pub body_canonicalization: CanonicalizationMethod,
    pub domain: String,
    pub signed_headers: Vec<String>,
    pub auid: String,
    pub body_length: Option<u64>,
    pub selector: String,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
    pub copied_headers: Option<Vec<String>>,
    pub raw_header: String,
}

/// Key type for DKIM public key records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

impl KeyType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rsa" => Some(KeyType::Rsa),
            "ed25519" => Some(KeyType::Ed25519),
            _ => None,
        }
    }
}

/// Hash algorithm constraint from key h= tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => Some(HashAlgorithm::Sha1),
            "sha256" => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }
}

/// Key flags from t= tag in DNS key record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFlag {
    /// t=y: testing mode
    Testing,
    /// t=s: strict mode (i= must exactly equal d=)
    Strict,
}

/// DKIM verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimResult {
    /// Signature verified successfully.
    Pass {
        domain: String,
        selector: String,
        testing: bool,
    },
    /// Cryptographic verification failed.
    Fail {
        kind: FailureKind,
        detail: String,
    },
    /// Permanent structural/configuration error.
    PermFail {
        kind: PermFailKind,
        detail: String,
    },
    /// Transient error (DNS timeout).
    TempFail {
        reason: String,
    },
    /// No DKIM-Signature header present.
    None,
}

/// Cryptographic failure kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    BodyHashMismatch,
    SignatureVerificationFailed,
}

/// Permanent failure kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
