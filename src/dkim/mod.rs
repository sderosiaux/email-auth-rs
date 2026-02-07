pub mod canon;
pub mod key;
pub mod sign;
pub mod signature;
pub mod verify;

pub use sign::DkimSigner;
pub use verify::DkimVerifier;

pub use key::{DkimPublicKey, HashAlgorithm, KeyFlag, KeyParseError, KeyType};
pub use signature::{Algorithm, CanonicalizationMethod, DkimParseError, DkimSignature};

// ---------------------------------------------------------------------------
// DkimResult
// ---------------------------------------------------------------------------

/// DKIM verification result (RFC 6376 Section 3.9 / RFC 8601).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimResult {
    /// Signature verified successfully.
    Pass {
        /// The signing domain (d= tag).
        domain: String,
        /// The selector used (s= tag).
        selector: String,
        /// Whether the key was in testing mode (t=y).
        testing: bool,
    },
    /// Signature exists but verification failed.
    Fail {
        reason: String,
    },
    /// Permanent failure — signature is malformed or structurally invalid.
    PermFail {
        reason: String,
    },
    /// Temporary failure — DNS lookup failed, try again later.
    TempFail {
        reason: String,
    },
    /// No DKIM signature present.
    None,
}

impl DkimResult {
    /// Whether this result represents a passing verification.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }
}

impl std::fmt::Display for DkimResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass { domain, selector, testing } => {
                write!(f, "pass (d={domain} s={selector}")?;
                if *testing {
                    write!(f, " testing")?;
                }
                write!(f, ")")
            }
            Self::Fail { reason } => write!(f, "fail ({reason})"),
            Self::PermFail { reason } => write!(f, "permfail ({reason})"),
            Self::TempFail { reason } => write!(f, "tempfail ({reason})"),
            Self::None => write!(f, "none"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_pass_display() {
        let r = DkimResult::Pass {
            domain: "example.com".into(),
            selector: "sel".into(),
            testing: false,
        };
        assert_eq!(r.to_string(), "pass (d=example.com s=sel)");
        assert!(r.is_pass());
    }

    #[test]
    fn result_pass_testing_display() {
        let r = DkimResult::Pass {
            domain: "example.com".into(),
            selector: "sel".into(),
            testing: true,
        };
        assert_eq!(r.to_string(), "pass (d=example.com s=sel testing)");
    }

    #[test]
    fn result_fail_display() {
        let r = DkimResult::Fail {
            reason: "bad sig".into(),
        };
        assert_eq!(r.to_string(), "fail (bad sig)");
        assert!(!r.is_pass());
    }

    #[test]
    fn result_permfail_display() {
        let r = DkimResult::PermFail {
            reason: "missing tag".into(),
        };
        assert_eq!(r.to_string(), "permfail (missing tag)");
    }

    #[test]
    fn result_tempfail_display() {
        let r = DkimResult::TempFail {
            reason: "dns timeout".into(),
        };
        assert_eq!(r.to_string(), "tempfail (dns timeout)");
    }

    #[test]
    fn result_none_display() {
        assert_eq!(DkimResult::None.to_string(), "none");
        assert!(!DkimResult::None.is_pass());
    }

    #[test]
    fn reexports_accessible() {
        // Verify re-exports compile
        let _: Algorithm = Algorithm::RsaSha256;
        let _: CanonicalizationMethod = CanonicalizationMethod::Simple;
        let _: KeyType = KeyType::Rsa;
        let _: KeyFlag = KeyFlag::Testing;
    }
}
