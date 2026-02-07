//! SPF (Sender Policy Framework) implementation — RFC 7208.

pub mod eval;
pub mod macro_exp;
pub mod mechanism;
pub mod record;

pub use macro_exp::{expand, MacroContext, MacroError};
pub use mechanism::{
    Directive, DualCidr, Mechanism, Qualifier, SpfParseError,
};
pub use record::SpfRecord;

use crate::common::dns::DnsResolver;
use std::net::IpAddr;

/// SPF evaluation result (RFC 7208 Section 2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfResult {
    /// No SPF record found.
    None,
    /// Explicit neutral (?all or ?mechanism match).
    Neutral,
    /// Sender is authorized.
    Pass,
    /// Sender is explicitly not authorized. May carry an explanation string from exp= modifier.
    Fail { explanation: Option<String> },
    /// Sender is probably not authorized (weak fail).
    SoftFail,
    /// Transient DNS error during evaluation.
    TempError,
    /// Permanent error (syntax, too many lookups, etc.).
    PermError,
}

impl std::fmt::Display for SpfResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfResult::None => write!(f, "none"),
            SpfResult::Neutral => write!(f, "neutral"),
            SpfResult::Pass => write!(f, "pass"),
            SpfResult::Fail { .. } => write!(f, "fail"),
            SpfResult::SoftFail => write!(f, "softfail"),
            SpfResult::TempError => write!(f, "temperror"),
            SpfResult::PermError => write!(f, "permerror"),
        }
    }
}

/// SPF verifier. Wraps the eval module's check_host function.
pub struct SpfVerifier<R: DnsResolver> {
    resolver: R,
    receiver: String,
}

impl<R: DnsResolver> SpfVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            receiver: "unknown".to_string(),
        }
    }

    /// Set the receiver hostname (used for %{r} macro and explanation context).
    pub fn with_receiver(mut self, receiver: impl Into<String>) -> Self {
        self.receiver = receiver.into();
        self
    }

    /// Perform full SPF evaluation per RFC 7208 Section 4.
    pub async fn check_host(
        &self,
        ip: IpAddr,
        helo: &str,
        sender: &str,
        domain: &str,
    ) -> SpfResult {
        eval::check_host(&self.resolver, ip, helo, sender, domain, &self.receiver).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_result_display() {
        assert_eq!(SpfResult::None.to_string(), "none");
        assert_eq!(SpfResult::Neutral.to_string(), "neutral");
        assert_eq!(SpfResult::Pass.to_string(), "pass");
        assert_eq!(
            SpfResult::Fail { explanation: None }.to_string(),
            "fail"
        );
        assert_eq!(
            SpfResult::Fail {
                explanation: Some("reason".into())
            }
            .to_string(),
            "fail"
        );
        assert_eq!(SpfResult::SoftFail.to_string(), "softfail");
        assert_eq!(SpfResult::TempError.to_string(), "temperror");
        assert_eq!(SpfResult::PermError.to_string(), "permerror");
    }

    #[test]
    fn spf_result_seven_variants() {
        // Verify all 7 variants exist by exhaustive match
        let results = [
            SpfResult::None,
            SpfResult::Neutral,
            SpfResult::Pass,
            SpfResult::Fail { explanation: None },
            SpfResult::SoftFail,
            SpfResult::TempError,
            SpfResult::PermError,
        ];
        assert_eq!(results.len(), 7);
    }

    #[test]
    fn parse_and_inspect_record() {
        let r = SpfRecord::parse("v=spf1 include:_spf.google.com ~all").unwrap();
        assert_eq!(r.directives.len(), 2);
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::Include("_spf.google.com".into())
        );
        assert_eq!(r.directives[0].qualifier, Qualifier::Pass);
        assert_eq!(r.directives[1].mechanism, Mechanism::All);
        assert_eq!(r.directives[1].qualifier, Qualifier::SoftFail);
    }

    #[test]
    fn verifier_compiles_with_mock() {
        use crate::common::dns::MockResolver;
        let resolver = MockResolver::new();
        let _verifier = SpfVerifier::new(resolver);
    }

    #[test]
    fn fail_with_explanation_equality() {
        let a = SpfResult::Fail { explanation: None };
        let b = SpfResult::Fail { explanation: None };
        assert_eq!(a, b);

        let c = SpfResult::Fail {
            explanation: Some("reason".into()),
        };
        let d = SpfResult::Fail {
            explanation: Some("reason".into()),
        };
        assert_eq!(c, d);

        // Different explanations are not equal
        let e = SpfResult::Fail {
            explanation: Some("other".into()),
        };
        assert_ne!(c, e);

        // None explanation vs Some are not equal
        assert_ne!(a, c);
    }
}
