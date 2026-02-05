mod alignment;
mod policy;
mod record;

use std::sync::Arc;

use crate::common::dns::DnsResolver;
use crate::common::psl::PublicSuffixList;
use crate::dkim::DkimResult;
use crate::spf::SpfResult;

pub use record::{DmarcRecord, ParseError, Policy};

/// DMARC evaluation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcResult {
    pub disposition: Disposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub policy: Option<Policy>,
    pub record: Option<DmarcRecord>,
}

impl DmarcResult {
    pub fn is_pass(&self) -> bool {
        matches!(self.disposition, Disposition::Pass)
    }

    /// No DMARC record found
    pub fn none() -> Self {
        Self {
            disposition: Disposition::None,
            dkim_aligned: false,
            spf_aligned: false,
            policy: None,
            record: None,
        }
    }
}

/// DMARC disposition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Pass,
    Quarantine,
    Reject,
    None,
}

/// DMARC verifier
pub struct DmarcVerifier<R: DnsResolver> {
    resolver: Arc<R>,
    psl: PublicSuffixList,
}

impl<R: DnsResolver> DmarcVerifier<R> {
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            psl: PublicSuffixList::new(),
        }
    }

    /// Verify DMARC for given SPF and DKIM results
    pub async fn verify(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult {
        // TODO: Implement in M5
        DmarcResult::none()
    }
}
