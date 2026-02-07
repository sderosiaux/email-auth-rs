pub mod record;
pub mod discover;
pub mod svg;

pub use record::{BimiRecord, BimiSelectorHeader};
pub use discover::BimiVerifier;

use crate::dmarc::{DmarcResult, Disposition, Policy};

/// BIMI validation result status.
#[derive(Debug, Clone, PartialEq)]
pub enum BimiResult {
    /// Validated successfully (record found, DMARC eligible).
    Pass,
    /// No BIMI record found.
    None,
    /// Validation failure.
    Fail { detail: String },
    /// DNS or fetch failure.
    TempError { detail: String },
    /// DMARC not eligible (p=none or DMARC fail).
    Skipped { reason: String },
    /// Domain published declination record.
    Declined,
}

/// Full BIMI validation result.
#[derive(Debug, Clone)]
pub struct BimiValidationResult {
    pub result: BimiResult,
    pub domain: String,
    pub selector: String,
    pub logo_uri: Option<String>,
    pub authority_uri: Option<String>,
}

/// Check if DMARC result qualifies for BIMI.
///
/// Requirements:
/// - DMARC disposition is Pass
/// - Applied policy is quarantine or reject (not none)
/// - pct is 100 (if record is available)
pub fn check_dmarc_eligibility(dmarc_result: &DmarcResult) -> bool {
    if dmarc_result.disposition != Disposition::Pass {
        return false;
    }

    match dmarc_result.applied_policy {
        Some(Policy::Quarantine) | Some(Policy::Reject) => {}
        _ => return false,
    }

    // Check pct == 100 if record available
    if let Some(ref record) = dmarc_result.record {
        if record.percent < 100 {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmarc::{DmarcResult, Disposition, Policy};

    fn pass_result(policy: Policy, pct: u8) -> DmarcResult {
        DmarcResult {
            disposition: Disposition::Pass,
            dkim_aligned: true,
            spf_aligned: true,
            applied_policy: Some(policy),
            record: Some(crate::dmarc::DmarcRecord {
                policy,
                subdomain_policy: policy,
                non_existent_subdomain_policy: None,
                dkim_alignment: crate::dmarc::AlignmentMode::Relaxed,
                spf_alignment: crate::dmarc::AlignmentMode::Relaxed,
                percent: pct,
                failure_options: vec![],
                report_format: crate::dmarc::record::ReportFormat::Afrf,
                report_interval: 86400,
                rua: vec![],
                ruf: vec![],
            }),
        }
    }

    #[test]
    fn test_eligible_quarantine() {
        assert!(check_dmarc_eligibility(&pass_result(Policy::Quarantine, 100)));
    }

    #[test]
    fn test_eligible_reject() {
        assert!(check_dmarc_eligibility(&pass_result(Policy::Reject, 100)));
    }

    #[test]
    fn test_not_eligible_none() {
        assert!(!check_dmarc_eligibility(&pass_result(Policy::None, 100)));
    }

    #[test]
    fn test_not_eligible_pct() {
        assert!(!check_dmarc_eligibility(&pass_result(Policy::Reject, 50)));
    }

    #[test]
    fn test_not_eligible_fail() {
        let result = DmarcResult {
            disposition: Disposition::Reject,
            dkim_aligned: false,
            spf_aligned: false,
            applied_policy: Some(Policy::Reject),
            record: None,
        };
        assert!(!check_dmarc_eligibility(&result));
    }
}
