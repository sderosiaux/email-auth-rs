mod record;
mod alignment;
mod policy;

pub use record::DmarcRecord;
pub use alignment::AlignmentMode;
pub use policy::{Policy, DmarcPolicy};

use thiserror::Error;
use crate::common::DnsResolver;
use crate::spf::SpfResult;
use crate::dkim::DkimResult;

#[derive(Debug, Clone, PartialEq)]
pub enum DmarcResult {
    Pass,
    Fail { policy: Policy },
    None,
    TempError { reason: String },
    PermError { reason: String },
}

#[derive(Debug, Error)]
pub enum DmarcError {
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("Invalid record: {0}")]
    InvalidRecord(String),
}

pub struct DmarcVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> DmarcVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub async fn verify(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult {
        let record = match self.lookup_dmarc_record(from_domain).await {
            Ok(Some(r)) => r,
            Ok(None) => return DmarcResult::None,
            Err(e) => return DmarcResult::TempError { reason: e.to_string() },
        };

        let dkim_aligned = alignment::check_dkim_alignment(
            from_domain,
            dkim_results,
            record.adkim,
        );

        let spf_aligned = alignment::check_spf_alignment(
            from_domain,
            spf_result,
            spf_domain,
            record.aspf,
        );

        if dkim_aligned || spf_aligned {
            return DmarcResult::Pass;
        }

        let applicable_policy = policy::get_applicable_policy(&record, from_domain);

        if !policy::apply_pct_sampling(record.pct) {
            return DmarcResult::Pass;
        }

        DmarcResult::Fail { policy: applicable_policy }
    }

    async fn lookup_dmarc_record(&self, domain: &str) -> Result<Option<DmarcRecord>, DmarcError> {
        let dmarc_domain = format!("_dmarc.{}", domain);

        match self.resolver.query_txt(&dmarc_domain).await {
            Ok(records) => {
                for txt in &records {
                    if let Some(record) = record::parse_dmarc_record(txt) {
                        return Ok(Some(record));
                    }
                }
                let org_domain = crate::common::organizational_domain(domain);
                if org_domain != domain {
                    let org_dmarc = format!("_dmarc.{}", org_domain);
                    match self.resolver.query_txt(&org_dmarc).await {
                        Ok(org_records) => {
                            for txt in &org_records {
                                if let Some(record) = record::parse_dmarc_record(txt) {
                                    return Ok(Some(record));
                                }
                            }
                        }
                        Err(e) if e.is_nxdomain() => {}
                        Err(e) => return Err(DmarcError::Dns(e.to_string())),
                    }
                }
                Ok(None)
            }
            Err(e) if e.is_nxdomain() => {
                let org_domain = crate::common::organizational_domain(domain);
                if org_domain != domain {
                    let org_dmarc = format!("_dmarc.{}", org_domain);
                    match self.resolver.query_txt(&org_dmarc).await {
                        Ok(org_records) => {
                            for txt in &org_records {
                                if let Some(record) = record::parse_dmarc_record(txt) {
                                    return Ok(Some(record));
                                }
                            }
                            Ok(None)
                        }
                        Err(e) if e.is_nxdomain() => Ok(None),
                        Err(e) => Err(DmarcError::Dns(e.to_string())),
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(DmarcError::Dns(e.to_string())),
        }
    }
}
