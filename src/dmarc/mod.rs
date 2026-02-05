mod record;
mod alignment;
mod policy;

pub use record::DmarcRecord;
pub use alignment::AlignmentMode;
pub use policy::PolicyAction;

use crate::common::{DnsResolver, organizational_domain};
use crate::spf::SpfResult;
use crate::dkim::DkimResult;

use thiserror::Error;

#[derive(Debug, Clone)]
pub enum DmarcResult {
    Pass { policy: PolicyAction },
    Fail { policy: PolicyAction, disposition: PolicyAction },
    None,
    TempError { reason: String },
    PermError { reason: String },
}

#[derive(Debug, Error)]
pub enum DmarcError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("DNS error: {0}")]
    DnsError(String),
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
        // Lookup DMARC record
        let (record, record_domain) = match self.lookup_dmarc(from_domain).await {
            Some(r) => r,
            None => return DmarcResult::None,
        };

        // Check DKIM alignment
        let dkim_aligned = dkim_results.iter().any(|r| {
            if let DkimResult::Pass { domain, .. } = r {
                check_alignment(from_domain, domain, record.adkim)
            } else {
                false
            }
        });

        // Check SPF alignment
        let spf_aligned = matches!(spf_result, SpfResult::Pass)
            && check_alignment(from_domain, spf_domain, record.aspf);

        // Determine pass/fail
        if dkim_aligned || spf_aligned {
            return DmarcResult::Pass {
                policy: record.policy.clone(),
            };
        }

        // Determine applicable policy
        let applicable_policy = self.get_applicable_policy(&record, from_domain, &record_domain);

        // Apply pct sampling
        let disposition = if should_apply_policy(record.pct) {
            applicable_policy.clone()
        } else {
            PolicyAction::None
        };

        DmarcResult::Fail {
            policy: applicable_policy,
            disposition,
        }
    }

    async fn lookup_dmarc(&self, domain: &str) -> Option<(DmarcRecord, String)> {
        // Try direct domain first
        let dmarc_domain = format!("_dmarc.{}", domain);
        if let Some(record) = self.query_dmarc(&dmarc_domain).await {
            return Some((record, domain.to_string()));
        }

        // Fall back to organizational domain
        if let Some(org_domain) = organizational_domain(domain) {
            if org_domain != domain {
                let dmarc_domain = format!("_dmarc.{}", org_domain);
                if let Some(record) = self.query_dmarc(&dmarc_domain).await {
                    return Some((record, org_domain));
                }
            }
        }

        None
    }

    async fn query_dmarc(&self, domain: &str) -> Option<DmarcRecord> {
        match self.resolver.query_txt(domain).await {
            Ok(records) => {
                for record in records {
                    if record.starts_with("v=DMARC1") {
                        return DmarcRecord::parse(&record).ok();
                    }
                }
                None
            }
            Err(_) => None,
        }
    }

    fn get_applicable_policy(
        &self,
        record: &DmarcRecord,
        from_domain: &str,
        record_domain: &str,
    ) -> PolicyAction {
        // Check if this is a subdomain of the organizational domain
        let is_subdomain = from_domain != record_domain;

        if is_subdomain {
            // Check for np= (non-existent subdomain policy) - RFC 7489 extension
            if let Some(ref np) = record.np {
                // np= applies to subdomains that don't have their own DMARC record
                return np.clone();
            }
            // Check for sp= (subdomain policy)
            if let Some(ref sp) = record.sp {
                return sp.clone();
            }
        }

        // Default to p=
        record.policy.clone()
    }
}

fn check_alignment(from_domain: &str, auth_domain: &str, mode: AlignmentMode) -> bool {
    let from_lower = from_domain.to_lowercase();
    let auth_lower = auth_domain.to_lowercase();

    match mode {
        AlignmentMode::Strict => from_lower == auth_lower,
        AlignmentMode::Relaxed => {
            // Check if organizational domains match
            let from_org = organizational_domain(&from_lower).unwrap_or_else(|| from_lower.clone());
            let auth_org = organizational_domain(&auth_lower).unwrap_or_else(|| auth_lower.clone());
            from_org == auth_org
        }
    }
}

fn should_apply_policy(pct: u8) -> bool {
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }

    let mut rng = rand::rng();
    let roll: u8 = rand::Rng::random_range(&mut rng, 1..=100);
    roll <= pct
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_alignment() {
        assert!(check_alignment("example.com", "example.com", AlignmentMode::Strict));
        assert!(!check_alignment("sub.example.com", "example.com", AlignmentMode::Strict));
    }

    #[test]
    fn test_relaxed_alignment() {
        // These tests may fail if PSL fetch fails
        // In production, PSL should be cached
        assert!(check_alignment("example.com", "example.com", AlignmentMode::Relaxed));
    }

    #[test]
    fn test_pct_sampling() {
        // Test edge cases
        assert!(should_apply_policy(100));
        assert!(!should_apply_policy(0));
    }
}
