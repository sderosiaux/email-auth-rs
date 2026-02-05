//! SPF check_host() evaluation algorithm (RFC 7208 Section 4).

use super::macro_exp::{expand, MacroContext};
use super::mechanism::{Mechanism, Qualifier};
use super::record::SpfRecord;
use super::{SpfError, SpfResult};
use crate::common::dns::{DnsError, DnsResolver};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_DNS_LOOKUPS: usize = 10;
const MAX_VOID_LOOKUPS: usize = 2;

/// SPF verifier.
#[derive(Clone)]
pub struct SpfVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> SpfVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Perform SPF check_host() evaluation.
    pub async fn check_host(
        &self,
        client_ip: IpAddr,
        domain: &str,
        sender: &str,
    ) -> SpfResult {
        let mut state = EvalState::new();
        self.check_host_inner(client_ip, domain, sender, domain, &mut state)
            .await
    }

    async fn check_host_inner(
        &self,
        client_ip: IpAddr,
        domain: &str,
        sender: &str,
        helo: &str,
        state: &mut EvalState,
    ) -> SpfResult {
        // Get SPF record
        let record = match self.get_spf_record(domain, state).await {
            Ok(Some(r)) => r,
            Ok(None) => return SpfResult::None,
            Err(SpfError::DnsError(DnsError::NxDomain)) => return SpfResult::None,
            Err(SpfError::DnsError(DnsError::ServFail | DnsError::Timeout)) => {
                return SpfResult::TempError
            }
            Err(_) => return SpfResult::PermError,
        };

        let ctx = MacroContext::new(sender, domain, client_ip, helo, "");

        // Evaluate directives
        for directive in &record.directives {
            if state.dns_lookups > MAX_DNS_LOOKUPS {
                return SpfResult::PermError;
            }

            let matched = match &directive.mechanism {
                Mechanism::All => true,
                Mechanism::Include { domain: inc_domain } => {
                    let expanded = match expand(inc_domain, &ctx) {
                        Ok(d) => d,
                        Err(_) => return SpfResult::PermError,
                    };
                    state.dns_lookups += 1;
                    let result = Box::pin(self.check_host_inner(
                        client_ip, &expanded, sender, helo, state,
                    ))
                    .await;
                    match result {
                        SpfResult::Pass => true,
                        SpfResult::TempError => return SpfResult::TempError,
                        SpfResult::PermError => return SpfResult::PermError,
                        _ => false,
                    }
                }
                Mechanism::A { domain: a_domain, cidr4, cidr6 } => {
                    let target = match a_domain {
                        Some(d) => match expand(d, &ctx) {
                            Ok(expanded) => expanded,
                            Err(_) => return SpfResult::PermError,
                        },
                        None => domain.to_string(),
                    };
                    state.dns_lookups += 1;
                    self.check_a(&target, client_ip, *cidr4, *cidr6, state).await
                }
                Mechanism::Mx { domain: mx_domain, cidr4, cidr6 } => {
                    let target = match mx_domain {
                        Some(d) => match expand(d, &ctx) {
                            Ok(expanded) => expanded,
                            Err(_) => return SpfResult::PermError,
                        },
                        None => domain.to_string(),
                    };
                    state.dns_lookups += 1;
                    match self.check_mx(&target, client_ip, *cidr4, *cidr6, state).await {
                        Ok(matched) => matched,
                        Err(SpfError::DnsError(DnsError::ServFail | DnsError::Timeout)) => {
                            return SpfResult::TempError
                        }
                        Err(_) => false,
                    }
                }
                Mechanism::Ptr { domain: ptr_domain } => {
                    let target = match ptr_domain {
                        Some(d) => match expand(d, &ctx) {
                            Ok(expanded) => expanded,
                            Err(_) => return SpfResult::PermError,
                        },
                        None => domain.to_string(),
                    };
                    state.dns_lookups += 1;
                    self.check_ptr(client_ip, &target, state).await
                }
                Mechanism::Ip4 { addr, prefix } => {
                    if let IpAddr::V4(client_v4) = client_ip {
                        ip4_in_cidr(client_v4, *addr, *prefix)
                    } else {
                        false
                    }
                }
                Mechanism::Ip6 { addr, prefix } => {
                    if let IpAddr::V6(client_v6) = client_ip {
                        ip6_in_cidr(client_v6, *addr, *prefix)
                    } else {
                        false
                    }
                }
                Mechanism::Exists { domain: exists_domain } => {
                    let expanded = match expand(exists_domain, &ctx) {
                        Ok(d) => d,
                        Err(_) => return SpfResult::PermError,
                    };
                    state.dns_lookups += 1;
                    match self.resolver.query_a(&expanded).await {
                        Ok(addrs) => !addrs.is_empty(),
                        Err(DnsError::NxDomain | DnsError::NoRecords) => {
                            state.void_lookups += 1;
                            if state.void_lookups > MAX_VOID_LOOKUPS {
                                return SpfResult::PermError;
                            }
                            false
                        }
                        Err(DnsError::ServFail | DnsError::Timeout) => {
                            return SpfResult::TempError
                        }
                        Err(_) => false,
                    }
                }
            };

            if matched {
                return match directive.qualifier {
                    Qualifier::Pass => SpfResult::Pass,
                    Qualifier::Fail => SpfResult::Fail { explanation: None },
                    Qualifier::SoftFail => SpfResult::SoftFail,
                    Qualifier::Neutral => SpfResult::Neutral,
                };
            }
        }

        // No match, check redirect
        if let Some(redirect) = &record.redirect {
            let expanded = match expand(redirect, &ctx) {
                Ok(d) => d,
                Err(_) => return SpfResult::PermError,
            };
            state.dns_lookups += 1;
            let result = Box::pin(self.check_host_inner(
                client_ip, &expanded, sender, helo, state,
            ))
            .await;
            if matches!(result, SpfResult::None) {
                return SpfResult::PermError; // redirect to no-SPF is PermError
            }
            return result;
        }

        // Default result is Neutral
        SpfResult::Neutral
    }

    async fn get_spf_record(
        &self,
        domain: &str,
        state: &mut EvalState,
    ) -> Result<Option<SpfRecord>, SpfError> {
        let txt_records = match self.resolver.query_txt(domain).await {
            Ok(r) => r,
            Err(DnsError::NxDomain | DnsError::NoRecords) => {
                state.void_lookups += 1;
                return Ok(None);
            }
            Err(e) => return Err(SpfError::DnsError(e)),
        };

        // Find SPF records (start with v=spf1)
        let spf_records: Vec<_> = txt_records
            .iter()
            .filter(|r| r.to_lowercase().starts_with("v=spf1"))
            .collect();

        match spf_records.len() {
            0 => Ok(None),
            1 => Ok(Some(SpfRecord::parse(spf_records[0])?)),
            _ => Err(SpfError::InvalidRecord("multiple SPF records".into())),
        }
    }

    async fn check_a(
        &self,
        domain: &str,
        client_ip: IpAddr,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
        state: &mut EvalState,
    ) -> bool {
        match client_ip {
            IpAddr::V4(client_v4) => {
                let prefix = cidr4.unwrap_or(32);
                match self.resolver.query_a(domain).await {
                    Ok(addrs) => addrs.iter().any(|a| ip4_in_cidr(client_v4, *a, prefix)),
                    Err(DnsError::NxDomain | DnsError::NoRecords) => {
                        state.void_lookups += 1;
                        false
                    }
                    Err(_) => false,
                }
            }
            IpAddr::V6(client_v6) => {
                let prefix = cidr6.unwrap_or(128);
                match self.resolver.query_aaaa(domain).await {
                    Ok(addrs) => addrs.iter().any(|a| ip6_in_cidr(client_v6, *a, prefix)),
                    Err(DnsError::NxDomain | DnsError::NoRecords) => {
                        state.void_lookups += 1;
                        false
                    }
                    Err(_) => false,
                }
            }
        }
    }

    async fn check_mx(
        &self,
        domain: &str,
        client_ip: IpAddr,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
        state: &mut EvalState,
    ) -> Result<bool, SpfError> {
        let mx_records = match self.resolver.query_mx(domain).await {
            Ok(r) => r,
            Err(DnsError::NxDomain | DnsError::NoRecords) => {
                state.void_lookups += 1;
                return Ok(false);
            }
            Err(e) => return Err(SpfError::DnsError(e)),
        };

        // Limit to first 10 MX records
        for mx in mx_records.iter().take(10) {
            if state.dns_lookups > MAX_DNS_LOOKUPS {
                return Err(SpfError::LookupLimitExceeded);
            }
            state.dns_lookups += 1;

            if self.check_a(&mx.exchange, client_ip, cidr4, cidr6, state).await {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn check_ptr(
        &self,
        client_ip: IpAddr,
        domain: &str,
        state: &mut EvalState,
    ) -> bool {
        // PTR is deprecated but must be supported
        let names = match self.resolver.query_ptr(client_ip).await {
            Ok(n) => n,
            Err(_) => {
                state.void_lookups += 1;
                return false;
            }
        };

        let domain_lower = domain.to_lowercase();

        // Limit to first 10 PTR results
        for name in names.iter().take(10) {
            if state.dns_lookups > MAX_DNS_LOOKUPS {
                return false;
            }
            state.dns_lookups += 1;

            // Forward lookup to validate
            let forward_ips = match client_ip {
                IpAddr::V4(_) => self.resolver.query_a(&name).await.ok().map(|v| {
                    v.into_iter().map(IpAddr::V4).collect::<Vec<_>>()
                }),
                IpAddr::V6(_) => self.resolver.query_aaaa(&name).await.ok().map(|v| {
                    v.into_iter().map(IpAddr::V6).collect::<Vec<_>>()
                }),
            };

            if let Some(ips) = forward_ips {
                if ips.contains(&client_ip) {
                    // Validated hostname - check if it matches domain
                    let name_lower = name.to_lowercase();
                    let name_lower = name_lower.strip_suffix('.').unwrap_or(&name_lower);
                    if name_lower == domain_lower
                        || name_lower.ends_with(&format!(".{}", domain_lower))
                    {
                        return true;
                    }
                }
            }
        }

        false
    }
}

struct EvalState {
    dns_lookups: usize,
    void_lookups: usize,
}

impl EvalState {
    fn new() -> Self {
        Self {
            dns_lookups: 0,
            void_lookups: 0,
        }
    }
}

fn ip4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = !0u32 << (32 - prefix);
    let ip_bits = u32::from(ip);
    let net_bits = u32::from(network);
    (ip_bits & mask) == (net_bits & mask)
}

fn ip6_in_cidr(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let mask = !0u128 << (128 - prefix);
    let ip_bits = u128::from(ip);
    let net_bits = u128::from(network);
    (ip_bits & mask) == (net_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[tokio::test]
    async fn test_simple_pass() {
        let resolver = MockResolver::new()
            .with_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
            )
            .await;

        assert!(matches!(result, SpfResult::Pass));
    }

    #[tokio::test]
    async fn test_simple_fail() {
        let resolver = MockResolver::new()
            .with_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                "example.com",
                "user@example.com",
            )
            .await;

        assert!(matches!(result, SpfResult::Fail { .. }));
    }

    #[tokio::test]
    async fn test_include_pass() {
        let resolver = MockResolver::new()
            .with_txt("example.com", vec!["v=spf1 include:_spf.example.com -all".into()])
            .with_txt("_spf.example.com", vec!["v=spf1 ip4:10.0.0.0/8 -all".into()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                "example.com",
                "user@example.com",
            )
            .await;

        assert!(matches!(result, SpfResult::Pass));
    }

    #[tokio::test]
    async fn test_no_record() {
        let resolver = MockResolver::new();

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
            )
            .await;

        assert!(matches!(result, SpfResult::None));
    }

    #[tokio::test]
    async fn test_a_mechanism() {
        let resolver = MockResolver::new()
            .with_txt("example.com", vec!["v=spf1 a -all".into()])
            .with_a("example.com", vec![Ipv4Addr::new(93, 184, 216, 34)]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                "example.com",
                "user@example.com",
            )
            .await;

        assert!(matches!(result, SpfResult::Pass));
    }

    #[test]
    fn test_ip4_cidr() {
        assert!(ip4_in_cidr(
            Ipv4Addr::new(192, 0, 2, 100),
            Ipv4Addr::new(192, 0, 2, 0),
            24
        ));
        assert!(!ip4_in_cidr(
            Ipv4Addr::new(192, 0, 3, 1),
            Ipv4Addr::new(192, 0, 2, 0),
            24
        ));
    }
}
