//! SPF check_host() evaluation algorithm (RFC 7208 Section 4)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::common::dns::{DnsError, DnsResolver};
use super::macro_exp::{expand_macros, MacroContext};
use super::mechanism::{Directive, Mechanism, Qualifier};
use super::record::SpfRecord;

/// SPF evaluation result (RFC 7208 Section 2.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

/// SPF verifier
#[derive(Clone)]
pub struct SpfVerifier<R: DnsResolver> {
    resolver: R,
    max_dns_lookups: usize,
    max_void_lookups: usize,
}

impl<R: DnsResolver> SpfVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            max_dns_lookups: 10,
            max_void_lookups: 2,
        }
    }

    /// Perform SPF check for a given IP, domain, and sender
    pub async fn check_host(
        &self,
        client_ip: IpAddr,
        domain: &str,
        sender: &str,
        helo: &str,
    ) -> SpfResult {
        let mut ctx = EvalContext {
            dns_lookups: 0,
            void_lookups: 0,
            max_dns_lookups: self.max_dns_lookups,
            max_void_lookups: self.max_void_lookups,
        };

        self.check_host_inner(client_ip, domain, sender, helo, &mut ctx)
            .await
    }

    async fn check_host_inner(
        &self,
        client_ip: IpAddr,
        domain: &str,
        sender: &str,
        helo: &str,
        ctx: &mut EvalContext,
    ) -> SpfResult {
        // Query TXT records for the domain
        let txt_records = match self.resolver.query_txt(domain).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) => return SpfResult::None,
            Err(DnsError::NoRecords) => return SpfResult::None,
            Err(_) => return SpfResult::TempError,
        };

        // Find SPF record
        let spf_records: Vec<_> = txt_records
            .iter()
            .filter(|r| r.to_lowercase().starts_with("v=spf1"))
            .collect();

        if spf_records.is_empty() {
            return SpfResult::None;
        }

        if spf_records.len() > 1 {
            return SpfResult::PermError;
        }

        let record = match SpfRecord::parse(spf_records[0]) {
            Ok(r) => r,
            Err(_) => return SpfResult::PermError,
        };

        // Evaluate directives
        let macro_ctx = MacroContext {
            sender,
            domain,
            client_ip,
            helo,
            receiver: None,
            is_exp: false,
        };

        for directive in &record.directives {
            match self.evaluate_mechanism(&directive.mechanism, client_ip, &macro_ctx, ctx).await {
                MechanismResult::Match => {
                    return qualifier_to_result(directive.qualifier);
                }
                MechanismResult::NoMatch => continue,
                MechanismResult::TempError => return SpfResult::TempError,
                MechanismResult::PermError => return SpfResult::PermError,
            }
        }

        // No match - check redirect
        if let Some(ref redirect_domain) = record.redirect {
            let expanded = match expand_macros(redirect_domain, &macro_ctx) {
                Ok(d) => d,
                Err(_) => return SpfResult::PermError,
            };

            ctx.dns_lookups += 1;
            if ctx.dns_lookups > ctx.max_dns_lookups {
                return SpfResult::PermError;
            }

            let result = Box::pin(self.check_host_inner(client_ip, &expanded, sender, helo, ctx)).await;

            // redirect to domain with no SPF = PermError
            if result == SpfResult::None {
                return SpfResult::PermError;
            }
            return result;
        }

        // Default result
        SpfResult::Neutral
    }

    async fn evaluate_mechanism(
        &self,
        mechanism: &Mechanism,
        client_ip: IpAddr,
        macro_ctx: &MacroContext<'_>,
        ctx: &mut EvalContext,
    ) -> MechanismResult {
        match mechanism {
            Mechanism::All => MechanismResult::Match,

            Mechanism::Include { domain } => {
                let expanded = match expand_macros(domain, macro_ctx) {
                    Ok(d) => d,
                    Err(_) => return MechanismResult::PermError,
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > ctx.max_dns_lookups {
                    return MechanismResult::PermError;
                }

                let result = Box::pin(self.check_host_inner(
                    client_ip,
                    &expanded,
                    macro_ctx.sender,
                    macro_ctx.helo,
                    ctx,
                ))
                .await;

                match result {
                    SpfResult::Pass => MechanismResult::Match,
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral | SpfResult::None => {
                        MechanismResult::NoMatch
                    }
                    SpfResult::TempError => MechanismResult::TempError,
                    SpfResult::PermError => MechanismResult::PermError,
                }
            }

            Mechanism::A { domain, cidr4, cidr6 } => {
                let target = match domain {
                    Some(d) => match expand_macros(d, macro_ctx) {
                        Ok(expanded) => expanded,
                        Err(_) => return MechanismResult::PermError,
                    },
                    None => macro_ctx.domain.to_string(),
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > ctx.max_dns_lookups {
                    return MechanismResult::PermError;
                }

                self.check_a_mechanism(client_ip, &target, *cidr4, *cidr6, ctx).await
            }

            Mechanism::Mx { domain, cidr4, cidr6 } => {
                let target = match domain {
                    Some(d) => match expand_macros(d, macro_ctx) {
                        Ok(expanded) => expanded,
                        Err(_) => return MechanismResult::PermError,
                    },
                    None => macro_ctx.domain.to_string(),
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > ctx.max_dns_lookups {
                    return MechanismResult::PermError;
                }

                self.check_mx_mechanism(client_ip, &target, *cidr4, *cidr6, ctx).await
            }

            Mechanism::Ptr { domain } => {
                let target = match domain {
                    Some(d) => match expand_macros(d, macro_ctx) {
                        Ok(expanded) => expanded,
                        Err(_) => return MechanismResult::PermError,
                    },
                    None => macro_ctx.domain.to_string(),
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > ctx.max_dns_lookups {
                    return MechanismResult::PermError;
                }

                self.check_ptr_mechanism(client_ip, &target, ctx).await
            }

            Mechanism::Ip4 { addr, prefix } => {
                if let IpAddr::V4(client_v4) = client_ip {
                    if ip4_in_cidr(client_v4, *addr, *prefix) {
                        MechanismResult::Match
                    } else {
                        MechanismResult::NoMatch
                    }
                } else {
                    MechanismResult::NoMatch
                }
            }

            Mechanism::Ip6 { addr, prefix } => {
                if let IpAddr::V6(client_v6) = client_ip {
                    if ip6_in_cidr(client_v6, *addr, *prefix) {
                        MechanismResult::Match
                    } else {
                        MechanismResult::NoMatch
                    }
                } else {
                    MechanismResult::NoMatch
                }
            }

            Mechanism::Exists { domain } => {
                let expanded = match expand_macros(domain, macro_ctx) {
                    Ok(d) => d,
                    Err(_) => return MechanismResult::PermError,
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > ctx.max_dns_lookups {
                    return MechanismResult::PermError;
                }

                match self.resolver.query_a(&expanded).await {
                    Ok(_) => MechanismResult::Match,
                    Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > ctx.max_void_lookups {
                            return MechanismResult::PermError;
                        }
                        MechanismResult::NoMatch
                    }
                    Err(_) => MechanismResult::TempError,
                }
            }
        }
    }

    async fn check_a_mechanism(
        &self,
        client_ip: IpAddr,
        domain: &str,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
        ctx: &mut EvalContext,
    ) -> MechanismResult {
        match client_ip {
            IpAddr::V4(client_v4) => {
                let prefix = cidr4.unwrap_or(32);
                match self.resolver.query_a(domain).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            if ip4_in_cidr(client_v4, addr, prefix) {
                                return MechanismResult::Match;
                            }
                        }
                        MechanismResult::NoMatch
                    }
                    Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > ctx.max_void_lookups {
                            return MechanismResult::PermError;
                        }
                        MechanismResult::NoMatch
                    }
                    Err(_) => MechanismResult::TempError,
                }
            }
            IpAddr::V6(client_v6) => {
                let prefix = cidr6.unwrap_or(128);
                match self.resolver.query_aaaa(domain).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            if ip6_in_cidr(client_v6, addr, prefix) {
                                return MechanismResult::Match;
                            }
                        }
                        MechanismResult::NoMatch
                    }
                    Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > ctx.max_void_lookups {
                            return MechanismResult::PermError;
                        }
                        MechanismResult::NoMatch
                    }
                    Err(_) => MechanismResult::TempError,
                }
            }
        }
    }

    async fn check_mx_mechanism(
        &self,
        client_ip: IpAddr,
        domain: &str,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
        ctx: &mut EvalContext,
    ) -> MechanismResult {
        let mx_records = match self.resolver.query_mx(domain).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                ctx.void_lookups += 1;
                if ctx.void_lookups > ctx.max_void_lookups {
                    return MechanismResult::PermError;
                }
                return MechanismResult::NoMatch;
            }
            Err(_) => return MechanismResult::TempError,
        };

        // Limit to first 10 MX records
        for (_, mx_host) in mx_records.into_iter().take(10) {
            ctx.dns_lookups += 1;
            if ctx.dns_lookups > ctx.max_dns_lookups {
                return MechanismResult::PermError;
            }

            let mx_host = mx_host.trim_end_matches('.');
            let result = self.check_a_mechanism(client_ip, mx_host, cidr4, cidr6, ctx).await;
            if matches!(result, MechanismResult::Match) {
                return MechanismResult::Match;
            }
            if matches!(result, MechanismResult::TempError | MechanismResult::PermError) {
                return result;
            }
        }

        MechanismResult::NoMatch
    }

    async fn check_ptr_mechanism(
        &self,
        client_ip: IpAddr,
        target_domain: &str,
        ctx: &mut EvalContext,
    ) -> MechanismResult {
        // PTR lookup
        let ptr_names = match self.resolver.query_ptr(client_ip).await {
            Ok(names) => names,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                ctx.void_lookups += 1;
                if ctx.void_lookups > ctx.max_void_lookups {
                    return MechanismResult::PermError;
                }
                return MechanismResult::NoMatch;
            }
            Err(_) => return MechanismResult::TempError,
        };

        // Limit to 10 PTR records
        for ptr_name in ptr_names.into_iter().take(10) {
            ctx.dns_lookups += 1;
            if ctx.dns_lookups > ctx.max_dns_lookups {
                return MechanismResult::PermError;
            }

            let ptr_name = ptr_name.trim_end_matches('.');

            // Forward lookup to validate
            let validated = match client_ip {
                IpAddr::V4(v4) => {
                    match self.resolver.query_a(ptr_name).await {
                        Ok(addrs) => addrs.contains(&v4),
                        Err(_) => false,
                    }
                }
                IpAddr::V6(v6) => {
                    match self.resolver.query_aaaa(ptr_name).await {
                        Ok(addrs) => addrs.contains(&v6),
                        Err(_) => false,
                    }
                }
            };

            if validated {
                // Check if ptr_name ends with target_domain
                let ptr_lower = ptr_name.to_lowercase();
                let target_lower = target_domain.to_lowercase();

                if ptr_lower == target_lower || ptr_lower.ends_with(&format!(".{}", target_lower)) {
                    return MechanismResult::Match;
                }
            }
        }

        MechanismResult::NoMatch
    }
}

struct EvalContext {
    dns_lookups: usize,
    void_lookups: usize,
    max_dns_lookups: usize,
    max_void_lookups: usize,
}

enum MechanismResult {
    Match,
    NoMatch,
    TempError,
    PermError,
}

fn qualifier_to_result(q: Qualifier) -> SpfResult {
    match q {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail,
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

fn ip4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }

    let mask = !((1u32 << (32 - prefix)) - 1);
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

    let mask = !((1u128 << (128 - prefix)) - 1);
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
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;

        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_simple_fail() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;

        assert_eq!(result, SpfResult::Fail);
    }

    #[tokio::test]
    async fn test_no_spf_record() {
        let resolver = MockResolver::new();
        // No TXT record added

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;

        assert_eq!(result, SpfResult::None);
    }

    #[tokio::test]
    async fn test_include_pass() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.example.net -all".to_string()]);
        resolver.add_txt("_spf.example.net", vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;

        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_a_mechanism() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 a -all".to_string()]);
        resolver.add_a("example.com", vec![Ipv4Addr::new(192, 0, 2, 1)]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;

        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_redirect() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 redirect=_spf.example.net".to_string()]);
        resolver.add_txt("_spf.example.net", vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;

        assert_eq!(result, SpfResult::Pass);
    }

    #[test]
    fn test_ip4_in_cidr() {
        assert!(ip4_in_cidr(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 0),
            24
        ));
        assert!(!ip4_in_cidr(
            Ipv4Addr::new(192, 0, 3, 1),
            Ipv4Addr::new(192, 0, 2, 0),
            24
        ));
        assert!(ip4_in_cidr(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            32
        ));
    }
}
