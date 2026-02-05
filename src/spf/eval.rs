use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::common::{DnsResolver, DnsError};
use super::record::SpfRecord;
use super::mechanism::{Mechanism, Qualifier};
use super::macro_exp::MacroContext;
use super::SpfResult;

pub struct SpfVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> SpfVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub async fn check_host(&self, ip: IpAddr, domain: &str, sender: &str) -> SpfResult {
        let mut ctx = EvalContext {
            dns_lookups: 0,
            void_lookups: 0,
        };

        self.check_host_inner(ip, domain, sender, domain, &mut ctx).await
    }

    fn check_host_inner<'a>(
        &'a self,
        ip: IpAddr,
        domain: &'a str,
        sender: &'a str,
        helo: &'a str,
        ctx: &'a mut EvalContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SpfResult> + Send + 'a>> {
        Box::pin(async move {
            if ctx.dns_lookups >= 10 {
                return SpfResult::PermError;
            }

            ctx.dns_lookups += 1;

            let txt_records = match self.resolver.query_txt(domain).await {
                Ok(records) => records,
                Err(DnsError::NxDomain) => return SpfResult::None,
                Err(_) => return SpfResult::TempError,
            };

            let spf_record = txt_records
                .iter()
                .find(|r| r.starts_with("v=spf1"))
                .map(|r| r.as_str());

            let record_str = match spf_record {
                Some(r) => r,
                None => return SpfResult::None,
            };

            let record = match SpfRecord::parse(record_str) {
                Ok(r) => r,
                Err(_) => return SpfResult::PermError,
            };

            let macro_ctx = MacroContext {
                sender,
                domain,
                ip,
                helo,
            };

            for (qualifier, mechanism) in &record.mechanisms {
                let matches = self.check_mechanism(mechanism, ip, domain, &macro_ctx, ctx).await;

                if let Some(true) = matches {
                    return qualifier_to_result(qualifier);
                }

                if matches.is_none() {
                    return SpfResult::TempError;
                }
            }

            // Check redirect
            if let Some(ref redirect_domain) = record.redirect {
                let expanded = macro_ctx.expand(redirect_domain);
                return self.check_host_inner(ip, &expanded, sender, helo, ctx).await;
            }

            SpfResult::Neutral
        })
    }

    async fn check_mechanism(
        &self,
        mechanism: &Mechanism,
        ip: IpAddr,
        domain: &str,
        macro_ctx: &MacroContext<'_>,
        ctx: &mut EvalContext,
    ) -> Option<bool> {
        match mechanism {
            Mechanism::All => Some(true),

            Mechanism::Include(target) => {
                let expanded = macro_ctx.expand(target);
                let result = self.check_host_inner(ip, &expanded, macro_ctx.sender, macro_ctx.helo, ctx).await;
                Some(matches!(result, SpfResult::Pass))
            }

            Mechanism::A(target, prefix4, prefix6) => {
                if ctx.dns_lookups >= 10 {
                    return None;
                }
                ctx.dns_lookups += 1;

                let target_domain = target.as_ref().map(|t| macro_ctx.expand(t)).unwrap_or_else(|| domain.to_string());

                let prefix = match ip {
                    IpAddr::V4(_) => prefix4.unwrap_or(32),
                    IpAddr::V6(_) => prefix6.unwrap_or(128),
                };

                let addrs = match ip {
                    IpAddr::V4(_) => self.resolver.query_a(&target_domain).await,
                    IpAddr::V6(_) => self.resolver.query_aaaa(&target_domain).await,
                };

                match addrs {
                    Ok(addresses) => {
                        for addr in addresses {
                            if ip_in_network(ip, addr, prefix) {
                                return Some(true);
                            }
                        }
                        Some(false)
                    }
                    Err(DnsError::NxDomain) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > 2 {
                            return None;
                        }
                        Some(false)
                    }
                    Err(_) => None,
                }
            }

            Mechanism::Mx(target, prefix4, prefix6) => {
                if ctx.dns_lookups >= 10 {
                    return None;
                }
                ctx.dns_lookups += 1;

                let target_domain = target.as_ref().map(|t| macro_ctx.expand(t)).unwrap_or_else(|| domain.to_string());

                let mx_records = match self.resolver.query_mx(&target_domain).await {
                    Ok(records) => records,
                    Err(DnsError::NxDomain) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > 2 {
                            return None;
                        }
                        return Some(false);
                    }
                    Err(_) => return None,
                };

                let prefix = match ip {
                    IpAddr::V4(_) => prefix4.unwrap_or(32),
                    IpAddr::V6(_) => prefix6.unwrap_or(128),
                };

                for mx in mx_records.iter().take(10) {
                    if ctx.dns_lookups >= 10 {
                        return None;
                    }
                    ctx.dns_lookups += 1;

                    let addrs = match ip {
                        IpAddr::V4(_) => self.resolver.query_a(mx).await,
                        IpAddr::V6(_) => self.resolver.query_aaaa(mx).await,
                    };

                    if let Ok(addresses) = addrs {
                        for addr in addresses {
                            if ip_in_network(ip, addr, prefix) {
                                return Some(true);
                            }
                        }
                    }
                }

                Some(false)
            }

            Mechanism::Ptr(_) => {
                // PTR mechanism is deprecated and rarely used
                Some(false)
            }

            Mechanism::Ip4(network, prefix) => {
                if let IpAddr::V4(client_ip) = ip {
                    Some(ipv4_in_network(client_ip, *network, *prefix))
                } else {
                    Some(false)
                }
            }

            Mechanism::Ip6(network, prefix) => {
                if let IpAddr::V6(client_ip) = ip {
                    Some(ipv6_in_network(client_ip, *network, *prefix))
                } else {
                    Some(false)
                }
            }

            Mechanism::Exists(target) => {
                if ctx.dns_lookups >= 10 {
                    return None;
                }
                ctx.dns_lookups += 1;

                let expanded = macro_ctx.expand(target);
                match self.resolver.query_a(&expanded).await {
                    Ok(addrs) if !addrs.is_empty() => Some(true),
                    Ok(_) => Some(false),
                    Err(DnsError::NxDomain) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > 2 {
                            return None;
                        }
                        Some(false)
                    }
                    Err(_) => None,
                }
            }
        }
    }
}

struct EvalContext {
    dns_lookups: u32,
    void_lookups: u32,
}

fn qualifier_to_result(qualifier: &Qualifier) -> SpfResult {
    match qualifier {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail,
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => ipv4_in_network(ip, net, prefix),
        (IpAddr::V6(ip), IpAddr::V6(net)) => ipv6_in_network(ip, net, prefix),
        _ => false,
    }
}

fn ipv4_in_network(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
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

fn ipv6_in_network(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let ip_bits = u128::from(ip);
    let net_bits = u128::from(network);
    let mask = !0u128 << (128 - prefix);
    (ip_bits & mask) == (net_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::MockResolver;

    #[tokio::test]
    async fn test_simple_pass() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.168.1.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier.check_host(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "example.com",
            "user@example.com"
        ).await;

        assert!(matches!(result, SpfResult::Pass));
    }

    #[tokio::test]
    async fn test_simple_fail() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.168.1.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier.check_host(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "example.com",
            "user@example.com"
        ).await;

        assert!(matches!(result, SpfResult::Fail));
    }

    #[tokio::test]
    async fn test_no_record() {
        let resolver = MockResolver::new();

        let verifier = SpfVerifier::new(resolver);
        let result = verifier.check_host(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "example.com",
            "user@example.com"
        ).await;

        assert!(matches!(result, SpfResult::None));
    }
}
