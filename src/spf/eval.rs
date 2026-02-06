use std::net::IpAddr;
use crate::common::DnsResolver;
use super::{SpfResult, SpfRecord};
use super::mechanism::{Mechanism, Qualifier};
use super::macro_exp::{expand_macros, MacroContext};

const MAX_DNS_LOOKUPS: usize = 10;
const MAX_VOID_LOOKUPS: usize = 2;

pub struct SpfVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> SpfVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub async fn check_host(&self, ip: IpAddr, domain: &str, sender: &str) -> SpfResult {
        let mut state = CheckState {
            dns_lookups: 0,
            void_lookups: 0,
        };

        self.check_host_inner(ip, domain, sender, &mut state).await
    }

    async fn check_host_inner(
        &self,
        ip: IpAddr,
        domain: &str,
        sender: &str,
        state: &mut CheckState,
    ) -> SpfResult {
        let txt_records = match self.resolver.query_txt(domain).await {
            Ok(records) => records,
            Err(e) if e.is_nxdomain() => return SpfResult::None,
            Err(_) => return SpfResult::TempError,
        };

        let spf_txt = txt_records.iter().find(|r| r.to_lowercase().starts_with("v=spf1"));

        let record = match spf_txt.and_then(|t| SpfRecord::parse(t)) {
            Some(r) => r,
            None => return SpfResult::None,
        };

        let ctx = MacroContext {
            sender,
            domain,
            ip,
            helo: domain,
        };

        for mech in &record.mechanisms {
            match self.evaluate_mechanism(mech, ip, domain, &ctx, state).await {
                MechResult::Match(q) => return qualifier_to_result(q),
                MechResult::NoMatch => continue,
                MechResult::TempError => return SpfResult::TempError,
                MechResult::PermError => return SpfResult::PermError,
            }
        }

        if let Some(ref redirect) = record.redirect {
            state.dns_lookups += 1;
            if state.dns_lookups > MAX_DNS_LOOKUPS {
                return SpfResult::PermError;
            }
            let redirect_domain = expand_macros(redirect, &ctx);
            return Box::pin(self.check_host_inner(ip, &redirect_domain, sender, state)).await;
        }

        SpfResult::Neutral
    }

    async fn evaluate_mechanism(
        &self,
        mech: &Mechanism,
        ip: IpAddr,
        domain: &str,
        ctx: &MacroContext<'_>,
        state: &mut CheckState,
    ) -> MechResult {
        match mech {
            Mechanism::All(q) => MechResult::Match(*q),

            Mechanism::Include { qualifier, domain: inc_domain } => {
                state.dns_lookups += 1;
                if state.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechResult::PermError;
                }

                let expanded = expand_macros(inc_domain, ctx);
                let result = Box::pin(self.check_host_inner(ip, &expanded, ctx.sender, state)).await;

                match result {
                    SpfResult::Pass => MechResult::Match(*qualifier),
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => MechResult::NoMatch,
                    SpfResult::TempError => MechResult::TempError,
                    SpfResult::PermError | SpfResult::None => MechResult::PermError,
                }
            }

            Mechanism::A { qualifier, domain: a_domain, prefix4, prefix6 } => {
                state.dns_lookups += 1;
                if state.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechResult::PermError;
                }

                let target = a_domain.as_ref().map(|d| expand_macros(d, ctx)).unwrap_or_else(|| domain.to_string());
                self.check_a_mechanism(ip, &target, *prefix4, *prefix6, *qualifier, state).await
            }

            Mechanism::Mx { qualifier, domain: mx_domain, prefix4, prefix6 } => {
                state.dns_lookups += 1;
                if state.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechResult::PermError;
                }

                let target = mx_domain.as_ref().map(|d| expand_macros(d, ctx)).unwrap_or_else(|| domain.to_string());
                self.check_mx_mechanism(ip, &target, *prefix4, *prefix6, *qualifier, state).await
            }

            Mechanism::Ptr { qualifier, domain: ptr_domain } => {
                state.dns_lookups += 1;
                if state.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechResult::PermError;
                }

                let target = ptr_domain.as_ref().map(|d| expand_macros(d, ctx)).unwrap_or_else(|| domain.to_string());
                self.check_ptr_mechanism(ip, &target, *qualifier, state).await
            }

            Mechanism::Ip4 { qualifier, addr, prefix } => {
                if ip_matches(ip, *addr, *prefix) {
                    MechResult::Match(*qualifier)
                } else {
                    MechResult::NoMatch
                }
            }

            Mechanism::Ip6 { qualifier, addr, prefix } => {
                if ip_matches(ip, *addr, *prefix) {
                    MechResult::Match(*qualifier)
                } else {
                    MechResult::NoMatch
                }
            }

            Mechanism::Exists { qualifier, domain: exists_domain } => {
                state.dns_lookups += 1;
                if state.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechResult::PermError;
                }

                let expanded = expand_macros(exists_domain, ctx);
                match self.resolver.query_exists(&expanded).await {
                    Ok(true) => MechResult::Match(*qualifier),
                    Ok(false) => {
                        state.void_lookups += 1;
                        if state.void_lookups > MAX_VOID_LOOKUPS {
                            return MechResult::PermError;
                        }
                        MechResult::NoMatch
                    }
                    Err(_) => MechResult::TempError,
                }
            }
        }
    }

    async fn check_a_mechanism(
        &self,
        ip: IpAddr,
        domain: &str,
        prefix4: Option<u8>,
        prefix6: Option<u8>,
        qualifier: Qualifier,
        state: &mut CheckState,
    ) -> MechResult {
        let result = match ip {
            IpAddr::V4(_) => self.resolver.query_a(domain).await,
            IpAddr::V6(_) => self.resolver.query_aaaa(domain).await,
        };

        match result {
            Ok(addrs) => {
                let prefix = match ip {
                    IpAddr::V4(_) => prefix4,
                    IpAddr::V6(_) => prefix6,
                };
                for addr in addrs {
                    if ip_matches(ip, addr, prefix) {
                        return MechResult::Match(qualifier);
                    }
                }
                MechResult::NoMatch
            }
            Err(e) if e.is_nxdomain() => {
                state.void_lookups += 1;
                if state.void_lookups > MAX_VOID_LOOKUPS {
                    return MechResult::PermError;
                }
                MechResult::NoMatch
            }
            Err(_) => MechResult::TempError,
        }
    }

    async fn check_mx_mechanism(
        &self,
        ip: IpAddr,
        domain: &str,
        prefix4: Option<u8>,
        prefix6: Option<u8>,
        qualifier: Qualifier,
        state: &mut CheckState,
    ) -> MechResult {
        let mx_hosts = match self.resolver.query_mx(domain).await {
            Ok(hosts) => hosts,
            Err(e) if e.is_nxdomain() => {
                state.void_lookups += 1;
                if state.void_lookups > MAX_VOID_LOOKUPS {
                    return MechResult::PermError;
                }
                return MechResult::NoMatch;
            }
            Err(_) => return MechResult::TempError,
        };

        for host in mx_hosts.iter().take(10) {
            state.dns_lookups += 1;
            if state.dns_lookups > MAX_DNS_LOOKUPS {
                return MechResult::PermError;
            }

            let result = match ip {
                IpAddr::V4(_) => self.resolver.query_a(host).await,
                IpAddr::V6(_) => self.resolver.query_aaaa(host).await,
            };

            if let Ok(addrs) = result {
                let prefix = match ip {
                    IpAddr::V4(_) => prefix4,
                    IpAddr::V6(_) => prefix6,
                };
                for addr in addrs {
                    if ip_matches(ip, addr, prefix) {
                        return MechResult::Match(qualifier);
                    }
                }
            }
        }

        MechResult::NoMatch
    }

    async fn check_ptr_mechanism(
        &self,
        ip: IpAddr,
        domain: &str,
        qualifier: Qualifier,
        state: &mut CheckState,
    ) -> MechResult {
        let names = match self.resolver.query_ptr(ip).await {
            Ok(n) => n,
            Err(e) if e.is_nxdomain() => {
                state.void_lookups += 1;
                if state.void_lookups > MAX_VOID_LOOKUPS {
                    return MechResult::PermError;
                }
                return MechResult::NoMatch;
            }
            Err(_) => return MechResult::TempError,
        };

        let domain_lower = domain.to_lowercase();

        for name in names.iter().take(10) {
            state.dns_lookups += 1;
            if state.dns_lookups > MAX_DNS_LOOKUPS {
                return MechResult::PermError;
            }

            let name_lower = name.to_lowercase();
            let name_lower = name_lower.strip_suffix('.').unwrap_or(&name_lower);

            if name_lower == domain_lower || name_lower.ends_with(&format!(".{}", domain_lower)) {
                let result = match ip {
                    IpAddr::V4(_) => self.resolver.query_a(name).await,
                    IpAddr::V6(_) => self.resolver.query_aaaa(name).await,
                };

                if let Ok(addrs) = result {
                    if addrs.contains(&ip) {
                        return MechResult::Match(qualifier);
                    }
                }
            }
        }

        MechResult::NoMatch
    }
}

struct CheckState {
    dns_lookups: usize,
    void_lookups: usize,
}

enum MechResult {
    Match(Qualifier),
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

fn ip_matches(client_ip: IpAddr, record_ip: IpAddr, prefix: Option<u8>) -> bool {
    match (client_ip, record_ip) {
        (IpAddr::V4(client), IpAddr::V4(record)) => {
            let prefix = prefix.unwrap_or(32).min(32);
            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            (u32::from(client) & mask) == (u32::from(record) & mask)
        }
        (IpAddr::V6(client), IpAddr::V6(record)) => {
            let prefix = prefix.unwrap_or(128).min(128);
            let client_bits = u128::from(client);
            let record_bits = u128::from(record);
            let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
            (client_bits & mask) == (record_bits & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::MockResolver;

    #[tokio::test]
    async fn test_simple_pass() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.168.1.0/24 -all".into()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier.check_host("192.168.1.100".parse().unwrap(), "example.com", "test@example.com").await;

        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_simple_fail() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.168.1.0/24 -all".into()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier.check_host("10.0.0.1".parse().unwrap(), "example.com", "test@example.com").await;

        assert_eq!(result, SpfResult::Fail);
    }

    #[tokio::test]
    async fn test_no_record() {
        let resolver = MockResolver::new();
        let verifier = SpfVerifier::new(resolver);
        let result = verifier.check_host("192.168.1.1".parse().unwrap(), "example.com", "test@example.com").await;

        assert_eq!(result, SpfResult::None);
    }

    #[tokio::test]
    async fn test_include() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.example.com -all".into()]);
        resolver.add_txt("_spf.example.com", vec!["v=spf1 ip4:10.0.0.0/8 -all".into()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier.check_host("10.1.2.3".parse().unwrap(), "example.com", "test@example.com").await;

        assert_eq!(result, SpfResult::Pass);
    }

    #[test]
    fn test_ip_matches_v4() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let network: IpAddr = "192.168.1.0".parse().unwrap();

        assert!(ip_matches(ip, network, Some(24)));
        assert!(!ip_matches(ip, network, Some(32)));
    }
}
