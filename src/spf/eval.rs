use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::common::dns::{DnsError, DnsResolver};

use super::macro_exp::{expand_macros, MacroContext};
use super::mechanism::{Mechanism, Modifier, Qualifier, Term};
use super::record::SpfRecord;
use super::SpfResult;

const MAX_DNS_LOOKUPS: usize = 10;
const MAX_VOID_LOOKUPS: usize = 2;

/// SPF verifier
pub struct SpfVerifier<R: DnsResolver> {
    resolver: Arc<R>,
}

impl<R: DnsResolver> SpfVerifier<R> {
    pub fn new(resolver: Arc<R>) -> Self {
        Self { resolver }
    }

    /// Evaluate SPF for the given parameters (RFC 7208 check_host())
    pub async fn check_host(
        &self,
        client_ip: IpAddr,
        domain: &str,
        sender: &str,
    ) -> SpfResult {
        let mut ctx = EvalContext::new(client_ip, domain, sender);
        self.check_host_inner(&mut ctx).await
    }

    async fn check_host_inner(&self, ctx: &mut EvalContext) -> SpfResult {
        // Lookup SPF record
        let record = match self.lookup_spf(&ctx.domain).await {
            Ok(Some(r)) => r,
            Ok(None) => return SpfResult::None,
            Err(_) => return SpfResult::TempError,
        };

        // Evaluate mechanisms
        for term in &record.terms {
            match term {
                Term::Mechanism(qualifier, mechanism) => {
                    match self.evaluate_mechanism(mechanism, ctx).await {
                        MechanismResult::Match => return qualifier_to_result(*qualifier),
                        MechanismResult::NoMatch => continue,
                        MechanismResult::TempError => return SpfResult::TempError,
                        MechanismResult::PermError => return SpfResult::PermError,
                    }
                }
                Term::Modifier(Modifier::Redirect(target)) => {
                    // Redirect is processed after all mechanisms
                    // (only if no mechanism matched)
                }
                Term::Modifier(_) => {}
            }
        }

        // If no mechanism matched, check for redirect
        if let Some(ref target) = record.redirect {
            // Expand macros in target
            let macro_ctx = MacroContext::new(&ctx.sender, &ctx.domain, ctx.client_ip, &ctx.helo);
            let expanded = match expand_macros(target, &macro_ctx) {
                Ok(e) => e,
                Err(_) => return SpfResult::PermError,
            };

            // Check lookup limit
            if !ctx.count_lookup() {
                return SpfResult::PermError;
            }

            ctx.domain = expanded;
            return Box::pin(self.check_host_inner(ctx)).await;
        }

        // Default result: Neutral
        SpfResult::Neutral
    }

    async fn lookup_spf(&self, domain: &str) -> Result<Option<SpfRecord>, DnsError> {
        let records = match self.resolver.query_txt(domain).await {
            Ok(r) => r,
            Err(DnsError::NxDomain(_)) => return Ok(None), // No domain = no SPF
            Err(e) => return Err(e),
        };

        // Find SPF record
        for record in records {
            if record.to_lowercase().starts_with("v=spf1") {
                match SpfRecord::parse(&record) {
                    Ok(spf) => return Ok(Some(spf)),
                    Err(_) => return Ok(None), // Invalid SPF = no SPF
                }
            }
        }

        Ok(None)
    }

    async fn evaluate_mechanism(
        &self,
        mechanism: &Mechanism,
        ctx: &mut EvalContext,
    ) -> MechanismResult {
        match mechanism {
            Mechanism::All => MechanismResult::Match,

            Mechanism::Include(domain) => {
                if !ctx.count_lookup() {
                    return MechanismResult::PermError;
                }

                let macro_ctx = MacroContext::new(&ctx.sender, &ctx.domain, ctx.client_ip, &ctx.helo);
                let expanded = match expand_macros(domain, &macro_ctx) {
                    Ok(e) => e,
                    Err(_) => return MechanismResult::PermError,
                };

                let mut sub_ctx = EvalContext {
                    client_ip: ctx.client_ip,
                    domain: expanded,
                    sender: ctx.sender.clone(),
                    helo: ctx.helo.clone(),
                    dns_lookups: ctx.dns_lookups,
                    void_lookups: ctx.void_lookups,
                };

                let result = Box::pin(self.check_host_inner(&mut sub_ctx)).await;

                // Update parent context counts
                ctx.dns_lookups = sub_ctx.dns_lookups;
                ctx.void_lookups = sub_ctx.void_lookups;

                match result {
                    SpfResult::Pass => MechanismResult::Match,
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral | SpfResult::None => {
                        MechanismResult::NoMatch
                    }
                    SpfResult::TempError => MechanismResult::TempError,
                    SpfResult::PermError => MechanismResult::PermError,
                }
            }

            Mechanism::A { domain, prefix4, prefix6 } => {
                if !ctx.count_lookup() {
                    return MechanismResult::PermError;
                }

                let target = match domain {
                    Some(d) => {
                        let macro_ctx = MacroContext::new(&ctx.sender, &ctx.domain, ctx.client_ip, &ctx.helo);
                        match expand_macros(d, &macro_ctx) {
                            Ok(e) => e,
                            Err(_) => return MechanismResult::PermError,
                        }
                    }
                    None => ctx.domain.clone(),
                };

                self.check_a(&target, ctx.client_ip, *prefix4, *prefix6, ctx).await
            }

            Mechanism::Mx { domain, prefix4, prefix6 } => {
                if !ctx.count_lookup() {
                    return MechanismResult::PermError;
                }

                let target = match domain {
                    Some(d) => {
                        let macro_ctx = MacroContext::new(&ctx.sender, &ctx.domain, ctx.client_ip, &ctx.helo);
                        match expand_macros(d, &macro_ctx) {
                            Ok(e) => e,
                            Err(_) => return MechanismResult::PermError,
                        }
                    }
                    None => ctx.domain.clone(),
                };

                self.check_mx(&target, ctx.client_ip, *prefix4, *prefix6, ctx).await
            }

            Mechanism::Ptr(domain) => {
                if !ctx.count_lookup() {
                    return MechanismResult::PermError;
                }

                let target = match domain {
                    Some(d) => {
                        let macro_ctx = MacroContext::new(&ctx.sender, &ctx.domain, ctx.client_ip, &ctx.helo);
                        match expand_macros(d, &macro_ctx) {
                            Ok(e) => e,
                            Err(_) => return MechanismResult::PermError,
                        }
                    }
                    None => ctx.domain.clone(),
                };

                self.check_ptr(&target, ctx.client_ip, ctx).await
            }

            Mechanism::Ip4(addr, prefix) => {
                if let IpAddr::V4(client) = ctx.client_ip {
                    if ip4_in_network(client, *addr, *prefix) {
                        MechanismResult::Match
                    } else {
                        MechanismResult::NoMatch
                    }
                } else {
                    MechanismResult::NoMatch
                }
            }

            Mechanism::Ip6(addr, prefix) => {
                if let IpAddr::V6(client) = ctx.client_ip {
                    if ip6_in_network(client, *addr, *prefix) {
                        MechanismResult::Match
                    } else {
                        MechanismResult::NoMatch
                    }
                } else {
                    MechanismResult::NoMatch
                }
            }

            Mechanism::Exists(domain) => {
                if !ctx.count_lookup() {
                    return MechanismResult::PermError;
                }

                let macro_ctx = MacroContext::new(&ctx.sender, &ctx.domain, ctx.client_ip, &ctx.helo);
                let expanded = match expand_macros(domain, &macro_ctx) {
                    Ok(e) => e,
                    Err(_) => return MechanismResult::PermError,
                };

                match self.resolver.query_a(&expanded).await {
                    Ok(addrs) if !addrs.is_empty() => MechanismResult::Match,
                    Ok(_) => {
                        ctx.count_void();
                        if ctx.void_lookups > MAX_VOID_LOOKUPS {
                            MechanismResult::PermError
                        } else {
                            MechanismResult::NoMatch
                        }
                    }
                    Err(DnsError::NxDomain(_)) => {
                        ctx.count_void();
                        if ctx.void_lookups > MAX_VOID_LOOKUPS {
                            MechanismResult::PermError
                        } else {
                            MechanismResult::NoMatch
                        }
                    }
                    Err(DnsError::Timeout) => MechanismResult::TempError,
                    Err(_) => MechanismResult::TempError,
                }
            }
        }
    }

    async fn check_a(
        &self,
        domain: &str,
        client_ip: IpAddr,
        prefix4: u8,
        prefix6: u8,
        ctx: &mut EvalContext,
    ) -> MechanismResult {
        match client_ip {
            IpAddr::V4(client) => {
                match self.resolver.query_a(domain).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            if let IpAddr::V4(a) = addr {
                                if ip4_in_network(client, a, prefix4) {
                                    return MechanismResult::Match;
                                }
                            }
                        }
                        MechanismResult::NoMatch
                    }
                    Err(DnsError::NxDomain(_)) => {
                        ctx.count_void();
                        MechanismResult::NoMatch
                    }
                    Err(_) => MechanismResult::TempError,
                }
            }
            IpAddr::V6(client) => {
                match self.resolver.query_aaaa(domain).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            if let IpAddr::V6(a) = addr {
                                if ip6_in_network(client, a, prefix6) {
                                    return MechanismResult::Match;
                                }
                            }
                        }
                        MechanismResult::NoMatch
                    }
                    Err(DnsError::NxDomain(_)) => {
                        ctx.count_void();
                        MechanismResult::NoMatch
                    }
                    Err(_) => MechanismResult::TempError,
                }
            }
        }
    }

    async fn check_mx(
        &self,
        domain: &str,
        client_ip: IpAddr,
        prefix4: u8,
        prefix6: u8,
        ctx: &mut EvalContext,
    ) -> MechanismResult {
        let mx_hosts = match self.resolver.query_mx(domain).await {
            Ok(hosts) => hosts,
            Err(DnsError::NxDomain(_)) => {
                ctx.count_void();
                return MechanismResult::NoMatch;
            }
            Err(_) => return MechanismResult::TempError,
        };

        // Each MX lookup counts as a DNS lookup
        for host in mx_hosts.into_iter().take(10) {
            if !ctx.count_lookup() {
                return MechanismResult::PermError;
            }

            match self.check_a(&host, client_ip, prefix4, prefix6, ctx).await {
                MechanismResult::Match => return MechanismResult::Match,
                MechanismResult::PermError => return MechanismResult::PermError,
                MechanismResult::TempError => return MechanismResult::TempError,
                MechanismResult::NoMatch => continue,
            }
        }

        MechanismResult::NoMatch
    }

    async fn check_ptr(
        &self,
        domain: &str,
        client_ip: IpAddr,
        ctx: &mut EvalContext,
    ) -> MechanismResult {
        // Reverse lookup
        let names = match self.resolver.query_ptr(client_ip).await {
            Ok(n) => n,
            Err(DnsError::NxDomain(_)) => {
                ctx.count_void();
                return MechanismResult::NoMatch;
            }
            Err(_) => return MechanismResult::TempError,
        };

        let domain_lower = domain.to_lowercase();

        // For each PTR name, verify forward lookup
        for name in names.into_iter().take(10) {
            let name_lower = name.to_lowercase();

            // Must be subdomain of or equal to target domain
            if !name_lower.ends_with(&domain_lower)
                && name_lower != domain_lower
                && !name_lower.ends_with(&format!(".{}", domain_lower))
            {
                continue;
            }

            if !ctx.count_lookup() {
                return MechanismResult::PermError;
            }

            // Forward lookup to verify
            let verified = match client_ip {
                IpAddr::V4(_) => {
                    match self.resolver.query_a(&name).await {
                        Ok(addrs) => addrs.contains(&client_ip),
                        Err(_) => false,
                    }
                }
                IpAddr::V6(_) => {
                    match self.resolver.query_aaaa(&name).await {
                        Ok(addrs) => addrs.contains(&client_ip),
                        Err(_) => false,
                    }
                }
            };

            if verified {
                return MechanismResult::Match;
            }
        }

        MechanismResult::NoMatch
    }
}

struct EvalContext {
    client_ip: IpAddr,
    domain: String,
    sender: String,
    helo: String,
    dns_lookups: usize,
    void_lookups: usize,
}

impl EvalContext {
    fn new(client_ip: IpAddr, domain: &str, sender: &str) -> Self {
        Self {
            client_ip,
            domain: domain.to_string(),
            sender: sender.to_string(),
            helo: domain.to_string(), // Default HELO to domain
            dns_lookups: 0,
            void_lookups: 0,
        }
    }

    fn count_lookup(&mut self) -> bool {
        self.dns_lookups += 1;
        self.dns_lookups <= MAX_DNS_LOOKUPS
    }

    fn count_void(&mut self) {
        self.void_lookups += 1;
    }
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

fn ip4_in_network(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = !0u32 << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ip6_in_network(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
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
    use crate::common::dns::MockResolver;

    #[test]
    fn test_ip4_in_network() {
        let network: Ipv4Addr = "192.168.1.0".parse().unwrap();
        assert!(ip4_in_network("192.168.1.5".parse().unwrap(), network, 24));
        assert!(ip4_in_network("192.168.1.255".parse().unwrap(), network, 24));
        assert!(!ip4_in_network("192.168.2.1".parse().unwrap(), network, 24));
        assert!(ip4_in_network("192.168.2.1".parse().unwrap(), network, 16));
    }

    #[tokio::test]
    async fn test_spf_all_fail() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 -all"]);

        let verifier = SpfVerifier::new(Arc::new(resolver));
        let result = verifier
            .check_host("1.2.3.4".parse().unwrap(), "example.com", "user@example.com")
            .await;

        assert_eq!(result, SpfResult::Fail);
    }

    #[tokio::test]
    async fn test_spf_ip4_match() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.168.1.0/24 -all"]);

        let verifier = SpfVerifier::new(Arc::new(resolver));

        let result = verifier
            .check_host("192.168.1.50".parse().unwrap(), "example.com", "user@example.com")
            .await;
        assert_eq!(result, SpfResult::Pass);

        let result = verifier
            .check_host("10.0.0.1".parse().unwrap(), "example.com", "user@example.com")
            .await;
        assert_eq!(result, SpfResult::Fail);
    }

    #[tokio::test]
    async fn test_spf_none() {
        let resolver = MockResolver::new();
        // No SPF record

        let verifier = SpfVerifier::new(Arc::new(resolver));
        let result = verifier
            .check_host("1.2.3.4".parse().unwrap(), "nonexistent.com", "user@nonexistent.com")
            .await;

        assert_eq!(result, SpfResult::None);
    }

    #[tokio::test]
    async fn test_spf_include() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.included.com -all"]);
        resolver.add_txt("_spf.included.com", vec!["v=spf1 ip4:10.0.0.0/8 -all"]);

        let verifier = SpfVerifier::new(Arc::new(resolver));

        let result = verifier
            .check_host("10.1.2.3".parse().unwrap(), "example.com", "user@example.com")
            .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_spf_a_mechanism() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 a -all"]);
        resolver.add_a("example.com", vec!["93.184.216.34".parse().unwrap()]);

        let verifier = SpfVerifier::new(Arc::new(resolver));

        let result = verifier
            .check_host("93.184.216.34".parse().unwrap(), "example.com", "user@example.com")
            .await;
        assert_eq!(result, SpfResult::Pass);

        let result = verifier
            .check_host("1.2.3.4".parse().unwrap(), "example.com", "user@example.com")
            .await;
        assert_eq!(result, SpfResult::Fail);
    }
}
