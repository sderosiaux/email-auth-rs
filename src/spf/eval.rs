use super::macro_exp::{expand_macros, MacroContext};
use super::mechanism::{Mechanism, Qualifier};
use super::record::SpfRecord;
use super::SpfResult;
use crate::common::{normalize_domain, DnsError, DnsResolver};
use std::net::IpAddr;

const MAX_DNS_LOOKUPS: u32 = 10;
const MAX_VOID_LOOKUPS: u32 = 2;

pub struct SpfVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> SpfVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Check host algorithm (RFC 7208 Section 4)
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
        };
        self.check_host_recursive(client_ip, domain, sender, helo, &mut ctx)
            .await
    }

    async fn check_host_recursive(
        &self,
        client_ip: IpAddr,
        domain: &str,
        sender: &str,
        helo: &str,
        ctx: &mut EvalContext,
    ) -> SpfResult {
        let domain = normalize_domain(domain);

        // Query SPF record
        let txt_records = match self.resolver.query_txt(&domain).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) => return SpfResult::None,
            Err(_) => return SpfResult::TempError,
        };

        // Find SPF record (exactly one must exist)
        let spf_records: Vec<_> = txt_records
            .iter()
            .filter(|r| r.to_lowercase().starts_with("v=spf1"))
            .collect();

        let record = match spf_records.len() {
            0 => return SpfResult::None,
            1 => match SpfRecord::parse(spf_records[0]) {
                Ok(r) => r,
                Err(_) => return SpfResult::PermError,
            },
            _ => return SpfResult::PermError, // Multiple SPF records
        };

        let macro_ctx = MacroContext {
            sender,
            domain: &domain,
            client_ip,
            helo,
            receiver: "",
            is_exp: false,
        };

        // Evaluate directives
        for directive in &record.directives {
            let matches = self
                .evaluate_mechanism(&directive.mechanism, client_ip, &domain, &macro_ctx, ctx)
                .await;

            match matches {
                MechanismResult::Match => {
                    return qualifier_to_result(directive.qualifier);
                }
                MechanismResult::NoMatch => continue,
                MechanismResult::TempError => return SpfResult::TempError,
                MechanismResult::PermError => return SpfResult::PermError,
            }
        }

        // No directive matched, check redirect
        if let Some(ref redirect_domain) = record.redirect {
            let expanded = match expand_macros(redirect_domain, &macro_ctx) {
                Ok(d) => d,
                Err(_) => return SpfResult::PermError,
            };

            ctx.dns_lookups += 1;
            if ctx.dns_lookups > MAX_DNS_LOOKUPS {
                return SpfResult::PermError;
            }

            let result = Box::pin(self.check_host_recursive(client_ip, &expanded, sender, helo, ctx))
                .await;

            // redirect to None -> PermError
            if result == SpfResult::None {
                return SpfResult::PermError;
            }
            return result;
        }

        // Default: Neutral
        SpfResult::Neutral
    }

    async fn evaluate_mechanism(
        &self,
        mechanism: &Mechanism,
        client_ip: IpAddr,
        current_domain: &str,
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
                if ctx.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechanismResult::PermError;
                }

                let result = Box::pin(self.check_host_recursive(
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
                let target_domain = match domain {
                    Some(d) => match expand_macros(d, macro_ctx) {
                        Ok(expanded) => expanded,
                        Err(_) => return MechanismResult::PermError,
                    },
                    None => current_domain.to_string(),
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechanismResult::PermError;
                }

                let prefix = match client_ip {
                    IpAddr::V4(_) => cidr4.unwrap_or(32),
                    IpAddr::V6(_) => cidr6.unwrap_or(128),
                };

                match client_ip {
                    IpAddr::V4(client_v4) => {
                        match self.resolver.query_a(&target_domain).await {
                            Ok(addrs) => {
                                for addr in addrs {
                                    if ip_in_cidr_v4(client_v4, addr, prefix) {
                                        return MechanismResult::Match;
                                    }
                                }
                                MechanismResult::NoMatch
                            }
                            Err(DnsError::NxDomain) => {
                                ctx.void_lookups += 1;
                                if ctx.void_lookups > MAX_VOID_LOOKUPS {
                                    return MechanismResult::PermError;
                                }
                                MechanismResult::NoMatch
                            }
                            Err(_) => MechanismResult::TempError,
                        }
                    }
                    IpAddr::V6(client_v6) => {
                        match self.resolver.query_aaaa(&target_domain).await {
                            Ok(addrs) => {
                                for addr in addrs {
                                    if ip_in_cidr_v6(client_v6, addr, prefix) {
                                        return MechanismResult::Match;
                                    }
                                }
                                MechanismResult::NoMatch
                            }
                            Err(DnsError::NxDomain) => {
                                ctx.void_lookups += 1;
                                if ctx.void_lookups > MAX_VOID_LOOKUPS {
                                    return MechanismResult::PermError;
                                }
                                MechanismResult::NoMatch
                            }
                            Err(_) => MechanismResult::TempError,
                        }
                    }
                }
            }

            Mechanism::Mx { domain, cidr4, cidr6 } => {
                let target_domain = match domain {
                    Some(d) => match expand_macros(d, macro_ctx) {
                        Ok(expanded) => expanded,
                        Err(_) => return MechanismResult::PermError,
                    },
                    None => current_domain.to_string(),
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechanismResult::PermError;
                }

                let mx_records = match self.resolver.query_mx(&target_domain).await {
                    Ok(mxs) => mxs,
                    Err(DnsError::NxDomain) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > MAX_VOID_LOOKUPS {
                            return MechanismResult::PermError;
                        }
                        return MechanismResult::NoMatch;
                    }
                    Err(_) => return MechanismResult::TempError,
                };

                let prefix = match client_ip {
                    IpAddr::V4(_) => cidr4.unwrap_or(32),
                    IpAddr::V6(_) => cidr6.unwrap_or(128),
                };

                // Limit to first 10 MX records
                for (_, mx_host) in mx_records.iter().take(10) {
                    ctx.dns_lookups += 1;
                    if ctx.dns_lookups > MAX_DNS_LOOKUPS {
                        return MechanismResult::PermError;
                    }

                    let mx_host = normalize_domain(mx_host);

                    match client_ip {
                        IpAddr::V4(client_v4) => {
                            if let Ok(addrs) = self.resolver.query_a(&mx_host).await {
                                for addr in addrs {
                                    if ip_in_cidr_v4(client_v4, addr, prefix) {
                                        return MechanismResult::Match;
                                    }
                                }
                            }
                        }
                        IpAddr::V6(client_v6) => {
                            if let Ok(addrs) = self.resolver.query_aaaa(&mx_host).await {
                                for addr in addrs {
                                    if ip_in_cidr_v6(client_v6, addr, prefix) {
                                        return MechanismResult::Match;
                                    }
                                }
                            }
                        }
                    }
                }

                MechanismResult::NoMatch
            }

            Mechanism::Ptr { domain } => {
                let target_domain = match domain {
                    Some(d) => match expand_macros(d, macro_ctx) {
                        Ok(expanded) => normalize_domain(&expanded),
                        Err(_) => return MechanismResult::PermError,
                    },
                    None => current_domain.to_string(),
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechanismResult::PermError;
                }

                // PTR lookup
                let ptr_names = match self.resolver.query_ptr(client_ip).await {
                    Ok(names) => names,
                    Err(DnsError::NxDomain) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > MAX_VOID_LOOKUPS {
                            return MechanismResult::PermError;
                        }
                        return MechanismResult::NoMatch;
                    }
                    Err(_) => return MechanismResult::TempError,
                };

                // Validate PTR names (limit to 10)
                for ptr_name in ptr_names.iter().take(10) {
                    let ptr_name = normalize_domain(ptr_name);

                    // Forward lookup to validate
                    ctx.dns_lookups += 1;
                    if ctx.dns_lookups > MAX_DNS_LOOKUPS {
                        return MechanismResult::PermError;
                    }

                    let validated = match client_ip {
                        IpAddr::V4(client_v4) => {
                            if let Ok(addrs) = self.resolver.query_a(&ptr_name).await {
                                addrs.contains(&client_v4)
                            } else {
                                false
                            }
                        }
                        IpAddr::V6(client_v6) => {
                            if let Ok(addrs) = self.resolver.query_aaaa(&ptr_name).await {
                                addrs.contains(&client_v6)
                            } else {
                                false
                            }
                        }
                    };

                    if validated {
                        // Check if ptr_name ends with target_domain
                        if ptr_name == target_domain
                            || ptr_name.ends_with(&format!(".{}", target_domain))
                        {
                            return MechanismResult::Match;
                        }
                    }
                }

                MechanismResult::NoMatch
            }

            Mechanism::Ip4 { addr, prefix } => {
                if let IpAddr::V4(client_v4) = client_ip {
                    if ip_in_cidr_v4(client_v4, *addr, *prefix) {
                        return MechanismResult::Match;
                    }
                }
                MechanismResult::NoMatch
            }

            Mechanism::Ip6 { addr, prefix } => {
                if let IpAddr::V6(client_v6) = client_ip {
                    if ip_in_cidr_v6(client_v6, *addr, *prefix) {
                        return MechanismResult::Match;
                    }
                }
                MechanismResult::NoMatch
            }

            Mechanism::Exists { domain } => {
                let expanded = match expand_macros(domain, macro_ctx) {
                    Ok(d) => d,
                    Err(_) => return MechanismResult::PermError,
                };

                ctx.dns_lookups += 1;
                if ctx.dns_lookups > MAX_DNS_LOOKUPS {
                    return MechanismResult::PermError;
                }

                match self.resolver.query_a(&expanded).await {
                    Ok(addrs) if !addrs.is_empty() => MechanismResult::Match,
                    Ok(_) => MechanismResult::NoMatch,
                    Err(DnsError::NxDomain) => {
                        ctx.void_lookups += 1;
                        if ctx.void_lookups > MAX_VOID_LOOKUPS {
                            return MechanismResult::PermError;
                        }
                        MechanismResult::NoMatch
                    }
                    Err(_) => MechanismResult::TempError,
                }
            }
        }
    }
}

struct EvalContext {
    dns_lookups: u32,
    void_lookups: u32,
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

fn ip_in_cidr_v4(ip: std::net::Ipv4Addr, network: std::net::Ipv4Addr, prefix: u8) -> bool {
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

fn ip_in_cidr_v6(ip: std::net::Ipv6Addr, network: std::net::Ipv6Addr, prefix: u8) -> bool {
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
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                "192.0.2.1".parse().unwrap(),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_simple_fail() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                "10.0.0.1".parse().unwrap(),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;
        assert_eq!(result, SpfResult::Fail);
    }

    #[tokio::test]
    async fn test_no_record() {
        let resolver = MockResolver::new();
        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                "192.0.2.1".parse().unwrap(),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;
        assert_eq!(result, SpfResult::None);
    }

    #[tokio::test]
    async fn test_include_pass() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "example.com",
            vec!["v=spf1 include:_spf.example.com -all".to_string()],
        );
        resolver.add_txt(
            "_spf.example.com",
            vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
        );

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                "192.0.2.1".parse().unwrap(),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_redirect() {
        let mut resolver = MockResolver::new();
        resolver.add_txt(
            "example.com",
            vec!["v=spf1 redirect=_spf.example.com".to_string()],
        );
        resolver.add_txt(
            "_spf.example.com",
            vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
        );

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                "192.0.2.1".parse().unwrap(),
                "example.com",
                "user@example.com",
                "mail.example.com",
            )
            .await;
        assert_eq!(result, SpfResult::Pass);
    }
}
