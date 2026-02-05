use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::common::dns::{DnsError, DnsResolver};
use super::macro_exp::MacroContext;
use super::mechanism::{Mechanism, Qualifier};
use super::record::SpfRecord;
use super::SpfResult;

const MAX_DNS_LOOKUPS: usize = 10;
const MAX_VOID_LOOKUPS: usize = 2;

/// SPF verifier
#[derive(Clone)]
pub struct SpfVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> SpfVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Check if an IP is authorized to send for a domain
    pub async fn check_host(&self, ip: IpAddr, domain: &str, sender: &str) -> SpfResult {
        let mut lookup_count = 0;
        let mut void_count = 0;
        self.check_host_inner(ip, domain, sender, &mut lookup_count, &mut void_count)
            .await
    }

    fn check_host_inner<'a>(
        &'a self,
        ip: IpAddr,
        domain: &'a str,
        sender: &'a str,
        lookup_count: &'a mut usize,
        void_count: &'a mut usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SpfResult> + Send + 'a>> {
        Box::pin(async move {
            // Lookup SPF record
            let record = match self.lookup_spf_record(domain, lookup_count, void_count).await {
                Ok(Some(r)) => r,
                Ok(None) => return SpfResult::None,
                Err(SpfResult::TempError) => return SpfResult::TempError,
                Err(r) => return r,
            };

            // Create macro context
            let ctx = MacroContext {
                sender,
                domain,
                client_ip: ip,
                helo: domain, // Use domain as HELO default
                receiver: None,
                is_exp_context: false,
            };

            // Evaluate directives
            for directive in &record.directives {
                match self
                    .evaluate_mechanism(ip, &directive.mechanism, &ctx, lookup_count, void_count)
                    .await
                {
                    Ok(true) => return self.qualifier_to_result(directive.qualifier),
                    Ok(false) => continue,
                    Err(SpfResult::TempError) => return SpfResult::TempError,
                    Err(SpfResult::PermError) => return SpfResult::PermError,
                    Err(_) => continue,
                }
            }

            // No match - check redirect
            if let Some(ref redirect_domain) = record.redirect {
                let expanded = match ctx.expand(redirect_domain) {
                    Ok(d) => d,
                    Err(_) => return SpfResult::PermError,
                };
                *lookup_count += 1;
                if *lookup_count > MAX_DNS_LOOKUPS {
                    return SpfResult::PermError;
                }
                let result = self
                    .check_host_inner(ip, &expanded, sender, lookup_count, void_count)
                    .await;
                // redirect with None result is PermError
                if matches!(result, SpfResult::None) {
                    return SpfResult::PermError;
                }
                return result;
            }

            // Default result: Neutral
            SpfResult::Neutral
        })
    }

    async fn lookup_spf_record(
        &self,
        domain: &str,
        _lookup_count: &mut usize,
        void_count: &mut usize,
    ) -> Result<Option<SpfRecord>, SpfResult> {
        let records = match self.resolver.query_txt(domain).await {
            Ok(r) => r,
            Err(DnsError::NxDomain) => {
                *void_count += 1;
                if *void_count > MAX_VOID_LOOKUPS {
                    return Err(SpfResult::PermError);
                }
                return Ok(None);
            }
            Err(DnsError::Timeout) | Err(DnsError::ServFail) => {
                return Err(SpfResult::TempError);
            }
            Err(_) => return Err(SpfResult::TempError),
        };

        // Find SPF records (v=spf1)
        let spf_records: Vec<_> = records
            .iter()
            .filter(|r| r.to_lowercase().starts_with("v=spf1"))
            .collect();

        match spf_records.len() {
            0 => {
                *void_count += 1;
                if *void_count > MAX_VOID_LOOKUPS {
                    return Err(SpfResult::PermError);
                }
                Ok(None)
            }
            1 => match SpfRecord::parse(spf_records[0]) {
                Ok(record) => Ok(Some(record)),
                Err(_) => Err(SpfResult::PermError),
            },
            _ => Err(SpfResult::PermError), // Multiple SPF records
        }
    }

    async fn evaluate_mechanism(
        &self,
        ip: IpAddr,
        mechanism: &Mechanism,
        ctx: &MacroContext<'_>,
        lookup_count: &mut usize,
        void_count: &mut usize,
    ) -> Result<bool, SpfResult> {
        match mechanism {
            Mechanism::All => Ok(true),

            Mechanism::Include { domain } => {
                let expanded = ctx.expand(domain).map_err(|_| SpfResult::PermError)?;
                *lookup_count += 1;
                if *lookup_count > MAX_DNS_LOOKUPS {
                    return Err(SpfResult::PermError);
                }

                let result = self
                    .check_host_inner(ip, &expanded, ctx.sender, lookup_count, void_count)
                    .await;

                match result {
                    SpfResult::Pass => Ok(true),
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral | SpfResult::None => Ok(false),
                    SpfResult::TempError => Err(SpfResult::TempError),
                    SpfResult::PermError => Err(SpfResult::PermError),
                }
            }

            Mechanism::A { domain, cidr4, cidr6 } => {
                let target_domain = match domain {
                    Some(d) => ctx.expand(d).map_err(|_| SpfResult::PermError)?,
                    None => ctx.domain.to_string(),
                };

                *lookup_count += 1;
                if *lookup_count > MAX_DNS_LOOKUPS {
                    return Err(SpfResult::PermError);
                }

                self.check_a_mechanism(ip, &target_domain, *cidr4, *cidr6, void_count)
                    .await
            }

            Mechanism::Mx { domain, cidr4, cidr6 } => {
                let target_domain = match domain {
                    Some(d) => ctx.expand(d).map_err(|_| SpfResult::PermError)?,
                    None => ctx.domain.to_string(),
                };

                *lookup_count += 1;
                if *lookup_count > MAX_DNS_LOOKUPS {
                    return Err(SpfResult::PermError);
                }

                self.check_mx_mechanism(ip, &target_domain, *cidr4, *cidr6, lookup_count, void_count)
                    .await
            }

            Mechanism::Ptr { domain } => {
                let target_domain = match domain {
                    Some(d) => ctx.expand(d).map_err(|_| SpfResult::PermError)?,
                    None => ctx.domain.to_string(),
                };

                *lookup_count += 1;
                if *lookup_count > MAX_DNS_LOOKUPS {
                    return Err(SpfResult::PermError);
                }

                self.check_ptr_mechanism(ip, &target_domain, lookup_count, void_count)
                    .await
            }

            Mechanism::Ip4 { addr, prefix } => {
                if let IpAddr::V4(client_ip) = ip {
                    Ok(Self::ip4_in_cidr(client_ip, *addr, *prefix))
                } else {
                    Ok(false)
                }
            }

            Mechanism::Ip6 { addr, prefix } => {
                if let IpAddr::V6(client_ip) = ip {
                    Ok(Self::ip6_in_cidr(client_ip, *addr, *prefix))
                } else {
                    Ok(false)
                }
            }

            Mechanism::Exists { domain } => {
                let expanded = ctx.expand(domain).map_err(|_| SpfResult::PermError)?;

                *lookup_count += 1;
                if *lookup_count > MAX_DNS_LOOKUPS {
                    return Err(SpfResult::PermError);
                }

                match self.resolver.query_a(&expanded).await {
                    Ok(addrs) if !addrs.is_empty() => Ok(true),
                    Ok(_) => {
                        *void_count += 1;
                        if *void_count > MAX_VOID_LOOKUPS {
                            return Err(SpfResult::PermError);
                        }
                        Ok(false)
                    }
                    Err(DnsError::NxDomain) => {
                        *void_count += 1;
                        if *void_count > MAX_VOID_LOOKUPS {
                            return Err(SpfResult::PermError);
                        }
                        Ok(false)
                    }
                    Err(DnsError::Timeout) | Err(DnsError::ServFail) => Err(SpfResult::TempError),
                    Err(_) => Err(SpfResult::TempError),
                }
            }
        }
    }

    async fn check_a_mechanism(
        &self,
        ip: IpAddr,
        domain: &str,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
        void_count: &mut usize,
    ) -> Result<bool, SpfResult> {
        match ip {
            IpAddr::V4(client_ip) => {
                let prefix = cidr4.unwrap_or(32);
                match self.resolver.query_a(domain).await {
                    Ok(addrs) if addrs.is_empty() => {
                        *void_count += 1;
                        if *void_count > MAX_VOID_LOOKUPS {
                            return Err(SpfResult::PermError);
                        }
                        Ok(false)
                    }
                    Ok(addrs) => Ok(addrs.iter().any(|a| Self::ip4_in_cidr(client_ip, *a, prefix))),
                    Err(DnsError::NxDomain) => {
                        *void_count += 1;
                        if *void_count > MAX_VOID_LOOKUPS {
                            return Err(SpfResult::PermError);
                        }
                        Ok(false)
                    }
                    Err(DnsError::Timeout) | Err(DnsError::ServFail) => Err(SpfResult::TempError),
                    Err(_) => Err(SpfResult::TempError),
                }
            }
            IpAddr::V6(client_ip) => {
                let prefix = cidr6.unwrap_or(128);
                match self.resolver.query_aaaa(domain).await {
                    Ok(addrs) if addrs.is_empty() => {
                        *void_count += 1;
                        if *void_count > MAX_VOID_LOOKUPS {
                            return Err(SpfResult::PermError);
                        }
                        Ok(false)
                    }
                    Ok(addrs) => Ok(addrs.iter().any(|a| Self::ip6_in_cidr(client_ip, *a, prefix))),
                    Err(DnsError::NxDomain) => {
                        *void_count += 1;
                        if *void_count > MAX_VOID_LOOKUPS {
                            return Err(SpfResult::PermError);
                        }
                        Ok(false)
                    }
                    Err(DnsError::Timeout) | Err(DnsError::ServFail) => Err(SpfResult::TempError),
                    Err(_) => Err(SpfResult::TempError),
                }
            }
        }
    }

    async fn check_mx_mechanism(
        &self,
        ip: IpAddr,
        domain: &str,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
        lookup_count: &mut usize,
        void_count: &mut usize,
    ) -> Result<bool, SpfResult> {
        let mx_records = match self.resolver.query_mx(domain).await {
            Ok(r) if r.is_empty() => {
                *void_count += 1;
                if *void_count > MAX_VOID_LOOKUPS {
                    return Err(SpfResult::PermError);
                }
                return Ok(false);
            }
            Ok(r) => r,
            Err(DnsError::NxDomain) => {
                *void_count += 1;
                if *void_count > MAX_VOID_LOOKUPS {
                    return Err(SpfResult::PermError);
                }
                return Ok(false);
            }
            Err(DnsError::Timeout) | Err(DnsError::ServFail) => return Err(SpfResult::TempError),
            Err(_) => return Err(SpfResult::TempError),
        };

        // Limit to first 10 MX records
        for (_, mx_host) in mx_records.iter().take(10) {
            *lookup_count += 1;
            if *lookup_count > MAX_DNS_LOOKUPS {
                return Err(SpfResult::PermError);
            }

            if self.check_a_mechanism(ip, mx_host, cidr4, cidr6, void_count).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn check_ptr_mechanism(
        &self,
        ip: IpAddr,
        target_domain: &str,
        lookup_count: &mut usize,
        void_count: &mut usize,
    ) -> Result<bool, SpfResult> {
        let ptr_names = match self.resolver.query_ptr(ip).await {
            Ok(names) if names.is_empty() => {
                *void_count += 1;
                if *void_count > MAX_VOID_LOOKUPS {
                    return Err(SpfResult::PermError);
                }
                return Ok(false);
            }
            Ok(names) => names,
            Err(_) => {
                *void_count += 1;
                if *void_count > MAX_VOID_LOOKUPS {
                    return Err(SpfResult::PermError);
                }
                return Ok(false);
            }
        };

        let target_lower = target_domain.to_lowercase();

        // Limit to first 10 PTR results
        for name in ptr_names.iter().take(10) {
            *lookup_count += 1;
            if *lookup_count > MAX_DNS_LOOKUPS {
                return Err(SpfResult::PermError);
            }

            // Forward lookup to validate
            let forward_ips: Vec<IpAddr> = match ip {
                IpAddr::V4(_) => self
                    .resolver
                    .query_a(name)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(IpAddr::V4)
                    .collect(),
                IpAddr::V6(_) => self
                    .resolver
                    .query_aaaa(name)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(IpAddr::V6)
                    .collect(),
            };

            // Validate: client IP must be in forward results
            if forward_ips.contains(&ip) {
                // Check if name ends with target domain
                let name_lower = name.to_lowercase();
                if name_lower == target_lower || name_lower.ends_with(&format!(".{}", target_lower)) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn qualifier_to_result(&self, qualifier: Qualifier) -> SpfResult {
        match qualifier {
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
        let ip_bits = u128::from(ip);
        let net_bits = u128::from(network);
        let mask = !0u128 << (128 - prefix);
        (ip_bits & mask) == (net_bits & mask)
    }
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
            )
            .await;

        assert_eq!(result, SpfResult::Fail);
    }

    #[tokio::test]
    async fn test_include() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.example.com -all".to_string()]);
        resolver.add_txt("_spf.example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
            )
            .await;

        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_no_record() {
        let resolver = MockResolver::new();
        resolver.set_nxdomain("example.com");

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
            )
            .await;

        assert_eq!(result, SpfResult::None);
    }

    #[tokio::test]
    async fn test_redirect() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 redirect=_spf.example.com".to_string()]);
        resolver.add_txt("_spf.example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()]);

        let verifier = SpfVerifier::new(resolver);
        let result = verifier
            .check_host(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                "example.com",
                "user@example.com",
            )
            .await;

        assert_eq!(result, SpfResult::Pass);
    }

    #[test]
    fn test_ip4_cidr() {
        assert!(SpfVerifier::<MockResolver>::ip4_in_cidr(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 0),
            24
        ));
        assert!(!SpfVerifier::<MockResolver>::ip4_in_cidr(
            Ipv4Addr::new(192, 0, 3, 1),
            Ipv4Addr::new(192, 0, 2, 0),
            24
        ));
    }
}
