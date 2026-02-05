use std::collections::HashMap;
use std::net::IpAddr;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{ResolveError, Resolver};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS query timeout")]
    Timeout,
    #[error("NXDOMAIN: {0}")]
    NxDomain(String),
    #[error("SERVFAIL: {0}")]
    ServFail(String),
    #[error("DNS error: {0}")]
    Other(String),
}

/// DNS resolver trait for testability
pub trait DnsResolver: Send + Sync {
    fn query_txt(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_a(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
    fn query_aaaa(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
    fn query_mx(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_ptr(
        &self,
        ip: IpAddr,
    ) -> impl std::future::Future<Output = Result<Vec<String>, DnsError>> + Send;

    /// Check if domain exists (has A, AAAA, or MX records)
    fn domain_exists(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<bool, DnsError>> + Send {
        async move {
            // Try A first
            match self.query_a(name).await {
                Ok(addrs) if !addrs.is_empty() => return Ok(true),
                Err(DnsError::NxDomain(_)) => {}
                Err(e) => return Err(e),
                _ => {}
            }
            // Try AAAA
            match self.query_aaaa(name).await {
                Ok(addrs) if !addrs.is_empty() => return Ok(true),
                Err(DnsError::NxDomain(_)) => {}
                Err(e) => return Err(e),
                _ => {}
            }
            // Try MX
            match self.query_mx(name).await {
                Ok(mxs) if !mxs.is_empty() => return Ok(true),
                Err(DnsError::NxDomain(_)) => return Ok(false),
                Err(e) => return Err(e),
                _ => {}
            }
            Ok(false)
        }
    }
}

pub type TokioResolver = Resolver<TokioConnectionProvider>;

/// Production DNS resolver using hickory-dns
pub struct HickoryResolver {
    resolver: TokioResolver,
}

impl HickoryResolver {
    pub fn new() -> Self {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();
        Self { resolver }
    }

    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Self {
        let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();
        Self { resolver }
    }
}

impl Default for HickoryResolver {
    fn default() -> Self {
        Self::new()
    }
}

fn map_resolve_error(e: ResolveError, name: &str) -> DnsError {
    if e.is_nx_domain() || e.is_no_records_found() {
        DnsError::NxDomain(name.to_string())
    } else {
        DnsError::Other(e.to_string())
    }
}

impl DnsResolver for HickoryResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        match self.resolver.txt_lookup(name).await {
            Ok(lookup) => {
                let records: Vec<String> = lookup
                    .iter()
                    .map(|txt| {
                        txt.txt_data()
                            .iter()
                            .map(|d| String::from_utf8_lossy(d).into_owned())
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .collect();
                Ok(records)
            }
            Err(e) => Err(map_resolve_error(e, name)),
        }
    }

    async fn query_a(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        match self.resolver.ipv4_lookup(name).await {
            Ok(lookup) => Ok(lookup.iter().map(|a| IpAddr::V4(a.0)).collect()),
            Err(e) => Err(map_resolve_error(e, name)),
        }
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        match self.resolver.ipv6_lookup(name).await {
            Ok(lookup) => Ok(lookup.iter().map(|a| IpAddr::V6(a.0)).collect()),
            Err(e) => Err(map_resolve_error(e, name)),
        }
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<String>, DnsError> {
        match self.resolver.mx_lookup(name).await {
            Ok(lookup) => Ok(lookup.iter().map(|mx| mx.exchange().to_ascii()).collect()),
            Err(e) => Err(map_resolve_error(e, name)),
        }
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => Ok(lookup.iter().map(|name| name.to_ascii()).collect()),
            Err(e) => Err(map_resolve_error(e, &ip.to_string())),
        }
    }
}

/// Mock DNS resolver for testing
#[derive(Default)]
pub struct MockResolver {
    txt_records: HashMap<String, Vec<String>>,
    a_records: HashMap<String, Vec<IpAddr>>,
    aaaa_records: HashMap<String, Vec<IpAddr>>,
    mx_records: HashMap<String, Vec<String>>,
    ptr_records: HashMap<IpAddr, Vec<String>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_txt(&mut self, name: &str, records: Vec<&str>) -> &mut Self {
        self.txt_records.insert(
            name.to_lowercase(),
            records.into_iter().map(String::from).collect(),
        );
        self
    }

    pub fn add_a(&mut self, name: &str, addrs: Vec<IpAddr>) -> &mut Self {
        self.a_records.insert(name.to_lowercase(), addrs);
        self
    }

    pub fn add_aaaa(&mut self, name: &str, addrs: Vec<IpAddr>) -> &mut Self {
        self.aaaa_records.insert(name.to_lowercase(), addrs);
        self
    }

    pub fn add_mx(&mut self, name: &str, exchanges: Vec<&str>) -> &mut Self {
        self.mx_records.insert(
            name.to_lowercase(),
            exchanges.into_iter().map(String::from).collect(),
        );
        self
    }

    pub fn add_ptr(&mut self, ip: IpAddr, names: Vec<&str>) -> &mut Self {
        self.ptr_records
            .insert(ip, names.into_iter().map(String::from).collect());
        self
    }
}

impl DnsResolver for MockResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.txt_records
            .get(&name.to_lowercase())
            .cloned()
            .ok_or_else(|| DnsError::NxDomain(name.to_string()))
    }

    async fn query_a(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.a_records
            .get(&name.to_lowercase())
            .cloned()
            .ok_or_else(|| DnsError::NxDomain(name.to_string()))
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.aaaa_records
            .get(&name.to_lowercase())
            .cloned()
            .ok_or_else(|| DnsError::NxDomain(name.to_string()))
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.mx_records
            .get(&name.to_lowercase())
            .cloned()
            .ok_or_else(|| DnsError::NxDomain(name.to_string()))
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        self.ptr_records
            .get(&ip)
            .cloned()
            .ok_or_else(|| DnsError::NxDomain(ip.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_resolver_txt() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 -all"]);

        let result = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["v=spf1 -all"]);
    }

    #[tokio::test]
    async fn test_mock_resolver_nxdomain() {
        let resolver = MockResolver::new();
        let result = resolver.query_txt("nonexistent.example.com").await;
        assert!(matches!(result, Err(DnsError::NxDomain(_))));
    }

    #[tokio::test]
    async fn test_mock_resolver_case_insensitive() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("EXAMPLE.COM", vec!["test"]);

        let result = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["test"]);
    }
}
