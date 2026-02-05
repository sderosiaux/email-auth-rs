//! DNS resolver trait and implementations

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("NXDOMAIN: domain does not exist")]
    NxDomain,
    #[error("SERVFAIL: server failure")]
    ServFail,
    #[error("timeout")]
    Timeout,
    #[error("no records found")]
    NoRecords,
    #[error("DNS error: {0}")]
    Other(String),
}

/// DNS resolver trait for testability
pub trait DnsResolver: Send + Sync + Clone {
    fn query_txt(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;

    fn query_a(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<Ipv4Addr>, DnsError>> + Send;

    fn query_aaaa(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<Ipv6Addr>, DnsError>> + Send;

    fn query_mx(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<(u16, String)>, DnsError>> + Send;

    fn query_ptr(
        &self,
        ip: std::net::IpAddr,
    ) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
}

/// Hickory-based DNS resolver
#[derive(Clone)]
pub struct HickoryResolver {
    resolver: hickory_resolver::Resolver<hickory_resolver::name_server::TokioConnectionProvider>,
}

impl HickoryResolver {
    pub fn new() -> Result<Self, DnsError> {
        use hickory_resolver::config::*;
        use hickory_resolver::name_server::TokioConnectionProvider;
        use hickory_resolver::Resolver;

        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self { resolver })
    }
}

impl Default for HickoryResolver {
    fn default() -> Self {
        Self::new().expect("failed to create DNS resolver")
    }
}

impl DnsResolver for HickoryResolver {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        match self.resolver.txt_lookup(domain).await {
            Ok(lookup) => {
                let records: Vec<String> = lookup
                    .iter()
                    .map(|txt| {
                        txt.iter()
                            .map(|data| String::from_utf8_lossy(data).into_owned())
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .collect();
                if records.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(records)
                }
            }
            Err(e) => Err(resolve_error_to_dns_error(e)),
        }
    }

    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        match self.resolver.ipv4_lookup(domain).await {
            Ok(lookup) => {
                let addrs: Vec<Ipv4Addr> = lookup.iter().map(|r| r.0).collect();
                if addrs.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(addrs)
                }
            }
            Err(e) => Err(resolve_error_to_dns_error(e)),
        }
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        match self.resolver.ipv6_lookup(domain).await {
            Ok(lookup) => {
                let addrs: Vec<Ipv6Addr> = lookup.iter().map(|r| r.0).collect();
                if addrs.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(addrs)
                }
            }
            Err(e) => Err(resolve_error_to_dns_error(e)),
        }
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
        match self.resolver.mx_lookup(domain).await {
            Ok(lookup) => {
                let records: Vec<(u16, String)> = lookup
                    .iter()
                    .map(|mx| (mx.preference(), mx.exchange().to_string()))
                    .collect();
                if records.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(records)
                }
            }
            Err(e) => Err(resolve_error_to_dns_error(e)),
        }
    }

    async fn query_ptr(&self, ip: std::net::IpAddr) -> Result<Vec<String>, DnsError> {
        match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                let names: Vec<String> = lookup.iter().map(|name| name.to_string()).collect();
                if names.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(names)
                }
            }
            Err(e) => Err(resolve_error_to_dns_error(e)),
        }
    }
}

fn resolve_error_to_dns_error(e: hickory_resolver::ResolveError) -> DnsError {
    if e.is_nx_domain() {
        DnsError::NxDomain
    } else if e.is_no_records_found() {
        DnsError::NoRecords
    } else {
        let msg = e.to_string();
        if msg.to_lowercase().contains("timeout") {
            DnsError::Timeout
        } else {
            DnsError::Other(msg)
        }
    }
}

/// Mock DNS resolver for testing
#[derive(Clone, Default)]
pub struct MockResolver {
    txt_records: Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<String>>>>,
    a_records: Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<Ipv4Addr>>>>,
    aaaa_records: Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<Ipv6Addr>>>>,
    mx_records: Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<(u16, String)>>>>,
    ptr_records: Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<String>>>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_txt(&self, domain: &str, records: Vec<String>) {
        self.txt_records
            .write()
            .unwrap()
            .insert(domain.to_lowercase(), records);
    }

    pub fn add_a(&self, domain: &str, addrs: Vec<Ipv4Addr>) {
        self.a_records
            .write()
            .unwrap()
            .insert(domain.to_lowercase(), addrs);
    }

    pub fn add_aaaa(&self, domain: &str, addrs: Vec<Ipv6Addr>) {
        self.aaaa_records
            .write()
            .unwrap()
            .insert(domain.to_lowercase(), addrs);
    }

    pub fn add_mx(&self, domain: &str, records: Vec<(u16, String)>) {
        self.mx_records
            .write()
            .unwrap()
            .insert(domain.to_lowercase(), records);
    }

    pub fn add_ptr(&self, ip: std::net::IpAddr, names: Vec<String>) {
        self.ptr_records
            .write()
            .unwrap()
            .insert(ip.to_string(), names);
    }
}

impl DnsResolver for MockResolver {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        self.txt_records
            .read()
            .unwrap()
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        self.a_records
            .read()
            .unwrap()
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        self.aaaa_records
            .read()
            .unwrap()
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
        self.mx_records
            .read()
            .unwrap()
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_ptr(&self, ip: std::net::IpAddr) -> Result<Vec<String>, DnsError> {
        self.ptr_records
            .read()
            .unwrap()
            .get(&ip.to_string())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_resolver_txt() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 -all".to_string()]);

        let result = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["v=spf1 -all"]);
    }

    #[tokio::test]
    async fn test_mock_resolver_nxdomain() {
        let resolver = MockResolver::new();
        let result = resolver.query_txt("nonexistent.com").await;
        assert!(matches!(result, Err(DnsError::NxDomain)));
    }

    #[tokio::test]
    async fn test_mock_resolver_case_insensitive() {
        let resolver = MockResolver::new();
        resolver.add_txt("EXAMPLE.COM", vec!["test".to_string()]);

        let result = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["test"]);
    }
}
