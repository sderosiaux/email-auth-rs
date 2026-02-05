use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("NXDOMAIN: domain does not exist")]
    NxDomain,
    #[error("SERVFAIL: server failure")]
    ServFail,
    #[error("timeout")]
    Timeout,
    #[error("DNS error: {0}")]
    Other(String),
}

/// DNS resolver trait for abstracting DNS lookups
pub trait DnsResolver: Clone + Send + Sync + 'static {
    fn query_txt(&self, domain: &str) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_a(&self, domain: &str) -> impl Future<Output = Result<Vec<Ipv4Addr>, DnsError>> + Send;
    fn query_aaaa(&self, domain: &str) -> impl Future<Output = Result<Vec<Ipv6Addr>, DnsError>> + Send;
    fn query_mx(&self, domain: &str) -> impl Future<Output = Result<Vec<(u16, String)>, DnsError>> + Send;
    fn query_ptr(&self, ip: IpAddr) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
}

/// Hickory DNS resolver implementation
#[derive(Clone)]
pub struct HickoryResolver {
    resolver: TokioResolver,
}

impl HickoryResolver {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();
        Ok(Self { resolver })
    }

    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();
        Ok(Self { resolver })
    }

    fn classify_error(e: &hickory_resolver::ResolveError) -> DnsError {
        let msg = e.to_string().to_lowercase();
        if msg.contains("nxdomain") || msg.contains("no records") {
            DnsError::NxDomain
        } else if msg.contains("timeout") {
            DnsError::Timeout
        } else if msg.contains("servfail") {
            DnsError::ServFail
        } else {
            DnsError::Other(e.to_string())
        }
    }
}

impl Default for HickoryResolver {
    fn default() -> Self {
        Self::new().expect("Failed to create default HickoryResolver")
    }
}

impl DnsResolver for HickoryResolver {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        match self.resolver.txt_lookup(domain).await {
            Ok(lookup) => {
                let records: Vec<String> = lookup
                    .iter()
                    .map(|txt| txt.to_string())
                    .collect();
                Ok(records)
            }
            Err(e) => Err(Self::classify_error(&e)),
        }
    }

    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        match self.resolver.ipv4_lookup(domain).await {
            Ok(lookup) => {
                let addrs: Vec<Ipv4Addr> = lookup.iter().map(|a| a.0).collect();
                Ok(addrs)
            }
            Err(e) => Err(Self::classify_error(&e)),
        }
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        match self.resolver.ipv6_lookup(domain).await {
            Ok(lookup) => {
                let addrs: Vec<Ipv6Addr> = lookup.iter().map(|a| a.0).collect();
                Ok(addrs)
            }
            Err(e) => Err(Self::classify_error(&e)),
        }
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
        match self.resolver.mx_lookup(domain).await {
            Ok(lookup) => {
                let records: Vec<(u16, String)> = lookup
                    .iter()
                    .map(|mx| (mx.preference(), mx.exchange().to_string().trim_end_matches('.').to_string()))
                    .collect();
                Ok(records)
            }
            Err(e) => Err(Self::classify_error(&e)),
        }
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                let names: Vec<String> = lookup
                    .iter()
                    .map(|name| name.to_string().trim_end_matches('.').to_string())
                    .collect();
                Ok(names)
            }
            Err(e) => Err(Self::classify_error(&e)),
        }
    }
}

/// Mock DNS resolver for testing
#[derive(Clone, Default)]
pub struct MockResolver {
    txt_records: Arc<Mutex<HashMap<String, Vec<String>>>>,
    a_records: Arc<Mutex<HashMap<String, Vec<Ipv4Addr>>>>,
    aaaa_records: Arc<Mutex<HashMap<String, Vec<Ipv6Addr>>>>,
    mx_records: Arc<Mutex<HashMap<String, Vec<(u16, String)>>>>,
    ptr_records: Arc<Mutex<HashMap<IpAddr, Vec<String>>>>,
    nxdomain: Arc<Mutex<Vec<String>>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_txt(&self, domain: &str, records: Vec<String>) {
        self.txt_records.lock().unwrap().insert(domain.to_lowercase(), records);
    }

    pub fn add_a(&self, domain: &str, addrs: Vec<Ipv4Addr>) {
        self.a_records.lock().unwrap().insert(domain.to_lowercase(), addrs);
    }

    pub fn add_aaaa(&self, domain: &str, addrs: Vec<Ipv6Addr>) {
        self.aaaa_records.lock().unwrap().insert(domain.to_lowercase(), addrs);
    }

    pub fn add_mx(&self, domain: &str, records: Vec<(u16, String)>) {
        self.mx_records.lock().unwrap().insert(domain.to_lowercase(), records);
    }

    pub fn add_ptr(&self, ip: IpAddr, names: Vec<String>) {
        self.ptr_records.lock().unwrap().insert(ip, names);
    }

    pub fn set_nxdomain(&self, domain: &str) {
        self.nxdomain.lock().unwrap().push(domain.to_lowercase());
    }
}

impl DnsResolver for MockResolver {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        let domain_lower = domain.to_lowercase();
        if self.nxdomain.lock().unwrap().contains(&domain_lower) {
            return Err(DnsError::NxDomain);
        }
        Ok(self.txt_records.lock().unwrap().get(&domain_lower).cloned().unwrap_or_default())
    }

    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        let domain_lower = domain.to_lowercase();
        if self.nxdomain.lock().unwrap().contains(&domain_lower) {
            return Err(DnsError::NxDomain);
        }
        Ok(self.a_records.lock().unwrap().get(&domain_lower).cloned().unwrap_or_default())
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        let domain_lower = domain.to_lowercase();
        if self.nxdomain.lock().unwrap().contains(&domain_lower) {
            return Err(DnsError::NxDomain);
        }
        Ok(self.aaaa_records.lock().unwrap().get(&domain_lower).cloned().unwrap_or_default())
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
        let domain_lower = domain.to_lowercase();
        if self.nxdomain.lock().unwrap().contains(&domain_lower) {
            return Err(DnsError::NxDomain);
        }
        Ok(self.mx_records.lock().unwrap().get(&domain_lower).cloned().unwrap_or_default())
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        Ok(self.ptr_records.lock().unwrap().get(&ip).cloned().unwrap_or_default())
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
        resolver.set_nxdomain("nonexistent.com");

        let result = resolver.query_txt("nonexistent.com").await;
        assert!(matches!(result, Err(DnsError::NxDomain)));
    }
}
