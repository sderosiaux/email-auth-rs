use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("NXDOMAIN: domain does not exist")]
    NxDomain,
    #[error("DNS lookup failed: {0}")]
    LookupFailed(String),
    #[error("timeout")]
    Timeout,
}

pub trait DnsResolver: Send + Sync {
    fn query_txt(&self, domain: &str) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_a(&self, domain: &str) -> impl Future<Output = Result<Vec<Ipv4Addr>, DnsError>> + Send;
    fn query_aaaa(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<Ipv6Addr>, DnsError>> + Send;
    fn query_mx(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<(u16, String)>, DnsError>> + Send;
    fn query_ptr(&self, ip: IpAddr) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
}

#[derive(Clone)]
pub struct HickoryResolver {
    resolver: hickory_resolver::Resolver<hickory_resolver::name_server::TokioConnectionProvider>,
}

impl HickoryResolver {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = hickory_resolver::Resolver::builder_with_config(
            hickory_resolver::config::ResolverConfig::default(),
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .build();
        Ok(Self { resolver })
    }
}

impl Default for HickoryResolver {
    fn default() -> Self {
        Self::new().expect("failed to create resolver")
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
                            .map(|data| String::from_utf8_lossy(data).to_string())
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .collect();
                Ok(records)
            }
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::LookupFailed(e.to_string()))
                }
            }
        }
    }

    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        match self.resolver.ipv4_lookup(domain).await {
            Ok(lookup) => Ok(lookup.iter().map(|a| a.0).collect()),
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::LookupFailed(e.to_string()))
                }
            }
        }
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        match self.resolver.ipv6_lookup(domain).await {
            Ok(lookup) => Ok(lookup.iter().map(|aaaa| aaaa.0).collect()),
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::LookupFailed(e.to_string()))
                }
            }
        }
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
        match self.resolver.mx_lookup(domain).await {
            Ok(lookup) => Ok(lookup
                .iter()
                .map(|mx| (mx.preference(), mx.exchange().to_string()))
                .collect()),
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::LookupFailed(e.to_string()))
                }
            }
        }
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => Ok(lookup.iter().map(|name| name.to_string()).collect()),
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::LookupFailed(e.to_string()))
                }
            }
        }
    }
}

/// Mock resolver for testing
pub struct MockResolver {
    pub txt_records: std::collections::HashMap<String, Vec<String>>,
    pub a_records: std::collections::HashMap<String, Vec<Ipv4Addr>>,
    pub aaaa_records: std::collections::HashMap<String, Vec<Ipv6Addr>>,
    pub mx_records: std::collections::HashMap<String, Vec<(u16, String)>>,
    pub ptr_records: std::collections::HashMap<IpAddr, Vec<String>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self {
            txt_records: std::collections::HashMap::new(),
            a_records: std::collections::HashMap::new(),
            aaaa_records: std::collections::HashMap::new(),
            mx_records: std::collections::HashMap::new(),
            ptr_records: std::collections::HashMap::new(),
        }
    }

    pub fn add_txt(&mut self, domain: &str, records: Vec<String>) {
        self.txt_records
            .insert(domain.to_lowercase(), records);
    }

    pub fn add_a(&mut self, domain: &str, ips: Vec<Ipv4Addr>) {
        self.a_records.insert(domain.to_lowercase(), ips);
    }

    pub fn add_aaaa(&mut self, domain: &str, ips: Vec<Ipv6Addr>) {
        self.aaaa_records.insert(domain.to_lowercase(), ips);
    }

    pub fn add_mx(&mut self, domain: &str, mxs: Vec<(u16, String)>) {
        self.mx_records.insert(domain.to_lowercase(), mxs);
    }

    pub fn add_ptr(&mut self, ip: IpAddr, names: Vec<String>) {
        self.ptr_records.insert(ip, names);
    }
}

impl Default for MockResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver for MockResolver {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        self.txt_records
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        self.a_records
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        self.aaaa_records
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
        self.mx_records
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        self.ptr_records
            .get(&ip)
            .cloned()
            .ok_or(DnsError::NxDomain)
    }
}

// Allow Arc<R> to also implement DnsResolver
impl<R: DnsResolver> DnsResolver for Arc<R> {
    fn query_txt(&self, domain: &str) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send {
        (**self).query_txt(domain)
    }

    fn query_a(&self, domain: &str) -> impl Future<Output = Result<Vec<Ipv4Addr>, DnsError>> + Send {
        (**self).query_a(domain)
    }

    fn query_aaaa(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<Ipv6Addr>, DnsError>> + Send {
        (**self).query_aaaa(domain)
    }

    fn query_mx(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<(u16, String)>, DnsError>> + Send {
        (**self).query_mx(domain)
    }

    fn query_ptr(&self, ip: IpAddr) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send {
        (**self).query_ptr(ip)
    }
}
