use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS error types distinguishing NxDomain, NoRecords, and TempFail.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsError {
    /// Domain does not exist (NXDOMAIN).
    NxDomain,
    /// Domain exists but has no records of the requested type.
    NoRecords,
    /// Transient DNS failure (SERVFAIL, timeout, network error).
    TempFail,
}

/// MX record with preference and exchange hostname.
#[derive(Debug, Clone, PartialEq)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// Abstract DNS resolver trait for testability.
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError>;
    async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError>;
    async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError>;
    async fn query_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError>;
    async fn query_ptr(&self, ip: std::net::IpAddr) -> Result<Vec<String>, DnsError>;
    async fn query_exists(&self, name: &str) -> Result<bool, DnsError>;
}

/// Blanket impl: &R is also a DnsResolver when R is.
#[async_trait::async_trait]
impl<R: DnsResolver> DnsResolver for &R {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        <R as DnsResolver>::query_txt(self, name).await
    }
    async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        <R as DnsResolver>::query_a(self, name).await
    }
    async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        <R as DnsResolver>::query_aaaa(self, name).await
    }
    async fn query_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError> {
        <R as DnsResolver>::query_mx(self, name).await
    }
    async fn query_ptr(&self, ip: std::net::IpAddr) -> Result<Vec<String>, DnsError> {
        <R as DnsResolver>::query_ptr(self, ip).await
    }
    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        <R as DnsResolver>::query_exists(self, name).await
    }
}

/// Mock DNS resolver for testing. Holds predefined responses.
#[derive(Debug, Clone, Default)]
pub struct MockResolver {
    pub txt: std::collections::HashMap<String, Result<Vec<String>, DnsError>>,
    pub a: std::collections::HashMap<String, Result<Vec<Ipv4Addr>, DnsError>>,
    pub aaaa: std::collections::HashMap<String, Result<Vec<Ipv6Addr>, DnsError>>,
    pub mx: std::collections::HashMap<String, Result<Vec<MxRecord>, DnsError>>,
    pub ptr: std::collections::HashMap<String, Result<Vec<String>, DnsError>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_txt(mut self, name: &str, records: Vec<&str>) -> Self {
        self.txt.insert(
            name.to_lowercase(),
            Ok(records.into_iter().map(String::from).collect()),
        );
        self
    }

    pub fn with_txt_err(mut self, name: &str, err: DnsError) -> Self {
        self.txt.insert(name.to_lowercase(), Err(err));
        self
    }

    pub fn with_a(mut self, name: &str, addrs: Vec<Ipv4Addr>) -> Self {
        self.a.insert(name.to_lowercase(), Ok(addrs));
        self
    }

    pub fn with_a_err(mut self, name: &str, err: DnsError) -> Self {
        self.a.insert(name.to_lowercase(), Err(err));
        self
    }

    pub fn with_aaaa(mut self, name: &str, addrs: Vec<Ipv6Addr>) -> Self {
        self.aaaa.insert(name.to_lowercase(), Ok(addrs));
        self
    }

    pub fn with_aaaa_err(mut self, name: &str, err: DnsError) -> Self {
        self.aaaa.insert(name.to_lowercase(), Err(err));
        self
    }

    pub fn with_mx(mut self, name: &str, records: Vec<MxRecord>) -> Self {
        self.mx.insert(name.to_lowercase(), Ok(records));
        self
    }

    pub fn with_ptr(mut self, ip: &str, names: Vec<&str>) -> Self {
        self.ptr.insert(
            ip.to_string(),
            Ok(names.into_iter().map(String::from).collect()),
        );
        self
    }

    pub fn with_nxdomain(mut self, name: &str) -> Self {
        let n = name.to_lowercase();
        self.txt.insert(n.clone(), Err(DnsError::NxDomain));
        self.a.insert(n.clone(), Err(DnsError::NxDomain));
        self.aaaa.insert(n.clone(), Err(DnsError::NxDomain));
        self.mx.insert(n, Err(DnsError::NxDomain));
        self
    }
}

#[async_trait::async_trait]
impl DnsResolver for MockResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.txt
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or(Err(DnsError::NxDomain))
    }

    async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        self.a
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or(Err(DnsError::NxDomain))
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        self.aaaa
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or(Err(DnsError::NxDomain))
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError> {
        self.mx
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or(Err(DnsError::NxDomain))
    }

    async fn query_ptr(&self, ip: std::net::IpAddr) -> Result<Vec<String>, DnsError> {
        self.ptr
            .get(&ip.to_string())
            .cloned()
            .unwrap_or(Err(DnsError::NxDomain))
    }

    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        match self.query_a(name).await {
            Ok(addrs) => Ok(!addrs.is_empty()),
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => Ok(false),
            Err(e) => Err(e),
        }
    }
}
