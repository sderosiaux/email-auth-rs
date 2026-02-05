//! DNS resolver abstraction for email authentication.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// DNS resolver trait for email authentication.
/// Uses `impl Future` (Rust 1.75+) instead of async-trait.
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
    ) -> impl Future<Output = Result<Vec<MxRecord>, DnsError>> + Send;

    fn query_ptr(
        &self,
        ip: IpAddr,
    ) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
}

/// Production DNS resolver using hickory-resolver.
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
        Self::new().expect("Failed to create DNS resolver")
    }
}

impl DnsResolver for HickoryResolver {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        let lookup = self
            .resolver
            .txt_lookup(domain)
            .await
            .map_err(|e| map_resolve_error(e))?;

        let records: Vec<String> = lookup
            .iter()
            .map(|txt| {
                txt.txt_data()
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
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

    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        let lookup = self
            .resolver
            .ipv4_lookup(domain)
            .await
            .map_err(|e| map_resolve_error(e))?;

        let addrs: Vec<Ipv4Addr> = lookup.iter().map(|a| a.0).collect();

        if addrs.is_empty() {
            Err(DnsError::NoRecords)
        } else {
            Ok(addrs)
        }
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        let lookup = self
            .resolver
            .ipv6_lookup(domain)
            .await
            .map_err(|e| map_resolve_error(e))?;

        let addrs: Vec<Ipv6Addr> = lookup.iter().map(|a| a.0).collect();

        if addrs.is_empty() {
            Err(DnsError::NoRecords)
        } else {
            Ok(addrs)
        }
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
        let lookup = self
            .resolver
            .mx_lookup(domain)
            .await
            .map_err(|e| map_resolve_error(e))?;

        let mut records: Vec<MxRecord> = lookup
            .iter()
            .map(|mx| MxRecord {
                preference: mx.preference(),
                exchange: mx.exchange().to_string(),
            })
            .collect();

        records.sort_by_key(|r| r.preference);

        if records.is_empty() {
            Err(DnsError::NoRecords)
        } else {
            Ok(records)
        }
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        let lookup = self
            .resolver
            .reverse_lookup(ip)
            .await
            .map_err(|e| map_resolve_error(e))?;

        let names: Vec<String> = lookup.iter().map(|name| name.to_string()).collect();

        if names.is_empty() {
            Err(DnsError::NoRecords)
        } else {
            Ok(names)
        }
    }
}

fn map_resolve_error(e: hickory_resolver::ResolveError) -> DnsError {
    // Use the convenience methods on ResolveError
    if e.is_nx_domain() {
        DnsError::NxDomain
    } else if e.is_no_records_found() {
        DnsError::NoRecords
    } else {
        // Check the error message for timeout indicators
        let msg = e.to_string().to_lowercase();
        if msg.contains("timeout") {
            DnsError::Timeout
        } else if msg.contains("servfail") {
            DnsError::ServFail
        } else {
            DnsError::Other(e.to_string())
        }
    }
}

/// Mock DNS resolver for testing.
#[derive(Clone, Default)]
pub struct MockResolver {
    txt_records: Arc<std::collections::HashMap<String, Vec<String>>>,
    a_records: Arc<std::collections::HashMap<String, Vec<Ipv4Addr>>>,
    aaaa_records: Arc<std::collections::HashMap<String, Vec<Ipv6Addr>>>,
    mx_records: Arc<std::collections::HashMap<String, Vec<MxRecord>>>,
    ptr_records: Arc<std::collections::HashMap<IpAddr, Vec<String>>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_txt(mut self, domain: &str, records: Vec<String>) -> Self {
        Arc::make_mut(&mut self.txt_records).insert(domain.to_lowercase(), records);
        self
    }

    pub fn with_a(mut self, domain: &str, addrs: Vec<Ipv4Addr>) -> Self {
        Arc::make_mut(&mut self.a_records).insert(domain.to_lowercase(), addrs);
        self
    }

    pub fn with_aaaa(mut self, domain: &str, addrs: Vec<Ipv6Addr>) -> Self {
        Arc::make_mut(&mut self.aaaa_records).insert(domain.to_lowercase(), addrs);
        self
    }

    pub fn with_mx(mut self, domain: &str, records: Vec<MxRecord>) -> Self {
        Arc::make_mut(&mut self.mx_records).insert(domain.to_lowercase(), records);
        self
    }

    pub fn with_ptr(mut self, ip: IpAddr, names: Vec<String>) -> Self {
        Arc::make_mut(&mut self.ptr_records).insert(ip, names);
        self
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

    async fn query_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
        self.mx_records
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        self.ptr_records.get(&ip).cloned().ok_or(DnsError::NxDomain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_resolver() {
        let resolver = MockResolver::new()
            .with_txt("example.com", vec!["v=spf1 -all".to_string()])
            .with_a("example.com", vec![Ipv4Addr::new(93, 184, 216, 34)]);

        let txt = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(txt, vec!["v=spf1 -all"]);

        let a = resolver.query_a("example.com").await.unwrap();
        assert_eq!(a, vec![Ipv4Addr::new(93, 184, 216, 34)]);

        let err = resolver.query_txt("nonexistent.com").await;
        assert!(matches!(err, Err(DnsError::NxDomain)));
    }
}
