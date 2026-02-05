use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;

#[derive(Debug, Clone)]
pub enum DnsError {
    NxDomain,
    ServFail,
    Timeout,
    Other(String),
}

pub trait DnsResolver: Clone + Send + Sync {
    fn query_txt(&self, name: &str) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_a(&self, name: &str) -> impl Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
    fn query_aaaa(&self, name: &str) -> impl Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
    fn query_mx(&self, name: &str) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
}

#[derive(Clone)]
pub struct HickoryResolver {
    resolver: TokioResolver,
}

impl HickoryResolver {
    pub fn new() -> Self {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        ).build();
        Self { resolver }
    }
}

impl Default for HickoryResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver for HickoryResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        match self.resolver.txt_lookup(name).await {
            Ok(lookup) => {
                let records: Vec<String> = lookup
                    .iter()
                    .map(|txt| txt.to_string())
                    .collect();
                Ok(records)
            }
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::Other(e.to_string()))
                }
            }
        }
    }

    async fn query_a(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        match self.resolver.ipv4_lookup(name).await {
            Ok(lookup) => {
                let addrs: Vec<IpAddr> = lookup.iter().map(|a| IpAddr::V4(a.0)).collect();
                Ok(addrs)
            }
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::Other(e.to_string()))
                }
            }
        }
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        match self.resolver.ipv6_lookup(name).await {
            Ok(lookup) => {
                let addrs: Vec<IpAddr> = lookup.iter().map(|a| IpAddr::V6(a.0)).collect();
                Ok(addrs)
            }
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::Other(e.to_string()))
                }
            }
        }
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<String>, DnsError> {
        match self.resolver.mx_lookup(name).await {
            Ok(lookup) => {
                let records: Vec<String> = lookup
                    .iter()
                    .map(|mx| mx.exchange().to_string())
                    .collect();
                Ok(records)
            }
            Err(e) => {
                if e.is_nx_domain() {
                    Err(DnsError::NxDomain)
                } else {
                    Err(DnsError::Other(e.to_string()))
                }
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct MockResolver {
    txt_records: Arc<RwLock<HashMap<String, Vec<String>>>>,
    a_records: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    aaaa_records: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    mx_records: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_txt(&self, name: &str, records: Vec<String>) {
        self.txt_records.write().unwrap().insert(name.to_lowercase(), records);
    }

    pub fn add_a(&self, name: &str, addrs: Vec<IpAddr>) {
        self.a_records.write().unwrap().insert(name.to_lowercase(), addrs);
    }

    pub fn add_aaaa(&self, name: &str, addrs: Vec<IpAddr>) {
        self.aaaa_records.write().unwrap().insert(name.to_lowercase(), addrs);
    }

    pub fn add_mx(&self, name: &str, exchanges: Vec<String>) {
        self.mx_records.write().unwrap().insert(name.to_lowercase(), exchanges);
    }
}

impl DnsResolver for MockResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.txt_records
            .read()
            .unwrap()
            .get(&name.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_a(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.a_records
            .read()
            .unwrap()
            .get(&name.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.aaaa_records
            .read()
            .unwrap()
            .get(&name.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.mx_records
            .read()
            .unwrap()
            .get(&name.to_lowercase())
            .cloned()
            .ok_or(DnsError::NxDomain)
    }
}
