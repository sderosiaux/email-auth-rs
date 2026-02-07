use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS error types distinguishing NxDomain, NoRecords, and transient failures.
#[derive(Debug, Clone)]
pub enum DnsError {
    /// Domain does not exist (NXDOMAIN)
    NxDomain,
    /// Domain exists but no records of requested type
    NoRecords,
    /// Transient failure (timeout, SERVFAIL)
    TempFail(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::NxDomain => write!(f, "NXDOMAIN"),
            DnsError::NoRecords => write!(f, "no records"),
            DnsError::TempFail(msg) => write!(f, "temporary failure: {}", msg),
        }
    }
}

impl std::error::Error for DnsError {}

/// MX record with preference and exchange hostname.
#[derive(Debug, Clone)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// Async DNS resolver trait. Implementations must be Send+Sync for use in async contexts.
pub trait DnsResolver: Send + Sync {
    fn query_txt(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;

    fn query_a(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Vec<Ipv4Addr>, DnsError>> + Send;

    fn query_aaaa(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Vec<Ipv6Addr>, DnsError>> + Send;

    fn query_mx(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Vec<MxRecord>, DnsError>> + Send;

    fn query_ptr(
        &self,
        ip: &str,
    ) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;

    fn query_exists(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<bool, DnsError>> + Send;
}

/// Blanket impl allowing &R to be used as a DnsResolver when R: DnsResolver.
/// Uses UFCS to avoid infinite recursion.
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
    async fn query_ptr(&self, ip: &str) -> Result<Vec<String>, DnsError> {
        <R as DnsResolver>::query_ptr(self, ip).await
    }
    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        <R as DnsResolver>::query_exists(self, name).await
    }
}

/// Production DNS resolver wrapping hickory-resolver.
#[derive(Clone)]
pub struct HickoryResolver {
    resolver: hickory_resolver::Resolver<hickory_resolver::name_server::TokioConnectionProvider>,
}

impl HickoryResolver {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = hickory_resolver::Resolver::builder_with_config(
            hickory_resolver::config::ResolverConfig::default(),
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .build();
        Ok(Self { resolver })
    }
}

impl DnsResolver for HickoryResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        use hickory_resolver::proto::rr::RecordType;
        match self.resolver.lookup(name, RecordType::TXT).await {
            Ok(lookup) => {
                let mut results = Vec::new();
                for record in lookup.record_iter() {
                    if let Some(txt) = record.data().as_txt() {
                        results.push(txt.to_string());
                    }
                }
                if results.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(results)
                }
            }
            Err(e) => Err(classify_hickory_error(&e)),
        }
    }

    async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        match self.resolver.ipv4_lookup(name).await {
            Ok(lookup) => {
                let addrs: Vec<Ipv4Addr> = lookup.into_iter().map(|a| a.0).collect();
                if addrs.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(addrs)
                }
            }
            Err(e) => Err(classify_hickory_error(&e)),
        }
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        match self.resolver.ipv6_lookup(name).await {
            Ok(lookup) => {
                let addrs: Vec<Ipv6Addr> = lookup.into_iter().map(|a| a.0).collect();
                if addrs.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(addrs)
                }
            }
            Err(e) => Err(classify_hickory_error(&e)),
        }
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError> {
        match self.resolver.mx_lookup(name).await {
            Ok(lookup) => {
                let records: Vec<MxRecord> = lookup
                    .into_iter()
                    .map(|mx| MxRecord {
                        preference: mx.preference(),
                        exchange: mx.exchange().to_ascii(),
                    })
                    .collect();
                if records.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(records)
                }
            }
            Err(e) => Err(classify_hickory_error(&e)),
        }
    }

    async fn query_ptr(&self, ip: &str) -> Result<Vec<String>, DnsError> {
        let addr: std::net::IpAddr = ip
            .parse()
            .map_err(|_| DnsError::TempFail(format!("invalid IP: {}", ip)))?;
        match self.resolver.reverse_lookup(addr).await {
            Ok(lookup) => {
                let names: Vec<String> = lookup.into_iter().map(|n| n.to_ascii()).collect();
                if names.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(names)
                }
            }
            Err(e) => Err(classify_hickory_error(&e)),
        }
    }

    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        match self.query_a(name).await {
            Ok(_) => Ok(true),
            Err(DnsError::NxDomain) => Ok(false),
            Err(DnsError::NoRecords) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

fn classify_hickory_error(e: &hickory_resolver::ResolveError) -> DnsError {
    if e.is_nx_domain() {
        DnsError::NxDomain
    } else if e.is_no_records_found() {
        DnsError::NoRecords
    } else {
        DnsError::TempFail(e.to_string())
    }
}

// --- MockResolver ---

/// Response type for mock DNS entries.
#[derive(Debug, Clone)]
pub enum MockDnsResponse<T: Clone> {
    Records(Vec<T>),
    NxDomain,
    TempFail(String),
}

/// Mock DNS resolver for testing. HashMap-backed, supports per-query error simulation.
#[derive(Debug, Clone)]
pub struct MockResolver {
    txt: HashMap<String, MockDnsResponse<String>>,
    a: HashMap<String, MockDnsResponse<Ipv4Addr>>,
    aaaa: HashMap<String, MockDnsResponse<Ipv6Addr>>,
    mx: HashMap<String, MockDnsResponse<MxRecord>>,
    ptr: HashMap<String, MockDnsResponse<String>>,
}

fn normalize_domain(domain: &str) -> String {
    domain.to_ascii_lowercase().trim_end_matches('.').to_string()
}

impl MockResolver {
    pub fn new() -> Self {
        Self {
            txt: HashMap::new(),
            a: HashMap::new(),
            aaaa: HashMap::new(),
            mx: HashMap::new(),
            ptr: HashMap::new(),
        }
    }

    pub fn add_txt(&mut self, domain: &str, records: Vec<String>) {
        self.txt.insert(
            normalize_domain(domain),
            MockDnsResponse::Records(records),
        );
    }

    pub fn add_txt_tempfail(&mut self, domain: &str, msg: &str) {
        self.txt.insert(
            normalize_domain(domain),
            MockDnsResponse::TempFail(msg.to_string()),
        );
    }

    pub fn add_txt_nxdomain(&mut self, domain: &str) {
        self.txt
            .insert(normalize_domain(domain), MockDnsResponse::NxDomain);
    }

    pub fn add_a(&mut self, domain: &str, addrs: Vec<Ipv4Addr>) {
        self.a.insert(
            normalize_domain(domain),
            MockDnsResponse::Records(addrs),
        );
    }

    pub fn add_a_nxdomain(&mut self, domain: &str) {
        self.a
            .insert(normalize_domain(domain), MockDnsResponse::NxDomain);
    }

    pub fn add_aaaa(&mut self, domain: &str, addrs: Vec<Ipv6Addr>) {
        self.aaaa.insert(
            normalize_domain(domain),
            MockDnsResponse::Records(addrs),
        );
    }

    pub fn add_aaaa_nxdomain(&mut self, domain: &str) {
        self.aaaa
            .insert(normalize_domain(domain), MockDnsResponse::NxDomain);
    }

    pub fn add_mx(&mut self, domain: &str, records: Vec<MxRecord>) {
        self.mx.insert(
            normalize_domain(domain),
            MockDnsResponse::Records(records),
        );
    }

    pub fn add_mx_nxdomain(&mut self, domain: &str) {
        self.mx
            .insert(normalize_domain(domain), MockDnsResponse::NxDomain);
    }

    pub fn add_ptr(&mut self, ip: &str, names: Vec<String>) {
        self.ptr.insert(
            ip.to_string(),
            MockDnsResponse::Records(names),
        );
    }

    fn resolve_mock<T: Clone>(
        map: &HashMap<String, MockDnsResponse<T>>,
        key: &str,
    ) -> Result<Vec<T>, DnsError> {
        match map.get(key) {
            Some(MockDnsResponse::Records(r)) => {
                if r.is_empty() {
                    Err(DnsError::NoRecords)
                } else {
                    Ok(r.clone())
                }
            }
            Some(MockDnsResponse::NxDomain) => Err(DnsError::NxDomain),
            Some(MockDnsResponse::TempFail(msg)) => Err(DnsError::TempFail(msg.clone())),
            None => Err(DnsError::NxDomain),
        }
    }
}

impl Default for MockResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver for MockResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        Self::resolve_mock(&self.txt, &normalize_domain(name))
    }

    async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        Self::resolve_mock(&self.a, &normalize_domain(name))
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        Self::resolve_mock(&self.aaaa, &normalize_domain(name))
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError> {
        Self::resolve_mock(&self.mx, &normalize_domain(name))
    }

    async fn query_ptr(&self, ip: &str) -> Result<Vec<String>, DnsError> {
        Self::resolve_mock(&self.ptr, ip)
    }

    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        match self.query_a(name).await {
            Ok(_) => Ok(true),
            Err(DnsError::NxDomain) => Ok(false),
            Err(DnsError::NoRecords) => Ok(false),
            Err(e) => Err(e),
        }
    }
}
