use std::future::Future;
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
pub struct DnsError {
    message: String,
    is_nxdomain: bool,
}

impl DnsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), is_nxdomain: false }
    }

    pub fn nxdomain() -> Self {
        Self { message: "NXDOMAIN".into(), is_nxdomain: true }
    }

    pub fn is_nxdomain(&self) -> bool {
        self.is_nxdomain
    }
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DnsError {}

pub trait DnsResolver: Send + Sync {
    fn query_txt(&self, domain: &str) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_a(&self, domain: &str) -> impl Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
    fn query_aaaa(&self, domain: &str) -> impl Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;
    fn query_mx(&self, domain: &str) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_exists(&self, domain: &str) -> impl Future<Output = Result<bool, DnsError>> + Send;
    fn query_ptr(&self, ip: IpAddr) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;
}

#[derive(Clone)]
pub struct HickoryResolver {
    resolver: hickory_resolver::TokioResolver,
}

impl HickoryResolver {
    pub fn new() -> Self {
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::name_server::TokioConnectionProvider;
        use hickory_resolver::TokioResolver;

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
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        match self.resolver.txt_lookup(domain).await {
            Ok(lookup) => {
                let records: Vec<String> = lookup
                    .iter()
                    .map(|txt| txt.to_string())
                    .collect();
                Ok(records)
            }
            Err(e) if is_nxdomain(&e) => Err(DnsError::nxdomain()),
            Err(e) => Err(DnsError::new(e.to_string())),
        }
    }

    async fn query_a(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        match self.resolver.ipv4_lookup(domain).await {
            Ok(lookup) => Ok(lookup.iter().map(|a| IpAddr::V4(a.0)).collect()),
            Err(e) if is_nxdomain(&e) => Err(DnsError::nxdomain()),
            Err(e) => Err(DnsError::new(e.to_string())),
        }
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        match self.resolver.ipv6_lookup(domain).await {
            Ok(lookup) => Ok(lookup.iter().map(|aaaa| IpAddr::V6(aaaa.0)).collect()),
            Err(e) if is_nxdomain(&e) => Err(DnsError::nxdomain()),
            Err(e) => Err(DnsError::new(e.to_string())),
        }
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        match self.resolver.mx_lookup(domain).await {
            Ok(lookup) => {
                let mut records: Vec<_> = lookup.iter().collect();
                records.sort_by_key(|mx| mx.preference());
                Ok(records.iter().map(|mx| mx.exchange().to_string()).collect())
            }
            Err(e) if is_nxdomain(&e) => Err(DnsError::nxdomain()),
            Err(e) => Err(DnsError::new(e.to_string())),
        }
    }

    async fn query_exists(&self, domain: &str) -> Result<bool, DnsError> {
        match self.query_a(domain).await {
            Ok(_) => Ok(true),
            Err(e) if e.is_nxdomain() => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => Ok(lookup.iter().map(|name| name.to_string()).collect()),
            Err(e) if is_nxdomain(&e) => Err(DnsError::nxdomain()),
            Err(e) => Err(DnsError::new(e.to_string())),
        }
    }
}

fn is_nxdomain(e: &hickory_resolver::ResolveError) -> bool {
    use hickory_resolver::ResolveErrorKind;
    match e.kind() {
        ResolveErrorKind::Proto(proto_err) => proto_err.is_nx_domain(),
        _ => false,
    }
}

#[derive(Default)]
pub struct MockResolver {
    txt_records: Mutex<HashMap<String, Vec<String>>>,
    a_records: Mutex<HashMap<String, Vec<IpAddr>>>,
    aaaa_records: Mutex<HashMap<String, Vec<IpAddr>>>,
    mx_records: Mutex<HashMap<String, Vec<String>>>,
    ptr_records: Mutex<HashMap<IpAddr, Vec<String>>>,
}

impl Clone for MockResolver {
    fn clone(&self) -> Self {
        Self {
            txt_records: Mutex::new(self.txt_records.lock().unwrap().clone()),
            a_records: Mutex::new(self.a_records.lock().unwrap().clone()),
            aaaa_records: Mutex::new(self.aaaa_records.lock().unwrap().clone()),
            mx_records: Mutex::new(self.mx_records.lock().unwrap().clone()),
            ptr_records: Mutex::new(self.ptr_records.lock().unwrap().clone()),
        }
    }
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_txt(&self, domain: &str, records: Vec<String>) {
        self.txt_records.lock().unwrap().insert(domain.to_lowercase(), records);
    }

    pub fn add_a(&self, domain: &str, ips: Vec<IpAddr>) {
        self.a_records.lock().unwrap().insert(domain.to_lowercase(), ips);
    }

    pub fn add_aaaa(&self, domain: &str, ips: Vec<IpAddr>) {
        self.aaaa_records.lock().unwrap().insert(domain.to_lowercase(), ips);
    }

    pub fn add_mx(&self, domain: &str, exchanges: Vec<String>) {
        self.mx_records.lock().unwrap().insert(domain.to_lowercase(), exchanges);
    }

    pub fn add_ptr(&self, ip: IpAddr, names: Vec<String>) {
        self.ptr_records.lock().unwrap().insert(ip, names);
    }
}

impl DnsResolver for MockResolver {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        self.txt_records
            .lock()
            .unwrap()
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or_else(DnsError::nxdomain)
    }

    async fn query_a(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.a_records
            .lock()
            .unwrap()
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or_else(DnsError::nxdomain)
    }

    async fn query_aaaa(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.aaaa_records
            .lock()
            .unwrap()
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or_else(DnsError::nxdomain)
    }

    async fn query_mx(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        self.mx_records
            .lock()
            .unwrap()
            .get(&domain.to_lowercase())
            .cloned()
            .ok_or_else(DnsError::nxdomain)
    }

    async fn query_exists(&self, domain: &str) -> Result<bool, DnsError> {
        Ok(self.a_records.lock().unwrap().contains_key(&domain.to_lowercase()))
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        self.ptr_records
            .lock()
            .unwrap()
            .get(&ip)
            .cloned()
            .ok_or_else(DnsError::nxdomain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_resolver_txt() {
        let resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 -all".into()]);

        let result = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["v=spf1 -all"]);
    }

    #[tokio::test]
    async fn test_mock_resolver_nxdomain() {
        let resolver = MockResolver::new();
        let result = resolver.query_txt("nonexistent.com").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().is_nxdomain());
    }
}
