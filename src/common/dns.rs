use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS error with NxDomain vs transient failure distinction.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DnsError {
    #[error("domain does not exist (NXDOMAIN)")]
    NxDomain,
    #[error("no records found")]
    NoRecords,
    #[error("temporary DNS failure: {0}")]
    TempFail(String),
}

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// Async DNS resolver trait. All email-auth DNS operations go through this.
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
        ip: IpAddr,
    ) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send;

    fn query_exists(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<bool, DnsError>> + Send;
}

// ---------------------------------------------------------------------------
// Blanket impl for references (enables sharing resolver across sub-verifiers)
// ---------------------------------------------------------------------------

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

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        <R as DnsResolver>::query_ptr(self, ip).await
    }

    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        <R as DnsResolver>::query_exists(self, name).await
    }
}

// ---------------------------------------------------------------------------
// HickoryResolver
// ---------------------------------------------------------------------------

use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;

#[derive(Clone)]
pub struct HickoryResolver {
    inner: Resolver<TokioConnectionProvider>,
}

impl HickoryResolver {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = Resolver::builder_with_config(
            Default::default(),
            TokioConnectionProvider::default(),
        )
        .build();
        Ok(Self { inner: resolver })
    }
}

fn resolve_error_to_dns(e: hickory_resolver::ResolveError) -> DnsError {
    if e.is_nx_domain() {
        DnsError::NxDomain
    } else if e.is_no_records_found() {
        DnsError::NoRecords
    } else {
        DnsError::TempFail(e.to_string())
    }
}

impl DnsResolver for HickoryResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        let lookup = self.inner.txt_lookup(name).await.map_err(resolve_error_to_dns)?;
        Ok(lookup
            .iter()
            .map(|txt| {
                txt.iter()
                    .map(|data| String::from_utf8_lossy(data).into_owned())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect())
    }

    async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        let lookup = self.inner.ipv4_lookup(name).await.map_err(resolve_error_to_dns)?;
        Ok(lookup.iter().map(|r| r.0).collect())
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        let lookup = self.inner.ipv6_lookup(name).await.map_err(resolve_error_to_dns)?;
        Ok(lookup.iter().map(|r| r.0).collect())
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError> {
        let lookup = self.inner.mx_lookup(name).await.map_err(resolve_error_to_dns)?;
        Ok(lookup
            .iter()
            .map(|mx| MxRecord {
                preference: mx.preference(),
                exchange: mx.exchange().to_ascii(),
            })
            .collect())
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        let lookup = self.inner.reverse_lookup(ip).await.map_err(resolve_error_to_dns)?;
        Ok(lookup.iter().map(|name| name.to_ascii()).collect())
    }

    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        match self.inner.ipv4_lookup(name).await {
            Ok(lookup) => Ok(lookup.iter().next().is_some()),
            Err(e) if e.is_nx_domain() || e.is_no_records_found() => Ok(false),
            Err(e) => Err(resolve_error_to_dns(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// MockResolver
// ---------------------------------------------------------------------------

/// DNS response for mock: either records, NxDomain, or TempFail.
#[derive(Debug, Clone)]
pub enum MockDnsResponse<T> {
    Records(Vec<T>),
    NxDomain,
    TempFail(String),
}

impl<T> MockDnsResponse<T> {
    fn into_result(self) -> Result<Vec<T>, DnsError> {
        match self {
            Self::Records(r) => Ok(r),
            Self::NxDomain => Err(DnsError::NxDomain),
            Self::TempFail(msg) => Err(DnsError::TempFail(msg)),
        }
    }
}

/// HashMap-backed mock resolver for deterministic testing.
#[derive(Debug, Clone, Default)]
pub struct MockResolver {
    pub txt: HashMap<String, MockDnsResponse<String>>,
    pub a: HashMap<String, MockDnsResponse<Ipv4Addr>>,
    pub aaaa: HashMap<String, MockDnsResponse<Ipv6Addr>>,
    pub mx: HashMap<String, MockDnsResponse<MxRecord>>,
    pub ptr: HashMap<String, MockDnsResponse<String>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup<T: Clone>(
        map: &HashMap<String, MockDnsResponse<T>>,
        name: &str,
    ) -> Result<Vec<T>, DnsError> {
        let key = normalize_domain(name);
        match map.get(&key) {
            Some(resp) => resp.clone().into_result(),
            None => Err(DnsError::NxDomain),
        }
    }
}

fn normalize_domain(name: &str) -> String {
    let s = name.to_ascii_lowercase();
    s.strip_suffix('.').unwrap_or(&s).to_string()
}

impl DnsResolver for MockResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        Self::lookup(&self.txt, name)
    }

    async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        Self::lookup(&self.a, name)
    }

    async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        Self::lookup(&self.aaaa, name)
    }

    async fn query_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError> {
        Self::lookup(&self.mx, name)
    }

    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        let key = ip.to_string();
        match self.ptr.get(&key) {
            Some(resp) => resp.clone().into_result(),
            None => Err(DnsError::NxDomain),
        }
    }

    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        match self.query_a(name).await {
            Ok(addrs) => Ok(!addrs.is_empty()),
            Err(DnsError::NxDomain | DnsError::NoRecords) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_resolver_txt() {
        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::Records(vec!["v=spf1 -all".into()]),
        );
        let result = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["v=spf1 -all"]);
    }

    #[tokio::test]
    async fn mock_resolver_nxdomain() {
        let mut resolver = MockResolver::new();
        resolver.txt.insert("example.com".into(), MockDnsResponse::NxDomain);
        let result = resolver.query_txt("example.com").await;
        assert!(matches!(result, Err(DnsError::NxDomain)));
    }

    #[tokio::test]
    async fn mock_resolver_missing_is_nxdomain() {
        let resolver = MockResolver::new();
        let result = resolver.query_txt("nonexistent.example.com").await;
        assert!(matches!(result, Err(DnsError::NxDomain)));
    }

    #[tokio::test]
    async fn mock_resolver_tempfail() {
        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::TempFail("timeout".into()),
        );
        let result = resolver.query_txt("example.com").await;
        assert!(matches!(result, Err(DnsError::TempFail(_))));
    }

    #[tokio::test]
    async fn mock_resolver_exists() {
        let mut resolver = MockResolver::new();
        resolver.a.insert(
            "example.com".into(),
            MockDnsResponse::Records(vec![Ipv4Addr::new(192, 0, 2, 1)]),
        );
        assert!(resolver.query_exists("example.com").await.unwrap());
        assert!(!resolver.query_exists("nonexistent.com").await.unwrap());
    }

    #[tokio::test]
    async fn mock_resolver_normalizes_case_and_trailing_dot() {
        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::Records(vec!["test".into()]),
        );
        let result = resolver.query_txt("EXAMPLE.COM.").await.unwrap();
        assert_eq!(result, vec!["test"]);
    }
}
