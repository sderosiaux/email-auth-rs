use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS error types — must distinguish NxDomain, NoRecords, and TempFail
/// for correct SPF void lookup tracking and error propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Domain does not exist (NXDOMAIN).
    NxDomain,
    /// Domain exists but has no records of the requested type.
    NoRecords,
    /// Transient DNS failure (timeout, SERVFAIL, network error).
    TempFail,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::NxDomain => write!(f, "NXDOMAIN"),
            DnsError::NoRecords => write!(f, "no records"),
            DnsError::TempFail => write!(f, "temporary DNS failure"),
        }
    }
}

impl std::error::Error for DnsError {}

/// MX record with preference and exchange hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// Abstract async DNS resolver trait.
///
/// DNS caching is the caller's responsibility. Implement this trait
/// with a caching layer at the resolver level.
///
/// Methods return `impl Future + Send` to allow use in `Pin<Box<dyn Future + Send>>` contexts
/// (required for SPF async recursion via include/redirect).
pub trait DnsResolver: Send + Sync {
    fn query_txt(&self, name: &str) -> impl std::future::Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_a(&self, name: &str) -> impl std::future::Future<Output = Result<Vec<Ipv4Addr>, DnsError>> + Send;
    fn query_aaaa(&self, name: &str) -> impl std::future::Future<Output = Result<Vec<Ipv6Addr>, DnsError>> + Send;
    fn query_mx(&self, name: &str) -> impl std::future::Future<Output = Result<Vec<MxRecord>, DnsError>> + Send;
    fn query_ptr(&self, ip: &IpAddr) -> impl std::future::Future<Output = Result<Vec<String>, DnsError>> + Send;
    fn query_exists(&self, name: &str) -> impl std::future::Future<Output = Result<bool, DnsError>> + Send;
}

/// Blanket impl: allow passing `&R` where `R: DnsResolver` is expected.
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
    async fn query_ptr(&self, ip: &IpAddr) -> Result<Vec<String>, DnsError> {
        <R as DnsResolver>::query_ptr(self, ip).await
    }
    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
        <R as DnsResolver>::query_exists(self, name).await
    }
}

/// Mock DNS resolver for testing. Configure responses per domain.
#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;

    #[derive(Debug, Default, Clone)]
    pub struct MockResolver {
        pub txt: HashMap<String, Result<Vec<String>, DnsError>>,
        pub a: HashMap<String, Result<Vec<Ipv4Addr>, DnsError>>,
        pub aaaa: HashMap<String, Result<Vec<Ipv6Addr>, DnsError>>,
        pub mx: HashMap<String, Result<Vec<MxRecord>, DnsError>>,
        pub ptr: HashMap<String, Result<Vec<String>, DnsError>>,
    }

    impl MockResolver {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn add_txt(&mut self, name: &str, records: Vec<String>) {
            self.txt.insert(name.to_lowercase(), Ok(records));
        }

        pub fn add_txt_err(&mut self, name: &str, err: DnsError) {
            self.txt.insert(name.to_lowercase(), Err(err));
        }

        pub fn add_a(&mut self, name: &str, addrs: Vec<Ipv4Addr>) {
            self.a.insert(name.to_lowercase(), Ok(addrs));
        }

        pub fn add_a_err(&mut self, name: &str, err: DnsError) {
            self.a.insert(name.to_lowercase(), Err(err));
        }

        pub fn add_aaaa(&mut self, name: &str, addrs: Vec<Ipv6Addr>) {
            self.aaaa.insert(name.to_lowercase(), Ok(addrs));
        }

        pub fn add_aaaa_err(&mut self, name: &str, err: DnsError) {
            self.aaaa.insert(name.to_lowercase(), Err(err));
        }

        pub fn add_mx(&mut self, name: &str, records: Vec<MxRecord>) {
            self.mx.insert(name.to_lowercase(), Ok(records));
        }

        pub fn add_mx_err(&mut self, name: &str, err: DnsError) {
            self.mx.insert(name.to_lowercase(), Err(err));
        }

        pub fn add_ptr(&mut self, ip_str: &str, names: Vec<String>) {
            self.ptr.insert(ip_str.to_string(), Ok(names));
        }

        pub fn add_ptr_err(&mut self, ip_str: &str, err: DnsError) {
            self.ptr.insert(ip_str.to_string(), Err(err));
        }

        fn lookup<T: Clone>(
            map: &HashMap<String, Result<Vec<T>, DnsError>>,
            key: &str,
        ) -> Result<Vec<T>, DnsError> {
            match map.get(&key.to_lowercase()) {
                Some(Ok(v)) => Ok(v.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(DnsError::NxDomain),
            }
        }
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

        async fn query_ptr(&self, ip: &IpAddr) -> Result<Vec<String>, DnsError> {
            let key = ip.to_string();
            match self.ptr.get(&key) {
                Some(Ok(v)) => Ok(v.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(DnsError::NxDomain),
            }
        }

        async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
            match self.query_a(name).await {
                Ok(addrs) => Ok(!addrs.is_empty()),
                Err(DnsError::NxDomain) => Ok(false),
                Err(DnsError::NoRecords) => Ok(false),
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::mock::MockResolver;

    // CHK-157: Abstract DNS resolver trait
    // CHK-158: Support async DNS queries
    // CHK-159: Methods needed
    #[tokio::test]
    async fn trait_has_all_required_methods() {
        let resolver = MockResolver::new();
        // Verify all 6 methods exist and return correct types
        let _: Result<Vec<String>, DnsError> = resolver.query_txt("example.com").await;
        let _: Result<Vec<Ipv4Addr>, DnsError> = resolver.query_a("example.com").await;
        let _: Result<Vec<Ipv6Addr>, DnsError> = resolver.query_aaaa("example.com").await;
        let _: Result<Vec<MxRecord>, DnsError> = resolver.query_mx("example.com").await;
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let _: Result<Vec<String>, DnsError> = resolver.query_ptr(&ip).await;
        let _: Result<bool, DnsError> = resolver.query_exists("example.com").await;
    }

    // CHK-160: query_txt
    #[tokio::test]
    async fn query_txt_returns_records() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 -all".to_string()]);
        let result = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["v=spf1 -all"]);
    }

    // CHK-161: query_a
    #[tokio::test]
    async fn query_a_returns_addresses() {
        let mut resolver = MockResolver::new();
        resolver.add_a("example.com", vec!["1.2.3.4".parse().unwrap()]);
        let result = resolver.query_a("example.com").await.unwrap();
        assert_eq!(result, vec!["1.2.3.4".parse::<Ipv4Addr>().unwrap()]);
    }

    // CHK-162: query_aaaa
    #[tokio::test]
    async fn query_aaaa_returns_addresses() {
        let mut resolver = MockResolver::new();
        resolver.add_aaaa("example.com", vec!["::1".parse().unwrap()]);
        let result = resolver.query_aaaa("example.com").await.unwrap();
        assert_eq!(result, vec!["::1".parse::<Ipv6Addr>().unwrap()]);
    }

    // CHK-163: query_mx
    #[tokio::test]
    async fn query_mx_returns_records() {
        let mut resolver = MockResolver::new();
        resolver.add_mx(
            "example.com",
            vec![MxRecord { preference: 10, exchange: "mail.example.com".into() }],
        );
        let result = resolver.query_mx("example.com").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].preference, 10);
        assert_eq!(result[0].exchange, "mail.example.com");
    }

    // CHK-164: query_ptr
    #[tokio::test]
    async fn query_ptr_returns_names() {
        let mut resolver = MockResolver::new();
        resolver.add_ptr("1.2.3.4", vec!["host.example.com".into()]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let result = resolver.query_ptr(&ip).await.unwrap();
        assert_eq!(result, vec!["host.example.com"]);
    }

    // CHK-165: query_exists
    #[tokio::test]
    async fn query_exists_returns_bool() {
        let mut resolver = MockResolver::new();
        resolver.add_a("example.com", vec!["1.2.3.4".parse().unwrap()]);
        assert!(resolver.query_exists("example.com").await.unwrap());
    }

    #[tokio::test]
    async fn query_exists_false_for_nxdomain() {
        let resolver = MockResolver::new();
        assert!(!resolver.query_exists("nonexistent.example.com").await.unwrap());
    }

    // CHK-166: DnsError distinguishes NxDomain, NoRecords, TempFail
    #[tokio::test]
    async fn dns_error_nxdomain() {
        let resolver = MockResolver::new();
        assert_eq!(
            resolver.query_txt("nope.example.com").await.unwrap_err(),
            DnsError::NxDomain
        );
    }

    #[tokio::test]
    async fn dns_error_tempfail() {
        let mut resolver = MockResolver::new();
        resolver.add_txt_err("fail.example.com", DnsError::TempFail);
        assert_eq!(
            resolver.query_txt("fail.example.com").await.unwrap_err(),
            DnsError::TempFail
        );
    }

    #[tokio::test]
    async fn dns_error_no_records() {
        let mut resolver = MockResolver::new();
        resolver.add_a_err("empty.example.com", DnsError::NoRecords);
        assert_eq!(
            resolver.query_a("empty.example.com").await.unwrap_err(),
            DnsError::NoRecords
        );
    }

    // CHK-167: DNS caching is caller responsibility
    // This is a documentation/design constraint — verified by trait lacking cache methods.
    // The DnsResolver trait has no cache-related methods.

    // Blanket impl test: &R implements DnsResolver
    #[tokio::test]
    async fn blanket_impl_ref_resolver() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["test".into()]);
        let r: &MockResolver = &resolver;
        let result = r.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["test"]);
    }

    // Mock: case-insensitive lookup
    #[tokio::test]
    async fn mock_case_insensitive() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("EXAMPLE.COM", vec!["data".into()]);
        let result = resolver.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["data"]);
    }
}
