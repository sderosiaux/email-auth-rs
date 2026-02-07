use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS error types distinguishing NxDomain from empty results from transient failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Domain does not exist (NXDOMAIN).
    NxDomain,
    /// Domain exists but has no records of the requested type.
    NoRecords,
    /// Transient failure (SERVFAIL, timeout, network error).
    TempFail,
}

/// MX record with preference and exchange hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// Async DNS resolver trait. Implementations must be Send + Sync for use in async contexts.
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError>;
    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError>;
    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError>;
    async fn query_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError>;
    async fn query_ptr(&self, ip: std::net::IpAddr) -> Result<Vec<String>, DnsError>;
    async fn query_exists(&self, domain: &str) -> Result<bool, DnsError>;
}

/// Blanket impl so &R works where R: DnsResolver.
#[async_trait::async_trait]
impl<R: DnsResolver> DnsResolver for &R {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        (*self).query_txt(domain).await
    }
    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        (*self).query_a(domain).await
    }
    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        (*self).query_aaaa(domain).await
    }
    async fn query_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
        (*self).query_mx(domain).await
    }
    async fn query_ptr(&self, ip: std::net::IpAddr) -> Result<Vec<String>, DnsError> {
        (*self).query_ptr(ip).await
    }
    async fn query_exists(&self, domain: &str) -> Result<bool, DnsError> {
        (*self).query_exists(domain).await
    }
}

/// Mock DNS resolver for testing. Stores responses keyed by domain/IP.
#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct MockResolver {
        pub txt: Mutex<HashMap<String, Result<Vec<String>, DnsError>>>,
        pub a: Mutex<HashMap<String, Result<Vec<Ipv4Addr>, DnsError>>>,
        pub aaaa: Mutex<HashMap<String, Result<Vec<Ipv6Addr>, DnsError>>>,
        pub mx: Mutex<HashMap<String, Result<Vec<MxRecord>, DnsError>>>,
        pub ptr: Mutex<HashMap<String, Result<Vec<String>, DnsError>>>,
        pub exists: Mutex<HashMap<String, Result<bool, DnsError>>>,
    }

    impl MockResolver {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn add_txt(&self, domain: &str, records: Vec<String>) {
            self.txt.lock().unwrap().insert(normalize(domain), Ok(records));
        }

        pub fn add_txt_err(&self, domain: &str, err: DnsError) {
            self.txt.lock().unwrap().insert(normalize(domain), Err(err));
        }

        pub fn add_a(&self, domain: &str, addrs: Vec<Ipv4Addr>) {
            self.a.lock().unwrap().insert(normalize(domain), Ok(addrs));
        }

        pub fn add_a_err(&self, domain: &str, err: DnsError) {
            self.a.lock().unwrap().insert(normalize(domain), Err(err));
        }

        pub fn add_aaaa(&self, domain: &str, addrs: Vec<Ipv6Addr>) {
            self.aaaa.lock().unwrap().insert(normalize(domain), Ok(addrs));
        }

        pub fn add_aaaa_err(&self, domain: &str, err: DnsError) {
            self.aaaa.lock().unwrap().insert(normalize(domain), Err(err));
        }

        pub fn add_mx(&self, domain: &str, records: Vec<MxRecord>) {
            self.mx.lock().unwrap().insert(normalize(domain), Ok(records));
        }

        pub fn add_ptr(&self, ip: IpAddr, names: Vec<String>) {
            self.ptr.lock().unwrap().insert(ip.to_string(), Ok(names));
        }

        pub fn add_exists(&self, domain: &str, exists: bool) {
            self.exists.lock().unwrap().insert(normalize(domain), Ok(exists));
        }
    }

    fn normalize(domain: &str) -> String {
        domain.to_ascii_lowercase().trim_end_matches('.').to_string()
    }

    #[async_trait::async_trait]
    impl DnsResolver for MockResolver {
        async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
            self.txt.lock().unwrap()
                .get(&normalize(domain))
                .cloned()
                .unwrap_or(Err(DnsError::NxDomain))
        }

        async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
            self.a.lock().unwrap()
                .get(&normalize(domain))
                .cloned()
                .unwrap_or(Err(DnsError::NxDomain))
        }

        async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
            self.aaaa.lock().unwrap()
                .get(&normalize(domain))
                .cloned()
                .unwrap_or(Err(DnsError::NxDomain))
        }

        async fn query_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
            self.mx.lock().unwrap()
                .get(&normalize(domain))
                .cloned()
                .unwrap_or(Err(DnsError::NxDomain))
        }

        async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
            self.ptr.lock().unwrap()
                .get(&ip.to_string())
                .cloned()
                .unwrap_or(Err(DnsError::NxDomain))
        }

        async fn query_exists(&self, domain: &str) -> Result<bool, DnsError> {
            self.exists.lock().unwrap()
                .get(&normalize(domain))
                .cloned()
                .unwrap_or(Err(DnsError::NxDomain))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mock::MockResolver;

    #[tokio::test]
    async fn mock_resolver_txt() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 -all".to_string()]);
        let result = r.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["v=spf1 -all"]);
    }

    #[tokio::test]
    async fn mock_resolver_nxdomain_default() {
        let r = MockResolver::new();
        let result = r.query_txt("nonexistent.com").await;
        assert_eq!(result, Err(DnsError::NxDomain));
    }

    #[tokio::test]
    async fn mock_resolver_case_insensitive() {
        let r = MockResolver::new();
        r.add_txt("Example.COM", vec!["test".to_string()]);
        let result = r.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["test"]);
    }

    #[tokio::test]
    async fn mock_resolver_trailing_dot() {
        let r = MockResolver::new();
        r.add_txt("example.com.", vec!["test".to_string()]);
        let result = r.query_txt("example.com").await.unwrap();
        assert_eq!(result, vec!["test"]);
    }

    #[tokio::test]
    async fn mock_resolver_tempfail() {
        let r = MockResolver::new();
        r.add_txt_err("fail.com", DnsError::TempFail);
        let result = r.query_txt("fail.com").await;
        assert_eq!(result, Err(DnsError::TempFail));
    }

    #[tokio::test]
    async fn blanket_ref_impl() {
        let r = MockResolver::new();
        r.add_a("example.com", vec!["1.2.3.4".parse().unwrap()]);
        let r_ref: &MockResolver = &r;
        let result = r_ref.query_a("example.com").await.unwrap();
        assert_eq!(result, vec!["1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap()]);
    }
}
