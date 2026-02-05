use std::net::{Ipv4Addr, Ipv6Addr};

/// SPF mechanism qualifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Qualifier {
    #[default]
    Pass,    // + (default)
    Fail,    // -
    SoftFail, // ~
    Neutral,  // ?
}

impl Qualifier {
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            '+' => Some(Qualifier::Pass),
            '-' => Some(Qualifier::Fail),
            '~' => Some(Qualifier::SoftFail),
            '?' => Some(Qualifier::Neutral),
            _ => None,
        }
    }
}

/// SPF mechanism
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    /// Match all
    All,
    /// Include another domain's SPF
    Include(String),
    /// Match A record
    A {
        domain: Option<String>,
        prefix4: u8,
        prefix6: u8,
    },
    /// Match MX record
    Mx {
        domain: Option<String>,
        prefix4: u8,
        prefix6: u8,
    },
    /// Match PTR (deprecated but must support)
    Ptr(Option<String>),
    /// Match IPv4 CIDR
    Ip4(Ipv4Addr, u8),
    /// Match IPv6 CIDR
    Ip6(Ipv6Addr, u8),
    /// Exists check
    Exists(String),
}

impl Mechanism {
    /// Check if this mechanism requires a DNS lookup
    pub fn requires_dns_lookup(&self) -> bool {
        !matches!(self, Mechanism::All | Mechanism::Ip4(..) | Mechanism::Ip6(..))
    }
}

/// SPF modifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modifier {
    /// Redirect to another domain's SPF
    Redirect(String),
    /// Explanation string
    Exp(String),
    /// Unknown modifier (ignored)
    Unknown(String, String),
}

/// A term in SPF record (mechanism with qualifier, or modifier)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Mechanism(Qualifier, Mechanism),
    Modifier(Modifier),
}
