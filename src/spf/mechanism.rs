use std::net::{Ipv4Addr, Ipv6Addr};

/// Qualifier determines result when mechanism matches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    /// + (default if omitted)
    Pass,
    /// -
    Fail,
    /// ~
    SoftFail,
    /// ?
    Neutral,
}

impl Default for Qualifier {
    fn default() -> Self {
        Self::Pass
    }
}

impl Qualifier {
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            '+' => Some(Self::Pass),
            '-' => Some(Self::Fail),
            '~' => Some(Self::SoftFail),
            '?' => Some(Self::Neutral),
            _ => None,
        }
    }
}

/// SPF mechanism types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    /// Matches everything
    All,
    /// Recursive lookup on another domain
    Include { domain: String },
    /// A/AAAA record check
    A {
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    /// MX record check
    Mx {
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    /// PTR record check (deprecated)
    Ptr { domain: Option<String> },
    /// IPv4 CIDR check
    Ip4 { addr: Ipv4Addr, prefix: u8 },
    /// IPv6 CIDR check
    Ip6 { addr: Ipv6Addr, prefix: u8 },
    /// DNS existence check
    Exists { domain: String },
}

/// A directive is a qualifier + mechanism
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

/// SPF modifiers
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modifier {
    /// Use another domain's policy
    Redirect { domain: String },
    /// Explanation for failures
    Exp { domain: String },
}
