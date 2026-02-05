//! SPF mechanism and modifier types.

use std::net::{Ipv4Addr, Ipv6Addr};

/// SPF qualifier determining the result when a mechanism matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Qualifier {
    #[default]
    Pass,     // + (default)
    Fail,     // -
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

/// An SPF directive (qualifier + mechanism).
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

/// SPF mechanism types.
#[derive(Debug, Clone, PartialEq)]
pub enum Mechanism {
    /// Matches everything.
    All,
    /// Recursive SPF lookup.
    Include { domain: String },
    /// A record lookup.
    A {
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    /// MX record lookup.
    Mx {
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    /// PTR record lookup (deprecated but must support).
    Ptr { domain: Option<String> },
    /// IPv4 CIDR match.
    Ip4 { addr: Ipv4Addr, prefix: u8 },
    /// IPv6 CIDR match.
    Ip6 { addr: Ipv6Addr, prefix: u8 },
    /// DNS existence check.
    Exists { domain: String },
}

/// SPF modifiers.
#[derive(Debug, Clone, PartialEq)]
pub enum Modifier {
    /// Use another domain's SPF policy.
    Redirect { domain: String },
    /// Explanation string for failures.
    Exp { domain: String },
}
