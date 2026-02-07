use std::net::{Ipv4Addr, Ipv6Addr};

/// SPF qualifier (RFC 7208 Section 4.6.2).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Qualifier {
    Pass,     // +
    Fail,     // -
    SoftFail, // ~
    Neutral,  // ?
}

/// A directive is a qualifier + mechanism.
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

/// SPF mechanism variants.
#[derive(Debug, Clone, PartialEq)]
pub enum Mechanism {
    All,
    Include { domain: String },
    A {
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    Mx {
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    Ptr { domain: Option<String> },
    Ip4 { addr: Ipv4Addr, prefix: Option<u8> },
    Ip6 { addr: Ipv6Addr, prefix: Option<u8> },
    Exists { domain: String },
}
