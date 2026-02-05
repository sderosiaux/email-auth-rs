use std::net::{Ipv4Addr, Ipv6Addr};

/// Qualifier determines the result when a mechanism matches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    Pass,     // + (default)
    Fail,     // -
    SoftFail, // ~
    Neutral,  // ?
}

impl Default for Qualifier {
    fn default() -> Self {
        Qualifier::Pass
    }
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

/// SPF mechanism types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    All,
    Include {
        domain: String,
    },
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
    Ptr {
        domain: Option<String>,
    },
    Ip4 {
        addr: Ipv4Addr,
        prefix: u8,
    },
    Ip6 {
        addr: Ipv6Addr,
        prefix: u8,
    },
    Exists {
        domain: String,
    },
}

/// Directive: mechanism with qualifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

/// SPF modifiers
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modifier {
    Redirect { domain: String },
    Exp { domain: String },
}
