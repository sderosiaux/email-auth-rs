use std::net::{Ipv4Addr, Ipv6Addr};

/// SPF evaluation result (RFC 7208 Section 2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfResult {
    /// Sender is authorized.
    Pass,
    /// Sender is NOT authorized, with optional explanation from exp=.
    Fail { explanation: Option<String> },
    /// Weak authorization failure.
    SoftFail,
    /// No assertion made.
    Neutral,
    /// No SPF record found.
    None,
    /// Transient DNS error.
    TempError,
    /// Permanent error (syntax, too many lookups, etc.).
    PermError,
}

/// Qualifier prefix on a directive (RFC 7208 Section 4.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
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

/// A directive is a qualifier + mechanism pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

/// SPF mechanism variants (RFC 7208 Section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    All,
    Include { domain: String },
    A { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> },
    Mx { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> },
    Ptr { domain: Option<String> },
    Ip4 { addr: Ipv4Addr, prefix: Option<u8> },
    Ip6 { addr: Ipv6Addr, prefix: Option<u8> },
    Exists { domain: String },
}

/// Parsed SPF record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub explanation: Option<String>,
}

impl SpfRecord {
    /// Parse an SPF record string (the TXT record value, starting with "v=spf1").
    /// Returns PermError description on parse failure.
    pub fn parse(record: &str) -> Result<Self, String> {
        super::parser::parse_record(record)
    }
}
