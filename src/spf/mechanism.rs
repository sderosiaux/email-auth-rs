//! SPF mechanism and directive types (RFC 7208 Section 5).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Qualifier prefix on a directive. Defaults to Pass if omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    Pass,     // +
    Fail,     // -
    SoftFail, // ~
    Neutral,  // ?
}

impl Qualifier {
    /// Parse a single-char qualifier prefix. Returns (Qualifier, remaining str).
    /// If no qualifier prefix, defaults to Pass.
    pub fn parse_prefix(s: &str) -> (Qualifier, &str) {
        match s.as_bytes().first() {
            Some(b'+') => (Qualifier::Pass, &s[1..]),
            Some(b'-') => (Qualifier::Fail, &s[1..]),
            Some(b'~') => (Qualifier::SoftFail, &s[1..]),
            Some(b'?') => (Qualifier::Neutral, &s[1..]),
            _ => (Qualifier::Pass, s),
        }
    }
}

impl fmt::Display for Qualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Qualifier::Pass => write!(f, "+"),
            Qualifier::Fail => write!(f, "-"),
            Qualifier::SoftFail => write!(f, "~"),
            Qualifier::Neutral => write!(f, "?"),
        }
    }
}

/// A CIDR prefix length pair for A and MX mechanisms.
/// `cidr4` defaults to 32, `cidr6` defaults to 128 when not specified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualCidr {
    pub v4: u8,
    pub v6: u8,
}

impl Default for DualCidr {
    fn default() -> Self {
        Self { v4: 32, v6: 128 }
    }
}

/// SPF mechanism (RFC 7208 Section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    /// `all`
    All,
    /// `include:<domain-spec>`
    Include(String),
    /// `a[:<domain-spec>][/cidr4][//cidr6]`
    A {
        domain: Option<String>,
        cidr: DualCidr,
    },
    /// `mx[:<domain-spec>][/cidr4][//cidr6]`
    Mx {
        domain: Option<String>,
        cidr: DualCidr,
    },
    /// `ptr[:<domain-spec>]`
    Ptr(Option<String>),
    /// `ip4:<ip4-network>[/cidr]`
    Ip4 {
        addr: Ipv4Addr,
        prefix_len: u8,
    },
    /// `ip6:<ip6-network>[/cidr]`
    Ip6 {
        addr: Ipv6Addr,
        prefix_len: u8,
    },
    /// `exists:<domain-spec>`
    Exists(String),
}

/// A directive = qualifier + mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

/// Error type for SPF record parsing. All parse failures map to PermError in evaluation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpfParseError {
    #[error("invalid SPF version: expected 'v=spf1'")]
    InvalidVersion,
    #[error("unknown mechanism: {0}")]
    UnknownMechanism(String),
    #[error("invalid mechanism argument: {0}")]
    InvalidArgument(String),
    #[error("duplicate modifier: {0}")]
    DuplicateModifier(String),
    #[error("missing required argument for {0}")]
    MissingArgument(String),
    #[error("invalid CIDR prefix: {0}")]
    InvalidCidr(String),
    #[error("empty SPF record")]
    Empty,
}

/// Parse a dual CIDR suffix from a string like "/24", "//64", "/24//64".
/// Returns (remaining_before_cidr, DualCidr).
fn parse_dual_cidr(s: &str) -> Result<(String, DualCidr), SpfParseError> {
    let mut cidr = DualCidr::default();
    let mut rest = s.to_string();

    // Look for //cidr6 first (must come after /cidr4 if both present)
    if let Some(pos) = rest.find("//") {
        let v6_str = &rest[pos + 2..];
        cidr.v6 = v6_str
            .parse::<u8>()
            .map_err(|_| SpfParseError::InvalidCidr(format!("invalid IPv6 CIDR: {v6_str}")))?;
        if cidr.v6 > 128 {
            return Err(SpfParseError::InvalidCidr(format!(
                "IPv6 CIDR {0} exceeds 128",
                cidr.v6
            )));
        }
        rest = rest[..pos].to_string();
    }

    // Look for /cidr4
    if let Some(pos) = rest.rfind('/') {
        let v4_str = &rest[pos + 1..];
        if !v4_str.is_empty() {
            cidr.v4 = v4_str
                .parse::<u8>()
                .map_err(|_| SpfParseError::InvalidCidr(format!("invalid IPv4 CIDR: {v4_str}")))?;
            if cidr.v4 > 32 {
                return Err(SpfParseError::InvalidCidr(format!(
                    "IPv4 CIDR {0} exceeds 32",
                    cidr.v4
                )));
            }
            rest = rest[..pos].to_string();
        }
    }

    Ok((rest, cidr))
}

/// Parse a mechanism from its textual representation (without qualifier prefix).
/// `name` is the lowercased mechanism name, `arg` is the optional `:value` part.
pub fn parse_mechanism(term: &str) -> Result<Mechanism, SpfParseError> {
    // Split on first ':'
    let (name_part, arg) = if let Some(pos) = term.find(':') {
        (&term[..pos], Some(&term[pos + 1..]))
    } else if let Some(pos) = term.find('/') {
        // A mechanism like "a/24" with no colon but with CIDR
        (&term[..pos], Some(&term[pos..]))
    } else {
        (term, None)
    };

    let name_lower = name_part.to_ascii_lowercase();

    match name_lower.as_str() {
        "all" => {
            if arg.is_some() {
                return Err(SpfParseError::InvalidArgument(
                    "all mechanism takes no arguments".into(),
                ));
            }
            Ok(Mechanism::All)
        }
        "include" => {
            let domain = arg
                .filter(|a| !a.is_empty())
                .ok_or_else(|| SpfParseError::MissingArgument("include".into()))?;
            Ok(Mechanism::Include(domain.to_string()))
        }
        "a" => {
            let full = arg.unwrap_or("");
            // Re-assemble: if term had '/' but no ':', we need the full suffix
            let full = if term.starts_with("a/") || term.starts_with("A/") {
                &term[1..]
            } else {
                full
            };
            let (domain_part, cidr) = parse_dual_cidr(full)?;
            let domain = if domain_part.is_empty() {
                None
            } else {
                Some(domain_part)
            };
            Ok(Mechanism::A { domain, cidr })
        }
        "mx" => {
            let full = arg.unwrap_or("");
            let full = if term.len() > 2
                && term.as_bytes()[2] == b'/'
                && !term[..2].contains(':')
            {
                &term[2..]
            } else {
                full
            };
            let (domain_part, cidr) = parse_dual_cidr(full)?;
            let domain = if domain_part.is_empty() {
                None
            } else {
                Some(domain_part)
            };
            Ok(Mechanism::Mx { domain, cidr })
        }
        "ptr" => {
            let domain = arg.filter(|a| !a.is_empty()).map(|a| a.to_string());
            Ok(Mechanism::Ptr(domain))
        }
        "ip4" => {
            let raw = arg
                .filter(|a| !a.is_empty())
                .ok_or_else(|| SpfParseError::MissingArgument("ip4".into()))?;
            let (addr_str, prefix_len) = if let Some(pos) = raw.find('/') {
                let prefix = raw[pos + 1..]
                    .parse::<u8>()
                    .map_err(|_| SpfParseError::InvalidCidr(raw.to_string()))?;
                if prefix > 32 {
                    return Err(SpfParseError::InvalidCidr(format!(
                        "IPv4 CIDR {prefix} exceeds 32"
                    )));
                }
                (&raw[..pos], prefix)
            } else {
                (raw, 32)
            };
            let addr: Ipv4Addr = addr_str
                .parse()
                .map_err(|_| SpfParseError::InvalidArgument(format!("invalid IPv4: {addr_str}")))?;
            Ok(Mechanism::Ip4 { addr, prefix_len })
        }
        "ip6" => {
            let raw = arg
                .filter(|a| !a.is_empty())
                .ok_or_else(|| SpfParseError::MissingArgument("ip6".into()))?;
            let (addr_str, prefix_len) = if let Some(pos) = raw.find('/') {
                let prefix = raw[pos + 1..]
                    .parse::<u8>()
                    .map_err(|_| SpfParseError::InvalidCidr(raw.to_string()))?;
                if prefix > 128 {
                    return Err(SpfParseError::InvalidCidr(format!(
                        "IPv6 CIDR {prefix} exceeds 128"
                    )));
                }
                (&raw[..pos], prefix)
            } else {
                (raw, 128)
            };
            let addr: Ipv6Addr = addr_str
                .parse()
                .map_err(|_| SpfParseError::InvalidArgument(format!("invalid IPv6: {addr_str}")))?;
            Ok(Mechanism::Ip6 { addr, prefix_len })
        }
        "exists" => {
            let domain = arg
                .filter(|a| !a.is_empty())
                .ok_or_else(|| SpfParseError::MissingArgument("exists".into()))?;
            Ok(Mechanism::Exists(domain.to_string()))
        }
        _ => Err(SpfParseError::UnknownMechanism(name_lower)),
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mechanism::All => write!(f, "all"),
            Mechanism::Include(d) => write!(f, "include:{d}"),
            Mechanism::A { domain, cidr } => {
                write!(f, "a")?;
                if let Some(d) = domain {
                    write!(f, ":{d}")?;
                }
                if cidr.v4 != 32 {
                    write!(f, "/{}", cidr.v4)?;
                }
                if cidr.v6 != 128 {
                    write!(f, "//{}", cidr.v6)?;
                }
                Ok(())
            }
            Mechanism::Mx { domain, cidr } => {
                write!(f, "mx")?;
                if let Some(d) = domain {
                    write!(f, ":{d}")?;
                }
                if cidr.v4 != 32 {
                    write!(f, "/{}", cidr.v4)?;
                }
                if cidr.v6 != 128 {
                    write!(f, "//{}", cidr.v6)?;
                }
                Ok(())
            }
            Mechanism::Ptr(d) => {
                write!(f, "ptr")?;
                if let Some(d) = d {
                    write!(f, ":{d}")?;
                }
                Ok(())
            }
            Mechanism::Ip4 { addr, prefix_len } => {
                write!(f, "ip4:{addr}")?;
                if *prefix_len != 32 {
                    write!(f, "/{prefix_len}")?;
                }
                Ok(())
            }
            Mechanism::Ip6 { addr, prefix_len } => {
                write!(f, "ip6:{addr}")?;
                if *prefix_len != 128 {
                    write!(f, "/{prefix_len}")?;
                }
                Ok(())
            }
            Mechanism::Exists(d) => write!(f, "exists:{d}"),
        }
    }
}

impl fmt::Display for Directive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only print qualifier if not Pass (the default)
        if self.qualifier != Qualifier::Pass {
            write!(f, "{}", self.qualifier)?;
        }
        write!(f, "{}", self.mechanism)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Qualifier ----

    #[test]
    fn qualifier_parse_explicit() {
        assert_eq!(Qualifier::parse_prefix("+all"), (Qualifier::Pass, "all"));
        assert_eq!(Qualifier::parse_prefix("-all"), (Qualifier::Fail, "all"));
        assert_eq!(
            Qualifier::parse_prefix("~all"),
            (Qualifier::SoftFail, "all")
        );
        assert_eq!(
            Qualifier::parse_prefix("?all"),
            (Qualifier::Neutral, "all")
        );
    }

    #[test]
    fn qualifier_parse_default() {
        assert_eq!(Qualifier::parse_prefix("all"), (Qualifier::Pass, "all"));
        assert_eq!(
            Qualifier::parse_prefix("include:x"),
            (Qualifier::Pass, "include:x")
        );
    }

    // ---- Mechanism: all ----

    #[test]
    fn parse_all() {
        assert_eq!(parse_mechanism("all").unwrap(), Mechanism::All);
    }

    #[test]
    fn parse_all_rejects_arg() {
        assert!(parse_mechanism("all:foo").is_err());
    }

    // ---- Mechanism: include ----

    #[test]
    fn parse_include() {
        assert_eq!(
            parse_mechanism("include:example.com").unwrap(),
            Mechanism::Include("example.com".into())
        );
    }

    #[test]
    fn parse_include_missing_domain() {
        assert!(parse_mechanism("include").is_err());
        assert!(parse_mechanism("include:").is_err());
    }

    // ---- Mechanism: a ----

    #[test]
    fn parse_a_bare() {
        assert_eq!(
            parse_mechanism("a").unwrap(),
            Mechanism::A {
                domain: None,
                cidr: DualCidr::default(),
            }
        );
    }

    #[test]
    fn parse_a_with_domain() {
        assert_eq!(
            parse_mechanism("a:example.com").unwrap(),
            Mechanism::A {
                domain: Some("example.com".into()),
                cidr: DualCidr::default(),
            }
        );
    }

    #[test]
    fn parse_a_with_cidr4() {
        assert_eq!(
            parse_mechanism("a/24").unwrap(),
            Mechanism::A {
                domain: None,
                cidr: DualCidr { v4: 24, v6: 128 },
            }
        );
    }

    #[test]
    fn parse_a_with_dual_cidr() {
        assert_eq!(
            parse_mechanism("a:example.com/24//64").unwrap(),
            Mechanism::A {
                domain: Some("example.com".into()),
                cidr: DualCidr { v4: 24, v6: 64 },
            }
        );
    }

    #[test]
    fn parse_a_with_cidr6_only() {
        assert_eq!(
            parse_mechanism("a//96").unwrap(),
            Mechanism::A {
                domain: None,
                cidr: DualCidr { v4: 32, v6: 96 },
            }
        );
    }

    #[test]
    fn parse_a_domain_and_cidr6_only() {
        assert_eq!(
            parse_mechanism("a:example.com//64").unwrap(),
            Mechanism::A {
                domain: Some("example.com".into()),
                cidr: DualCidr { v4: 32, v6: 64 },
            }
        );
    }

    // ---- Mechanism: mx ----

    #[test]
    fn parse_mx_bare() {
        assert_eq!(
            parse_mechanism("mx").unwrap(),
            Mechanism::Mx {
                domain: None,
                cidr: DualCidr::default(),
            }
        );
    }

    #[test]
    fn parse_mx_with_domain_and_cidr() {
        assert_eq!(
            parse_mechanism("mx:example.com/24//64").unwrap(),
            Mechanism::Mx {
                domain: Some("example.com".into()),
                cidr: DualCidr { v4: 24, v6: 64 },
            }
        );
    }

    #[test]
    fn parse_mx_cidr4_only() {
        assert_eq!(
            parse_mechanism("mx/28").unwrap(),
            Mechanism::Mx {
                domain: None,
                cidr: DualCidr { v4: 28, v6: 128 },
            }
        );
    }

    // ---- Mechanism: ptr ----

    #[test]
    fn parse_ptr_bare() {
        assert_eq!(parse_mechanism("ptr").unwrap(), Mechanism::Ptr(None));
    }

    #[test]
    fn parse_ptr_with_domain() {
        assert_eq!(
            parse_mechanism("ptr:example.com").unwrap(),
            Mechanism::Ptr(Some("example.com".into()))
        );
    }

    // ---- Mechanism: ip4 ----

    #[test]
    fn parse_ip4_host() {
        assert_eq!(
            parse_mechanism("ip4:192.168.1.1").unwrap(),
            Mechanism::Ip4 {
                addr: Ipv4Addr::new(192, 168, 1, 1),
                prefix_len: 32,
            }
        );
    }

    #[test]
    fn parse_ip4_network() {
        assert_eq!(
            parse_mechanism("ip4:10.0.0.0/8").unwrap(),
            Mechanism::Ip4 {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix_len: 8,
            }
        );
    }

    #[test]
    fn parse_ip4_missing_addr() {
        assert!(parse_mechanism("ip4").is_err());
        assert!(parse_mechanism("ip4:").is_err());
    }

    #[test]
    fn parse_ip4_bad_cidr() {
        assert!(parse_mechanism("ip4:10.0.0.0/33").is_err());
    }

    // ---- Mechanism: ip6 ----

    #[test]
    fn parse_ip6_host() {
        assert_eq!(
            parse_mechanism("ip6:::1").unwrap(),
            Mechanism::Ip6 {
                addr: "::1".parse().unwrap(),
                prefix_len: 128,
            }
        );
    }

    #[test]
    fn parse_ip6_network() {
        assert_eq!(
            parse_mechanism("ip6:2001:db8::/32").unwrap(),
            Mechanism::Ip6 {
                addr: "2001:db8::".parse().unwrap(),
                prefix_len: 32,
            }
        );
    }

    #[test]
    fn parse_ip6_bad_cidr() {
        assert!(parse_mechanism("ip6:::1/129").is_err());
    }

    // ---- Mechanism: exists ----

    #[test]
    fn parse_exists() {
        assert_eq!(
            parse_mechanism("exists:%{ir}.sbl.example.com").unwrap(),
            Mechanism::Exists("%{ir}.sbl.example.com".into())
        );
    }

    #[test]
    fn parse_exists_missing() {
        assert!(parse_mechanism("exists").is_err());
        assert!(parse_mechanism("exists:").is_err());
    }

    // ---- Unknown mechanism ----

    #[test]
    fn parse_unknown_mechanism() {
        let err = parse_mechanism("bogus:foo").unwrap_err();
        assert!(matches!(err, SpfParseError::UnknownMechanism(_)));
    }

    // ---- Display round-trip ----

    #[test]
    fn display_directive() {
        let d = Directive {
            qualifier: Qualifier::Fail,
            mechanism: Mechanism::All,
        };
        assert_eq!(d.to_string(), "-all");

        let d2 = Directive {
            qualifier: Qualifier::Pass,
            mechanism: Mechanism::Include("example.com".into()),
        };
        assert_eq!(d2.to_string(), "include:example.com");
    }

    #[test]
    fn display_a_with_dual_cidr() {
        let m = Mechanism::A {
            domain: Some("example.com".into()),
            cidr: DualCidr { v4: 24, v6: 64 },
        };
        assert_eq!(m.to_string(), "a:example.com/24//64");
    }

    // ---- CIDR edge cases ----

    #[test]
    fn cidr_v4_zero() {
        assert_eq!(
            parse_mechanism("a/0").unwrap(),
            Mechanism::A {
                domain: None,
                cidr: DualCidr { v4: 0, v6: 128 },
            }
        );
    }

    #[test]
    fn cidr_v6_zero() {
        assert_eq!(
            parse_mechanism("a//0").unwrap(),
            Mechanism::A {
                domain: None,
                cidr: DualCidr { v4: 32, v6: 0 },
            }
        );
    }

    // ---- Case insensitivity ----

    #[test]
    fn mechanism_name_case_insensitive() {
        assert_eq!(parse_mechanism("ALL").unwrap(), Mechanism::All);
        assert_eq!(
            parse_mechanism("INCLUDE:example.com").unwrap(),
            Mechanism::Include("example.com".into())
        );
        assert_eq!(
            parse_mechanism("IP4:1.2.3.4").unwrap(),
            Mechanism::Ip4 {
                addr: Ipv4Addr::new(1, 2, 3, 4),
                prefix_len: 32,
            }
        );
    }
}
