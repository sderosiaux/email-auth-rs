//! SPF mechanisms and qualifiers

use super::record::SpfParseError;
use std::net::{Ipv4Addr, Ipv6Addr};

/// SPF qualifier (determines result on mechanism match)
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

/// SPF mechanism types
#[derive(Debug, Clone, PartialEq)]
pub enum Mechanism {
    All,
    Include { domain: String },
    A { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> },
    Mx { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> },
    Ptr { domain: Option<String> },
    Ip4 { addr: Ipv4Addr, prefix: u8 },
    Ip6 { addr: Ipv6Addr, prefix: u8 },
    Exists { domain: String },
}

/// A directive is a mechanism with a qualifier
#[derive(Debug, Clone)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

impl Directive {
    pub fn parse(term: &str) -> Result<Self, SpfParseError> {
        let (qualifier, rest) = match term.chars().next() {
            Some('+') => (Qualifier::Pass, &term[1..]),
            Some('-') => (Qualifier::Fail, &term[1..]),
            Some('~') => (Qualifier::SoftFail, &term[1..]),
            Some('?') => (Qualifier::Neutral, &term[1..]),
            _ => (Qualifier::Pass, term),
        };

        let mechanism = parse_mechanism(rest)?;
        Ok(Directive { qualifier, mechanism })
    }
}

fn parse_mechanism(s: &str) -> Result<Mechanism, SpfParseError> {
    let s_lower = s.to_lowercase();

    if s_lower == "all" {
        return Ok(Mechanism::All);
    }

    if let Some(rest) = s_lower.strip_prefix("include:") {
        return Ok(Mechanism::Include { domain: rest.to_string() });
    }

    if s_lower == "a" || s_lower.starts_with("a:") || s_lower.starts_with("a/") {
        return parse_a_mx_mechanism(&s_lower, "a");
    }

    if s_lower == "mx" || s_lower.starts_with("mx:") || s_lower.starts_with("mx/") {
        return parse_a_mx_mechanism(&s_lower, "mx");
    }

    if s_lower == "ptr" || s_lower.starts_with("ptr:") {
        let domain = s_lower.strip_prefix("ptr:").map(|d| d.to_string());
        return Ok(Mechanism::Ptr { domain });
    }

    if let Some(rest) = s_lower.strip_prefix("ip4:") {
        return parse_ip4(rest);
    }

    if let Some(rest) = s_lower.strip_prefix("ip6:") {
        return parse_ip6(rest);
    }

    if let Some(rest) = s_lower.strip_prefix("exists:") {
        return Ok(Mechanism::Exists { domain: rest.to_string() });
    }

    Err(SpfParseError::InvalidMechanism(s.to_string()))
}

fn parse_a_mx_mechanism(s: &str, prefix: &str) -> Result<Mechanism, SpfParseError> {
    let rest = s.strip_prefix(prefix).unwrap_or("");

    let (domain_part, cidr_part) = if let Some(slash_pos) = rest.find('/') {
        (&rest[..slash_pos], &rest[slash_pos..])
    } else {
        (rest, "")
    };

    let domain = if domain_part.is_empty() || domain_part == ":" {
        None
    } else {
        Some(domain_part.trim_start_matches(':').to_string())
    };

    let (cidr4, cidr6) = parse_cidr_suffix(cidr_part)?;

    if prefix == "a" {
        Ok(Mechanism::A { domain, cidr4, cidr6 })
    } else {
        Ok(Mechanism::Mx { domain, cidr4, cidr6 })
    }
}

fn parse_cidr_suffix(s: &str) -> Result<(Option<u8>, Option<u8>), SpfParseError> {
    if s.is_empty() {
        return Ok((None, None));
    }

    // Format: /<cidr4> or //<cidr6> or /<cidr4>//<cidr6>
    let mut cidr4 = None;
    let mut cidr6 = None;

    let parts: Vec<&str> = s.split("//").collect();
    match parts.len() {
        1 => {
            // Just /<cidr4>
            if let Some(c4) = parts[0].strip_prefix('/') {
                if !c4.is_empty() {
                    cidr4 = Some(c4.parse().map_err(|_| {
                        SpfParseError::InvalidMechanism(format!("invalid CIDR: {}", s))
                    })?);
                }
            }
        }
        2 => {
            // /<cidr4>//<cidr6> or //<cidr6>
            if !parts[0].is_empty() {
                if let Some(c4) = parts[0].strip_prefix('/') {
                    if !c4.is_empty() {
                        cidr4 = Some(c4.parse().map_err(|_| {
                            SpfParseError::InvalidMechanism(format!("invalid CIDR: {}", s))
                        })?);
                    }
                }
            }
            if !parts[1].is_empty() {
                cidr6 = Some(parts[1].parse().map_err(|_| {
                    SpfParseError::InvalidMechanism(format!("invalid CIDR: {}", s))
                })?);
            }
        }
        _ => return Err(SpfParseError::InvalidMechanism(format!("invalid CIDR: {}", s))),
    }

    Ok((cidr4, cidr6))
}

fn parse_ip4(s: &str) -> Result<Mechanism, SpfParseError> {
    let (addr_str, prefix) = if let Some(slash_pos) = s.find('/') {
        let prefix: u8 = s[slash_pos + 1..]
            .parse()
            .map_err(|_| SpfParseError::InvalidMechanism(format!("invalid ip4: {}", s)))?;
        (&s[..slash_pos], prefix)
    } else {
        (s, 32)
    };

    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|_| SpfParseError::InvalidMechanism(format!("invalid ip4: {}", s)))?;

    Ok(Mechanism::Ip4 { addr, prefix })
}

fn parse_ip6(s: &str) -> Result<Mechanism, SpfParseError> {
    let (addr_str, prefix) = if let Some(slash_pos) = s.find('/') {
        let prefix: u8 = s[slash_pos + 1..]
            .parse()
            .map_err(|_| SpfParseError::InvalidMechanism(format!("invalid ip6: {}", s)))?;
        (&s[..slash_pos], prefix)
    } else {
        (s, 128)
    };

    let addr: Ipv6Addr = addr_str
        .parse()
        .map_err(|_| SpfParseError::InvalidMechanism(format!("invalid ip6: {}", s)))?;

    Ok(Mechanism::Ip6 { addr, prefix })
}

/// SPF modifier types
#[derive(Debug, Clone)]
pub enum Modifier {
    Redirect { domain: String },
    Exp { domain: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all() {
        let d = Directive::parse("-all").unwrap();
        assert_eq!(d.qualifier, Qualifier::Fail);
        assert_eq!(d.mechanism, Mechanism::All);
    }

    #[test]
    fn test_parse_include() {
        let d = Directive::parse("include:_spf.google.com").unwrap();
        assert_eq!(d.qualifier, Qualifier::Pass);
        assert!(matches!(d.mechanism, Mechanism::Include { domain } if domain == "_spf.google.com"));
    }

    #[test]
    fn test_parse_ip4() {
        let d = Directive::parse("ip4:192.0.2.0/24").unwrap();
        assert!(matches!(
            d.mechanism,
            Mechanism::Ip4 { addr, prefix } if addr == "192.0.2.0".parse::<Ipv4Addr>().unwrap() && prefix == 24
        ));
    }

    #[test]
    fn test_parse_ip4_no_prefix() {
        let d = Directive::parse("ip4:192.0.2.1").unwrap();
        assert!(matches!(
            d.mechanism,
            Mechanism::Ip4 { prefix, .. } if prefix == 32
        ));
    }

    #[test]
    fn test_parse_a_with_cidr() {
        let d = Directive::parse("a/24").unwrap();
        assert!(matches!(
            d.mechanism,
            Mechanism::A { domain: None, cidr4: Some(24), cidr6: None }
        ));
    }

    #[test]
    fn test_parse_mx_with_domain() {
        let d = Directive::parse("mx:example.com").unwrap();
        assert!(matches!(
            d.mechanism,
            Mechanism::Mx { domain: Some(d), .. } if d == "example.com"
        ));
    }

    #[test]
    fn test_qualifiers() {
        assert_eq!(Directive::parse("+all").unwrap().qualifier, Qualifier::Pass);
        assert_eq!(Directive::parse("-all").unwrap().qualifier, Qualifier::Fail);
        assert_eq!(Directive::parse("~all").unwrap().qualifier, Qualifier::SoftFail);
        assert_eq!(Directive::parse("?all").unwrap().qualifier, Qualifier::Neutral);
        assert_eq!(Directive::parse("all").unwrap().qualifier, Qualifier::Pass);
    }
}
