//! SPF record parsing.

use super::mechanism::{Directive, Mechanism, Qualifier};
use super::SpfError;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parsed SPF record.
#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub exp: Option<String>,
    pub raw: String,
}

impl SpfRecord {
    /// Parse an SPF TXT record.
    pub fn parse(txt: &str) -> Result<Self, SpfError> {
        let txt = txt.trim();

        // Must start with "v=spf1" (case-insensitive)
        if !txt.to_lowercase().starts_with("v=spf1") {
            return Err(SpfError::InvalidRecord("missing v=spf1".into()));
        }

        let remainder = &txt[6..]; // Skip "v=spf1"
        let parts: Vec<&str> = remainder.split_whitespace().collect();

        let mut directives = Vec::new();
        let mut redirect = None;
        let mut exp = None;

        for part in parts {
            let part_lower = part.to_lowercase();

            // Check for modifiers
            if let Some(domain) = part_lower.strip_prefix("redirect=") {
                if redirect.is_some() {
                    return Err(SpfError::InvalidRecord("duplicate redirect modifier".into()));
                }
                redirect = Some(domain.to_string());
                continue;
            }

            if let Some(domain) = part_lower.strip_prefix("exp=") {
                if exp.is_some() {
                    return Err(SpfError::InvalidRecord("duplicate exp modifier".into()));
                }
                exp = Some(domain.to_string());
                continue;
            }

            // Check for unknown modifiers (ignore per RFC)
            if part.contains('=') && !part.starts_with(|c: char| "+-~?".contains(c)) {
                continue; // Unknown modifier, ignore
            }

            // Parse directive (qualifier + mechanism)
            let (qualifier, mech_str) = parse_qualifier(part);
            let mechanism = parse_mechanism(&mech_str.to_lowercase(), &mech_str)?;
            directives.push(Directive {
                qualifier,
                mechanism,
            });
        }

        Ok(SpfRecord {
            directives,
            redirect,
            exp,
            raw: txt.to_string(),
        })
    }
}

fn parse_qualifier(s: &str) -> (Qualifier, &str) {
    match s.chars().next() {
        Some('+') => (Qualifier::Pass, &s[1..]),
        Some('-') => (Qualifier::Fail, &s[1..]),
        Some('~') => (Qualifier::SoftFail, &s[1..]),
        Some('?') => (Qualifier::Neutral, &s[1..]),
        _ => (Qualifier::Pass, s), // Default is Pass
    }
}

fn parse_mechanism(lower: &str, original: &str) -> Result<Mechanism, SpfError> {
    // all
    if lower == "all" {
        return Ok(Mechanism::All);
    }

    // include:domain
    if let Some(domain) = lower.strip_prefix("include:") {
        if domain.is_empty() {
            return Err(SpfError::InvalidRecord("include requires domain".into()));
        }
        return Ok(Mechanism::Include {
            domain: domain.to_string(),
        });
    }

    // exists:domain
    if let Some(domain) = lower.strip_prefix("exists:") {
        if domain.is_empty() {
            return Err(SpfError::InvalidRecord("exists requires domain".into()));
        }
        return Ok(Mechanism::Exists {
            domain: domain.to_string(),
        });
    }

    // ip4:addr/prefix
    if let Some(rest) = lower.strip_prefix("ip4:") {
        return parse_ip4(rest);
    }

    // ip6:addr/prefix
    if let Some(rest) = lower.strip_prefix("ip6:") {
        return parse_ip6(rest);
    }

    // ptr or ptr:domain
    if lower == "ptr" {
        return Ok(Mechanism::Ptr { domain: None });
    }
    if let Some(domain) = lower.strip_prefix("ptr:") {
        return Ok(Mechanism::Ptr {
            domain: Some(domain.to_string()),
        });
    }

    // a or a:domain or a/cidr or a:domain/cidr
    if lower == "a" || lower.starts_with("a:") || lower.starts_with("a/") {
        return parse_a_or_mx(lower, "a");
    }

    // mx or mx:domain or mx/cidr or mx:domain/cidr
    if lower == "mx" || lower.starts_with("mx:") || lower.starts_with("mx/") {
        return parse_a_or_mx(lower, "mx");
    }

    Err(SpfError::InvalidRecord(format!(
        "unknown mechanism: {}",
        original
    )))
}

fn parse_ip4(s: &str) -> Result<Mechanism, SpfError> {
    let (addr_str, prefix) = if let Some((a, p)) = s.split_once('/') {
        let prefix: u8 = p
            .parse()
            .map_err(|_| SpfError::InvalidRecord(format!("invalid prefix: {}", p)))?;
        if prefix > 32 {
            return Err(SpfError::InvalidRecord("IPv4 prefix > 32".into()));
        }
        (a, prefix)
    } else {
        (s, 32)
    };

    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|_| SpfError::InvalidRecord(format!("invalid IPv4: {}", addr_str)))?;

    Ok(Mechanism::Ip4 { addr, prefix })
}

fn parse_ip6(s: &str) -> Result<Mechanism, SpfError> {
    let (addr_str, prefix) = if let Some((a, p)) = s.split_once('/') {
        let prefix: u8 = p
            .parse()
            .map_err(|_| SpfError::InvalidRecord(format!("invalid prefix: {}", p)))?;
        if prefix > 128 {
            return Err(SpfError::InvalidRecord("IPv6 prefix > 128".into()));
        }
        (a, prefix)
    } else {
        (s, 128)
    };

    let addr: Ipv6Addr = addr_str
        .parse()
        .map_err(|_| SpfError::InvalidRecord(format!("invalid IPv6: {}", addr_str)))?;

    Ok(Mechanism::Ip6 { addr, prefix })
}

fn parse_a_or_mx(s: &str, kind: &str) -> Result<Mechanism, SpfError> {
    let rest = if s == kind {
        ""
    } else if let Some(r) = s.strip_prefix(&format!("{}:", kind)) {
        r
    } else if let Some(r) = s.strip_prefix(&format!("{}/", kind)) {
        // Handle a/cidr case
        return parse_a_mx_cidr(None, r, kind);
    } else {
        return Err(SpfError::InvalidRecord(format!("invalid {} mechanism", kind)));
    };

    if rest.is_empty() {
        return match kind {
            "a" => Ok(Mechanism::A {
                domain: None,
                cidr4: None,
                cidr6: None,
            }),
            "mx" => Ok(Mechanism::Mx {
                domain: None,
                cidr4: None,
                cidr6: None,
            }),
            _ => unreachable!(),
        };
    }

    // domain/cidr4//cidr6 or domain/cidr4 or domain//cidr6 or domain
    if let Some((domain, cidr_part)) = rest.split_once('/') {
        parse_a_mx_cidr(Some(domain), cidr_part, kind)
    } else {
        match kind {
            "a" => Ok(Mechanism::A {
                domain: Some(rest.to_string()),
                cidr4: None,
                cidr6: None,
            }),
            "mx" => Ok(Mechanism::Mx {
                domain: Some(rest.to_string()),
                cidr4: None,
                cidr6: None,
            }),
            _ => unreachable!(),
        }
    }
}

fn parse_a_mx_cidr(
    domain: Option<&str>,
    cidr_part: &str,
    kind: &str,
) -> Result<Mechanism, SpfError> {
    let (cidr4, cidr6) = if let Some((c4, c6)) = cidr_part.split_once("//") {
        let c4 = if c4.is_empty() {
            None
        } else {
            Some(c4.parse().map_err(|_| {
                SpfError::InvalidRecord(format!("invalid cidr4: {}", c4))
            })?)
        };
        let c6 = if c6.is_empty() {
            None
        } else {
            Some(c6.parse().map_err(|_| {
                SpfError::InvalidRecord(format!("invalid cidr6: {}", c6))
            })?)
        };
        (c4, c6)
    } else {
        // Just cidr4
        let c4: u8 = cidr_part.parse().map_err(|_| {
            SpfError::InvalidRecord(format!("invalid cidr: {}", cidr_part))
        })?;
        (Some(c4), None)
    };

    let domain = domain.filter(|d| !d.is_empty()).map(String::from);

    match kind {
        "a" => Ok(Mechanism::A {
            domain,
            cidr4,
            cidr6,
        }),
        "mx" => Ok(Mechanism::Mx {
            domain,
            cidr4,
            cidr6,
        }),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let record = SpfRecord::parse("v=spf1 -all").unwrap();
        assert_eq!(record.directives.len(), 1);
        assert_eq!(record.directives[0].qualifier, Qualifier::Fail);
        assert_eq!(record.directives[0].mechanism, Mechanism::All);
    }

    #[test]
    fn test_parse_multiple_mechanisms() {
        let record =
            SpfRecord::parse("v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all").unwrap();
        assert_eq!(record.directives.len(), 3);
        assert!(matches!(
            &record.directives[0].mechanism,
            Mechanism::Ip4 { addr, prefix: 24 } if *addr == Ipv4Addr::new(192, 0, 2, 0)
        ));
    }

    #[test]
    fn test_parse_include() {
        let record = SpfRecord::parse("v=spf1 include:_spf.google.com -all").unwrap();
        assert!(matches!(
            &record.directives[0].mechanism,
            Mechanism::Include { domain } if domain == "_spf.google.com"
        ));
    }

    #[test]
    fn test_parse_redirect() {
        let record = SpfRecord::parse("v=spf1 redirect=_spf.example.com").unwrap();
        assert_eq!(record.redirect, Some("_spf.example.com".to_string()));
    }

    #[test]
    fn test_parse_case_insensitive() {
        let record = SpfRecord::parse("V=SPF1 IP4:192.0.2.1 -ALL").unwrap();
        assert_eq!(record.directives.len(), 2);
    }

    #[test]
    fn test_parse_a_mechanism() {
        let record = SpfRecord::parse("v=spf1 a a:example.com a/24 a:example.com/24//64 -all").unwrap();
        assert_eq!(record.directives.len(), 5);
    }

    #[test]
    fn test_invalid_version() {
        let err = SpfRecord::parse("v=spf2 -all");
        assert!(err.is_err());
    }
}
