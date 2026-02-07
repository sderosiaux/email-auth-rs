use super::mechanism::{Directive, Mechanism, Qualifier};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parsed SPF record.
#[derive(Debug, Clone, PartialEq)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpfParseError {
    InvalidVersion,
    UnknownMechanism(String),
    InvalidSyntax(String),
    DuplicateModifier(String),
}

impl std::fmt::Display for SpfParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVersion => write!(f, "invalid SPF version"),
            Self::UnknownMechanism(m) => write!(f, "unknown mechanism: {m}"),
            Self::InvalidSyntax(s) => write!(f, "invalid syntax: {s}"),
            Self::DuplicateModifier(m) => write!(f, "duplicate modifier: {m}"),
        }
    }
}

impl SpfRecord {
    pub fn parse(input: &str) -> Result<Self, SpfParseError> {
        let input = input.trim();
        let lower = input.to_ascii_lowercase();

        // Version check
        if !lower.starts_with("v=spf1") {
            return Err(SpfParseError::InvalidVersion);
        }
        // Must be exactly "v=spf1" or "v=spf1 ..."
        if lower.len() > 6 && !lower.as_bytes()[6].is_ascii_whitespace() {
            return Err(SpfParseError::InvalidVersion);
        }

        let rest = if input.len() > 6 {
            input[6..].trim()
        } else {
            ""
        };

        let mut directives = Vec::new();
        let mut redirect = None;
        let mut explanation = None;

        if rest.is_empty() {
            return Ok(SpfRecord {
                directives,
                redirect,
                explanation,
            });
        }

        for term in rest.split_whitespace() {
            let term_lower = term.to_ascii_lowercase();

            // Check for modifiers (name=value)
            if let Some((name, _value)) = term_lower.split_once('=') {
                match name {
                    "redirect" => {
                        if redirect.is_some() {
                            return Err(SpfParseError::DuplicateModifier("redirect".into()));
                        }
                        let (_, val) = term.split_once('=').unwrap();
                        redirect = Some(val.to_string());
                    }
                    "exp" => {
                        if explanation.is_some() {
                            return Err(SpfParseError::DuplicateModifier("exp".into()));
                        }
                        let (_, val) = term.split_once('=').unwrap();
                        explanation = Some(val.to_string());
                    }
                    _ => {
                        // Check if it looks like a mechanism with ':'
                        // Unknown modifiers with '=' are ignored (forward compat)
                        // But we need to distinguish mechanism:arg from modifier=val
                        // Modifiers have form: name=value where name has no qualifier prefix
                        // and name is not a known mechanism
                        // If name contains a qualifier prefix, it's a mechanism parse error
                        // Actually, modifiers use '=', mechanisms use ':' or have no delimiter
                        // So anything with '=' that isn't redirect/exp is an unknown modifier
                        // → ignore per RFC 7208 §6
                        continue;
                    }
                }
                continue;
            }

            // Parse directive: [qualifier] mechanism
            let (qualifier, mech_str) = parse_qualifier(&term_lower);
            let directive = parse_mechanism(mech_str, term, qualifier)?;
            directives.push(directive);
        }

        Ok(SpfRecord {
            directives,
            redirect,
            explanation,
        })
    }
}

fn parse_qualifier(term: &str) -> (Qualifier, &str) {
    match term.as_bytes().first() {
        Some(b'+') => (Qualifier::Pass, &term[1..]),
        Some(b'-') => (Qualifier::Fail, &term[1..]),
        Some(b'~') => (Qualifier::SoftFail, &term[1..]),
        Some(b'?') => (Qualifier::Neutral, &term[1..]),
        _ => (Qualifier::Pass, term),
    }
}

fn parse_mechanism(
    mech_lower: &str,
    original: &str,
    qualifier: Qualifier,
) -> Result<Directive, SpfParseError> {
    // Strip qualifier from original too
    let orig_rest = match original.as_bytes().first() {
        Some(b'+' | b'-' | b'~' | b'?') => &original[1..],
        _ => original,
    };

    let mechanism = if mech_lower == "all" {
        Mechanism::All
    } else if mech_lower.starts_with("include:") {
        let (_, d) = orig_rest.split_once(':').unwrap();
        Mechanism::Include {
            domain: d.to_string(),
        }
    } else if mech_lower == "a" || mech_lower.starts_with("a:") || mech_lower.starts_with("a/") {
        parse_a_mx_mechanism(orig_rest, true)?
    } else if mech_lower == "mx"
        || mech_lower.starts_with("mx:")
        || mech_lower.starts_with("mx/")
    {
        parse_a_mx_mechanism(orig_rest, false)?
    } else if mech_lower == "ptr" || mech_lower.starts_with("ptr:") {
        let domain = if let Some((_, d)) = orig_rest.split_once(':') {
            if d.is_empty() {
                None
            } else {
                Some(d.to_string())
            }
        } else {
            None
        };
        Mechanism::Ptr { domain }
    } else if mech_lower.starts_with("ip4:") {
        let (_, val) = orig_rest.split_once(':').unwrap();
        parse_ip4(val)?
    } else if mech_lower.starts_with("ip6:") {
        let (_, val) = orig_rest.split_once(':').unwrap();
        parse_ip6(val)?
    } else if mech_lower.starts_with("exists:") {
        let (_, d) = orig_rest.split_once(':').unwrap();
        Mechanism::Exists {
            domain: d.to_string(),
        }
    } else {
        return Err(SpfParseError::UnknownMechanism(mech_lower.to_string()));
    };

    Ok(Directive {
        qualifier,
        mechanism,
    })
}

fn parse_a_mx_mechanism(s: &str, is_a: bool) -> Result<Mechanism, SpfParseError> {
    let prefix_len = if is_a { 1 } else { 2 }; // "a" or "mx"
    let rest = &s[prefix_len..];

    let (domain_part, cidr_part) = if let Some(slash_pos) = rest.find('/') {
        (&rest[..slash_pos], &rest[slash_pos..])
    } else {
        (rest, "")
    };

    let domain = if domain_part.starts_with(':') {
        let d = &domain_part[1..];
        if d.is_empty() {
            None
        } else {
            Some(d.to_string())
        }
    } else {
        None
    };

    let (cidr4, cidr6) = parse_dual_cidr(cidr_part)?;

    if is_a {
        Ok(Mechanism::A {
            domain,
            cidr4,
            cidr6,
        })
    } else {
        Ok(Mechanism::Mx {
            domain,
            cidr4,
            cidr6,
        })
    }
}

fn parse_dual_cidr(s: &str) -> Result<(Option<u8>, Option<u8>), SpfParseError> {
    if s.is_empty() {
        return Ok((None, None));
    }

    // Format: /cidr4 or //cidr6 or /cidr4//cidr6
    let s = s.strip_prefix('/').unwrap_or(s);

    if let Some((v4_str, v6_str)) = s.split_once("//") {
        let cidr4 = if v4_str.is_empty() {
            None
        } else {
            Some(parse_prefix(v4_str, 32)?)
        };
        let cidr6 = if v6_str.is_empty() {
            None
        } else {
            Some(parse_prefix(v6_str, 128)?)
        };
        Ok((cidr4, cidr6))
    } else {
        let cidr4 = Some(parse_prefix(s, 32)?);
        Ok((cidr4, None))
    }
}

fn parse_prefix(s: &str, max: u8) -> Result<u8, SpfParseError> {
    let val: u8 = s
        .parse()
        .map_err(|_| SpfParseError::InvalidSyntax(format!("invalid prefix: {s}")))?;
    if val > max {
        return Err(SpfParseError::InvalidSyntax(format!(
            "prefix {val} exceeds max {max}"
        )));
    }
    Ok(val)
}

fn parse_ip4(s: &str) -> Result<Mechanism, SpfParseError> {
    if let Some((addr_str, prefix_str)) = s.split_once('/') {
        let addr: Ipv4Addr = addr_str
            .parse()
            .map_err(|_| SpfParseError::InvalidSyntax(format!("invalid IPv4: {addr_str}")))?;
        let prefix = parse_prefix(prefix_str, 32)?;
        Ok(Mechanism::Ip4 {
            addr,
            prefix: Some(prefix),
        })
    } else {
        let addr: Ipv4Addr = s
            .parse()
            .map_err(|_| SpfParseError::InvalidSyntax(format!("invalid IPv4: {s}")))?;
        Ok(Mechanism::Ip4 { addr, prefix: None })
    }
}

fn parse_ip6(s: &str) -> Result<Mechanism, SpfParseError> {
    if let Some((addr_str, prefix_str)) = s.rsplit_once('/') {
        let addr: Ipv6Addr = addr_str
            .parse()
            .map_err(|_| SpfParseError::InvalidSyntax(format!("invalid IPv6: {addr_str}")))?;
        let prefix = parse_prefix(prefix_str, 128)?;
        Ok(Mechanism::Ip6 {
            addr,
            prefix: Some(prefix),
        })
    } else {
        let addr: Ipv6Addr = s
            .parse()
            .map_err(|_| SpfParseError::InvalidSyntax(format!("invalid IPv6: {s}")))?;
        Ok(Mechanism::Ip6 { addr, prefix: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal() {
        let r = SpfRecord::parse("v=spf1 -all").unwrap();
        assert_eq!(r.directives.len(), 1);
        assert_eq!(r.directives[0].qualifier, Qualifier::Fail);
        assert_eq!(r.directives[0].mechanism, Mechanism::All);
    }

    #[test]
    fn test_multiple_mechanisms() {
        let r =
            SpfRecord::parse("v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all").unwrap();
        assert_eq!(r.directives.len(), 3);
    }

    #[test]
    fn test_include() {
        let r = SpfRecord::parse("v=spf1 include:_spf.google.com -all").unwrap();
        assert_eq!(r.directives.len(), 2);
        if let Mechanism::Include { domain } = &r.directives[0].mechanism {
            assert_eq!(domain, "_spf.google.com");
        } else {
            panic!("expected Include");
        }
    }

    #[test]
    fn test_case_insensitive() {
        let r = SpfRecord::parse("V=SPF1 IP4:192.0.2.1 -ALL").unwrap();
        assert_eq!(r.directives.len(), 2);
    }

    #[test]
    fn test_invalid_version() {
        assert!(SpfRecord::parse("v=spf2 -all").is_err());
    }

    #[test]
    fn test_duplicate_redirect() {
        assert!(SpfRecord::parse("v=spf1 redirect=a redirect=b").is_err());
    }

    #[test]
    fn test_unknown_modifier_ignored() {
        let r = SpfRecord::parse("v=spf1 foo=bar -all").unwrap();
        assert_eq!(r.directives.len(), 1);
    }

    #[test]
    fn test_unknown_mechanism_error() {
        assert!(SpfRecord::parse("v=spf1 custom:example.com -all").is_err());
    }

    #[test]
    fn test_dual_cidr() {
        let r = SpfRecord::parse("v=spf1 a:example.com/24//64 -all").unwrap();
        if let Mechanism::A {
            domain,
            cidr4,
            cidr6,
        } = &r.directives[0].mechanism
        {
            assert_eq!(domain.as_deref(), Some("example.com"));
            assert_eq!(*cidr4, Some(24));
            assert_eq!(*cidr6, Some(64));
        } else {
            panic!("expected A mechanism");
        }
    }

    #[test]
    fn test_redirect() {
        let r = SpfRecord::parse("v=spf1 redirect=example.com").unwrap();
        assert_eq!(r.redirect.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_exp() {
        let r = SpfRecord::parse("v=spf1 -all exp=explain.example.com").unwrap();
        assert_eq!(r.explanation.as_deref(), Some("explain.example.com"));
    }

    #[test]
    fn test_prefix_edge_cases() {
        let r = SpfRecord::parse("v=spf1 a/0 -all").unwrap();
        if let Mechanism::A { cidr4, .. } = &r.directives[0].mechanism {
            assert_eq!(*cidr4, Some(0));
        } else {
            panic!("expected A");
        }
    }

    #[test]
    fn test_ip6_mechanism() {
        let r = SpfRecord::parse("v=spf1 ip6:2001:db8::1/48 -all").unwrap();
        if let Mechanism::Ip6 { addr, prefix } = &r.directives[0].mechanism {
            assert_eq!(*addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
            assert_eq!(*prefix, Some(48));
        } else {
            panic!("expected Ip6");
        }
    }

    #[test]
    fn test_exists() {
        let r = SpfRecord::parse("v=spf1 exists:%{ir}.sbl.example.com -all").unwrap();
        if let Mechanism::Exists { domain } = &r.directives[0].mechanism {
            assert_eq!(domain, "%{ir}.sbl.example.com");
        } else {
            panic!("expected Exists");
        }
    }

    #[test]
    fn test_multiple_whitespace() {
        let r = SpfRecord::parse("v=spf1   ip4:1.2.3.4   -all  ").unwrap();
        assert_eq!(r.directives.len(), 2);
    }

    #[test]
    fn test_ptr() {
        let r = SpfRecord::parse("v=spf1 ptr:example.com -all").unwrap();
        if let Mechanism::Ptr { domain } = &r.directives[0].mechanism {
            assert_eq!(domain.as_deref(), Some("example.com"));
        } else {
            panic!("expected Ptr");
        }
    }

    #[test]
    fn test_v_only() {
        let r = SpfRecord::parse("v=spf1").unwrap();
        assert!(r.directives.is_empty());
    }

    #[test]
    fn test_mx_no_domain() {
        let r = SpfRecord::parse("v=spf1 mx -all").unwrap();
        if let Mechanism::Mx { domain, .. } = &r.directives[0].mechanism {
            assert_eq!(*domain, None);
        } else {
            panic!("expected Mx");
        }
    }
}
