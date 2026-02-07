use std::net::{Ipv4Addr, Ipv6Addr};

/// SPF qualifier (RFC 7208 Section 4.6.2).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Qualifier {
    Pass,     // +
    Fail,     // -
    SoftFail, // ~
    Neutral,  // ?
}

/// A directive: qualifier + mechanism.
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

/// SPF mechanisms (RFC 7208 Section 5).
#[derive(Debug, Clone, PartialEq)]
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
        prefix: Option<u8>,
    },
    Ip6 {
        addr: Ipv6Addr,
        prefix: Option<u8>,
    },
    Exists {
        domain: String,
    },
}

/// Parse a qualifier character to a Qualifier enum.
fn parse_qualifier(c: char) -> Option<Qualifier> {
    match c {
        '+' => Some(Qualifier::Pass),
        '-' => Some(Qualifier::Fail),
        '~' => Some(Qualifier::SoftFail),
        '?' => Some(Qualifier::Neutral),
        _ => None,
    }
}

/// Parse a dual CIDR suffix: /cidr4 or //cidr6 or /cidr4//cidr6
fn parse_dual_cidr(s: &str) -> Result<(Option<u8>, Option<u8>), String> {
    if s.is_empty() {
        return Ok((None, None));
    }
    if !s.starts_with('/') {
        return Err(format!("expected / in CIDR: {}", s));
    }
    let s = &s[1..]; // strip leading /
    if let Some(pos) = s.find("//") {
        let cidr4 = if pos == 0 {
            None
        } else {
            Some(
                s[..pos]
                    .parse::<u8>()
                    .map_err(|_| format!("invalid cidr4: {}", &s[..pos]))?,
            )
        };
        let cidr6_str = &s[pos + 2..];
        let cidr6 = if cidr6_str.is_empty() {
            None
        } else {
            Some(
                cidr6_str
                    .parse::<u8>()
                    .map_err(|_| format!("invalid cidr6: {}", cidr6_str))?,
            )
        };
        Ok((cidr4, cidr6))
    } else {
        let cidr4 = s
            .parse::<u8>()
            .map_err(|_| format!("invalid cidr4: {}", s))?;
        Ok((Some(cidr4), None))
    }
}

type DomainCidr = (Option<String>, Option<u8>, Option<u8>);

/// Parse domain and dual CIDR from a mechanism argument like ":domain/cidr4//cidr6"
fn parse_domain_cidr(arg: &str) -> Result<DomainCidr, String> {
    if arg.is_empty() {
        return Ok((None, None, None));
    }
    let s = arg.strip_prefix(':').unwrap_or(arg);
    if let Some(slash) = s.find('/') {
        let domain = if slash == 0 {
            None
        } else {
            Some(s[..slash].to_string())
        };
        let (c4, c6) = parse_dual_cidr(&s[slash..])?;
        Ok((domain, c4, c6))
    } else if s.is_empty() {
        Ok((None, None, None))
    } else {
        Ok((Some(s.to_string()), None, None))
    }
}

/// Parse a single SPF term (directive or modifier).
/// Returns Ok(Some(Directive)) for a mechanism, Ok(None) for a modifier, Err for unknown mechanism.
pub fn parse_term(
    term: &str,
) -> Result<
    TermKind,
    String,
> {
    let term = term.trim();
    if term.is_empty() {
        return Err("empty term".to_string());
    }

    // Check if it's a modifier (contains '=')
    if let Some(eq_pos) = term.find('=') {
        let name = &term[..eq_pos];
        let value = &term[eq_pos + 1..];
        // Modifiers have name=value syntax. Mechanism names don't contain '='
        // But mechanisms like ip4:1.2.3.4 don't have '=', so if name contains
        // mechanism-like characters, it's a mechanism parse error, not a modifier.
        // Per RFC: if it looks like name=value and name is alphabetic, it's a modifier.
        if name.chars().all(|c| c.is_ascii_alphabetic() || c == '-') && !name.is_empty() {
            return Ok(TermKind::Modifier(name.to_string(), value.to_string()));
        }
    }

    // Parse qualifier
    let (qualifier, mech_str) = {
        let first = term.chars().next().unwrap();
        if let Some(q) = parse_qualifier(first) {
            (q, &term[1..])
        } else {
            (Qualifier::Pass, term)
        }
    };

    // Split mechanism name from argument
    let (name, arg) = if let Some(colon) = mech_str.find(':') {
        (&mech_str[..colon], &mech_str[colon..])
    } else if let Some(slash) = mech_str.find('/') {
        (&mech_str[..slash], &mech_str[slash..])
    } else {
        (mech_str, "")
    };

    let name_lower = name.to_ascii_lowercase();
    let mechanism = match name_lower.as_str() {
        "all" => Mechanism::All,
        "include" => {
            let domain = arg.strip_prefix(':').unwrap_or(arg);
            if domain.is_empty() {
                return Err("include requires a domain".to_string());
            }
            Mechanism::Include {
                domain: domain.to_string(),
            }
        }
        "a" => {
            let (domain, c4, c6) = parse_domain_cidr(arg)?;
            Mechanism::A {
                domain,
                cidr4: c4,
                cidr6: c6,
            }
        }
        "mx" => {
            let (domain, c4, c6) = parse_domain_cidr(arg)?;
            Mechanism::Mx {
                domain,
                cidr4: c4,
                cidr6: c6,
            }
        }
        "ptr" => {
            let domain = if arg.is_empty() {
                None
            } else {
                let d = arg.strip_prefix(':').unwrap_or(arg);
                if d.is_empty() {
                    None
                } else {
                    Some(d.to_string())
                }
            };
            Mechanism::Ptr { domain }
        }
        "ip4" => {
            let addr_str = arg.strip_prefix(':').unwrap_or(arg);
            if let Some(slash) = addr_str.find('/') {
                let addr: Ipv4Addr = addr_str[..slash]
                    .parse()
                    .map_err(|e| format!("invalid ip4 address: {}", e))?;
                let prefix: u8 = addr_str[slash + 1..]
                    .parse()
                    .map_err(|e| format!("invalid ip4 prefix: {}", e))?;
                Mechanism::Ip4 {
                    addr,
                    prefix: Some(prefix),
                }
            } else {
                let addr: Ipv4Addr = addr_str
                    .parse()
                    .map_err(|e| format!("invalid ip4 address: {}", e))?;
                Mechanism::Ip4 { addr, prefix: None }
            }
        }
        "ip6" => {
            let addr_str = arg.strip_prefix(':').unwrap_or(arg);
            if let Some(slash) = addr_str.rfind('/') {
                let addr: Ipv6Addr = addr_str[..slash]
                    .parse()
                    .map_err(|e| format!("invalid ip6 address: {}", e))?;
                let prefix: u8 = addr_str[slash + 1..]
                    .parse()
                    .map_err(|e| format!("invalid ip6 prefix: {}", e))?;
                Mechanism::Ip6 {
                    addr,
                    prefix: Some(prefix),
                }
            } else {
                let addr: Ipv6Addr = addr_str
                    .parse()
                    .map_err(|e| format!("invalid ip6 address: {}", e))?;
                Mechanism::Ip6 { addr, prefix: None }
            }
        }
        "exists" => {
            let domain = arg.strip_prefix(':').unwrap_or(arg);
            if domain.is_empty() {
                return Err("exists requires a domain".to_string());
            }
            Mechanism::Exists {
                domain: domain.to_string(),
            }
        }
        _ => {
            return Err(format!("unknown mechanism: {}", name_lower));
        }
    };

    Ok(TermKind::Directive(Directive { qualifier, mechanism }))
}

/// Parsed term: either a directive (mechanism+qualifier) or a modifier (name=value).
#[derive(Debug)]
pub enum TermKind {
    Directive(Directive),
    Modifier(String, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all() {
        match parse_term("-all").unwrap() {
            TermKind::Directive(d) => {
                assert_eq!(d.qualifier, Qualifier::Fail);
                assert_eq!(d.mechanism, Mechanism::All);
            }
            _ => panic!("expected directive"),
        }
    }

    #[test]
    fn test_parse_ip4() {
        match parse_term("ip4:192.0.2.0/24").unwrap() {
            TermKind::Directive(d) => {
                assert_eq!(d.qualifier, Qualifier::Pass);
                assert_eq!(
                    d.mechanism,
                    Mechanism::Ip4 {
                        addr: "192.0.2.0".parse().unwrap(),
                        prefix: Some(24),
                    }
                );
            }
            _ => panic!("expected directive"),
        }
    }

    #[test]
    fn test_parse_dual_cidr() {
        match parse_term("a:example.com/24//64").unwrap() {
            TermKind::Directive(d) => {
                assert_eq!(
                    d.mechanism,
                    Mechanism::A {
                        domain: Some("example.com".to_string()),
                        cidr4: Some(24),
                        cidr6: Some(64),
                    }
                );
            }
            _ => panic!("expected directive"),
        }
    }

    #[test]
    fn test_unknown_mechanism_error() {
        assert!(parse_term("custom:example.com").is_err());
    }

    #[test]
    fn test_unknown_modifier_ok() {
        match parse_term("foo=bar").unwrap() {
            TermKind::Modifier(name, value) => {
                assert_eq!(name, "foo");
                assert_eq!(value, "bar");
            }
            _ => panic!("expected modifier"),
        }
    }
}
