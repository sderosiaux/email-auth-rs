use super::mechanism::{Directive, Mechanism, Qualifier};
use super::SpfError;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parsed SPF record
#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub exp: Option<String>,
    pub raw: String,
}

impl SpfRecord {
    /// Parse an SPF record from a TXT string
    pub fn parse(txt: &str) -> Result<Self, SpfError> {
        let txt = txt.trim();

        // Check version
        if !txt.to_lowercase().starts_with("v=spf1") {
            return Err(SpfError::Parse("missing v=spf1".to_string()));
        }

        // Skip version prefix
        let rest = &txt[6..];

        let mut directives = Vec::new();
        let mut redirect = None;
        let mut exp = None;

        for term in rest.split_whitespace() {
            let term_lower = term.to_lowercase();

            // Check for modifiers
            if let Some(domain) = term_lower.strip_prefix("redirect=") {
                if redirect.is_some() {
                    return Err(SpfError::Parse("duplicate redirect modifier".to_string()));
                }
                redirect = Some(domain.to_string());
                continue;
            }
            if let Some(domain) = term_lower.strip_prefix("exp=") {
                if exp.is_some() {
                    return Err(SpfError::Parse("duplicate exp modifier".to_string()));
                }
                exp = Some(domain.to_string());
                continue;
            }

            // Unknown modifier (name=value) - ignore for forward compatibility
            if term.contains('=') && !term_lower.starts_with("v=") {
                continue;
            }

            // Parse directive (qualifier + mechanism)
            let directive = parse_directive(term)?;
            directives.push(directive);
        }

        Ok(SpfRecord {
            directives,
            redirect,
            exp,
            raw: txt.to_string(),
        })
    }
}

fn parse_directive(term: &str) -> Result<Directive, SpfError> {
    let term = term.trim();
    if term.is_empty() {
        return Err(SpfError::Parse("empty directive".to_string()));
    }

    let first_char = term.chars().next().unwrap();
    let (qualifier, mech_str) = if let Some(q) = Qualifier::from_char(first_char) {
        (q, &term[1..])
    } else {
        (Qualifier::Pass, term)
    };

    let mech_str_lower = mech_str.to_lowercase();
    let mechanism = parse_mechanism(&mech_str_lower)?;

    Ok(Directive {
        qualifier,
        mechanism,
    })
}

fn parse_mechanism(s: &str) -> Result<Mechanism, SpfError> {
    if s == "all" {
        return Ok(Mechanism::All);
    }

    if let Some(domain) = s.strip_prefix("include:") {
        return Ok(Mechanism::Include {
            domain: domain.to_string(),
        });
    }

    if s == "a" || s.starts_with("a:") || s.starts_with("a/") {
        return parse_a_mx_mechanism(s, true);
    }

    if s == "mx" || s.starts_with("mx:") || s.starts_with("mx/") {
        return parse_a_mx_mechanism(s, false);
    }

    if s == "ptr" || s.starts_with("ptr:") {
        let domain = s.strip_prefix("ptr:").map(|d| d.to_string());
        return Ok(Mechanism::Ptr { domain });
    }

    if let Some(rest) = s.strip_prefix("ip4:") {
        return parse_ip4(rest);
    }

    if let Some(rest) = s.strip_prefix("ip6:") {
        return parse_ip6(rest);
    }

    if let Some(domain) = s.strip_prefix("exists:") {
        return Ok(Mechanism::Exists {
            domain: domain.to_string(),
        });
    }

    Err(SpfError::Parse(format!("unknown mechanism: {}", s)))
}

fn parse_a_mx_mechanism(s: &str, is_a: bool) -> Result<Mechanism, SpfError> {
    // Format: a | a:<domain> | a/<cidr4> | a/<cidr4>//<cidr6> | a:<domain>/<cidr4> | etc.
    let prefix = if is_a { "a" } else { "mx" };
    let rest = s.strip_prefix(prefix).unwrap_or("");

    let mut domain = None;
    let mut cidr4 = None;
    let mut cidr6 = None;

    let rest = if let Some(d) = rest.strip_prefix(':') {
        // Has domain spec
        if let Some(slash_pos) = d.find('/') {
            domain = Some(d[..slash_pos].to_string());
            &d[slash_pos..]
        } else {
            domain = Some(d.to_string());
            ""
        }
    } else {
        rest
    };

    // Parse CIDR: /cidr4 or /cidr4//cidr6 or //cidr6
    if let Some(cidrs) = rest.strip_prefix('/') {
        if let Some(c6) = cidrs.strip_prefix('/') {
            // //cidr6
            cidr6 = Some(
                c6.parse::<u8>()
                    .map_err(|_| SpfError::Parse(format!("invalid cidr6: {}", c6)))?,
            );
        } else if let Some(pos) = cidrs.find("//") {
            // cidr4//cidr6
            cidr4 = Some(
                cidrs[..pos]
                    .parse::<u8>()
                    .map_err(|_| SpfError::Parse(format!("invalid cidr4: {}", &cidrs[..pos])))?,
            );
            cidr6 = Some(
                cidrs[pos + 2..]
                    .parse::<u8>()
                    .map_err(|_| SpfError::Parse(format!("invalid cidr6: {}", &cidrs[pos + 2..])))?,
            );
        } else {
            // just cidr4
            cidr4 = Some(
                cidrs
                    .parse::<u8>()
                    .map_err(|_| SpfError::Parse(format!("invalid cidr4: {}", cidrs)))?,
            );
        }
    }

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

fn parse_ip4(s: &str) -> Result<Mechanism, SpfError> {
    let (addr_str, prefix) = if let Some(slash_pos) = s.find('/') {
        let prefix = s[slash_pos + 1..]
            .parse::<u8>()
            .map_err(|_| SpfError::Parse(format!("invalid ip4 prefix: {}", &s[slash_pos + 1..])))?;
        (&s[..slash_pos], prefix)
    } else {
        (s, 32)
    };

    let addr = addr_str
        .parse::<Ipv4Addr>()
        .map_err(|_| SpfError::Parse(format!("invalid ipv4 address: {}", addr_str)))?;

    Ok(Mechanism::Ip4 { addr, prefix })
}

fn parse_ip6(s: &str) -> Result<Mechanism, SpfError> {
    let (addr_str, prefix) = if let Some(slash_pos) = s.find('/') {
        let prefix = s[slash_pos + 1..]
            .parse::<u8>()
            .map_err(|_| SpfError::Parse(format!("invalid ip6 prefix: {}", &s[slash_pos + 1..])))?;
        (&s[..slash_pos], prefix)
    } else {
        (s, 128)
    };

    let addr = addr_str
        .parse::<Ipv6Addr>()
        .map_err(|_| SpfError::Parse(format!("invalid ipv6 address: {}", addr_str)))?;

    Ok(Mechanism::Ip6 { addr, prefix })
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
    fn test_parse_ip4() {
        let record = SpfRecord::parse("v=spf1 ip4:192.0.2.0/24 -all").unwrap();
        assert_eq!(record.directives.len(), 2);
        match &record.directives[0].mechanism {
            Mechanism::Ip4 { addr, prefix } => {
                assert_eq!(*addr, "192.0.2.0".parse::<Ipv4Addr>().unwrap());
                assert_eq!(*prefix, 24);
            }
            _ => panic!("expected Ip4"),
        }
    }

    #[test]
    fn test_parse_include() {
        let record = SpfRecord::parse("v=spf1 include:_spf.google.com -all").unwrap();
        assert_eq!(record.directives.len(), 2);
        match &record.directives[0].mechanism {
            Mechanism::Include { domain } => {
                assert_eq!(domain, "_spf.google.com");
            }
            _ => panic!("expected Include"),
        }
    }

    #[test]
    fn test_parse_redirect() {
        let record = SpfRecord::parse("v=spf1 redirect=_spf.example.com").unwrap();
        assert_eq!(record.redirect, Some("_spf.example.com".to_string()));
    }

    #[test]
    fn test_case_insensitive() {
        let record = SpfRecord::parse("V=SPF1 IP4:192.0.2.1 -ALL").unwrap();
        assert_eq!(record.directives.len(), 2);
    }

    #[test]
    fn test_invalid_version() {
        assert!(SpfRecord::parse("v=spf2 -all").is_err());
    }
}
