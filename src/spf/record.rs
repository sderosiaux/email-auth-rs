use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use super::mechanism::{Mechanism, Modifier, Qualifier, Term};

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("not an SPF record")]
    NotSpf,
    #[error("invalid mechanism: {0}")]
    InvalidMechanism(String),
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid CIDR prefix: {0}")]
    InvalidPrefix(String),
    #[error("missing domain argument")]
    MissingDomain,
    #[error("duplicate modifier: {0}")]
    DuplicateModifier(String),
}

/// Parsed SPF record
#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub terms: Vec<Term>,
    pub redirect: Option<String>,
    pub exp: Option<String>,
}

impl SpfRecord {
    /// Parse SPF record from TXT record value
    pub fn parse(txt: &str) -> Result<Self, ParseError> {
        let txt = txt.trim();

        // Must start with v=spf1
        if !txt.to_lowercase().starts_with("v=spf1") {
            return Err(ParseError::NotSpf);
        }

        let mut terms = Vec::new();
        let mut redirect = None;
        let mut exp = None;

        // Split by whitespace and parse each term
        for part in txt.split_whitespace().skip(1) {
            let part_lower = part.to_lowercase();

            // Check for modifiers first
            if let Some((name, value)) = part.split_once('=') {
                let name_lower = name.to_lowercase();
                match name_lower.as_str() {
                    "redirect" => {
                        if redirect.is_some() {
                            return Err(ParseError::DuplicateModifier("redirect".to_string()));
                        }
                        redirect = Some(value.to_string());
                        terms.push(Term::Modifier(Modifier::Redirect(value.to_string())));
                    }
                    "exp" => {
                        if exp.is_some() {
                            return Err(ParseError::DuplicateModifier("exp".to_string()));
                        }
                        exp = Some(value.to_string());
                        terms.push(Term::Modifier(Modifier::Exp(value.to_string())));
                    }
                    _ => {
                        // Unknown modifier - ignore per RFC
                        terms.push(Term::Modifier(Modifier::Unknown(
                            name.to_string(),
                            value.to_string(),
                        )));
                    }
                }
                continue;
            }

            // Parse mechanism with qualifier
            let (qualifier, mech_str) = parse_qualifier(&part_lower);
            let mechanism = parse_mechanism(mech_str)?;
            terms.push(Term::Mechanism(qualifier, mechanism));
        }

        Ok(SpfRecord {
            terms,
            redirect,
            exp,
        })
    }

    /// Get all mechanisms (excluding modifiers)
    pub fn mechanisms(&self) -> impl Iterator<Item = (&Qualifier, &Mechanism)> {
        self.terms.iter().filter_map(|t| match t {
            Term::Mechanism(q, m) => Some((q, m)),
            _ => None,
        })
    }
}

fn parse_qualifier(s: &str) -> (Qualifier, &str) {
    let first = s.chars().next();
    match first {
        Some('+') => (Qualifier::Pass, &s[1..]),
        Some('-') => (Qualifier::Fail, &s[1..]),
        Some('~') => (Qualifier::SoftFail, &s[1..]),
        Some('?') => (Qualifier::Neutral, &s[1..]),
        _ => (Qualifier::Pass, s), // Default qualifier is Pass
    }
}

fn parse_mechanism(s: &str) -> Result<Mechanism, ParseError> {
    // Handle mechanisms with arguments
    if s == "all" {
        return Ok(Mechanism::All);
    }

    if let Some(domain) = s.strip_prefix("include:") {
        if domain.is_empty() {
            return Err(ParseError::MissingDomain);
        }
        return Ok(Mechanism::Include(domain.to_string()));
    }

    if let Some(rest) = s.strip_prefix("a") {
        return parse_a_mx_mechanism(rest, true);
    }

    if let Some(rest) = s.strip_prefix("mx") {
        return parse_a_mx_mechanism(rest, false);
    }

    if let Some(domain) = s.strip_prefix("ptr:") {
        return Ok(Mechanism::Ptr(Some(domain.to_string())));
    }
    if s == "ptr" {
        return Ok(Mechanism::Ptr(None));
    }

    if let Some(cidr) = s.strip_prefix("ip4:") {
        return parse_ip4(cidr);
    }

    if let Some(cidr) = s.strip_prefix("ip6:") {
        return parse_ip6(cidr);
    }

    if let Some(domain) = s.strip_prefix("exists:") {
        if domain.is_empty() {
            return Err(ParseError::MissingDomain);
        }
        return Ok(Mechanism::Exists(domain.to_string()));
    }

    Err(ParseError::InvalidMechanism(s.to_string()))
}

fn parse_a_mx_mechanism(rest: &str, is_a: bool) -> Result<Mechanism, ParseError> {
    let (domain, prefix_str) = if rest.is_empty() {
        (None, "")
    } else if rest.starts_with(':') {
        // a:domain or a:domain/prefix
        let rest = &rest[1..];
        if let Some((d, p)) = rest.split_once('/') {
            (Some(d.to_string()), p)
        } else {
            (Some(rest.to_string()), "")
        }
    } else if rest.starts_with('/') {
        // a/prefix (no domain)
        (None, &rest[1..])
    } else {
        return Err(ParseError::InvalidMechanism(format!(
            "{}{}",
            if is_a { "a" } else { "mx" },
            rest
        )));
    };

    let (prefix4, prefix6) = parse_dual_cidr(prefix_str)?;

    if is_a {
        Ok(Mechanism::A {
            domain,
            prefix4,
            prefix6,
        })
    } else {
        Ok(Mechanism::Mx {
            domain,
            prefix4,
            prefix6,
        })
    }
}

fn parse_dual_cidr(s: &str) -> Result<(u8, u8), ParseError> {
    if s.is_empty() {
        return Ok((32, 128)); // Default: exact match
    }

    // Format: prefix4 or prefix4//prefix6
    if let Some((p4, p6)) = s.split_once("//") {
        let prefix4 = p4
            .parse()
            .map_err(|_| ParseError::InvalidPrefix(p4.to_string()))?;
        let prefix6 = p6
            .parse()
            .map_err(|_| ParseError::InvalidPrefix(p6.to_string()))?;
        validate_prefix(prefix4, 32)?;
        validate_prefix(prefix6, 128)?;
        Ok((prefix4, prefix6))
    } else {
        let prefix4: u8 = s
            .parse()
            .map_err(|_| ParseError::InvalidPrefix(s.to_string()))?;
        validate_prefix(prefix4, 32)?;
        Ok((prefix4, 128))
    }
}

fn validate_prefix(prefix: u8, max: u8) -> Result<(), ParseError> {
    if prefix > max {
        return Err(ParseError::InvalidPrefix(format!(
            "{} exceeds max {}",
            prefix, max
        )));
    }
    Ok(())
}

fn parse_ip4(s: &str) -> Result<Mechanism, ParseError> {
    let (addr_str, prefix) = if let Some((a, p)) = s.split_once('/') {
        let prefix: u8 = p
            .parse()
            .map_err(|_| ParseError::InvalidPrefix(p.to_string()))?;
        validate_prefix(prefix, 32)?;
        (a, prefix)
    } else {
        (s, 32)
    };

    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|_| ParseError::InvalidIp(addr_str.to_string()))?;

    Ok(Mechanism::Ip4(addr, prefix))
}

fn parse_ip6(s: &str) -> Result<Mechanism, ParseError> {
    let (addr_str, prefix) = if let Some((a, p)) = s.split_once('/') {
        let prefix: u8 = p
            .parse()
            .map_err(|_| ParseError::InvalidPrefix(p.to_string()))?;
        validate_prefix(prefix, 128)?;
        (a, prefix)
    } else {
        (s, 128)
    };

    let addr: Ipv6Addr = addr_str
        .parse()
        .map_err(|_| ParseError::InvalidIp(addr_str.to_string()))?;

    Ok(Mechanism::Ip6(addr, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let record = SpfRecord::parse("v=spf1 -all").unwrap();
        assert_eq!(record.terms.len(), 1);
        assert!(matches!(
            &record.terms[0],
            Term::Mechanism(Qualifier::Fail, Mechanism::All)
        ));
    }

    #[test]
    fn test_parse_ip4() {
        let record = SpfRecord::parse("v=spf1 ip4:192.168.1.0/24 -all").unwrap();
        assert!(matches!(
            &record.terms[0],
            Term::Mechanism(Qualifier::Pass, Mechanism::Ip4(_, 24))
        ));
    }

    #[test]
    fn test_parse_include() {
        let record = SpfRecord::parse("v=spf1 include:_spf.google.com -all").unwrap();
        assert!(matches!(
            &record.terms[0],
            Term::Mechanism(Qualifier::Pass, Mechanism::Include(d)) if d == "_spf.google.com"
        ));
    }

    #[test]
    fn test_parse_a_mechanism() {
        let record = SpfRecord::parse("v=spf1 a a:mail.example.com a/24 -all").unwrap();
        assert!(matches!(
            &record.terms[0],
            Term::Mechanism(Qualifier::Pass, Mechanism::A { domain: None, prefix4: 32, prefix6: 128 })
        ));
        assert!(matches!(
            &record.terms[1],
            Term::Mechanism(Qualifier::Pass, Mechanism::A { domain: Some(d), .. }) if d == "mail.example.com"
        ));
        assert!(matches!(
            &record.terms[2],
            Term::Mechanism(Qualifier::Pass, Mechanism::A { domain: None, prefix4: 24, .. })
        ));
    }

    #[test]
    fn test_parse_redirect() {
        let record = SpfRecord::parse("v=spf1 redirect=_spf.example.com").unwrap();
        assert_eq!(record.redirect, Some("_spf.example.com".to_string()));
    }

    #[test]
    fn test_parse_not_spf() {
        let result = SpfRecord::parse("not an spf record");
        assert!(matches!(result, Err(ParseError::NotSpf)));
    }

    #[test]
    fn test_parse_qualifiers() {
        let record = SpfRecord::parse("v=spf1 +a -a ~a ?a").unwrap();
        let qualifiers: Vec<_> = record.mechanisms().map(|(q, _)| q).collect();
        assert_eq!(
            qualifiers,
            vec![
                &Qualifier::Pass,
                &Qualifier::Fail,
                &Qualifier::SoftFail,
                &Qualifier::Neutral
            ]
        );
    }
}
