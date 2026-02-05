use std::net::{Ipv4Addr, Ipv6Addr};

use super::mechanism::{Directive, Mechanism, Qualifier};
use super::SpfError;

/// Parsed SPF record
#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub exp: Option<String>,
    pub raw: String,
}

impl SpfRecord {
    /// Parse an SPF record from a TXT record string
    pub fn parse(txt: &str) -> Result<Self, SpfError> {
        let txt = txt.trim();

        // Must start with v=spf1 (case-insensitive)
        if !txt.to_lowercase().starts_with("v=spf1") {
            return Err(SpfError::Parse("record must start with v=spf1".to_string()));
        }

        // Get the part after "v=spf1"
        let remainder = &txt[6..].trim_start();

        let mut directives = Vec::new();
        let mut redirect = None;
        let mut exp = None;

        // Split by whitespace
        for term in remainder.split_whitespace() {
            let term_lower = term.to_lowercase();

            // Check for modifiers first
            if let Some(value) = term_lower.strip_prefix("redirect=") {
                if redirect.is_some() {
                    return Err(SpfError::Parse("duplicate redirect modifier".to_string()));
                }
                redirect = Some(value.to_string());
                continue;
            }

            if let Some(value) = term_lower.strip_prefix("exp=") {
                if exp.is_some() {
                    return Err(SpfError::Parse("duplicate exp modifier".to_string()));
                }
                exp = Some(value.to_string());
                continue;
            }

            // Skip unknown modifiers (forward compatibility)
            if term.contains('=') && !term.starts_with(|c: char| "+-~?".contains(c)) {
                continue;
            }

            // Parse directive
            let directive = Self::parse_directive(term)?;
            directives.push(directive);
        }

        Ok(Self {
            directives,
            redirect,
            exp,
            raw: txt.to_string(),
        })
    }

    fn parse_directive(term: &str) -> Result<Directive, SpfError> {
        let term_lower = term.to_lowercase();

        // Extract qualifier
        let (qualifier, mech_str) = if let Some(q) = term_lower.chars().next().and_then(Qualifier::from_char) {
            (q, &term_lower[1..])
        } else {
            (Qualifier::Pass, term_lower.as_str())
        };

        let mechanism = Self::parse_mechanism(mech_str)?;
        Ok(Directive { qualifier, mechanism })
    }

    fn parse_mechanism(s: &str) -> Result<Mechanism, SpfError> {
        if s == "all" {
            return Ok(Mechanism::All);
        }

        if let Some(domain) = s.strip_prefix("include:") {
            if domain.is_empty() {
                return Err(SpfError::Parse("include requires domain".to_string()));
            }
            return Ok(Mechanism::Include { domain: domain.to_string() });
        }

        if s == "a" || s.starts_with("a:") || s.starts_with("a/") {
            return Self::parse_a_mx(s, true);
        }

        if s == "mx" || s.starts_with("mx:") || s.starts_with("mx/") {
            return Self::parse_a_mx(s, false);
        }

        if s == "ptr" || s.starts_with("ptr:") {
            let domain = s.strip_prefix("ptr:").map(|d| d.to_string());
            return Ok(Mechanism::Ptr { domain });
        }

        if let Some(rest) = s.strip_prefix("ip4:") {
            return Self::parse_ip4(rest);
        }

        if let Some(rest) = s.strip_prefix("ip6:") {
            return Self::parse_ip6(rest);
        }

        if let Some(domain) = s.strip_prefix("exists:") {
            if domain.is_empty() {
                return Err(SpfError::Parse("exists requires domain".to_string()));
            }
            return Ok(Mechanism::Exists { domain: domain.to_string() });
        }

        Err(SpfError::Parse(format!("unknown mechanism: {}", s)))
    }

    fn parse_a_mx(s: &str, is_a: bool) -> Result<Mechanism, SpfError> {
        let prefix = if is_a { "a" } else { "mx" };
        let rest = s.strip_prefix(prefix).unwrap_or("");

        let mut domain = None;
        let mut cidr4 = None;
        let mut cidr6 = None;

        // Parse domain and CIDR
        // Formats: a, a:domain, a/cidr4, a:domain/cidr4, a//cidr6, a/cidr4//cidr6, etc.
        let mut remaining = rest;

        if let Some(d) = remaining.strip_prefix(':') {
            // Has domain
            if let Some(slash_pos) = d.find('/') {
                domain = Some(d[..slash_pos].to_string());
                remaining = &d[slash_pos..];
            } else {
                domain = Some(d.to_string());
                remaining = "";
            }
        }

        // Parse CIDR suffixes
        if let Some(rest) = remaining.strip_prefix("//") {
            // IPv6 only
            if !rest.is_empty() {
                cidr6 = Some(rest.parse().map_err(|_| SpfError::Parse("invalid CIDR6".to_string()))?);
            }
        } else if let Some(rest) = remaining.strip_prefix('/') {
            // IPv4, possibly followed by //cidr6
            if let Some(pos) = rest.find("//") {
                let c4 = &rest[..pos];
                let c6 = &rest[pos + 2..];
                if !c4.is_empty() {
                    cidr4 = Some(c4.parse().map_err(|_| SpfError::Parse("invalid CIDR4".to_string()))?);
                }
                if !c6.is_empty() {
                    cidr6 = Some(c6.parse().map_err(|_| SpfError::Parse("invalid CIDR6".to_string()))?);
                }
            } else if !rest.is_empty() {
                cidr4 = Some(rest.parse().map_err(|_| SpfError::Parse("invalid CIDR4".to_string()))?);
            }
        }

        if is_a {
            Ok(Mechanism::A { domain, cidr4, cidr6 })
        } else {
            Ok(Mechanism::Mx { domain, cidr4, cidr6 })
        }
    }

    fn parse_ip4(s: &str) -> Result<Mechanism, SpfError> {
        let (addr_str, prefix) = if let Some(pos) = s.find('/') {
            let prefix: u8 = s[pos + 1..]
                .parse()
                .map_err(|_| SpfError::Parse("invalid prefix length".to_string()))?;
            (&s[..pos], prefix)
        } else {
            (s, 32)
        };

        let addr: Ipv4Addr = addr_str
            .parse()
            .map_err(|_| SpfError::Parse("invalid IPv4 address".to_string()))?;

        if prefix > 32 {
            return Err(SpfError::Parse("IPv4 prefix must be <= 32".to_string()));
        }

        Ok(Mechanism::Ip4 { addr, prefix })
    }

    fn parse_ip6(s: &str) -> Result<Mechanism, SpfError> {
        let (addr_str, prefix) = if let Some(pos) = s.find('/') {
            let prefix: u8 = s[pos + 1..]
                .parse()
                .map_err(|_| SpfError::Parse("invalid prefix length".to_string()))?;
            (&s[..pos], prefix)
        } else {
            (s, 128)
        };

        let addr: Ipv6Addr = addr_str
            .parse()
            .map_err(|_| SpfError::Parse("invalid IPv6 address".to_string()))?;

        if prefix > 128 {
            return Err(SpfError::Parse("IPv6 prefix must be <= 128".to_string()));
        }

        Ok(Mechanism::Ip6 { addr, prefix })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
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
                assert_eq!(*addr, Ipv4Addr::new(192, 0, 2, 0));
                assert_eq!(*prefix, 24);
            }
            _ => panic!("expected Ip4"),
        }
    }

    #[test]
    fn test_parse_include() {
        let record = SpfRecord::parse("v=spf1 include:_spf.google.com ~all").unwrap();
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
    fn test_parse_case_insensitive() {
        let record = SpfRecord::parse("V=SPF1 IP4:192.0.2.1 -ALL").unwrap();
        assert_eq!(record.directives.len(), 2);
    }

    #[test]
    fn test_parse_a_mechanism() {
        let record = SpfRecord::parse("v=spf1 a a:mail.example.com a/24 a:mail.example.com/24//64 -all").unwrap();
        assert_eq!(record.directives.len(), 5);
    }

    #[test]
    fn test_invalid_version() {
        let result = SpfRecord::parse("v=spf2 -all");
        assert!(result.is_err());
    }
}
