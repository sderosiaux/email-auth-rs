use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Qualifier {
    #[default]
    Pass,      // + (default)
    Fail,      // -
    SoftFail,  // ~
    Neutral,   // ?
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

impl std::fmt::Display for Qualifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Qualifier::Pass => write!(f, "+"),
            Qualifier::Fail => write!(f, "-"),
            Qualifier::SoftFail => write!(f, "~"),
            Qualifier::Neutral => write!(f, "?"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Mechanism {
    All(Qualifier),
    Include { qualifier: Qualifier, domain: String },
    A { qualifier: Qualifier, domain: Option<String>, prefix4: Option<u8>, prefix6: Option<u8> },
    Mx { qualifier: Qualifier, domain: Option<String>, prefix4: Option<u8>, prefix6: Option<u8> },
    Ptr { qualifier: Qualifier, domain: Option<String> },
    Ip4 { qualifier: Qualifier, addr: IpAddr, prefix: Option<u8> },
    Ip6 { qualifier: Qualifier, addr: IpAddr, prefix: Option<u8> },
    Exists { qualifier: Qualifier, domain: String },
}

impl Mechanism {
    pub fn qualifier(&self) -> Qualifier {
        match self {
            Mechanism::All(q) => *q,
            Mechanism::Include { qualifier, .. } => *qualifier,
            Mechanism::A { qualifier, .. } => *qualifier,
            Mechanism::Mx { qualifier, .. } => *qualifier,
            Mechanism::Ptr { qualifier, .. } => *qualifier,
            Mechanism::Ip4 { qualifier, .. } => *qualifier,
            Mechanism::Ip6 { qualifier, .. } => *qualifier,
            Mechanism::Exists { qualifier, .. } => *qualifier,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        let (qualifier, rest) = if let Some(q) = Qualifier::from_char(s.chars().next()?) {
            (q, &s[1..])
        } else {
            (Qualifier::Pass, s)
        };

        let lower = rest.to_lowercase();

        if lower == "all" {
            return Some(Mechanism::All(qualifier));
        }

        if let Some(domain) = lower.strip_prefix("include:") {
            return Some(Mechanism::Include {
                qualifier,
                domain: domain.to_string(),
            });
        }

        if lower.starts_with("a") && (lower.len() == 1 || lower.chars().nth(1).is_some_and(|c| c == ':' || c == '/')) {
            let rest = if lower.len() > 1 { &rest[1..] } else { "" };
            let (domain, prefix4, prefix6) = parse_domain_and_prefix(rest);
            return Some(Mechanism::A { qualifier, domain, prefix4, prefix6 });
        }

        if lower.starts_with("mx") && (lower.len() == 2 || lower.chars().nth(2).is_some_and(|c| c == ':' || c == '/')) {
            let rest = if lower.len() > 2 { &rest[2..] } else { "" };
            let (domain, prefix4, prefix6) = parse_domain_and_prefix(rest);
            return Some(Mechanism::Mx { qualifier, domain, prefix4, prefix6 });
        }

        if let Some(rest) = lower.strip_prefix("ptr") {
            let domain = rest.strip_prefix(':').map(|s| s.to_string());
            return Some(Mechanism::Ptr { qualifier, domain });
        }

        if let Some(cidr) = lower.strip_prefix("ip4:") {
            let (addr, prefix) = parse_ip_cidr(cidr)?;
            return Some(Mechanism::Ip4 { qualifier, addr, prefix });
        }

        if let Some(cidr) = lower.strip_prefix("ip6:") {
            let (addr, prefix) = parse_ip_cidr(cidr)?;
            return Some(Mechanism::Ip6 { qualifier, addr, prefix });
        }

        if let Some(domain) = lower.strip_prefix("exists:") {
            return Some(Mechanism::Exists {
                qualifier,
                domain: domain.to_string(),
            });
        }

        None
    }
}

fn parse_domain_and_prefix(s: &str) -> (Option<String>, Option<u8>, Option<u8>) {
    let s = s.strip_prefix(':').unwrap_or(s);
    if s.is_empty() {
        return (None, None, None);
    }

    let (domain_part, prefix_part) = if let Some(pos) = s.find('/') {
        (&s[..pos], Some(&s[pos..]))
    } else {
        (s, None)
    };

    let domain = if domain_part.is_empty() { None } else { Some(domain_part.to_string()) };

    let (prefix4, prefix6) = if let Some(prefix) = prefix_part {
        parse_dual_prefix(prefix)
    } else {
        (None, None)
    };

    (domain, prefix4, prefix6)
}

fn parse_dual_prefix(s: &str) -> (Option<u8>, Option<u8>) {
    let s = s.strip_prefix('/').unwrap_or(s);

    if let Some(pos) = s.find("//") {
        let prefix4 = s[..pos].parse().ok();
        let prefix6 = s[pos + 2..].parse().ok();
        (prefix4, prefix6)
    } else {
        let prefix = s.parse().ok();
        (prefix, None)
    }
}

fn parse_ip_cidr(s: &str) -> Option<(IpAddr, Option<u8>)> {
    if let Some(pos) = s.find('/') {
        let addr: IpAddr = s[..pos].parse().ok()?;
        let prefix: u8 = s[pos + 1..].parse().ok()?;
        Some((addr, Some(prefix)))
    } else {
        let addr: IpAddr = s.parse().ok()?;
        Some((addr, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all() {
        assert_eq!(Mechanism::parse("all"), Some(Mechanism::All(Qualifier::Pass)));
        assert_eq!(Mechanism::parse("-all"), Some(Mechanism::All(Qualifier::Fail)));
        assert_eq!(Mechanism::parse("~all"), Some(Mechanism::All(Qualifier::SoftFail)));
    }

    #[test]
    fn test_parse_include() {
        assert_eq!(
            Mechanism::parse("include:example.com"),
            Some(Mechanism::Include {
                qualifier: Qualifier::Pass,
                domain: "example.com".into(),
            })
        );
    }

    #[test]
    fn test_parse_ip4() {
        assert_eq!(
            Mechanism::parse("ip4:192.168.1.0/24"),
            Some(Mechanism::Ip4 {
                qualifier: Qualifier::Pass,
                addr: "192.168.1.0".parse().unwrap(),
                prefix: Some(24),
            })
        );
    }

    #[test]
    fn test_parse_a() {
        assert_eq!(
            Mechanism::parse("a"),
            Some(Mechanism::A {
                qualifier: Qualifier::Pass,
                domain: None,
                prefix4: None,
                prefix6: None,
            })
        );
        assert_eq!(
            Mechanism::parse("a:mail.example.com"),
            Some(Mechanism::A {
                qualifier: Qualifier::Pass,
                domain: Some("mail.example.com".into()),
                prefix4: None,
                prefix6: None,
            })
        );
    }
}
