use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq)]
pub enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

#[derive(Debug, Clone)]
pub enum Mechanism {
    All,
    Include(String),
    A(Option<String>, Option<u8>, Option<u8>),
    Mx(Option<String>, Option<u8>, Option<u8>),
    Ptr(Option<String>),
    Ip4(Ipv4Addr, u8),
    Ip6(Ipv6Addr, u8),
    Exists(String),
}

impl Mechanism {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.to_lowercase();

        if s == "all" {
            return Some(Mechanism::All);
        }

        if let Some(domain) = s.strip_prefix("include:") {
            return Some(Mechanism::Include(domain.to_string()));
        }

        if let Some(domain) = s.strip_prefix("exists:") {
            return Some(Mechanism::Exists(domain.to_string()));
        }

        if let Some(rest) = s.strip_prefix("ip4:") {
            return parse_ip4(rest);
        }

        if let Some(rest) = s.strip_prefix("ip6:") {
            return parse_ip6(rest);
        }

        if s == "a" || s.starts_with("a:") || s.starts_with("a/") {
            return parse_a_or_mx(&s, "a");
        }

        if s == "mx" || s.starts_with("mx:") || s.starts_with("mx/") {
            return parse_a_or_mx(&s, "mx");
        }

        if s == "ptr" {
            return Some(Mechanism::Ptr(None));
        }
        if let Some(domain) = s.strip_prefix("ptr:") {
            return Some(Mechanism::Ptr(Some(domain.to_string())));
        }

        None
    }
}

fn parse_ip4(s: &str) -> Option<Mechanism> {
    let (addr_str, prefix) = if let Some(idx) = s.find('/') {
        let prefix: u8 = s[idx + 1..].parse().ok()?;
        (&s[..idx], prefix)
    } else {
        (s, 32)
    };

    let addr: Ipv4Addr = addr_str.parse().ok()?;
    Some(Mechanism::Ip4(addr, prefix))
}

fn parse_ip6(s: &str) -> Option<Mechanism> {
    let (addr_str, prefix) = if let Some(idx) = s.find('/') {
        let prefix: u8 = s[idx + 1..].parse().ok()?;
        (&s[..idx], prefix)
    } else {
        (s, 128)
    };

    let addr: Ipv6Addr = addr_str.parse().ok()?;
    Some(Mechanism::Ip6(addr, prefix))
}

fn parse_a_or_mx(s: &str, kind: &str) -> Option<Mechanism> {
    let rest = if s == kind {
        ""
    } else if let Some(r) = s.strip_prefix(&format!("{}:", kind)) {
        r
    } else if let Some(r) = s.strip_prefix(&format!("{}/", kind)) {
        return parse_prefix_only(r, kind);
    } else {
        return None;
    };

    if rest.is_empty() {
        return match kind {
            "a" => Some(Mechanism::A(None, None, None)),
            "mx" => Some(Mechanism::Mx(None, None, None)),
            _ => None,
        };
    }

    let (domain, prefix4, prefix6) = parse_domain_with_prefix(rest)?;

    match kind {
        "a" => Some(Mechanism::A(Some(domain), prefix4, prefix6)),
        "mx" => Some(Mechanism::Mx(Some(domain), prefix4, prefix6)),
        _ => None,
    }
}

fn parse_prefix_only(s: &str, kind: &str) -> Option<Mechanism> {
    let (p4, p6) = parse_dual_cidr(s)?;
    match kind {
        "a" => Some(Mechanism::A(None, Some(p4), p6)),
        "mx" => Some(Mechanism::Mx(None, Some(p4), p6)),
        _ => None,
    }
}

fn parse_domain_with_prefix(s: &str) -> Option<(String, Option<u8>, Option<u8>)> {
    if let Some(idx) = s.find('/') {
        let domain = s[..idx].to_string();
        let (p4, p6) = parse_dual_cidr(&s[idx + 1..])?;
        Some((domain, Some(p4), p6))
    } else {
        Some((s.to_string(), None, None))
    }
}

fn parse_dual_cidr(s: &str) -> Option<(u8, Option<u8>)> {
    if let Some(idx) = s.find("//") {
        let p4: u8 = s[..idx].parse().ok()?;
        let p6: u8 = s[idx + 2..].parse().ok()?;
        Some((p4, Some(p6)))
    } else {
        let p4: u8 = s.parse().ok()?;
        Some((p4, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all() {
        assert!(matches!(Mechanism::parse("all"), Some(Mechanism::All)));
    }

    #[test]
    fn test_parse_include() {
        assert!(matches!(
            Mechanism::parse("include:example.com"),
            Some(Mechanism::Include(d)) if d == "example.com"
        ));
    }

    #[test]
    fn test_parse_ip4() {
        assert!(matches!(
            Mechanism::parse("ip4:192.168.1.0/24"),
            Some(Mechanism::Ip4(_, 24))
        ));
    }

    #[test]
    fn test_parse_a() {
        assert!(matches!(Mechanism::parse("a"), Some(Mechanism::A(None, None, None))));
        assert!(matches!(
            Mechanism::parse("a:example.com"),
            Some(Mechanism::A(Some(d), None, None)) if d == "example.com"
        ));
    }
}
