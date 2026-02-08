use std::net::{Ipv4Addr, Ipv6Addr};

use super::types::{Directive, Mechanism, Qualifier, SpfRecord};

/// Parse an SPF record string. The input must start with "v=spf1".
pub(crate) fn parse_record(record: &str) -> Result<SpfRecord, String> {
    let trimmed = record.trim();

    // Validate version prefix (case-insensitive)
    let lower = trimmed.to_ascii_lowercase();
    if lower == "v=spf1" {
        return Ok(SpfRecord {
            directives: Vec::new(),
            redirect: None,
            explanation: None,
        });
    }
    if !lower.starts_with("v=spf1 ") {
        return Err(format!("invalid SPF version: {}", trimmed.split_whitespace().next().unwrap_or("")));
    }

    // Split by whitespace after version
    let body = &trimmed[7..]; // skip "v=spf1 "
    let terms: Vec<&str> = body.split_whitespace().collect();

    let mut directives = Vec::new();
    let mut redirect: Option<String> = None;
    let mut explanation: Option<String> = None;

    for term in terms {
        if term.is_empty() {
            continue;
        }

        // Check if this is a modifier (name=value)
        if let Some((name, value)) = try_parse_modifier(term) {
            let name_lower = name.to_ascii_lowercase();
            match name_lower.as_str() {
                "redirect" => {
                    if redirect.is_some() {
                        return Err("duplicate redirect modifier".into());
                    }
                    redirect = Some(value.to_string());
                }
                "exp" => {
                    if explanation.is_some() {
                        return Err("duplicate exp modifier".into());
                    }
                    explanation = Some(value.to_string());
                }
                _ => {
                    // Unknown modifier → silently ignore (forward compatibility)
                }
            }
            continue;
        }

        // Parse as directive
        let directive = parse_directive(term)?;
        directives.push(directive);
    }

    Ok(SpfRecord {
        directives,
        redirect,
        explanation,
    })
}

/// Try to parse a term as a modifier (name=value).
/// Returns None if it's not a modifier.
/// A modifier has the form `name=value` where name is alphabetic.
fn try_parse_modifier(term: &str) -> Option<(&str, &str)> {
    // Modifier names consist of alphabetic chars only.
    // The '=' must appear after at least one alpha char.
    let eq_pos = term.find('=')?;
    let name = &term[..eq_pos];

    // Modifier name must be non-empty and all alphabetic
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    // Make sure this isn't a known mechanism with an '=' in its argument
    // Known mechanism names should be parsed as directives, not modifiers.
    let name_lower = name.to_ascii_lowercase();
    if is_known_mechanism_name(&name_lower) {
        return None;
    }

    // Also check if there's a qualifier prefix
    let first = name.as_bytes()[0];
    if matches!(first, b'+' | b'-' | b'~' | b'?') {
        // If the rest after qualifier is a known mechanism, it's a directive not a modifier
        let after_q = &name_lower[1..];
        if is_known_mechanism_name(after_q) {
            return None;
        }
    }

    let value = &term[eq_pos + 1..];
    Some((name, value))
}

fn is_known_mechanism_name(name: &str) -> bool {
    matches!(
        name,
        "all" | "include" | "a" | "mx" | "ptr" | "ip4" | "ip6" | "exists"
    )
}

/// Parse a single directive term: [qualifier]mechanism[:argument][/cidr]
fn parse_directive(term: &str) -> Result<Directive, String> {
    let (qualifier, rest) = extract_qualifier(term);

    // Split mechanism name from argument
    let (mech_name, arg) = split_mechanism_arg(rest);
    let mech_lower = mech_name.to_ascii_lowercase();

    let mechanism = match mech_lower.as_str() {
        "all" => {
            // all takes no arguments
            Mechanism::All
        }
        "include" => {
            let domain = arg.ok_or("include requires a domain argument")?;
            if domain.is_empty() {
                return Err("include requires a non-empty domain".into());
            }
            Mechanism::Include { domain: domain.to_string() }
        }
        "a" => parse_a_mx_mechanism(arg, true)?,
        "mx" => parse_a_mx_mechanism(arg, false)?,
        "ptr" => {
            let domain = arg.map(|s| s.to_string()).filter(|s| !s.is_empty());
            Mechanism::Ptr { domain }
        }
        "ip4" => {
            let arg_str = arg.ok_or("ip4 requires an address argument")?;
            parse_ip4(arg_str)?
        }
        "ip6" => {
            let arg_str = arg.ok_or("ip6 requires an address argument")?;
            parse_ip6(arg_str)?
        }
        "exists" => {
            let domain = arg.ok_or("exists requires a domain argument")?;
            if domain.is_empty() {
                return Err("exists requires a non-empty domain".into());
            }
            Mechanism::Exists { domain: domain.to_string() }
        }
        _ => {
            return Err(format!("unknown mechanism: {}", mech_name));
        }
    };

    Ok(Directive { qualifier, mechanism })
}

/// Extract qualifier prefix if present, default to Pass.
fn extract_qualifier(term: &str) -> (Qualifier, &str) {
    if let Some(first) = term.chars().next() {
        if let Some(q) = Qualifier::from_char(first) {
            return (q, &term[1..]);
        }
    }
    (Qualifier::Pass, term)
}

/// Split "mechanism:argument" or "mechanism/cidr" — the arg includes everything after ':'
/// For mechanisms without ':', the whole string is the name.
fn split_mechanism_arg(s: &str) -> (&str, Option<&str>) {
    if let Some(colon_pos) = s.find(':') {
        (&s[..colon_pos], Some(&s[colon_pos + 1..]))
    } else if let Some(slash_pos) = s.find('/') {
        // a/24 or mx//64 — mechanism name is before the slash, arg is from the slash
        (&s[..slash_pos], Some(&s[slash_pos..]))
    } else {
        (s, None)
    }
}

/// Parse A or MX mechanism with optional domain and dual CIDR.
/// Forms: a, a:domain, a/cidr4, a:domain/cidr4, a//cidr6, a:domain//cidr6,
///        a/cidr4//cidr6, a:domain/cidr4//cidr6
fn parse_a_mx_mechanism(arg: Option<&str>, is_a: bool) -> Result<Mechanism, String> {
    let (domain, cidr4, cidr6) = match arg {
        None => (None, None, None),
        Some(s) if s.is_empty() => (None, None, None),
        Some(s) => parse_domain_cidr(s)?,
    };

    if is_a {
        Ok(Mechanism::A { domain, cidr4, cidr6 })
    } else {
        Ok(Mechanism::Mx { domain, cidr4, cidr6 })
    }
}

/// Parse "domain/cidr4//cidr6" or "/cidr4//cidr6" or "//cidr6" etc.
fn parse_domain_cidr(s: &str) -> Result<(Option<String>, Option<u8>, Option<u8>), String> {
    // Check for double-slash (cidr6 marker)
    let (before_dslash, cidr6_str) = if let Some(pos) = s.find("//") {
        (&s[..pos], Some(&s[pos + 2..]))
    } else {
        (s, None)
    };

    // Parse cidr6 if present
    let cidr6 = match cidr6_str {
        Some(c) => {
            let v: u8 = c.parse().map_err(|_| format!("invalid IPv6 prefix: {}", c))?;
            if v > 128 {
                return Err(format!("IPv6 prefix {} out of range (0-128)", v));
            }
            Some(v)
        }
        None => None,
    };

    // Now parse domain and cidr4 from before_dslash
    let (domain, cidr4) = if let Some(slash_pos) = before_dslash.rfind('/') {
        let domain_part = &before_dslash[..slash_pos];
        let cidr4_str = &before_dslash[slash_pos + 1..];
        let v: u8 = cidr4_str.parse().map_err(|_| format!("invalid IPv4 prefix: {}", cidr4_str))?;
        if v > 32 {
            return Err(format!("IPv4 prefix {} out of range (0-32)", v));
        }
        let domain = if domain_part.is_empty() { None } else { Some(domain_part.to_string()) };
        (domain, Some(v))
    } else {
        let domain = if before_dslash.is_empty() { None } else { Some(before_dslash.to_string()) };
        (domain, None)
    };

    Ok((domain, cidr4, cidr6))
}

/// Parse ip4:addr or ip4:addr/prefix
fn parse_ip4(arg: &str) -> Result<Mechanism, String> {
    if let Some(slash_pos) = arg.find('/') {
        let addr_str = &arg[..slash_pos];
        let prefix_str = &arg[slash_pos + 1..];
        let addr: Ipv4Addr = addr_str.parse().map_err(|e| format!("invalid IPv4 address: {}", e))?;
        let prefix: u8 = prefix_str.parse().map_err(|_| format!("invalid prefix: {}", prefix_str))?;
        if prefix > 32 {
            return Err(format!("IPv4 prefix {} out of range (0-32)", prefix));
        }
        Ok(Mechanism::Ip4 { addr, prefix: Some(prefix) })
    } else {
        let addr: Ipv4Addr = arg.parse().map_err(|e| format!("invalid IPv4 address: {}", e))?;
        Ok(Mechanism::Ip4 { addr, prefix: None })
    }
}

/// Parse ip6:addr or ip6:addr/prefix
fn parse_ip6(arg: &str) -> Result<Mechanism, String> {
    // IPv6 addresses contain colons, so we need to find the /prefix carefully.
    // The prefix is after the LAST '/' character.
    if let Some(slash_pos) = arg.rfind('/') {
        let addr_str = &arg[..slash_pos];
        let prefix_str = &arg[slash_pos + 1..];
        // Only treat as prefix if the part after / is numeric
        if prefix_str.chars().all(|c| c.is_ascii_digit()) && !prefix_str.is_empty() {
            let addr: Ipv6Addr = addr_str.parse().map_err(|e| format!("invalid IPv6 address: {}", e))?;
            let prefix: u8 = prefix_str.parse().map_err(|_| format!("invalid prefix: {}", prefix_str))?;
            if prefix > 128 {
                return Err(format!("IPv6 prefix {} out of range (0-128)", prefix));
            }
            return Ok(Mechanism::Ip6 { addr, prefix: Some(prefix) });
        }
    }
    let addr: Ipv6Addr = arg.parse().map_err(|e| format!("invalid IPv6 address: {}", e))?;
    Ok(Mechanism::Ip6 { addr, prefix: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    // CHK-181: Minimal v=spf1 -all
    #[test]
    fn parse_minimal_record() {
        let rec = SpfRecord::parse("v=spf1 -all").unwrap();
        assert_eq!(rec.directives.len(), 1);
        assert_eq!(rec.directives[0].qualifier, Qualifier::Fail);
        assert_eq!(rec.directives[0].mechanism, Mechanism::All);
        assert!(rec.redirect.is_none());
        assert!(rec.explanation.is_none());
    }

    // CHK-182: Multiple mechanisms
    #[test]
    fn parse_multiple_mechanisms() {
        let rec = SpfRecord::parse("v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all").unwrap();
        assert_eq!(rec.directives.len(), 3);
        assert_eq!(rec.directives[0].qualifier, Qualifier::Pass);
        match &rec.directives[0].mechanism {
            Mechanism::Ip4 { addr, prefix } => {
                assert_eq!(*addr, "192.0.2.0".parse::<Ipv4Addr>().unwrap());
                assert_eq!(*prefix, Some(24));
            }
            _ => panic!("expected Ip4"),
        }
        assert_eq!(rec.directives[2].qualifier, Qualifier::Fail);
        assert_eq!(rec.directives[2].mechanism, Mechanism::All);
    }

    // CHK-183: Include
    #[test]
    fn parse_include() {
        let rec = SpfRecord::parse("v=spf1 include:_spf.google.com -all").unwrap();
        assert_eq!(rec.directives.len(), 2);
        match &rec.directives[0].mechanism {
            Mechanism::Include { domain } => assert_eq!(domain, "_spf.google.com"),
            _ => panic!("expected Include"),
        }
    }

    // CHK-184: All mechanism types with argument forms
    #[test]
    fn parse_all_mechanism_types() {
        let rec = SpfRecord::parse(
            "v=spf1 +all ~include:ex.com a a:d.com mx:d.com/24 ptr ptr:d.com ip4:1.2.3.4 ip6:::1 exists:d.com -all"
        ).unwrap();
        // +all, ~include, a, a:d.com, mx:d.com/24, ptr, ptr:d.com, ip4, ip6, exists, -all = 11
        assert_eq!(rec.directives.len(), 11);
        assert_eq!(rec.directives[0].mechanism, Mechanism::All);
        assert_eq!(rec.directives[0].qualifier, Qualifier::Pass);
        match &rec.directives[1].mechanism {
            Mechanism::Include { domain } => assert_eq!(domain, "ex.com"),
            _ => panic!("expected Include"),
        }
        assert_eq!(rec.directives[1].qualifier, Qualifier::SoftFail);
        assert_eq!(rec.directives[2].mechanism, Mechanism::A { domain: None, cidr4: None, cidr6: None });
        match &rec.directives[3].mechanism {
            Mechanism::A { domain, cidr4, cidr6 } => {
                assert_eq!(domain.as_deref(), Some("d.com"));
                assert_eq!(*cidr4, None);
                assert_eq!(*cidr6, None);
            }
            _ => panic!("expected A"),
        }
        match &rec.directives[4].mechanism {
            Mechanism::Mx { domain, cidr4, cidr6 } => {
                assert_eq!(domain.as_deref(), Some("d.com"));
                assert_eq!(*cidr4, Some(24));
                assert_eq!(*cidr6, None);
            }
            _ => panic!("expected Mx"),
        }
        assert_eq!(rec.directives[5].mechanism, Mechanism::Ptr { domain: None });
        assert_eq!(rec.directives[6].mechanism, Mechanism::Ptr { domain: Some("d.com".into()) });
        match &rec.directives[7].mechanism {
            Mechanism::Ip4 { addr, prefix } => {
                assert_eq!(*addr, "1.2.3.4".parse::<Ipv4Addr>().unwrap());
                assert_eq!(*prefix, None);
            }
            _ => panic!("expected Ip4"),
        }
        match &rec.directives[8].mechanism {
            Mechanism::Ip6 { addr, prefix } => {
                assert_eq!(*addr, "::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(*prefix, None);
            }
            _ => panic!("expected Ip6"),
        }
        match &rec.directives[9].mechanism {
            Mechanism::Exists { domain } => assert_eq!(domain, "d.com"),
            _ => panic!("expected Exists"),
        }
        assert_eq!(rec.directives[10].qualifier, Qualifier::Fail);
        assert_eq!(rec.directives[10].mechanism, Mechanism::All);
    }

    // CHK-185: Macros in domain specs (parser passes through raw macro strings)
    #[test]
    fn parse_macros_in_domain() {
        let rec = SpfRecord::parse("v=spf1 exists:%{ir}.sbl.example.com -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::Exists { domain } => assert_eq!(domain, "%{ir}.sbl.example.com"),
            _ => panic!("expected Exists"),
        }
    }

    // CHK-186: Case insensitivity
    #[test]
    fn parse_case_insensitive() {
        let rec = SpfRecord::parse("V=SPF1 IP4:192.0.2.1 -ALL").unwrap();
        assert_eq!(rec.directives.len(), 2);
        match &rec.directives[0].mechanism {
            Mechanism::Ip4 { addr, .. } => assert_eq!(*addr, "192.0.2.1".parse::<Ipv4Addr>().unwrap()),
            _ => panic!("expected Ip4"),
        }
        assert_eq!(rec.directives[1].mechanism, Mechanism::All);
    }

    // CHK-187: Invalid version
    #[test]
    fn parse_invalid_version() {
        assert!(SpfRecord::parse("v=spf2 -all").is_err());
    }

    // CHK-188: Duplicate modifiers
    #[test]
    fn parse_duplicate_redirect() {
        let err = SpfRecord::parse("v=spf1 redirect=a.com redirect=b.com").unwrap_err();
        assert!(err.contains("duplicate redirect"), "error: {}", err);
    }

    #[test]
    fn parse_duplicate_exp() {
        let err = SpfRecord::parse("v=spf1 exp=a.com exp=b.com -all").unwrap_err();
        assert!(err.contains("duplicate exp"), "error: {}", err);
    }

    // CHK-189: Unknown modifier ignored
    #[test]
    fn parse_unknown_modifier_ignored() {
        let rec = SpfRecord::parse("v=spf1 foo=bar -all").unwrap();
        assert_eq!(rec.directives.len(), 1);
        assert_eq!(rec.directives[0].mechanism, Mechanism::All);
    }

    // CHK-190: Unknown mechanism → PermError
    #[test]
    fn parse_unknown_mechanism() {
        let err = SpfRecord::parse("v=spf1 custom:example.com -all").unwrap_err();
        assert!(err.contains("unknown mechanism"), "error: {}", err);
    }

    // CHK-191: Multiple whitespace between terms
    #[test]
    fn parse_multiple_whitespace() {
        let rec = SpfRecord::parse("v=spf1   ip4:1.2.3.4   -all").unwrap();
        assert_eq!(rec.directives.len(), 2);
    }

    // CHK-192: Trailing whitespace
    #[test]
    fn parse_trailing_whitespace() {
        let rec = SpfRecord::parse("v=spf1 -all  ").unwrap();
        assert_eq!(rec.directives.len(), 1);
    }

    // CHK-193: Dual CIDR
    #[test]
    fn parse_dual_cidr() {
        let rec = SpfRecord::parse("v=spf1 a:example.com/24//64 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::A { domain, cidr4, cidr6 } => {
                assert_eq!(domain.as_deref(), Some("example.com"));
                assert_eq!(*cidr4, Some(24));
                assert_eq!(*cidr6, Some(64));
            }
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn parse_dual_cidr_cidr6_only() {
        let rec = SpfRecord::parse("v=spf1 a://64 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::A { domain, cidr4, cidr6 } => {
                assert!(domain.is_none());
                assert_eq!(*cidr4, None);
                assert_eq!(*cidr6, Some(64));
            }
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn parse_mx_dual_cidr() {
        let rec = SpfRecord::parse("v=spf1 mx/24//64 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::Mx { domain, cidr4, cidr6 } => {
                assert!(domain.is_none());
                assert_eq!(*cidr4, Some(24));
                assert_eq!(*cidr6, Some(64));
            }
            _ => panic!("expected Mx"),
        }
    }

    // CHK-194: Prefix edge cases
    #[test]
    fn parse_prefix_zero_cidr4() {
        let rec = SpfRecord::parse("v=spf1 a/0 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::A { cidr4, cidr6, .. } => {
                assert_eq!(*cidr4, Some(0));
                assert_eq!(*cidr6, None);
            }
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn parse_prefix_zero_cidr6() {
        let rec = SpfRecord::parse("v=spf1 a//0 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::A { cidr4, cidr6, .. } => {
                assert_eq!(*cidr4, None);
                assert_eq!(*cidr6, Some(0));
            }
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn parse_prefix_max_values() {
        let rec = SpfRecord::parse("v=spf1 a/32//128 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::A { cidr4, cidr6, .. } => {
                assert_eq!(*cidr4, Some(32));
                assert_eq!(*cidr6, Some(128));
            }
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn parse_prefix_out_of_range_v4() {
        assert!(SpfRecord::parse("v=spf1 a/33 -all").is_err());
    }

    #[test]
    fn parse_prefix_out_of_range_v6() {
        assert!(SpfRecord::parse("v=spf1 a//129 -all").is_err());
    }

    // Additional: ip4 prefix validation
    #[test]
    fn parse_ip4_prefix_out_of_range() {
        assert!(SpfRecord::parse("v=spf1 ip4:1.2.3.4/33").is_err());
    }

    // Additional: ip6 prefix validation
    #[test]
    fn parse_ip6_prefix_out_of_range() {
        assert!(SpfRecord::parse("v=spf1 ip6:::1/129").is_err());
    }

    // Additional: redirect modifier parsed
    #[test]
    fn parse_redirect_modifier() {
        let rec = SpfRecord::parse("v=spf1 redirect=_spf.example.com").unwrap();
        assert_eq!(rec.redirect.as_deref(), Some("_spf.example.com"));
        assert!(rec.directives.is_empty());
    }

    // Additional: exp modifier parsed
    #[test]
    fn parse_exp_modifier() {
        let rec = SpfRecord::parse("v=spf1 -all exp=explain.example.com").unwrap();
        assert_eq!(rec.explanation.as_deref(), Some("explain.example.com"));
    }

    // Version only record
    #[test]
    fn parse_version_only() {
        let rec = SpfRecord::parse("v=spf1").unwrap();
        assert!(rec.directives.is_empty());
        assert!(rec.redirect.is_none());
    }

    // ip6 with full address
    #[test]
    fn parse_ip6_full() {
        let rec = SpfRecord::parse("v=spf1 ip6:2001:db8::1/32 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::Ip6 { addr, prefix } => {
                assert_eq!(*addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(*prefix, Some(32));
            }
            _ => panic!("expected Ip6"),
        }
    }

    // ip6 without prefix
    #[test]
    fn parse_ip6_no_prefix() {
        let rec = SpfRecord::parse("v=spf1 ip6:2001:db8::1 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::Ip6 { addr, prefix } => {
                assert_eq!(*addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(*prefix, None);
            }
            _ => panic!("expected Ip6"),
        }
    }

    // All qualifier types
    #[test]
    fn parse_all_qualifiers() {
        let rec = SpfRecord::parse("v=spf1 +a -a ~a ?a").unwrap();
        assert_eq!(rec.directives[0].qualifier, Qualifier::Pass);
        assert_eq!(rec.directives[1].qualifier, Qualifier::Fail);
        assert_eq!(rec.directives[2].qualifier, Qualifier::SoftFail);
        assert_eq!(rec.directives[3].qualifier, Qualifier::Neutral);
    }

    // Default qualifier is Pass
    #[test]
    fn parse_default_qualifier() {
        let rec = SpfRecord::parse("v=spf1 a -all").unwrap();
        assert_eq!(rec.directives[0].qualifier, Qualifier::Pass);
    }

    // Include requires domain
    #[test]
    fn parse_include_missing_domain() {
        assert!(SpfRecord::parse("v=spf1 include: -all").is_err());
    }

    // ip4 without prefix defaults to None (evaluator will use /32)
    #[test]
    fn parse_ip4_no_prefix() {
        let rec = SpfRecord::parse("v=spf1 ip4:10.0.0.1 -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::Ip4 { addr, prefix } => {
                assert_eq!(*addr, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
                assert_eq!(*prefix, None);
            }
            _ => panic!("expected Ip4"),
        }
    }

    // Exists with macro
    #[test]
    fn parse_exists_macro() {
        let rec = SpfRecord::parse("v=spf1 exists:%{l}.%{d} -all").unwrap();
        match &rec.directives[0].mechanism {
            Mechanism::Exists { domain } => assert_eq!(domain, "%{l}.%{d}"),
            _ => panic!("expected Exists"),
        }
    }
}
