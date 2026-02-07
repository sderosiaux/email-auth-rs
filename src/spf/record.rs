use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    All,
    Include { domain: String },
    A { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> },
    Mx { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> },
    Ptr { domain: Option<String> },
    Ip4 { addr: Ipv4Addr, prefix: Option<u8> },
    Ip6 { addr: Ipv6Addr, prefix: Option<u8> },
    Exists { domain: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfResult {
    Pass,
    Fail { explanation: Option<String> },
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

// ---------------------------------------------------------------------------
// Known mechanism names (lowercase) — used to distinguish unknown modifiers
// from unknown mechanisms.
// ---------------------------------------------------------------------------

const KNOWN_MECHANISMS: &[&str] = &[
    "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists",
];

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

impl SpfRecord {
    /// Parse an SPF TXT record string into a structured `SpfRecord`.
    ///
    /// Returns `Err(SpfResult::PermError)` on any syntax error.
    pub fn parse(record: &str) -> Result<SpfRecord, SpfResult> {
        let record = record.trim();

        // --- version tag -----------------------------------------------------
        let rest = match record.get(..6) {
            Some(v) if v.eq_ignore_ascii_case("v=spf1") => &record[6..],
            _ => return Err(SpfResult::PermError),
        };

        // After "v=spf1" we require either end-of-string or whitespace.
        if !rest.is_empty() && !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
            return Err(SpfResult::PermError);
        }

        let mut directives = Vec::new();
        let mut redirect: Option<String> = None;
        let mut explanation: Option<String> = None;

        for token in rest.split_ascii_whitespace() {
            if token.is_empty() {
                continue;
            }

            // Try modifier first: contains '=' where the name portion is valid.
            if let Some(eq_pos) = token.find('=') {
                let name = &token[..eq_pos];
                let value = &token[eq_pos + 1..];

                // A modifier name must not contain ':' or '=' (besides the
                // splitting one) and must not be a known mechanism name.
                if !name.is_empty()
                    && !name.contains(':')
                    && !KNOWN_MECHANISMS.contains(&name.to_ascii_lowercase().as_str())
                {
                    match name.to_ascii_lowercase().as_str() {
                        "redirect" => {
                            if redirect.is_some() {
                                return Err(SpfResult::PermError);
                            }
                            redirect = Some(value.to_string());
                        }
                        "exp" => {
                            if explanation.is_some() {
                                return Err(SpfResult::PermError);
                            }
                            explanation = Some(value.to_string());
                        }
                        _ => {
                            // Unknown modifier — silently ignore per RFC 7208 s6.
                        }
                    }
                    continue;
                }
            }

            // Otherwise it is a directive (qualifier + mechanism).
            let (qualifier, mech_str) = parse_qualifier(token);
            let mechanism = parse_mechanism(mech_str)?;
            directives.push(Directive { qualifier, mechanism });
        }

        Ok(SpfRecord { directives, redirect, explanation })
    }
}

// ---------------------------------------------------------------------------
// Qualifier
// ---------------------------------------------------------------------------

fn parse_qualifier(token: &str) -> (Qualifier, &str) {
    match token.as_bytes().first() {
        Some(b'+') => (Qualifier::Pass, &token[1..]),
        Some(b'-') => (Qualifier::Fail, &token[1..]),
        Some(b'~') => (Qualifier::SoftFail, &token[1..]),
        Some(b'?') => (Qualifier::Neutral, &token[1..]),
        _ => (Qualifier::Pass, token),
    }
}

// ---------------------------------------------------------------------------
// Mechanism
// ---------------------------------------------------------------------------

fn parse_mechanism(s: &str) -> Result<Mechanism, SpfResult> {
    // Split on ':' to get the mechanism name and optional argument.
    // For ip4/ip6 the colon separates name from address; for others it
    // separates name from domain-spec.  Mechanisms without ':' may still
    // have a '/' for CIDR (a, mx).
    let (name, arg) = if let Some(colon) = s.find(':') {
        (&s[..colon], Some(&s[colon + 1..]))
    } else if let Some(slash) = s.find('/') {
        // a/24 or mx//128 — no domain, just CIDR
        (&s[..slash], Some(&s[slash..]))
    } else {
        (s, None)
    };

    match name.to_ascii_lowercase().as_str() {
        "all" => {
            if arg.is_some() {
                return Err(SpfResult::PermError);
            }
            Ok(Mechanism::All)
        }
        "include" => {
            let domain = arg.ok_or(SpfResult::PermError)?;
            if domain.is_empty() {
                return Err(SpfResult::PermError);
            }
            Ok(Mechanism::Include { domain: domain.to_string() })
        }
        "a" => {
            let (domain, cidr4, cidr6) = parse_domain_cidr(arg)?;
            Ok(Mechanism::A { domain, cidr4, cidr6 })
        }
        "mx" => {
            let (domain, cidr4, cidr6) = parse_domain_cidr(arg)?;
            Ok(Mechanism::Mx { domain, cidr4, cidr6 })
        }
        "ptr" => {
            let domain = arg.map(|a| a.to_string()).filter(|a| !a.is_empty());
            Ok(Mechanism::Ptr { domain })
        }
        "ip4" => {
            let raw = arg.ok_or(SpfResult::PermError)?;
            parse_ip4(raw)
        }
        "ip6" => {
            let raw = arg.ok_or(SpfResult::PermError)?;
            parse_ip6(raw)
        }
        "exists" => {
            let domain = arg.ok_or(SpfResult::PermError)?;
            if domain.is_empty() {
                return Err(SpfResult::PermError);
            }
            Ok(Mechanism::Exists { domain: domain.to_string() })
        }
        _ => Err(SpfResult::PermError),
    }
}

// ---------------------------------------------------------------------------
// Domain + dual-CIDR helper  (used by A and MX)
//
// Accepted forms:
//   None                 -> (None, None, None)
//   domain               -> (Some(domain), None, None)
//   domain/cidr4         -> (Some(domain), Some(cidr4), None)
//   domain//cidr6        -> (Some(domain), None, Some(cidr6))
//   domain/cidr4//cidr6  -> (Some(domain), Some(cidr4), Some(cidr6))
//   /cidr4               -> (None, Some(cidr4), None)
//   //cidr6              -> (None, None, Some(cidr6))
//   /cidr4//cidr6        -> (None, Some(cidr4), Some(cidr6))
// ---------------------------------------------------------------------------

fn parse_domain_cidr(
    arg: Option<&str>,
) -> Result<(Option<String>, Option<u8>, Option<u8>), SpfResult> {
    let arg = match arg {
        None => return Ok((None, None, None)),
        Some(a) if a.is_empty() => return Ok((None, None, None)),
        Some(a) => a,
    };

    // The argument starts with '/' when the caller already split on '/'
    // (mechanism without ':' like "a/24").  In that case the full arg is
    // "/<rest>" and we have no domain component.
    let (domain_part, cidr_part) = if arg.starts_with('/') {
        ("", arg)
    } else if let Some(slash) = arg.find('/') {
        (&arg[..slash], &arg[slash..])
    } else {
        // No CIDR at all — the whole thing is a domain.
        return Ok((Some(arg.to_string()), None, None));
    };

    let domain = if domain_part.is_empty() { None } else { Some(domain_part.to_string()) };

    // cidr_part now starts with '/'.  Parse dual-CIDR.
    let (cidr4, cidr6) = parse_dual_cidr(cidr_part)?;

    Ok((domain, cidr4, cidr6))
}

/// Parse a dual-CIDR suffix that starts with '/'.
///
/// Formats: `/cidr4`, `//cidr6`, `/cidr4//cidr6`
fn parse_dual_cidr(s: &str) -> Result<(Option<u8>, Option<u8>), SpfResult> {
    debug_assert!(s.starts_with('/'));

    // Strip the leading '/'.
    // After stripping, possible forms:
    //   "cidr4"          -> cidr4 only         (input was "/cidr4")
    //   "/cidr6"         -> cidr6 only         (input was "//cidr6")
    //   "cidr4//cidr6"   -> both               (input was "/cidr4//cidr6")
    let inner = &s[1..];

    if inner.starts_with('/') {
        // cidr6-only: original was "//cidr6"
        let cidr6_str = &inner[1..];
        if cidr6_str.is_empty() {
            return Err(SpfResult::PermError);
        }
        let cidr6 = parse_cidr_value(cidr6_str, 128)?;
        Ok((None, Some(cidr6)))
    } else if let Some(sep) = inner.find("//") {
        // Both: "cidr4//cidr6"
        let cidr4_str = &inner[..sep];
        let cidr6_str = &inner[sep + 2..];

        let cidr4 = if cidr4_str.is_empty() {
            None
        } else {
            Some(parse_cidr_value(cidr4_str, 32)?)
        };
        let cidr6 = if cidr6_str.is_empty() {
            None
        } else {
            Some(parse_cidr_value(cidr6_str, 128)?)
        };
        Ok((cidr4, cidr6))
    } else {
        // cidr4 only
        if inner.is_empty() {
            return Err(SpfResult::PermError);
        }
        let cidr4 = parse_cidr_value(inner, 32)?;
        Ok((Some(cidr4), None))
    }
}

fn parse_cidr_value(s: &str, max: u8) -> Result<u8, SpfResult> {
    let val: u8 = s.parse().map_err(|_| SpfResult::PermError)?;
    if val > max {
        return Err(SpfResult::PermError);
    }
    Ok(val)
}

// ---------------------------------------------------------------------------
// IP address helpers
// ---------------------------------------------------------------------------

fn parse_ip4(raw: &str) -> Result<Mechanism, SpfResult> {
    let (addr_str, prefix) = split_prefix(raw);
    let addr: Ipv4Addr = addr_str.parse().map_err(|_| SpfResult::PermError)?;
    let prefix = match prefix {
        Some(p) => Some(parse_cidr_value(p, 32)?),
        None => None,
    };
    Ok(Mechanism::Ip4 { addr, prefix })
}

fn parse_ip6(raw: &str) -> Result<Mechanism, SpfResult> {
    // IPv6 addresses contain ':', so we need to find the *last* '/' that
    // separates the address from the prefix length.
    let (addr_str, prefix) = split_prefix_ip6(raw);
    let addr: Ipv6Addr = addr_str.parse().map_err(|_| SpfResult::PermError)?;
    let prefix = match prefix {
        Some(p) => Some(parse_cidr_value(p, 128)?),
        None => None,
    };
    Ok(Mechanism::Ip6 { addr, prefix })
}

/// Split "1.2.3.4/24" into ("1.2.3.4", Some("24")).
fn split_prefix(s: &str) -> (&str, Option<&str>) {
    match s.rfind('/') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

/// Split an IPv6-with-prefix. Since IPv6 addresses don't contain '/', a
/// simple rfind('/') works.
fn split_prefix_ip6(s: &str) -> (&str, Option<&str>) {
    match s.rfind('/') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> SpfRecord {
        SpfRecord::parse(input).expect("expected successful parse")
    }

    fn err(input: &str) -> SpfResult {
        SpfRecord::parse(input).expect_err("expected parse error")
    }

    // -- basic valid records ------------------------------------------------

    #[test]
    fn minimal_record() {
        let rec = ok("v=spf1 -all");
        assert_eq!(rec.directives.len(), 1);
        assert_eq!(rec.directives[0].qualifier, Qualifier::Fail);
        assert_eq!(rec.directives[0].mechanism, Mechanism::All);
        assert!(rec.redirect.is_none());
        assert!(rec.explanation.is_none());
    }

    #[test]
    fn multiple_mechanisms() {
        let rec = ok("v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all");
        assert_eq!(rec.directives.len(), 3);
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ip4 {
                addr: "192.0.2.0".parse().unwrap(),
                prefix: Some(24),
            }
        );
        assert_eq!(
            rec.directives[1].mechanism,
            Mechanism::Ip4 {
                addr: "198.51.100.0".parse().unwrap(),
                prefix: Some(24),
            }
        );
        assert_eq!(rec.directives[2].mechanism, Mechanism::All);
    }

    #[test]
    fn include_mechanism() {
        let rec = ok("v=spf1 include:_spf.google.com -all");
        assert_eq!(rec.directives.len(), 2);
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Include { domain: "_spf.google.com".into() }
        );
    }

    #[test]
    fn case_insensitivity() {
        let rec = ok("V=SPF1 IP4:1.2.3.4 -ALL");
        assert_eq!(rec.directives.len(), 2);
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ip4 {
                addr: "1.2.3.4".parse().unwrap(),
                prefix: None,
            }
        );
        assert_eq!(rec.directives[1].qualifier, Qualifier::Fail);
        assert_eq!(rec.directives[1].mechanism, Mechanism::All);
    }

    // -- version errors -----------------------------------------------------

    #[test]
    fn invalid_version() {
        assert_eq!(err("v=spf2"), SpfResult::PermError);
    }

    #[test]
    fn missing_version() {
        assert_eq!(err("include:_spf.google.com -all"), SpfResult::PermError);
    }

    #[test]
    fn version_no_space() {
        // "v=spf1-all" — no space after version tag
        assert_eq!(err("v=spf1-all"), SpfResult::PermError);
    }

    // -- modifiers ----------------------------------------------------------

    #[test]
    fn redirect_modifier() {
        let rec = ok("v=spf1 redirect=_spf.example.com");
        assert_eq!(rec.redirect.as_deref(), Some("_spf.example.com"));
        assert!(rec.directives.is_empty());
    }

    #[test]
    fn exp_modifier() {
        let rec = ok("v=spf1 -all exp=explain._example.com");
        assert_eq!(rec.explanation.as_deref(), Some("explain._example.com"));
    }

    #[test]
    fn duplicate_redirect() {
        assert_eq!(err("v=spf1 redirect=a redirect=b"), SpfResult::PermError);
    }

    #[test]
    fn duplicate_exp() {
        assert_eq!(err("v=spf1 exp=a exp=b -all"), SpfResult::PermError);
    }

    #[test]
    fn unknown_modifier_ignored() {
        let rec = ok("v=spf1 foo=bar -all");
        assert_eq!(rec.directives.len(), 1);
        assert_eq!(rec.directives[0].mechanism, Mechanism::All);
    }

    // -- unknown mechanism --------------------------------------------------

    #[test]
    fn unknown_mechanism_permerror() {
        assert_eq!(err("v=spf1 custom:example.com"), SpfResult::PermError);
    }

    // -- A/MX dual CIDR -----------------------------------------------------

    #[test]
    fn a_dual_cidr() {
        let rec = ok("v=spf1 a:example.com/24//64");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::A {
                domain: Some("example.com".into()),
                cidr4: Some(24),
                cidr6: Some(64),
            }
        );
    }

    #[test]
    fn a_cidr4_only() {
        let rec = ok("v=spf1 a/0");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::A {
                domain: None,
                cidr4: Some(0),
                cidr6: None,
            }
        );
    }

    #[test]
    fn a_cidr6_only() {
        let rec = ok("v=spf1 a//0");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::A {
                domain: None,
                cidr4: None,
                cidr6: Some(0),
            }
        );
    }

    #[test]
    fn mx_dual_cidr_no_domain() {
        let rec = ok("v=spf1 mx/16//64");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Mx {
                domain: None,
                cidr4: Some(16),
                cidr6: Some(64),
            }
        );
    }

    #[test]
    fn a_with_domain_no_cidr() {
        let rec = ok("v=spf1 a:example.com");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::A {
                domain: Some("example.com".into()),
                cidr4: None,
                cidr6: None,
            }
        );
    }

    #[test]
    fn cidr4_out_of_range() {
        assert_eq!(err("v=spf1 a/33"), SpfResult::PermError);
    }

    #[test]
    fn cidr6_out_of_range() {
        assert_eq!(err("v=spf1 a//129"), SpfResult::PermError);
    }

    // -- ip4/ip6 ------------------------------------------------------------

    #[test]
    fn ip4_no_prefix() {
        let rec = ok("v=spf1 ip4:10.0.0.1");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ip4 {
                addr: "10.0.0.1".parse().unwrap(),
                prefix: None,
            }
        );
    }

    #[test]
    fn ip6_with_prefix() {
        let rec = ok("v=spf1 ip6:2001:db8::/32");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ip6 {
                addr: "2001:db8::".parse().unwrap(),
                prefix: Some(32),
            }
        );
    }

    #[test]
    fn ip6_no_prefix() {
        let rec = ok("v=spf1 ip6:::1");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ip6 {
                addr: "::1".parse().unwrap(),
                prefix: None,
            }
        );
    }

    // -- ptr / exists -------------------------------------------------------

    #[test]
    fn ptr_with_domain() {
        let rec = ok("v=spf1 ptr:example.com");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ptr { domain: Some("example.com".into()) }
        );
    }

    #[test]
    fn ptr_no_domain() {
        let rec = ok("v=spf1 ptr");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ptr { domain: None }
        );
    }

    #[test]
    fn exists_mechanism() {
        let rec = ok("v=spf1 exists:%{ir}.sbl.example.com");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Exists { domain: "%{ir}.sbl.example.com".into() }
        );
    }

    // -- whitespace ---------------------------------------------------------

    #[test]
    fn multiple_whitespace() {
        let rec = ok("v=spf1   ip4:1.2.3.4   -all");
        assert_eq!(rec.directives.len(), 2);
    }

    #[test]
    fn trailing_whitespace() {
        let rec = ok("v=spf1 -all   ");
        assert_eq!(rec.directives.len(), 1);
    }

    #[test]
    fn leading_whitespace() {
        let rec = ok("  v=spf1 -all");
        assert_eq!(rec.directives.len(), 1);
    }

    // -- qualifiers ---------------------------------------------------------

    #[test]
    fn all_qualifiers() {
        let rec = ok("v=spf1 +all");
        assert_eq!(rec.directives[0].qualifier, Qualifier::Pass);

        let rec = ok("v=spf1 -all");
        assert_eq!(rec.directives[0].qualifier, Qualifier::Fail);

        let rec = ok("v=spf1 ~all");
        assert_eq!(rec.directives[0].qualifier, Qualifier::SoftFail);

        let rec = ok("v=spf1 ?all");
        assert_eq!(rec.directives[0].qualifier, Qualifier::Neutral);
    }

    #[test]
    fn default_qualifier_is_pass() {
        let rec = ok("v=spf1 all");
        assert_eq!(rec.directives[0].qualifier, Qualifier::Pass);
    }

    // -- version only -------------------------------------------------------

    #[test]
    fn version_only() {
        let rec = ok("v=spf1");
        assert!(rec.directives.is_empty());
        assert!(rec.redirect.is_none());
        assert!(rec.explanation.is_none());
    }

    // -- all mechanism types with arguments ---------------------------------

    #[test]
    fn all_mechanism_types() {
        let input = "v=spf1 \
            ip4:10.0.0.0/8 \
            ip6:fe80::/10 \
            a:example.com/24//48 \
            mx:mail.example.com/16 \
            ptr:example.com \
            include:_spf.example.com \
            exists:%{d}.example.com \
            redirect=other.example.com \
            exp=msg.example.com \
            -all";
        let rec = ok(input);
        assert_eq!(rec.directives.len(), 8);
        assert_eq!(rec.redirect.as_deref(), Some("other.example.com"));
        assert_eq!(rec.explanation.as_deref(), Some("msg.example.com"));
    }

    // -- redirect and exp together ------------------------------------------

    #[test]
    fn redirect_and_exp() {
        let rec = ok("v=spf1 redirect=_spf.example.com exp=msg.example.com");
        assert_eq!(rec.redirect.as_deref(), Some("_spf.example.com"));
        assert_eq!(rec.explanation.as_deref(), Some("msg.example.com"));
    }

    // -- macros in domain spec (just parsing, not expanding) ----------------

    #[test]
    fn macros_in_domain() {
        let rec = ok("v=spf1 exists:%{ir}.sbl.example.com -all");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Exists { domain: "%{ir}.sbl.example.com".into() }
        );
    }

    // -- mx variants --------------------------------------------------------

    #[test]
    fn mx_bare() {
        let rec = ok("v=spf1 mx -all");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Mx { domain: None, cidr4: None, cidr6: None }
        );
    }

    #[test]
    fn mx_with_domain() {
        let rec = ok("v=spf1 mx:example.com -all");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Mx {
                domain: Some("example.com".into()),
                cidr4: None,
                cidr6: None,
            }
        );
    }

    // -- a bare -------------------------------------------------------------

    #[test]
    fn a_bare() {
        let rec = ok("v=spf1 a -all");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::A { domain: None, cidr4: None, cidr6: None }
        );
    }

    // -- edge: include without domain is PermError --------------------------

    #[test]
    fn include_missing_domain() {
        assert_eq!(err("v=spf1 include:"), SpfResult::PermError);
    }

    #[test]
    fn include_no_colon() {
        // "include" by itself, no colon — this is an unknown mechanism with
        // name "include" and no argument. The mechanism parser requires the
        // ':' for include, so this should PermError.
        assert_eq!(err("v=spf1 include"), SpfResult::PermError);
    }

    // -- ip4 prefix boundary ------------------------------------------------

    #[test]
    fn ip4_prefix_0() {
        let rec = ok("v=spf1 ip4:0.0.0.0/0");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ip4 {
                addr: "0.0.0.0".parse().unwrap(),
                prefix: Some(0),
            }
        );
    }

    #[test]
    fn ip4_prefix_32() {
        let rec = ok("v=spf1 ip4:1.2.3.4/32");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ip4 {
                addr: "1.2.3.4".parse().unwrap(),
                prefix: Some(32),
            }
        );
    }

    #[test]
    fn ip4_prefix_33() {
        assert_eq!(err("v=spf1 ip4:1.2.3.4/33"), SpfResult::PermError);
    }

    #[test]
    fn ip6_prefix_128() {
        let rec = ok("v=spf1 ip6:::1/128");
        assert_eq!(
            rec.directives[0].mechanism,
            Mechanism::Ip6 {
                addr: "::1".parse().unwrap(),
                prefix: Some(128),
            }
        );
    }

    #[test]
    fn ip6_prefix_129() {
        assert_eq!(err("v=spf1 ip6:::1/129"), SpfResult::PermError);
    }
}
