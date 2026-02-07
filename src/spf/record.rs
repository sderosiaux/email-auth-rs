//! SPF record parsing (RFC 7208 Section 4.5, 12).

use crate::spf::mechanism::{
    parse_mechanism, Directive, Qualifier, SpfParseError,
};

/// A parsed SPF record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub explanation: Option<String>,
    /// Unknown modifiers preserved for forward compatibility (name=value).
    pub unknown_modifiers: Vec<(String, String)>,
}

impl SpfRecord {
    /// Parse a raw SPF TXT record string (e.g. "v=spf1 include:example.com -all").
    ///
    /// Returns `Err(SpfParseError)` on:
    ///   - Missing or invalid version tag
    ///   - Unknown mechanism names
    ///   - Duplicate redirect or exp modifiers
    ///   - Invalid mechanism arguments
    pub fn parse(record: &str) -> Result<Self, SpfParseError> {
        let record = record.trim();
        if record.is_empty() {
            return Err(SpfParseError::Empty);
        }

        // Version check: must start with "v=spf1" (case-insensitive) followed by
        // either end-of-string or a space.
        let lower = record.to_ascii_lowercase();
        if !lower.starts_with("v=spf1") {
            return Err(SpfParseError::InvalidVersion);
        }
        let after_version = &record[6..];
        if !after_version.is_empty() && !after_version.starts_with(' ') {
            return Err(SpfParseError::InvalidVersion);
        }

        let terms: Vec<&str> = after_version.split_whitespace().collect();

        let mut directives = Vec::new();
        let mut redirect: Option<String> = None;
        let mut explanation: Option<String> = None;
        let mut unknown_modifiers = Vec::new();

        for term in terms {
            // Check if this is a modifier (contains '=' that is not part of mechanism)
            // Modifiers have the form: name=value
            // Mechanisms never contain '=' except as part of macro strings in domain-specs
            // A modifier name must match [a-zA-Z][a-zA-Z0-9._-]*
            if let Some((mod_name, mod_value)) = try_parse_modifier(term) {
                let mod_name_lower = mod_name.to_ascii_lowercase();
                match mod_name_lower.as_str() {
                    "redirect" => {
                        if redirect.is_some() {
                            return Err(SpfParseError::DuplicateModifier("redirect".into()));
                        }
                        redirect = Some(mod_value.to_string());
                    }
                    "exp" => {
                        if explanation.is_some() {
                            return Err(SpfParseError::DuplicateModifier("exp".into()));
                        }
                        explanation = Some(mod_value.to_string());
                    }
                    _ => {
                        // Unknown modifiers: ignore per RFC 7208 Section 6
                        unknown_modifiers
                            .push((mod_name_lower, mod_value.to_string()));
                    }
                }
            } else {
                // Parse as directive: qualifier + mechanism
                let (qualifier, mech_str) = Qualifier::parse_prefix(term);
                let mechanism = parse_mechanism(mech_str)?;
                directives.push(Directive {
                    qualifier,
                    mechanism,
                });
            }
        }

        Ok(SpfRecord {
            directives,
            redirect,
            explanation,
            unknown_modifiers,
        })
    }
}

/// Try to parse a term as a modifier (name=value).
/// Modifier names must start with an alpha char and contain only [a-zA-Z0-9._-].
/// Returns None if not a valid modifier form — meaning it should be parsed as a mechanism.
fn try_parse_modifier(term: &str) -> Option<(&str, &str)> {
    let eq_pos = term.find('=')?;

    // Modifier name is everything before '='
    let name = &term[..eq_pos];
    let value = &term[eq_pos + 1..];

    // Must not be empty
    if name.is_empty() {
        return None;
    }

    // First char must be alpha
    if !name.as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }

    // If the name starts with a qualifier char, strip it for the check but
    // this means it's actually a mechanism with qualifier prefix, not a modifier.
    // Qualifier chars: + - ~ ?
    // But actually: "+redirect=..." would be parsed as qualifier '+' then "redirect=..."
    // which is not a valid mechanism. The RFC says modifiers don't have qualifiers.
    // So if a term has a qualifier prefix before the name, it's a mechanism parse attempt.
    let first = name.as_bytes()[0];
    if first == b'+' || first == b'-' || first == b'~' || first == b'?' {
        return None;
    }

    // Remaining chars: alphanumeric, dot, underscore, hyphen
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return None;
    }

    // Known mechanism names with arguments must NOT be treated as modifiers.
    // "v" is also not a modifier (it's the version).
    let name_lower = name.to_ascii_lowercase();
    match name_lower.as_str() {
        "include" | "a" | "mx" | "ptr" | "ip4" | "ip6" | "exists" | "all" => return None,
        _ => {}
    }

    Some((name, value))
}

impl std::fmt::Display for SpfRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v=spf1")?;
        for d in &self.directives {
            write!(f, " {d}")?;
        }
        if let Some(ref r) = self.redirect {
            write!(f, " redirect={r}")?;
        }
        if let Some(ref e) = self.explanation {
            write!(f, " exp={e}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::mechanism::{DualCidr, Mechanism, Qualifier};
    use std::net::Ipv4Addr;

    // ---- Version ----

    #[test]
    fn valid_version_only() {
        let r = SpfRecord::parse("v=spf1").unwrap();
        assert!(r.directives.is_empty());
        assert!(r.redirect.is_none());
        assert!(r.explanation.is_none());
    }

    #[test]
    fn invalid_version() {
        assert!(SpfRecord::parse("v=spf2 -all").is_err());
        assert!(SpfRecord::parse("spf1 -all").is_err());
        assert!(SpfRecord::parse("").is_err());
    }

    #[test]
    fn version_case_insensitive() {
        assert!(SpfRecord::parse("V=SPF1 -all").is_ok());
        assert!(SpfRecord::parse("V=Spf1").is_ok());
    }

    #[test]
    fn version_must_be_followed_by_space_or_end() {
        // "v=spf1xyz" is not valid
        assert!(SpfRecord::parse("v=spf1xyz").is_err());
    }

    // ---- Simple records ----

    #[test]
    fn simple_dash_all() {
        let r = SpfRecord::parse("v=spf1 -all").unwrap();
        assert_eq!(r.directives.len(), 1);
        assert_eq!(r.directives[0].qualifier, Qualifier::Fail);
        assert_eq!(r.directives[0].mechanism, Mechanism::All);
    }

    #[test]
    fn typical_record() {
        let r = SpfRecord::parse(
            "v=spf1 ip4:192.168.0.0/16 include:example.com mx -all",
        )
        .unwrap();
        assert_eq!(r.directives.len(), 4);
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::Ip4 {
                addr: Ipv4Addr::new(192, 168, 0, 0),
                prefix_len: 16,
            }
        );
        assert_eq!(
            r.directives[1].mechanism,
            Mechanism::Include("example.com".into())
        );
        assert_eq!(
            r.directives[2].mechanism,
            Mechanism::Mx {
                domain: None,
                cidr: DualCidr::default(),
            }
        );
        assert_eq!(r.directives[3].mechanism, Mechanism::All);
        assert_eq!(r.directives[3].qualifier, Qualifier::Fail);
    }

    // ---- Modifiers ----

    #[test]
    fn redirect_modifier() {
        let r = SpfRecord::parse("v=spf1 redirect=example.com").unwrap();
        assert!(r.directives.is_empty());
        assert_eq!(r.redirect.as_deref(), Some("example.com"));
    }

    #[test]
    fn exp_modifier() {
        let r = SpfRecord::parse("v=spf1 -all exp=explain.example.com").unwrap();
        assert_eq!(r.explanation.as_deref(), Some("explain.example.com"));
    }

    #[test]
    fn duplicate_redirect_error() {
        let err = SpfRecord::parse("v=spf1 redirect=a.com redirect=b.com").unwrap_err();
        assert!(matches!(err, SpfParseError::DuplicateModifier(ref m) if m == "redirect"));
    }

    #[test]
    fn duplicate_exp_error() {
        let err = SpfRecord::parse("v=spf1 exp=a.com exp=b.com -all").unwrap_err();
        assert!(matches!(err, SpfParseError::DuplicateModifier(ref m) if m == "exp"));
    }

    #[test]
    fn unknown_modifiers_ignored() {
        let r = SpfRecord::parse("v=spf1 custom=value -all").unwrap();
        assert_eq!(r.directives.len(), 1);
        assert_eq!(r.unknown_modifiers.len(), 1);
        assert_eq!(r.unknown_modifiers[0], ("custom".into(), "value".into()));
    }

    // ---- Unknown mechanism -> error ----

    #[test]
    fn unknown_mechanism_error() {
        let err = SpfRecord::parse("v=spf1 bogus -all").unwrap_err();
        assert!(matches!(err, SpfParseError::UnknownMechanism(_)));
    }

    // ---- Complex records ----

    #[test]
    fn a_with_dual_cidr_in_record() {
        let r = SpfRecord::parse("v=spf1 a:example.com/24//64 -all").unwrap();
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::A {
                domain: Some("example.com".into()),
                cidr: DualCidr { v4: 24, v6: 64 },
            }
        );
    }

    #[test]
    fn mx_with_qualifier() {
        let r = SpfRecord::parse("v=spf1 ~mx:example.com -all").unwrap();
        assert_eq!(r.directives[0].qualifier, Qualifier::SoftFail);
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::Mx {
                domain: Some("example.com".into()),
                cidr: DualCidr::default(),
            }
        );
    }

    #[test]
    fn ip6_mechanism_in_record() {
        let r = SpfRecord::parse("v=spf1 ip6:2001:db8::/32 -all").unwrap();
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::Ip6 {
                addr: "2001:db8::".parse().unwrap(),
                prefix_len: 32,
            }
        );
    }

    #[test]
    fn exists_with_macro() {
        let r = SpfRecord::parse("v=spf1 exists:%{ir}.sbl.example.com -all").unwrap();
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::Exists("%{ir}.sbl.example.com".into())
        );
    }

    #[test]
    fn multiple_spaces_between_terms() {
        let r = SpfRecord::parse("v=spf1   mx   -all").unwrap();
        assert_eq!(r.directives.len(), 2);
    }

    // ---- Display ----

    #[test]
    fn display_roundtrip() {
        let r = SpfRecord::parse("v=spf1 include:example.com -all").unwrap();
        assert_eq!(r.to_string(), "v=spf1 include:example.com -all");
    }

    #[test]
    fn display_with_redirect() {
        let r = SpfRecord::parse("v=spf1 redirect=example.com").unwrap();
        assert_eq!(r.to_string(), "v=spf1 redirect=example.com");
    }

    // ---- Whitespace handling ----

    #[test]
    fn leading_trailing_whitespace() {
        let r = SpfRecord::parse("  v=spf1 -all  ").unwrap();
        assert_eq!(r.directives.len(), 1);
    }

    // ---- Edge: all with qualifiers ----

    #[test]
    fn all_qualifiers() {
        for (input, expected_q) in [
            ("v=spf1 +all", Qualifier::Pass),
            ("v=spf1 -all", Qualifier::Fail),
            ("v=spf1 ~all", Qualifier::SoftFail),
            ("v=spf1 ?all", Qualifier::Neutral),
        ] {
            let r = SpfRecord::parse(input).unwrap();
            assert_eq!(r.directives[0].qualifier, expected_q, "input: {input}");
        }
    }

    // ---- ptr in record ----

    #[test]
    fn ptr_in_record() {
        let r = SpfRecord::parse("v=spf1 ptr:example.com -all").unwrap();
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::Ptr(Some("example.com".into()))
        );
    }

    // ---- Modifier that looks like mechanism name should still parse as mechanism ----

    #[test]
    fn include_not_treated_as_modifier() {
        // "include=foo" should NOT be treated as an unknown modifier — the name "include"
        // is reserved as a mechanism. This term should fail as a mechanism parse.
        // Actually per our try_parse_modifier, mechanism names are excluded, so this
        // will be treated as mechanism parse: "include=foo" -> mechanism "include" with
        // arg "foo" (which has = in it). That's fine — it parses as include with domain "foo".
        // Wait, no: the colon split won't find ':', it'll hit '/' check... let me verify.
        // Actually "include=foo" has no ':', no '/' so name_part="include=foo", arg=None.
        // name_lower = "include=foo" which doesn't match any mechanism -> UnknownMechanism.
        // That's the correct behavior: "include=foo" is a malformed term.
        let err = SpfRecord::parse("v=spf1 include=foo -all").unwrap_err();
        assert!(matches!(err, SpfParseError::UnknownMechanism(_)));
    }
}
