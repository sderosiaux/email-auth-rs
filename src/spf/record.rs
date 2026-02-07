use super::mechanism::{parse_term, Directive, TermKind};

/// Parsed SPF record.
#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub explanation: Option<String>,
}

impl SpfRecord {
    /// Parse an SPF record string (after "v=spf1 " prefix).
    pub fn parse(record: &str) -> Result<Self, String> {
        let record = record.trim();
        let lower = record.to_ascii_lowercase();

        // Validate version
        if lower == "v=spf1" {
            return Ok(SpfRecord {
                directives: Vec::new(),
                redirect: None,
                explanation: None,
            });
        }
        if !lower.starts_with("v=spf1 ") {
            return Err(format!("not an SPF record: {}", record));
        }

        let body = &record[7..]; // after "v=spf1 "
        let mut directives = Vec::new();
        let mut redirect: Option<String> = None;
        let mut explanation: Option<String> = None;

        for part in body.split_whitespace() {
            match parse_term(part)? {
                TermKind::Directive(d) => directives.push(d),
                TermKind::Modifier(name, value) => {
                    let name_lower = name.to_ascii_lowercase();
                    match name_lower.as_str() {
                        "redirect" => {
                            if redirect.is_some() {
                                return Err("duplicate redirect modifier".to_string());
                            }
                            redirect = Some(value);
                        }
                        "exp" => {
                            if explanation.is_some() {
                                return Err("duplicate exp modifier".to_string());
                            }
                            explanation = Some(value);
                        }
                        _ => {
                            // Unknown modifier: ignore (forward compatibility)
                        }
                    }
                }
            }
        }

        Ok(SpfRecord {
            directives,
            redirect,
            explanation,
        })
    }

    /// Filter DNS TXT records to find the SPF record.
    /// Returns None if no SPF record, PermError if multiple.
    pub fn from_txt_records(records: &[String]) -> Result<Option<SpfRecord>, String> {
        let spf_records: Vec<&String> = records
            .iter()
            .filter(|r| {
                let lower = r.to_ascii_lowercase();
                lower == "v=spf1" || lower.starts_with("v=spf1 ")
            })
            .collect();

        match spf_records.len() {
            0 => Ok(None),
            1 => Ok(Some(SpfRecord::parse(spf_records[0])?)),
            _ => Err("multiple SPF records found".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::mechanism::{Mechanism, Qualifier};

    #[test]
    fn test_parse_minimal() {
        let r = SpfRecord::parse("v=spf1 -all").unwrap();
        assert_eq!(r.directives.len(), 1);
        assert_eq!(r.directives[0].qualifier, Qualifier::Fail);
        assert_eq!(r.directives[0].mechanism, Mechanism::All);
    }

    #[test]
    fn test_parse_multiple_mechanisms() {
        let r =
            SpfRecord::parse("v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all").unwrap();
        assert_eq!(r.directives.len(), 3);
    }

    #[test]
    fn test_parse_include() {
        let r = SpfRecord::parse("v=spf1 include:_spf.google.com -all").unwrap();
        assert_eq!(r.directives.len(), 2);
        match &r.directives[0].mechanism {
            Mechanism::Include { domain } => assert_eq!(domain, "_spf.google.com"),
            _ => panic!("expected include"),
        }
    }

    #[test]
    fn test_parse_redirect() {
        let r = SpfRecord::parse("v=spf1 redirect=example.com").unwrap();
        assert_eq!(r.redirect, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_case_insensitive() {
        let r = SpfRecord::parse("V=SPF1 IP4:192.0.2.1 -ALL").unwrap();
        assert_eq!(r.directives.len(), 2);
    }

    #[test]
    fn test_parse_invalid_version() {
        assert!(SpfRecord::parse("v=spf2 -all").is_err());
    }

    #[test]
    fn test_parse_duplicate_redirect() {
        assert!(SpfRecord::parse("v=spf1 redirect=a redirect=b").is_err());
    }

    #[test]
    fn test_parse_unknown_modifier_ignored() {
        let r = SpfRecord::parse("v=spf1 foo=bar -all").unwrap();
        assert_eq!(r.directives.len(), 1);
    }

    #[test]
    fn test_parse_unknown_mechanism_error() {
        assert!(SpfRecord::parse("v=spf1 custom:example.com -all").is_err());
    }

    #[test]
    fn test_from_txt_records_none() {
        let records = vec!["some other record".to_string()];
        assert!(SpfRecord::from_txt_records(&records).unwrap().is_none());
    }

    #[test]
    fn test_from_txt_records_multiple() {
        let records = vec![
            "v=spf1 +all".to_string(),
            "v=spf1 -all".to_string(),
        ];
        assert!(SpfRecord::from_txt_records(&records).is_err());
    }

    #[test]
    fn test_v_spf10_not_matched() {
        let records = vec!["v=spf10 +all".to_string()];
        assert!(SpfRecord::from_txt_records(&records).unwrap().is_none());
    }

    #[test]
    fn test_parse_exp_modifier() {
        let r = SpfRecord::parse("v=spf1 -all exp=explain.example.com").unwrap();
        assert_eq!(r.explanation, Some("explain.example.com".to_string()));
    }
}
