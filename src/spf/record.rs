use super::mechanism::{Mechanism, Qualifier};
use super::SpfError;

#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub mechanisms: Vec<(Qualifier, Mechanism)>,
    pub redirect: Option<String>,
    pub exp: Option<String>,
}

impl SpfRecord {
    pub fn parse(record: &str) -> Result<Self, SpfError> {
        let record = record.trim();

        if !record.starts_with("v=spf1") {
            return Err(SpfError::InvalidRecord("missing v=spf1".into()));
        }

        let mut mechanisms = Vec::new();
        let mut redirect = None;
        let mut exp = None;

        let parts: Vec<&str> = record.split_whitespace().skip(1).collect();

        for part in parts {
            if let Some(domain) = part.strip_prefix("redirect=") {
                redirect = Some(domain.to_string());
                continue;
            }
            if let Some(domain) = part.strip_prefix("exp=") {
                exp = Some(domain.to_string());
                continue;
            }

            let (qualifier, mechanism_str) = parse_qualifier(part);
            if let Some(mechanism) = Mechanism::parse(mechanism_str) {
                mechanisms.push((qualifier, mechanism));
            }
        }

        Ok(SpfRecord {
            mechanisms,
            redirect,
            exp,
        })
    }
}

fn parse_qualifier(s: &str) -> (Qualifier, &str) {
    match s.chars().next() {
        Some('+') => (Qualifier::Pass, &s[1..]),
        Some('-') => (Qualifier::Fail, &s[1..]),
        Some('~') => (Qualifier::SoftFail, &s[1..]),
        Some('?') => (Qualifier::Neutral, &s[1..]),
        _ => (Qualifier::Pass, s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let record = SpfRecord::parse("v=spf1 mx -all").unwrap();
        assert_eq!(record.mechanisms.len(), 2);
        assert_eq!(record.mechanisms[0].0, Qualifier::Pass);
        assert_eq!(record.mechanisms[1].0, Qualifier::Fail);
    }

    #[test]
    fn test_parse_redirect() {
        let record = SpfRecord::parse("v=spf1 redirect=_spf.example.com").unwrap();
        assert_eq!(record.redirect, Some("_spf.example.com".to_string()));
    }

    #[test]
    fn test_invalid_version() {
        assert!(SpfRecord::parse("v=spf2 mx").is_err());
    }
}
