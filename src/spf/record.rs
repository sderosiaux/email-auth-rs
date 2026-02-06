use super::mechanism::Mechanism;

#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub mechanisms: Vec<Mechanism>,
    pub redirect: Option<String>,
    pub explanation: Option<String>,
}

impl SpfRecord {
    pub fn parse(txt: &str) -> Option<Self> {
        let txt = txt.trim();

        if !txt.to_lowercase().starts_with("v=spf1") {
            return None;
        }

        let rest = txt[6..].trim();
        let mut mechanisms = Vec::new();
        let mut redirect = None;
        let mut explanation = None;

        for part in rest.split_whitespace() {
            let lower = part.to_lowercase();

            if let Some(domain) = lower.strip_prefix("redirect=") {
                redirect = Some(domain.to_string());
            } else if let Some(domain) = lower.strip_prefix("exp=") {
                explanation = Some(domain.to_string());
            } else if let Some(mech) = Mechanism::parse(part) {
                mechanisms.push(mech);
            }
        }

        Some(SpfRecord {
            mechanisms,
            redirect,
            explanation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::mechanism::Qualifier;

    #[test]
    fn test_parse_simple() {
        let record = SpfRecord::parse("v=spf1 -all").unwrap();
        assert_eq!(record.mechanisms.len(), 1);
        assert_eq!(record.mechanisms[0], Mechanism::All(Qualifier::Fail));
    }

    #[test]
    fn test_parse_complex() {
        let record = SpfRecord::parse("v=spf1 ip4:192.168.0.0/16 include:example.com -all").unwrap();
        assert_eq!(record.mechanisms.len(), 3);
    }

    #[test]
    fn test_parse_redirect() {
        let record = SpfRecord::parse("v=spf1 redirect=example.com").unwrap();
        assert_eq!(record.redirect, Some("example.com".into()));
    }

    #[test]
    fn test_invalid_version() {
        assert!(SpfRecord::parse("v=spf2 -all").is_none());
    }
}
