//! SPF record parsing

use super::mechanism::{Directive, Modifier};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpfParseError {
    #[error("invalid SPF version")]
    InvalidVersion,
    #[error("invalid mechanism: {0}")]
    InvalidMechanism(String),
    #[error("duplicate modifier: {0}")]
    DuplicateModifier(String),
}

/// Parsed SPF record
#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub directives: Vec<Directive>,
    pub redirect: Option<String>,
    pub exp: Option<String>,
    pub raw: String,
}

impl SpfRecord {
    pub fn parse(txt: &str) -> Result<Self, SpfParseError> {
        let txt = txt.trim();

        // Must start with v=spf1 (case-insensitive)
        if !txt.to_lowercase().starts_with("v=spf1") {
            return Err(SpfParseError::InvalidVersion);
        }

        let rest = &txt[6..]; // Skip "v=spf1"
        let mut directives = Vec::new();
        let mut redirect = None;
        let mut exp = None;

        for term in rest.split_whitespace() {
            if term.is_empty() {
                continue;
            }

            // Check for modifiers (name=value)
            if let Some(eq_pos) = term.find('=') {
                let name = &term[..eq_pos].to_lowercase();
                let value = &term[eq_pos + 1..];

                match name.as_str() {
                    "redirect" => {
                        if redirect.is_some() {
                            return Err(SpfParseError::DuplicateModifier("redirect".to_string()));
                        }
                        redirect = Some(value.to_string());
                    }
                    "exp" => {
                        if exp.is_some() {
                            return Err(SpfParseError::DuplicateModifier("exp".to_string()));
                        }
                        exp = Some(value.to_string());
                    }
                    _ => {
                        // Unknown modifier - ignore per RFC
                    }
                }
            } else {
                // It's a directive (mechanism with optional qualifier)
                let directive = Directive::parse(term)?;
                directives.push(directive);
            }
        }

        Ok(SpfRecord {
            directives,
            redirect,
            exp,
            raw: txt.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::mechanism::Qualifier;

    #[test]
    fn test_parse_minimal() {
        let record = SpfRecord::parse("v=spf1 -all").unwrap();
        assert_eq!(record.directives.len(), 1);
        assert!(record.redirect.is_none());
    }

    #[test]
    fn test_parse_with_redirect() {
        let record = SpfRecord::parse("v=spf1 redirect=_spf.example.com").unwrap();
        assert_eq!(record.redirect, Some("_spf.example.com".to_string()));
    }

    #[test]
    fn test_parse_case_insensitive() {
        let record = SpfRecord::parse("V=SPF1 -ALL").unwrap();
        assert_eq!(record.directives.len(), 1);
    }

    #[test]
    fn test_invalid_version() {
        assert!(SpfRecord::parse("v=spf2 -all").is_err());
    }

    #[test]
    fn test_duplicate_redirect() {
        assert!(SpfRecord::parse("v=spf1 redirect=a redirect=b").is_err());
    }
}
