use crate::dkim::signature::parse_tags;

/// BIMI DNS record.
#[derive(Debug, Clone, PartialEq)]
pub struct BimiRecord {
    pub version: String,
    pub logo_uris: Vec<String>,
    pub authority_uri: Option<String>,
    /// True if this is a declination record (empty l=, no a=).
    pub is_declination: bool,
}

/// BIMI-Selector header.
#[derive(Debug, Clone, PartialEq)]
pub struct BimiSelectorHeader {
    pub version: String,
    pub selector: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BimiParseError {
    MissingVersion,
    InvalidVersion(String),
    MissingLogo,
    NonHttpsUri(String),
    TooManyLogos,
    InvalidSyntax(String),
}

impl std::fmt::Display for BimiParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingVersion => write!(f, "missing v= tag"),
            Self::InvalidVersion(s) => write!(f, "invalid version: {s}"),
            Self::MissingLogo => write!(f, "missing l= tag"),
            Self::NonHttpsUri(s) => write!(f, "non-HTTPS URI: {s}"),
            Self::TooManyLogos => write!(f, "more than 2 logo URIs"),
            Self::InvalidSyntax(s) => write!(f, "invalid syntax: {s}"),
        }
    }
}

impl BimiRecord {
    pub fn parse(input: &str) -> Result<Self, BimiParseError> {
        let tags = parse_tags(input)
            .map_err(|e| BimiParseError::InvalidSyntax(e.to_string()))?;

        let get = |name: &str| -> Option<&str> {
            tags.iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        // v= must be first tag and must be BIMI1
        if let Some((first_name, first_val)) = tags.first() {
            if first_name != "v" {
                return Err(BimiParseError::MissingVersion);
            }
            if first_val.trim() != "BIMI1" {
                return Err(BimiParseError::InvalidVersion(first_val.trim().to_string()));
            }
        } else {
            return Err(BimiParseError::MissingVersion);
        }

        // l= tag
        let logo_str = get("l");
        let authority_str = get("a");

        // Check for declination record: v=BIMI1; with empty/missing l= and no a=
        let is_declination = match (logo_str, authority_str) {
            (None, None) => true,
            (Some(l), None) if l.trim().is_empty() => true,
            _ => false,
        };

        if is_declination {
            return Ok(BimiRecord {
                version: "BIMI1".into(),
                logo_uris: Vec::new(),
                authority_uri: None,
                is_declination: true,
            });
        }

        // Parse logo URIs
        let logo_uris = if let Some(l_str) = logo_str {
            let uris: Vec<String> = l_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if uris.len() > 2 {
                return Err(BimiParseError::TooManyLogos);
            }

            for uri in &uris {
                if !uri.to_ascii_lowercase().starts_with("https://") {
                    return Err(BimiParseError::NonHttpsUri(uri.clone()));
                }
            }

            uris
        } else {
            return Err(BimiParseError::MissingLogo);
        };

        // Parse authority URI
        let authority_uri = if let Some(a_str) = authority_str {
            let trimmed = a_str.trim();
            if trimmed.is_empty() {
                None
            } else {
                if !trimmed.to_ascii_lowercase().starts_with("https://") {
                    return Err(BimiParseError::NonHttpsUri(trimmed.into()));
                }
                Some(trimmed.to_string())
            }
        } else {
            None
        };

        Ok(BimiRecord {
            version: "BIMI1".into(),
            logo_uris,
            authority_uri,
            is_declination: false,
        })
    }
}

/// Parse a BIMI-Selector header value.
pub fn parse_bimi_selector(header_value: &str) -> Result<BimiSelectorHeader, String> {
    let tags = parse_tags(header_value).map_err(|e| e.to_string())?;

    let get = |name: &str| -> Option<&str> {
        tags.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };

    let version = get("v")
        .ok_or("missing v= tag")?
        .trim();
    if version != "BIMI1" {
        return Err(format!("invalid version: {version}"));
    }

    let selector = get("s")
        .unwrap_or("default")
        .trim()
        .to_string();

    Ok(BimiSelectorHeader {
        version: version.to_string(),
        selector,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_record() {
        let r = BimiRecord::parse(
            "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem",
        )
        .unwrap();
        assert_eq!(r.logo_uris, vec!["https://example.com/logo.svg"]);
        assert_eq!(r.authority_uri, Some("https://example.com/cert.pem".into()));
        assert!(!r.is_declination);
    }

    #[test]
    fn test_multiple_logos() {
        let r = BimiRecord::parse(
            "v=BIMI1; l=https://a.com/1.svg,https://a.com/2.svg",
        )
        .unwrap();
        assert_eq!(r.logo_uris.len(), 2);
    }

    #[test]
    fn test_too_many_logos() {
        let result = BimiRecord::parse(
            "v=BIMI1; l=https://a.com/1.svg,https://a.com/2.svg,https://a.com/3.svg",
        );
        assert!(matches!(result, Err(BimiParseError::TooManyLogos)));
    }

    #[test]
    fn test_non_https() {
        let result = BimiRecord::parse("v=BIMI1; l=http://example.com/logo.svg");
        assert!(matches!(result, Err(BimiParseError::NonHttpsUri(_))));
    }

    #[test]
    fn test_declination() {
        let r = BimiRecord::parse("v=BIMI1;").unwrap();
        assert!(r.is_declination);
        assert!(r.logo_uris.is_empty());
    }

    #[test]
    fn test_declination_empty_l() {
        let r = BimiRecord::parse("v=BIMI1; l=").unwrap();
        assert!(r.is_declination);
    }

    #[test]
    fn test_missing_version() {
        assert!(BimiRecord::parse("l=https://example.com/logo.svg").is_err());
    }

    #[test]
    fn test_invalid_version() {
        let result = BimiRecord::parse("v=BIMI2; l=https://example.com/logo.svg");
        assert!(matches!(result, Err(BimiParseError::InvalidVersion(_))));
    }

    #[test]
    fn test_parse_bimi_selector() {
        let s = parse_bimi_selector(" v=BIMI1; s=brand").unwrap();
        assert_eq!(s.selector, "brand");
    }

    #[test]
    fn test_parse_bimi_selector_default() {
        let s = parse_bimi_selector(" v=BIMI1").unwrap();
        assert_eq!(s.selector, "default");
    }
}
