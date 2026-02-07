use std::fmt;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BimiRecord {
    pub logo_uris: Vec<String>,
    pub authority_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BimiSelectorHeader {
    pub selector: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BimiParseError {
    MissingVersion,
    VersionNotFirst,
    InvalidVersion(String),
    MissingLogo,
    NonHttpsUri(String),
    TooManyUris,
}

impl fmt::Display for BimiParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVersion => write!(f, "missing v=BIMI1 tag"),
            Self::VersionNotFirst => write!(f, "v= tag must be the first tag"),
            Self::InvalidVersion(v) => write!(f, "invalid BIMI version: {v}"),
            Self::MissingLogo => write!(f, "missing l= tag"),
            Self::NonHttpsUri(u) => write!(f, "non-HTTPS URI: {u}"),
            Self::TooManyUris => write!(f, "l= tag contains more than 2 URIs"),
        }
    }
}

impl std::error::Error for BimiParseError {}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

impl BimiRecord {
    /// Parse a BIMI DNS TXT record.
    ///
    /// Returns `Ok(None)` for declination records (v=BIMI1 with empty or
    /// absent `l=`).
    pub fn parse(txt: &str) -> Result<Option<BimiRecord>, BimiParseError> {
        let tags = parse_tags(txt);

        // v= must exist and be first.
        if tags.is_empty() {
            return Err(BimiParseError::MissingVersion);
        }
        let (first_key, first_val) = &tags[0];
        if !first_key.eq_ignore_ascii_case("v") {
            return Err(BimiParseError::VersionNotFirst);
        }
        if !first_val.eq_ignore_ascii_case("bimi1") {
            return Err(BimiParseError::InvalidVersion(first_val.clone()));
        }

        // Collect remaining tags. First occurrence wins for duplicates.
        let mut l_val: Option<&str> = None;
        let mut a_val: Option<&str> = None;

        for (key, val) in &tags[1..] {
            let k = key.to_ascii_lowercase();
            match k.as_str() {
                "l" => {
                    if l_val.is_none() {
                        l_val = Some(val.as_str());
                    }
                }
                "a" => {
                    if a_val.is_none() {
                        a_val = Some(val.as_str());
                    }
                }
                _ => {} // unknown tags silently ignored
            }
        }

        // Parse logo URIs from l= tag.
        let logo_uris = parse_logo_uris(l_val)?;

        // Parse authority URI from a= tag.
        let authority_uri = match a_val {
            Some(v) if !v.is_empty() => {
                require_https(v)?;
                Some(v.to_string())
            }
            _ => None,
        };

        // Declination: no logo URIs → Ok(None), regardless of a= presence.
        if logo_uris.is_empty() {
            return Ok(None);
        }

        Ok(Some(BimiRecord {
            logo_uris,
            authority_uri,
        }))
    }
}

// ---------------------------------------------------------------------------
// Tag=value parser
// ---------------------------------------------------------------------------

fn parse_tags(txt: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(eq) = part.find('=') {
            let tag = part[..eq].trim().to_string();
            let val = part[eq + 1..].trim().to_string();
            if !tag.is_empty() {
                result.push((tag, val));
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Logo URI parsing
// ---------------------------------------------------------------------------

fn parse_logo_uris(val: Option<&str>) -> Result<Vec<String>, BimiParseError> {
    let val = match val {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(Vec::new()),
    };

    let mut uris = Vec::new();
    for part in val.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        require_https(part)?;
        uris.push(part.to_string());
    }

    if uris.len() > 2 {
        return Err(BimiParseError::TooManyUris);
    }

    Ok(uris)
}

// ---------------------------------------------------------------------------
// HTTPS enforcement
// ---------------------------------------------------------------------------

fn require_https(uri: &str) -> Result<(), BimiParseError> {
    if uri.len() >= 8 && uri[..8].eq_ignore_ascii_case("https://") {
        Ok(())
    } else {
        Err(BimiParseError::NonHttpsUri(uri.to_string()))
    }
}

// ---------------------------------------------------------------------------
// BIMI-Selector header parsing
// ---------------------------------------------------------------------------

/// Parse a BIMI-Selector header value into a [`BimiSelectorHeader`].
///
/// Expected format: `v=BIMI1; s=selector`
pub fn parse_bimi_selector(header_value: &str) -> Result<BimiSelectorHeader, String> {
    let tags = parse_tags(header_value);

    if tags.is_empty() {
        return Err("missing v= tag".to_string());
    }
    let (first_key, first_val) = &tags[0];
    if !first_key.eq_ignore_ascii_case("v") {
        return Err("v= tag must be the first tag".to_string());
    }
    if !first_val.eq_ignore_ascii_case("bimi1") {
        return Err(format!("invalid BIMI version: {first_val}"));
    }

    let mut selector = "default".to_string();
    for (key, val) in &tags[1..] {
        if key.eq_ignore_ascii_case("s") && !val.is_empty() {
            selector = val.clone();
            break;
        }
    }

    Ok(BimiSelectorHeader { selector })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> BimiRecord {
        BimiRecord::parse(input)
            .expect("expected successful parse")
            .expect("expected non-declination record")
    }

    fn declination(input: &str) {
        let result = BimiRecord::parse(input).expect("expected successful parse");
        assert_eq!(result, None, "expected declination (Ok(None))");
    }

    fn err(input: &str) -> BimiParseError {
        BimiRecord::parse(input).expect_err("expected parse error")
    }

    // 1. valid_record
    #[test]
    fn valid_record() {
        let rec = ok("v=BIMI1; l=https://example.com/logo.svg;");
        assert_eq!(rec.logo_uris, vec!["https://example.com/logo.svg"]);
        assert_eq!(rec.authority_uri, None);
    }

    // 2. valid_with_authority
    #[test]
    fn valid_with_authority() {
        let rec = ok("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem");
        assert_eq!(rec.logo_uris, vec!["https://example.com/logo.svg"]);
        assert_eq!(
            rec.authority_uri,
            Some("https://example.com/cert.pem".to_string())
        );
    }

    // 3. multiple_logo_uris
    #[test]
    fn multiple_logo_uris() {
        let rec = ok("v=BIMI1; l=https://a.com/1.svg,https://a.com/2.svg");
        assert_eq!(
            rec.logo_uris,
            vec!["https://a.com/1.svg", "https://a.com/2.svg"]
        );
    }

    // 4. declination_empty_l
    #[test]
    fn declination_empty_l() {
        declination("v=BIMI1; l=;");
    }

    // 5. declination_no_l
    #[test]
    fn declination_no_l() {
        declination("v=BIMI1;");
    }

    // 6. missing_version
    #[test]
    fn missing_version() {
        assert_eq!(err(""), BimiParseError::MissingVersion);
    }

    // 7. version_not_first
    #[test]
    fn version_not_first() {
        assert_eq!(
            err("l=https://example.com/logo.svg; v=BIMI1"),
            BimiParseError::VersionNotFirst
        );
    }

    // 8. invalid_version
    #[test]
    fn invalid_version() {
        assert_eq!(
            err("v=BIMI2; l=https://example.com/logo.svg"),
            BimiParseError::InvalidVersion("BIMI2".into())
        );
    }

    // 9. non_https_logo
    #[test]
    fn non_https_logo() {
        assert_eq!(
            err("v=BIMI1; l=http://example.com/logo.svg"),
            BimiParseError::NonHttpsUri("http://example.com/logo.svg".into())
        );
    }

    // 10. non_https_authority
    #[test]
    fn non_https_authority() {
        assert_eq!(
            err("v=BIMI1; l=https://example.com/logo.svg; a=http://example.com/cert.pem"),
            BimiParseError::NonHttpsUri("http://example.com/cert.pem".into())
        );
    }

    // 11. too_many_uris
    #[test]
    fn too_many_uris() {
        assert_eq!(
            err("v=BIMI1; l=https://a.com/1.svg,https://a.com/2.svg,https://a.com/3.svg"),
            BimiParseError::TooManyUris
        );
    }

    // 12. unknown_tags_ignored
    #[test]
    fn unknown_tags_ignored() {
        let rec = ok("v=BIMI1; l=https://example.com/logo.svg; custom=value; foo=bar");
        assert_eq!(rec.logo_uris, vec!["https://example.com/logo.svg"]);
    }

    // 13. whitespace_handling
    #[test]
    fn whitespace_handling() {
        let rec = ok("  v=BIMI1 ;  l = https://example.com/logo.svg  ;  ");
        assert_eq!(rec.logo_uris, vec!["https://example.com/logo.svg"]);
    }

    // 14. case_insensitive_version
    #[test]
    fn case_insensitive_version() {
        let rec = ok("v=bimi1; l=https://example.com/logo.svg");
        assert_eq!(rec.logo_uris, vec!["https://example.com/logo.svg"]);
    }

    // 15. trailing_semicolons
    #[test]
    fn trailing_semicolons() {
        let rec = ok("v=BIMI1; l=https://example.com/logo.svg;;;");
        assert_eq!(rec.logo_uris, vec!["https://example.com/logo.svg"]);
    }

    // 16. selector_header_default
    #[test]
    fn selector_header_default() {
        let hdr = parse_bimi_selector("v=BIMI1;").unwrap();
        assert_eq!(hdr.selector, "default");
    }

    // 17. selector_header_custom
    #[test]
    fn selector_header_custom() {
        let hdr = parse_bimi_selector("v=BIMI1; s=brand1").unwrap();
        assert_eq!(hdr.selector, "brand1");
    }

    // 18. selector_header_invalid_version
    #[test]
    fn selector_header_invalid_version() {
        let result = parse_bimi_selector("v=BIMI2; s=brand1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid BIMI version"));
    }

    // 19. single_uri
    #[test]
    fn single_uri() {
        let rec = ok("v=BIMI1; l=https://brand.example.com/logo.svg");
        assert_eq!(rec.logo_uris.len(), 1);
        assert_eq!(rec.logo_uris[0], "https://brand.example.com/logo.svg");
    }

    // 20. authority_only_no_logo
    #[test]
    fn authority_only_no_logo() {
        declination("v=BIMI1; a=https://example.com/cert.pem");
    }

    // -- additional edge cases --

    #[test]
    fn empty_input() {
        assert_eq!(err(""), BimiParseError::MissingVersion);
    }

    #[test]
    fn version_not_first_with_l_before_v() {
        assert_eq!(
            err("l=https://example.com/logo.svg; v=BIMI1"),
            BimiParseError::VersionNotFirst
        );
    }

    #[test]
    fn duplicate_l_first_wins() {
        let rec = ok("v=BIMI1; l=https://a.com/1.svg; l=https://b.com/2.svg");
        assert_eq!(rec.logo_uris, vec!["https://a.com/1.svg"]);
    }

    #[test]
    fn two_uris_exactly_at_limit() {
        let rec = ok("v=BIMI1; l=https://a.com/1.svg,https://a.com/2.svg");
        assert_eq!(rec.logo_uris.len(), 2);
    }

    #[test]
    fn logo_uri_with_path_and_query() {
        let rec = ok("v=BIMI1; l=https://cdn.example.com/brand/logo.svg?v=2");
        assert_eq!(
            rec.logo_uris,
            vec!["https://cdn.example.com/brand/logo.svg?v=2"]
        );
    }

    #[test]
    fn selector_header_missing_v() {
        let result = parse_bimi_selector("s=brand1");
        assert!(result.is_err());
    }

    #[test]
    fn selector_header_empty_s_uses_default() {
        let hdr = parse_bimi_selector("v=BIMI1; s=").unwrap();
        assert_eq!(hdr.selector, "default");
    }

    #[test]
    fn declination_empty_l_with_authority() {
        declination("v=BIMI1; l=; a=https://example.com/cert.pem");
    }

    #[test]
    fn comma_separated_uris_with_spaces() {
        let rec = ok("v=BIMI1; l=https://a.com/1.svg , https://a.com/2.svg");
        assert_eq!(
            rec.logo_uris,
            vec!["https://a.com/1.svg", "https://a.com/2.svg"]
        );
    }

    #[test]
    fn display_errors() {
        assert_eq!(
            BimiParseError::MissingVersion.to_string(),
            "missing v=BIMI1 tag"
        );
        assert_eq!(
            BimiParseError::VersionNotFirst.to_string(),
            "v= tag must be the first tag"
        );
        assert_eq!(
            BimiParseError::InvalidVersion("X".into()).to_string(),
            "invalid BIMI version: X"
        );
        assert_eq!(BimiParseError::MissingLogo.to_string(), "missing l= tag");
        assert_eq!(
            BimiParseError::NonHttpsUri("http://x".into()).to_string(),
            "non-HTTPS URI: http://x"
        );
        assert_eq!(
            BimiParseError::TooManyUris.to_string(),
            "l= tag contains more than 2 URIs"
        );
    }

    #[test]
    fn ftp_uri_rejected() {
        assert_eq!(
            err("v=BIMI1; l=ftp://example.com/logo.svg"),
            BimiParseError::NonHttpsUri("ftp://example.com/logo.svg".into())
        );
    }
}
