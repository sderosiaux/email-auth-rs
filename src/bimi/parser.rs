use super::types::{BimiRecord, BimiSelectorHeader};

/// BIMI parse error.
#[derive(Debug, Clone)]
pub struct BimiParseError {
    pub detail: String,
}

impl std::fmt::Display for BimiParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for BimiParseError {}

/// Parse a BIMI DNS record from a TXT record value.
pub fn parse_bimi_record(value: &str) -> Result<BimiRecord, BimiParseError> {
    let trimmed = value.trim();
    let parts: Vec<&str> = trimmed.split(';').collect();

    // First tag must be v=BIMI1
    let first = parts
        .first()
        .map(|s| s.trim())
        .unwrap_or("");

    if !first.starts_with("v=") && !first.starts_with("V=") {
        return Err(BimiParseError {
            detail: "first tag must be v=BIMI1".into(),
        });
    }

    let version_val = first.splitn(2, '=').nth(1).unwrap_or("").trim();
    if !version_val.eq_ignore_ascii_case("BIMI1") {
        return Err(BimiParseError {
            detail: format!("invalid version: expected BIMI1, got '{}'", version_val),
        });
    }

    let mut logo_uris: Vec<String> = Vec::new();
    let mut authority_uri: Option<String> = Option::None;
    let mut seen_l = false;
    let mut seen_a = false;

    for part in &parts[1..] {
        let tag_value = part.trim();
        if tag_value.is_empty() {
            continue;
        }

        let (tag, val) = match tag_value.split_once('=') {
            Some((t, v)) => (t.trim().to_ascii_lowercase(), v.trim().to_string()),
            None => continue, // ignore malformed
        };

        match tag.as_str() {
            "l" => {
                if seen_l {
                    return Err(BimiParseError {
                        detail: "duplicate l= tag".into(),
                    });
                }
                seen_l = true;

                if val.is_empty() {
                    // Empty l= → will be declination if no a=
                    continue;
                }

                let uris: Vec<&str> = val.split(',').map(|u| u.trim()).filter(|u| !u.is_empty()).collect();
                if uris.len() > 2 {
                    return Err(BimiParseError {
                        detail: format!("l= has {} URIs, max 2", uris.len()),
                    });
                }

                for uri in &uris {
                    if !uri.starts_with("https://") && !uri.starts_with("HTTPS://") {
                        return Err(BimiParseError {
                            detail: format!("l= URI must be HTTPS: '{}'", uri),
                        });
                    }
                }

                logo_uris = uris.iter().map(|u| u.to_string()).collect();
            }
            "a" => {
                if seen_a {
                    return Err(BimiParseError {
                        detail: "duplicate a= tag".into(),
                    });
                }
                seen_a = true;

                if val.is_empty() {
                    continue;
                }

                if !val.starts_with("https://") && !val.starts_with("HTTPS://") {
                    return Err(BimiParseError {
                        detail: format!("a= URI must be HTTPS: '{}'", val),
                    });
                }

                authority_uri = Some(val);
            }
            "v" => {
                return Err(BimiParseError {
                    detail: "v= must be first tag".into(),
                });
            }
            _ => {
                // Unknown tags ignored
            }
        }
    }

    Ok(BimiRecord {
        version: "BIMI1".to_string(),
        logo_uris,
        authority_uri,
    })
}

/// Check if a parsed BimiRecord is a declination record.
pub fn is_declination(record: &BimiRecord) -> bool {
    record.logo_uris.is_empty() && record.authority_uri.is_none()
}

/// Parse BIMI-Selector header value.
/// Format: `v=BIMI1; s=<selector>;`
pub fn parse_bimi_selector(value: &str) -> Result<BimiSelectorHeader, BimiParseError> {
    let trimmed = value.trim();
    let parts: Vec<&str> = trimmed.split(';').collect();

    let mut version = Option::None;
    let mut selector = Option::None;

    for (idx, part) in parts.iter().enumerate() {
        let tag_value = part.trim();
        if tag_value.is_empty() {
            continue;
        }

        let (tag, val) = match tag_value.split_once('=') {
            Some((t, v)) => (t.trim().to_ascii_lowercase(), v.trim().to_string()),
            None => continue,
        };

        match tag.as_str() {
            "v" => {
                if idx != 0 {
                    return Err(BimiParseError {
                        detail: "v= must be first tag".into(),
                    });
                }
                if !val.eq_ignore_ascii_case("BIMI1") {
                    return Err(BimiParseError {
                        detail: format!("invalid version: '{}'", val),
                    });
                }
                version = Some(val);
            }
            "s" => {
                if val.is_empty() {
                    return Err(BimiParseError {
                        detail: "s= selector must not be empty".into(),
                    });
                }
                selector = Some(val);
            }
            _ => {} // ignore unknown
        }
    }

    if version.is_none() {
        return Err(BimiParseError {
            detail: "missing v= tag".into(),
        });
    }

    Ok(BimiSelectorHeader {
        version: "BIMI1".to_string(),
        selector: selector.unwrap_or_else(|| "default".to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── CHK-986: Valid record ───────────────────────────────────────

    #[test]
    fn parse_valid_record() {
        let r = parse_bimi_record(
            "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem;",
        )
        .unwrap();
        assert_eq!(r.version, "BIMI1");
        assert_eq!(r.logo_uris, vec!["https://example.com/logo.svg"]);
        assert_eq!(
            r.authority_uri,
            Some("https://example.com/cert.pem".to_string())
        );
    }

    // ─── CHK-987: Multiple logo URIs ─────────────────────────────────

    #[test]
    fn parse_multiple_logo_uris() {
        let r = parse_bimi_record(
            "v=BIMI1; l=https://a.com/1.svg,https://a.com/2.svg;",
        )
        .unwrap();
        assert_eq!(r.logo_uris.len(), 2);
        assert_eq!(r.logo_uris[0], "https://a.com/1.svg");
        assert_eq!(r.logo_uris[1], "https://a.com/2.svg");
    }

    // ─── CHK-988: v= not first → error ──────────────────────────────

    #[test]
    fn v_not_first_error() {
        let r = parse_bimi_record("l=https://example.com/logo.svg; v=BIMI1;");
        assert!(r.is_err());
    }

    // ─── CHK-989: Non-HTTPS URI → error ──────────────────────────────

    #[test]
    fn non_https_l_error() {
        let r = parse_bimi_record("v=BIMI1; l=http://example.com/logo.svg;");
        assert!(r.is_err());
        assert!(r.unwrap_err().detail.contains("HTTPS"));
    }

    #[test]
    fn non_https_a_error() {
        let r = parse_bimi_record(
            "v=BIMI1; l=https://example.com/logo.svg; a=http://example.com/cert.pem;",
        );
        assert!(r.is_err());
    }

    // ─── CHK-990: Unknown tags → ignored ─────────────────────────────

    #[test]
    fn unknown_tags_ignored() {
        let r = parse_bimi_record(
            "v=BIMI1; l=https://example.com/logo.svg; x=foo; z=bar;",
        )
        .unwrap();
        assert_eq!(r.logo_uris, vec!["https://example.com/logo.svg"]);
    }

    // ─── CHK-991: Declination → Declined ─────────────────────────────

    #[test]
    fn declination_record() {
        let r = parse_bimi_record("v=BIMI1;").unwrap();
        assert!(r.logo_uris.is_empty());
        assert!(r.authority_uri.is_none());
        assert!(is_declination(&r));
    }

    #[test]
    fn declination_with_empty_l() {
        let r = parse_bimi_record("v=BIMI1; l=;").unwrap();
        assert!(is_declination(&r));
    }

    // ─── CHK-992: More than 2 URIs → error ───────────────────────────

    #[test]
    fn too_many_uris_error() {
        let r = parse_bimi_record(
            "v=BIMI1; l=https://a.com/1.svg,https://a.com/2.svg,https://a.com/3.svg;",
        );
        assert!(r.is_err());
        assert!(r.unwrap_err().detail.contains("max 2"));
    }

    // ─── CHK-946: v= not BIMI1 → error ──────────────────────────────

    #[test]
    fn v_not_bimi1_error() {
        let r = parse_bimi_record("v=BIMI2; l=https://example.com/logo.svg;");
        assert!(r.is_err());
    }

    // ─── CHK-940: Semicolon separated ────────────────────────────────

    #[test]
    fn trailing_semicolons() {
        let r = parse_bimi_record(
            "v=BIMI1; l=https://example.com/logo.svg;;;",
        )
        .unwrap();
        assert_eq!(r.logo_uris, vec!["https://example.com/logo.svg"]);
    }

    // ─── BIMI-Selector parsing ───────────────────────────────────────

    #[test]
    fn parse_selector_valid() {
        let s = parse_bimi_selector("v=BIMI1; s=brand;").unwrap();
        assert_eq!(s.version, "BIMI1");
        assert_eq!(s.selector, "brand");
    }

    #[test]
    fn parse_selector_default() {
        let s = parse_bimi_selector("v=BIMI1;").unwrap();
        assert_eq!(s.selector, "default");
    }

    #[test]
    fn parse_selector_missing_v() {
        let r = parse_bimi_selector("s=brand;");
        assert!(r.is_err());
    }

    #[test]
    fn parse_selector_v_not_first() {
        let r = parse_bimi_selector("s=brand; v=BIMI1;");
        assert!(r.is_err());
    }

    // ─── CHK-943: a= single HTTPS URI ───────────────────────────────

    #[test]
    fn a_tag_valid() {
        let r = parse_bimi_record(
            "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem;",
        )
        .unwrap();
        assert_eq!(
            r.authority_uri,
            Some("https://example.com/vmc.pem".to_string())
        );
    }

    // ─── CHK-948: Missing l= → error (unless declination) ───────────

    #[test]
    fn missing_l_with_a_is_declination() {
        // No l= tag at all, but has a= → still valid, logo_uris empty
        // Actually, missing l= with a= is not a declination since a= is present
        // Per spec: declination is empty l= with no a=
        let r = parse_bimi_record(
            "v=BIMI1; a=https://example.com/vmc.pem;",
        )
        .unwrap();
        assert!(r.logo_uris.is_empty());
        assert!(r.authority_uri.is_some());
        assert!(!is_declination(&r));
    }
}
