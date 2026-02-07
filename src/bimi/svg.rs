use quick_xml::events::Event;
use quick_xml::Reader;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Maximum SVG file size allowed by BIMI (32 KiB).
const MAX_SVG_SIZE: usize = 32_768;

/// Maximum title length in characters.
const MAX_TITLE_LEN: usize = 65;

/// Elements prohibited in SVG Tiny PS.
const PROHIBITED_ELEMENTS: &[&str] = &[
    "script",
    "animate",
    "animateTransform",
    "animateMotion",
    "animateColor",
    "set",
    "image",
    "foreignObject",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvgError {
    TooLarge(usize),
    NotSvgRoot,
    MissingBaseProfile,
    InvalidBaseProfile(String),
    MissingTitle,
    TitleTooLong(usize),
    ProhibitedElement(String),
    ProhibitedAttribute(String),
    ExternalReference(String),
    EntityDeclaration,
    NonSquareViewBox,
    CommaInViewBox,
    ParseError(String),
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate an SVG string against the SVG Tiny PS (Portable/Secure) profile
/// required by BIMI (RFC 9495 / Brand Indicators for Message Identification).
pub fn validate_svg_tiny_ps(svg: &str) -> Result<(), SvgError> {
    // 1. Size check
    if svg.len() > MAX_SVG_SIZE {
        return Err(SvgError::TooLarge(svg.len()));
    }

    // 2. Entity declaration check (XXE prevention)
    check_entity_declarations(svg)?;

    // 3. Parse and validate structure
    let mut reader = Reader::from_str(svg);

    let mut seen_root = false;
    let mut in_title = false;
    let mut title_text = String::new();
    let mut has_title = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let qname = e.name();
                let name = std::str::from_utf8(qname.as_ref()).unwrap_or("");

                if !seen_root {
                    seen_root = true;
                    if !name.eq_ignore_ascii_case("svg") {
                        return Err(SvgError::NotSvgRoot);
                    }
                    validate_root_attrs(e)?;
                } else {
                    check_prohibited_element(name)?;
                }

                check_prohibited_attrs(e)?;

                if name.eq_ignore_ascii_case("title") {
                    in_title = true;
                    title_text.clear();
                }
            }
            Ok(Event::Empty(ref e)) => {
                let qname = e.name();
                let name = std::str::from_utf8(qname.as_ref()).unwrap_or("");

                if !seen_root {
                    seen_root = true;
                    if !name.eq_ignore_ascii_case("svg") {
                        return Err(SvgError::NotSvgRoot);
                    }
                    validate_root_attrs(e)?;
                } else {
                    check_prohibited_element(name)?;
                }

                check_prohibited_attrs(e)?;
            }
            Ok(Event::End(ref e)) => {
                let qname = e.name();
                let name = std::str::from_utf8(qname.as_ref()).unwrap_or("");
                if name.eq_ignore_ascii_case("title") && in_title {
                    in_title = false;
                    has_title = true;
                    let len = title_text.chars().count();
                    if len > MAX_TITLE_LEN {
                        return Err(SvgError::TitleTooLong(len));
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_title {
                    let text = e.unescape().unwrap_or_default();
                    title_text.push_str(&text);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SvgError::ParseError(e.to_string())),
            _ => {}
        }
    }

    if !seen_root {
        return Err(SvgError::NotSvgRoot);
    }
    if !has_title {
        return Err(SvgError::MissingTitle);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Scan for `<!ENTITY` declarations (case-insensitive) to prevent XXE.
fn check_entity_declarations(svg: &str) -> Result<(), SvgError> {
    let lower = svg.to_ascii_lowercase();
    if lower.contains("<!entity") {
        return Err(SvgError::EntityDeclaration);
    }
    Ok(())
}

/// Validate the root `<svg>` element attributes: baseProfile and viewBox.
fn validate_root_attrs(e: &quick_xml::events::BytesStart<'_>) -> Result<(), SvgError> {
    let mut base_profile: Option<String> = None;
    let mut view_box: Option<String> = None;

    for attr in e.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        let val = std::str::from_utf8(&attr.value).unwrap_or("");

        if key.eq_ignore_ascii_case("baseProfile") {
            base_profile = Some(val.to_string());
        } else if key == "viewBox" {
            view_box = Some(val.to_string());
        }
    }

    // baseProfile must be present and equal to "tiny-ps"
    match base_profile {
        None => return Err(SvgError::MissingBaseProfile),
        Some(ref v) if v.eq_ignore_ascii_case("tiny-ps") => {}
        Some(v) => return Err(SvgError::InvalidBaseProfile(v)),
    }

    // viewBox validation (if present)
    if let Some(vb) = view_box {
        validate_viewbox(&vb)?;
    }

    Ok(())
}

/// Validate the viewBox attribute value: must be space-delimited, square
/// aspect ratio.
fn validate_viewbox(vb: &str) -> Result<(), SvgError> {
    if vb.contains(',') {
        return Err(SvgError::CommaInViewBox);
    }

    let parts: Vec<&str> = vb.split_ascii_whitespace().collect();
    if parts.len() == 4 {
        let width: f64 = parts[2].parse().unwrap_or(f64::NAN);
        let height: f64 = parts[3].parse().unwrap_or(f64::NAN);
        if width.is_nan() || height.is_nan() {
            return Err(SvgError::ParseError(format!(
                "invalid viewBox dimensions: {vb}"
            )));
        }
        if (width - height).abs() > f64::EPSILON {
            return Err(SvgError::NonSquareViewBox);
        }
    }

    Ok(())
}

/// Check whether an element name is prohibited in SVG Tiny PS.
fn check_prohibited_element(name: &str) -> Result<(), SvgError> {
    // Strip namespace prefix if present (e.g. "svg:script" -> "script")
    let local = name.rsplit(':').next().unwrap_or(name);
    for &prohibited in PROHIBITED_ELEMENTS {
        if local.eq_ignore_ascii_case(prohibited) {
            return Err(SvgError::ProhibitedElement(name.to_string()));
        }
    }
    Ok(())
}

/// Check all attributes on an element for prohibited patterns:
/// - Event handler attributes (on*)
/// - javascript: URIs in href/xlink:href
/// - External references in href/xlink:href
fn check_prohibited_attrs(e: &quick_xml::events::BytesStart<'_>) -> Result<(), SvgError> {
    let qname = e.name();
    let elem_name = std::str::from_utf8(qname.as_ref()).unwrap_or("");

    for attr in e.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        let val = std::str::from_utf8(&attr.value).unwrap_or("");
        let key_lower = key.to_ascii_lowercase();

        // Event handlers: any attribute starting with "on"
        if key_lower.starts_with("on") {
            return Err(SvgError::ProhibitedAttribute(key.to_string()));
        }

        // href / xlink:href checks
        if key_lower == "href" || key_lower == "xlink:href" {
            let val_trimmed = val.trim();

            // javascript: URI
            if val_trimmed
                .to_ascii_lowercase()
                .starts_with("javascript:")
            {
                return Err(SvgError::ProhibitedAttribute(format!(
                    "{key}=\"{val}\""
                )));
            }

            // External reference (not a fragment-only reference)
            // Skip namespace declarations on the root <svg> element
            if !val_trimmed.starts_with('#') && !elem_name.eq_ignore_ascii_case("svg") {
                return Err(SvgError::ExternalReference(val.to_string()));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Brand Logo</title>
  <circle cx="50" cy="50" r="40" fill="blue"/>
</svg>"#;

    // -- valid cases --------------------------------------------------------

    #[test]
    fn valid_svg_tiny_ps() {
        assert_eq!(validate_svg_tiny_ps(VALID_SVG), Ok(()));
    }

    #[test]
    fn valid_with_content() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 200 200">
  <title>Complex Logo</title>
  <rect x="10" y="10" width="80" height="80" fill="red"/>
  <circle cx="100" cy="100" r="50" fill="green"/>
  <path d="M 10 80 Q 95 10 180 80" stroke="black" fill="none"/>
  <polygon points="100,10 40,198 190,78 10,78 160,198" fill="lime"/>
  <text x="50" y="150" font-size="12">Brand</text>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Ok(()));
    }

    #[test]
    fn square_viewbox() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Ok(()));
    }

    #[test]
    fn title_exactly_65() {
        let title = "A".repeat(65);
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>{title}</title>
</svg>"#
        );
        assert_eq!(validate_svg_tiny_ps(&svg), Ok(()));
    }

    // -- size ---------------------------------------------------------------

    #[test]
    fn too_large() {
        let padding = " ".repeat(33_000);
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <!-- {padding} -->
</svg>"#
        );
        assert!(svg.len() > MAX_SVG_SIZE);
        assert_eq!(
            validate_svg_tiny_ps(&svg),
            Err(SvgError::TooLarge(svg.len()))
        );
    }

    // -- root element -------------------------------------------------------

    #[test]
    fn not_svg_root() {
        let svg = r#"<html><body>not svg</body></html>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::NotSvgRoot));
    }

    // -- baseProfile --------------------------------------------------------

    #[test]
    fn missing_base_profile() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" viewBox="0 0 100 100">
  <title>Logo</title>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::MissingBaseProfile)
        );
    }

    #[test]
    fn wrong_base_profile() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="full" viewBox="0 0 100 100">
  <title>Logo</title>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::InvalidBaseProfile("full".into()))
        );
    }

    // -- title --------------------------------------------------------------

    #[test]
    fn missing_title() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <circle cx="50" cy="50" r="40" fill="blue"/>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::MissingTitle));
    }

    #[test]
    fn title_too_long() {
        let title = "A".repeat(66);
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>{title}</title>
</svg>"#
        );
        assert_eq!(validate_svg_tiny_ps(&svg), Err(SvgError::TitleTooLong(66)));
    }

    // -- prohibited elements ------------------------------------------------

    #[test]
    fn script_element() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <script>alert('xss')</script>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("script".into()))
        );
    }

    #[test]
    fn animate_element() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <animate attributeName="cx" from="50" to="100" dur="1s"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("animate".into()))
        );
    }

    #[test]
    fn image_element() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <image href="https://example.com/logo.png" width="100" height="100"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("image".into()))
        );
    }

    #[test]
    fn foreign_object() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <foreignObject width="100" height="100">
    <div>HTML inside SVG</div>
  </foreignObject>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("foreignObject".into()))
        );
    }

    // -- prohibited attributes ----------------------------------------------

    #[test]
    fn onclick_attribute() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <circle cx="50" cy="50" r="40" fill="blue" onclick="alert('xss')"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedAttribute("onclick".into()))
        );
    }

    #[test]
    fn onload_attribute() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <rect x="0" y="0" width="100" height="100" onload="alert('xss')"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedAttribute("onload".into()))
        );
    }

    #[test]
    fn self_closing_with_event_handler() {
        // v3 bug fix: Empty (self-closing) events must also be checked
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <rect x="0" y="0" width="50" height="50" onclick="evil()"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedAttribute("onclick".into()))
        );
    }

    #[test]
    fn javascript_href() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <a href="javascript:alert('xss')">
    <circle cx="50" cy="50" r="40" fill="blue"/>
  </a>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedAttribute(
                "href=\"javascript:alert('xss')\"".into()
            ))
        );
    }

    // -- external references ------------------------------------------------

    #[test]
    fn external_reference() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <use href="https://evil.com/shape"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ExternalReference(
                "https://evil.com/shape".into()
            ))
        );
    }

    #[test]
    fn internal_reference_ok() {
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <defs>
    <circle id="myCircle" cx="50" cy="50" r="40" fill="blue"/>
  </defs>
  <use href="#myCircle"/>
</svg>"##;
        assert_eq!(validate_svg_tiny_ps(svg), Ok(()));
    }

    // -- entity declaration -------------------------------------------------

    #[test]
    fn entity_declaration() {
        let svg = r#"<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <text>&xxe;</text>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::EntityDeclaration));
    }

    #[test]
    fn entity_declaration_case_insensitive() {
        let svg = r#"<?xml version="1.0"?>
<!DOCTYPE svg [
  <!entity xxe "pwned">
]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::EntityDeclaration));
    }

    // -- viewBox ------------------------------------------------------------

    #[test]
    fn comma_viewbox() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0,0,100,100">
  <title>Logo</title>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::CommaInViewBox));
    }

    #[test]
    fn non_square_viewbox() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 200">
  <title>Logo</title>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::NonSquareViewBox));
    }

    // -- parse error --------------------------------------------------------

    #[test]
    fn parse_error_malformed_xml() {
        // Unmatched close tag — quick-xml reports IllFormed error
        let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.2\" \
                    baseProfile=\"tiny-ps\" viewBox=\"0 0 100 100\">\
                    <title>Logo</title>\
                    </wrong>\
                    </svg>";
        assert!(matches!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ParseError(_))
        ));
    }

    // -- empty / edge cases -------------------------------------------------

    #[test]
    fn empty_input() {
        assert_eq!(validate_svg_tiny_ps(""), Err(SvgError::NotSvgRoot));
    }

    #[test]
    fn no_viewbox_is_ok() {
        // viewBox is optional; if absent we skip the square check
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Logo</title>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Ok(()));
    }

    #[test]
    fn base_profile_case_insensitive() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="Tiny-PS" viewBox="0 0 50 50">
  <title>Logo</title>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Ok(()));
    }
}
