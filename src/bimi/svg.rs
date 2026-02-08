use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::fmt;

/// Maximum SVG file size: 32KB (32,768 bytes).
const MAX_SVG_SIZE: usize = 32_768;

/// Maximum title length in characters.
const MAX_TITLE_LENGTH: usize = 65;

/// Prohibited SVG elements.
const PROHIBITED_ELEMENTS: &[&[u8]] = &[
    b"script",
    b"animate",
    b"animateTransform",
    b"animateMotion",
    b"animateColor",
    b"set",
    b"image",
    b"foreignObject",
];

/// Prohibited URI schemes in attributes.
const PROHIBITED_URI_PREFIX: &str = "javascript:";

/// Event handler attribute prefix.
const EVENT_HANDLER_PREFIX: &str = "on";

/// Errors from SVG Tiny PS validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvgError {
    /// SVG exceeds 32KB size limit.
    TooLarge(usize),
    /// Root element is not <svg>.
    NotSvgRoot,
    /// Missing baseProfile="tiny-ps" attribute.
    MissingBaseProfile,
    /// Missing <title> element.
    MissingTitle,
    /// Title exceeds 65 characters.
    TitleTooLong(usize),
    /// viewBox uses comma delimiters instead of spaces.
    CommaViewBox,
    /// Non-square aspect ratio.
    NonSquareAspect,
    /// Prohibited element found.
    ProhibitedElement(String),
    /// Event handler attribute found.
    EventHandler(String),
    /// javascript: URI found.
    JavaScriptUri(String),
    /// Entity declaration found (XXE prevention).
    EntityDeclaration,
    /// External reference found.
    ExternalReference(String),
    /// XML parsing error.
    ParseError(String),
}

impl fmt::Display for SvgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SvgError::TooLarge(size) => {
                write!(f, "SVG exceeds 32KB limit: {} bytes", size)
            }
            SvgError::NotSvgRoot => write!(f, "root element is not <svg>"),
            SvgError::MissingBaseProfile => {
                write!(f, "missing baseProfile=\"tiny-ps\" attribute")
            }
            SvgError::MissingTitle => write!(f, "missing <title> element"),
            SvgError::TitleTooLong(len) => {
                write!(f, "title exceeds 65 characters: {} chars", len)
            }
            SvgError::CommaViewBox => {
                write!(f, "viewBox uses comma delimiters instead of spaces")
            }
            SvgError::NonSquareAspect => write!(f, "non-square aspect ratio"),
            SvgError::ProhibitedElement(name) => {
                write!(f, "prohibited element: <{}>", name)
            }
            SvgError::EventHandler(attr) => {
                write!(f, "event handler attribute: {}", attr)
            }
            SvgError::JavaScriptUri(attr) => {
                write!(f, "javascript: URI in attribute: {}", attr)
            }
            SvgError::EntityDeclaration => {
                write!(f, "entity declaration found (XXE prevention)")
            }
            SvgError::ExternalReference(detail) => {
                write!(f, "external reference: {}", detail)
            }
            SvgError::ParseError(msg) => write!(f, "XML parse error: {}", msg),
        }
    }
}

/// Validate SVG content against SVG Tiny PS profile.
///
/// Checks:
/// - Size limit (32KB)
/// - Root element is `<svg>` with `baseProfile="tiny-ps"`
/// - `<title>` element present (max 65 chars)
/// - Square aspect ratio via viewBox
/// - No prohibited elements (script, animate, image, foreignObject, etc.)
/// - No event handler attributes (`on*`)
/// - No `javascript:` URIs
/// - No `<!ENTITY>` declarations (XXE)
/// - viewBox is space-delimited (not comma)
pub fn validate_svg_tiny_ps(svg: &str) -> Result<(), SvgError> {
    // CHK-966/CHK-958: Size limit enforcement BEFORE parsing
    if svg.len() > MAX_SVG_SIZE {
        return Err(SvgError::TooLarge(svg.len()));
    }

    // CHK-963: Check for entity declarations before XML parsing (XXE prevention)
    if svg.contains("<!ENTITY") {
        return Err(SvgError::EntityDeclaration);
    }

    let mut reader = Reader::from_str(svg);
    reader.config_mut().trim_text(true);

    let mut found_svg_root = false;
    let mut has_base_profile = false;
    let mut has_title = false;
    let mut in_title = false;
    let mut title_text = String::new();
    let mut first_element = true;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let local_name = e.local_name();
                let name_bytes = local_name.as_ref();

                // First element must be <svg>
                if first_element {
                    first_element = false;
                    if name_bytes != b"svg" {
                        return Err(SvgError::NotSvgRoot);
                    }
                    found_svg_root = true;

                    // Check baseProfile and viewBox on <svg>
                    check_svg_root_attrs(e)?;
                    has_base_profile = true;
                    continue;
                }

                // Check if element is prohibited
                check_prohibited_element(name_bytes)?;

                // Check for title
                if name_bytes == b"title" {
                    in_title = true;
                    title_text.clear();
                }

                // Check attributes on Start elements
                check_element_attrs(e)?;
            }
            Ok(Event::Empty(ref e)) => {
                let local_name = e.local_name();
                let name_bytes = local_name.as_ref();

                if first_element {
                    first_element = false;
                    if name_bytes != b"svg" {
                        return Err(SvgError::NotSvgRoot);
                    }
                    // Self-closing <svg/> — not valid SVG but handle it
                    found_svg_root = true;
                    check_svg_root_attrs(e)?;
                    has_base_profile = true;
                    continue;
                }

                // Check if element is prohibited (Event::Empty too!)
                check_prohibited_element(name_bytes)?;

                // Check attributes on Empty (self-closing) elements
                check_element_attrs(e)?;
            }
            Ok(Event::Text(ref e)) => {
                if in_title {
                    match e.unescape() {
                        Ok(text) => title_text.push_str(&text),
                        Err(err) => {
                            return Err(SvgError::ParseError(format!(
                                "title text decode: {}",
                                err
                            )));
                        }
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let local_name = e.local_name();
                if local_name.as_ref() == b"title" && in_title {
                    in_title = false;
                    has_title = true;
                    // CHK-955: Title max 65 characters
                    if title_text.len() > MAX_TITLE_LENGTH {
                        return Err(SvgError::TitleTooLong(title_text.len()));
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SvgError::ParseError(format!("{}", e)));
            }
            _ => {}
        }
    }

    if !found_svg_root {
        return Err(SvgError::NotSvgRoot);
    }
    if !has_base_profile {
        return Err(SvgError::MissingBaseProfile);
    }
    if !has_title {
        return Err(SvgError::MissingTitle);
    }

    Ok(())
}

/// Check <svg> root element attributes for baseProfile and viewBox.
fn check_svg_root_attrs(e: &quick_xml::events::BytesStart<'_>) -> Result<(), SvgError> {
    let mut found_base_profile = false;
    let mut viewbox_value: Option<String> = None;

    for attr_result in e.attributes() {
        match attr_result {
            Ok(attr) => {
                let key = attr.key.local_name();
                let key_bytes = key.as_ref();

                if key_bytes == b"baseProfile" {
                    let val = attr
                        .unescape_value()
                        .map_err(|err| SvgError::ParseError(format!("baseProfile: {}", err)))?;
                    if val.as_ref() == "tiny-ps" {
                        found_base_profile = true;
                    } else {
                        return Err(SvgError::MissingBaseProfile);
                    }
                }

                if key_bytes == b"viewBox" {
                    let val = attr
                        .unescape_value()
                        .map_err(|err| SvgError::ParseError(format!("viewBox: {}", err)))?;
                    viewbox_value = Some(val.to_string());
                }

                // Check for event handlers and javascript: URIs on root too
                check_attr_security(key_bytes, &attr)?;
            }
            Err(err) => {
                return Err(SvgError::ParseError(format!("attribute: {}", err)));
            }
        }
    }

    if !found_base_profile {
        return Err(SvgError::MissingBaseProfile);
    }

    // Validate viewBox if present
    if let Some(ref vb) = viewbox_value {
        // CHK-957: viewBox MUST be space-delimited, NOT comma-delimited
        if vb.contains(',') {
            return Err(SvgError::CommaViewBox);
        }

        // CHK-956: Square aspect ratio (width == height)
        let parts: Vec<&str> = vb.split_whitespace().collect();
        if parts.len() == 4 {
            if let (Ok(w), Ok(h)) = (parts[2].parse::<f64>(), parts[3].parse::<f64>()) {
                if (w - h).abs() > f64::EPSILON && w > 0.0 && h > 0.0 {
                    return Err(SvgError::NonSquareAspect);
                }
            }
        }
    }

    Ok(())
}

/// Check if an element name is prohibited.
fn check_prohibited_element(name: &[u8]) -> Result<(), SvgError> {
    for &prohibited in PROHIBITED_ELEMENTS {
        if name.eq_ignore_ascii_case(prohibited) {
            let name_str = String::from_utf8_lossy(name).to_string();
            return Err(SvgError::ProhibitedElement(name_str));
        }
    }
    Ok(())
}

/// Check attributes on a Start or Empty element for security issues.
fn check_element_attrs(e: &quick_xml::events::BytesStart<'_>) -> Result<(), SvgError> {
    for attr_result in e.attributes() {
        match attr_result {
            Ok(attr) => {
                let key = attr.key.local_name();
                check_attr_security(key.as_ref(), &attr)?;
            }
            Err(err) => {
                return Err(SvgError::ParseError(format!("attribute: {}", err)));
            }
        }
    }
    Ok(())
}

/// Check a single attribute for event handlers and javascript: URIs.
fn check_attr_security(
    key_bytes: &[u8],
    attr: &quick_xml::events::attributes::Attribute<'_>,
) -> Result<(), SvgError> {
    let key_str = std::str::from_utf8(key_bytes).unwrap_or("");

    // CHK-959/CHK-1014: Event handler attributes (on*)
    if key_str.to_ascii_lowercase().starts_with(EVENT_HANDLER_PREFIX) && key_str.len() > 2 {
        return Err(SvgError::EventHandler(key_str.to_string()));
    }

    // CHK-964: javascript: URIs in href, xlink:href, src, etc.
    let val = attr
        .unescape_value()
        .map_err(|err| SvgError::ParseError(format!("attr value: {}", err)))?;
    let val_trimmed = val.trim().to_ascii_lowercase();
    if val_trimmed.starts_with(PROHIBITED_URI_PREFIX) {
        return Err(SvgError::JavaScriptUri(key_str.to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── CHK-1008: Valid SVG Tiny PS → pass ──────────────────────────

    #[test]
    fn valid_svg_tiny_ps() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Example Logo</title>
  <rect width="100" height="100" fill="red"/>
</svg>"#;
        assert!(validate_svg_tiny_ps(svg).is_ok());
    }

    // ─── CHK-1009: Missing baseProfile → fail ────────────────────────

    #[test]
    fn missing_base_profile() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" viewBox="0 0 100 100">
  <title>Logo</title>
  <rect width="100" height="100" fill="red"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::MissingBaseProfile)
        );
    }

    // ─── CHK-1010: Contains <script> → fail ──────────────────────────

    #[test]
    fn script_element_prohibited() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <script>alert('xss')</script>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("script".into()))
        );
    }

    // ─── CHK-1011: Exceeds 32KB → fail ───────────────────────────────

    #[test]
    fn exceeds_32kb() {
        let svg = "x".repeat(MAX_SVG_SIZE + 1);
        match validate_svg_tiny_ps(&svg) {
            Err(SvgError::TooLarge(size)) => assert_eq!(size, MAX_SVG_SIZE + 1),
            other => panic!("expected TooLarge, got {:?}", other),
        }
    }

    // ─── CHK-1012: Missing <title> → fail ────────────────────────────

    #[test]
    fn missing_title() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <rect width="100" height="100" fill="red"/>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::MissingTitle));
    }

    // ─── CHK-1013: Comma-delimited viewBox → fail ────────────────────

    #[test]
    fn comma_viewbox() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0,0,100,100">
  <title>Logo</title>
  <rect width="100" height="100" fill="red"/>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::CommaViewBox));
    }

    // ─── CHK-1014: Event handler on self-closing element → fail ──────

    #[test]
    fn event_handler_self_closing() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <rect onclick="alert(1)" width="100" height="100" fill="red"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::EventHandler("onclick".into()))
        );
    }

    // ─── CHK-1015: javascript: URI in href → fail ────────────────────

    #[test]
    fn javascript_uri_in_href() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <a href="javascript:alert(1)"><rect width="100" height="100"/></a>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::JavaScriptUri("href".into()))
        );
    }

    // ─── CHK-1016: <animate> element → fail ──────────────────────────

    #[test]
    fn animate_element_prohibited() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <animate attributeName="opacity" from="1" to="0" dur="1s"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("animate".into()))
        );
    }

    // ─── CHK-1017: <image> element → fail ────────────────────────────

    #[test]
    fn image_element_prohibited() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <image href="data:image/png;base64,abc" width="100" height="100"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("image".into()))
        );
    }

    // ─── CHK-1018: <foreignObject> element → fail ────────────────────

    #[test]
    fn foreign_object_prohibited() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <foreignObject width="100" height="100">
    <div xmlns="http://www.w3.org/1999/xhtml">Hello</div>
  </foreignObject>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("foreignObject".into()))
        );
    }

    // ─── CHK-1019: Title exceeding 65 characters → fail ──────────────

    #[test]
    fn title_too_long() {
        let long_title = "A".repeat(66);
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>{}</title>
  <rect width="100" height="100" fill="red"/>
</svg>"#,
            long_title
        );
        assert_eq!(
            validate_svg_tiny_ps(&svg),
            Err(SvgError::TitleTooLong(66))
        );
    }

    #[test]
    fn title_exactly_65_chars_ok() {
        let title = "A".repeat(65);
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>{}</title>
  <rect width="100" height="100" fill="red"/>
</svg>"#,
            title
        );
        assert!(validate_svg_tiny_ps(&svg).is_ok());
    }

    // ─── CHK-1020: Entity declaration → fail (XXE prevention) ────────

    #[test]
    fn entity_declaration_xxe() {
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

    // ─── Additional: Non-square aspect ratio ─────────────────────────

    #[test]
    fn non_square_aspect_ratio() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 200 100">
  <title>Logo</title>
  <rect width="200" height="100" fill="red"/>
</svg>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::NonSquareAspect));
    }

    // ─── Additional: Event handler on Start element ──────────────────

    #[test]
    fn event_handler_start_element() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <g onclick="alert(1)"><rect width="100" height="100"/></g>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::EventHandler("onclick".into()))
        );
    }

    // ─── Additional: animateTransform prohibited ─────────────────────

    #[test]
    fn animate_transform_prohibited() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title>
  <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="1s"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::ProhibitedElement("animateTransform".into()))
        );
    }

    // ─── Additional: Root not <svg> ──────────────────────────────────

    #[test]
    fn root_not_svg() {
        let svg = r#"<div>Not an SVG</div>"#;
        assert_eq!(validate_svg_tiny_ps(svg), Err(SvgError::NotSvgRoot));
    }

    // ─── Additional: Wrong baseProfile value ─────────────────────────

    #[test]
    fn wrong_base_profile_value() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="full" viewBox="0 0 100 100">
  <title>Logo</title>
  <rect width="100" height="100" fill="red"/>
</svg>"#;
        assert_eq!(
            validate_svg_tiny_ps(svg),
            Err(SvgError::MissingBaseProfile)
        );
    }

    // ─── Additional: Size exactly at limit ───────────────────────────

    #[test]
    fn size_exactly_at_limit() {
        // Build a valid SVG that's exactly MAX_SVG_SIZE bytes
        let prefix = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>L</title><rect fill="r"#;
        let suffix = r#"ed"/></svg>"#;
        let padding_needed = MAX_SVG_SIZE - prefix.len() - suffix.len();
        let padding = " ".repeat(padding_needed);
        let svg = format!("{}{}{}", prefix, padding, suffix);
        assert_eq!(svg.len(), MAX_SVG_SIZE);
        assert!(validate_svg_tiny_ps(&svg).is_ok());
    }
}
