# Learnings — Cycle 1, Lane 15: bimi-svg-validation

## FRICTION
- **quick-xml 0.37 API**: `e.local_name()` returns `QName`, need `.as_ref()` to get `&[u8]`. Attribute access via `e.attributes()` returns `Result<Attribute>` iterator. `attr.key.local_name()` for key bytes, `attr.unescape_value()` for decoded value string.
- **Event::Empty vs Event::Start**: Self-closing elements (`<rect/>`) emit `Event::Empty`, not `Event::Start`. Spec §11.1.1 explicitly flags this as a prior bug. Both branches must check prohibited elements and event handler attributes.
- **Title max length**: Spec §11.1.2 notes prior bug used 64 instead of 65. Used `MAX_TITLE_LENGTH = 65` (correct per spec §4.1).

## GAP
- **Spec says "external references (except XML namespace declarations)" are prohibited**: Not straightforward to detect at parse-time since `xmlns:` declarations are attributes, not elements. Decided to not block xmlns attributes but note this gap. The `xlink:href` with external URLs would need URL resolution which is overkill for a validator. The `javascript:` URI check covers the main attack vector.
- **viewBox square aspect**: Spec says "square aspect ratio (1:1)" but doesn't define tolerance. Used `(w - h).abs() > f64::EPSILON` which is strict float equality. Acceptable since viewBox values are typically integers.

## DECISION
- **Entity declaration check via string search before XML parsing**: `svg.contains("<!ENTITY")` runs before the XML parser sees the content. This is safer than relying on quick-xml to report entity declarations, since quick-xml's behavior with DTDs may vary. Belt-and-suspenders approach.
- **format_bimi_headers takes optional validated_svg parameter**: The caller is responsible for fetching+validating SVG and passing it in. This keeps the library HTTP-free. BIMI-Indicator is base64-encoded SVG per spec. Without VMC (no `validated_svg`), only BIMI-Location is produced.
- **BimiHeaders struct**: New struct with `location: String` and `indicator: Option<String>` fields. Cleaner than returning a tuple.
- **Security notes (CHK-1042, CHK-1043) are design-level concerns**: TLS 1.2 minimum is a caller responsibility (reqwest config). Lookalike domain prevention is out of scope. Both documented as non-blocking.

## SURPRISE
- quick-xml `Reader::from_str` doesn't require explicit buffer management (unlike `from_reader` which needs `Vec<u8>` buffer). Clean API for string input.
- The `size_exactly_at_limit` test required careful padding calculation — the SVG prefix/suffix structure must be valid XML while hitting exactly 32768 bytes.

## DEBT
- **CHK-1044 (strip BIMI-Location before processing)**: Already handled in lane 14's `strip_bimi_headers()`. Listed in lane 15 checkboxes as a security concern but implementation is reused from lane 14.
- **External reference detection is incomplete**: Only `javascript:` URIs are checked. Full external reference blocking (e.g., `xlink:href="http://..."`) would require URL parsing and protocol allowlisting. Current approach catches the security-critical cases.
