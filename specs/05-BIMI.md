# BIMI Implementation Spec (Brand Indicators for Message Identification)

> LLM-actionable specification for implementing BIMI logo discovery and validation

**Note**: BIMI is defined by Internet-Drafts (draft-brand-indicators-for-message-identification), not a published RFC. VMC validation is defined in draft-fetch-validation-vmc-wchuang.

## Overview

BIMI enables domain owners to publish brand logos in DNS that email clients display next to authenticated messages. It requires DMARC pass with enforcement policy (quarantine/reject). Optional VMC (Verified Mark Certificate) provides cryptographic proof of logo ownership.

**Scope**: DNS record discovery, record parsing, DMARC eligibility check, SVG Tiny PS validation. VMC certificate chain validation. Logo fetching is caller responsibility (requires HTTPS client).

---

## 1. Data Types

### 1.1 BIMI DNS Record

```rust
pub struct BimiRecord {
    pub version: String,                // "BIMI1" (required, must be first tag)
    pub logo_uris: Vec<String>,         // l= tag: 1-2 HTTPS URIs (comma-separated)
    pub authority_uri: Option<String>,   // a= tag: VMC certificate location (HTTPS)
}
```

- [ ] `v=` — version, MUST be "BIMI1", MUST be first tag
- [ ] `l=` — logo URI(s), comma-separated, 1-2 URIs, MUST be HTTPS
- [ ] `a=` — authority evidence URI (VMC), MUST be HTTPS if present
- [ ] Empty `l=` with no `a=` → declination record (domain opts out)
- [ ] Unknown tags → ignored

### 1.2 BIMI-Selector Header

```rust
pub struct BimiSelectorHeader {
    pub version: String,   // "BIMI1"
    pub selector: String,  // default: "default"
}
```

- [ ] Optional header in email, SHOULD be DKIM-signed
- [ ] Format: `BIMI-Selector: v=BIMI1; s=<selector>;`

### 1.3 BIMI Result

```rust
pub enum BimiResult {
    Pass,       // validated successfully
    None,       // no BIMI record found
    Fail,       // validation failure
    TempError,  // DNS or fetch failure
    Skipped,    // DMARC not eligible
    Declined,   // domain published declination record
}

pub struct BimiValidationResult {
    pub result: BimiResult,
    pub domain: String,
    pub selector: String,
    pub logo_uri: Option<String>,
    pub authority_uri: Option<String>,
    pub logo_svg: Option<String>,       // validated SVG content (caller fetches)
}
```

---

## 2. Record Discovery

### 2.1 DNS Query

- [ ] Query: `<selector>._bimi.<author-domain>` TXT record
- [ ] Default selector: "default"
- [ ] Custom selector: from BIMI-Selector header s= tag
- [ ] If no record at author domain → fallback to `<selector>._bimi.<organizational-domain>`
- [ ] Filter: records starting with `v=`
- [ ] Exactly one valid record required: parse ALL TXT records, count valid BIMI records, multiple valid → Fail (do NOT silently pick first)

### 2.2 DMARC Eligibility (MUST check before BIMI lookup)

- [ ] DMARC result MUST be Pass (disposition == Pass)
- [ ] DMARC policy MUST be `quarantine` or `reject` (NOT `none`)
- [ ] DMARC pct MUST be 100: access `dmarc_result.record` and verify `record.percent == 100`. pct < 100 → NOT eligible.
- [ ] SPF or DKIM alignment: `dmarc_result.dkim_aligned || dmarc_result.spf_aligned` (redundant with Pass disposition but spec-mandated — check explicitly)

### 2.3 Sender-Inserted Header Removal

- [ ] Before BIMI processing, strip any pre-existing `BIMI-Location` and `BIMI-Indicator` headers from the message
- [ ] These headers are receiver-only; senders MUST NOT insert them
- [ ] If present, treat as potentially malicious and remove before evaluation

---

## 3. Record Parsing

### 3.1 Tag-Value Parsing

- [ ] Semicolon-separated tag=value pairs
- [ ] First tag MUST be `v=BIMI1`
- [ ] `l=` tag: comma-separated URIs, each MUST be HTTPS
- [ ] `a=` tag: single HTTPS URI
- [ ] Max 2 logo URIs in `l=`
- [ ] Unknown tags → ignored

### 3.2 Validation Rules

- [ ] v= not first → error
- [ ] v= not "BIMI1" → error
- [ ] Missing l= → error (unless declination)
- [ ] Non-HTTPS URI → error
- [ ] More than 2 logo URIs → error

### 3.3 Declination Record

- [ ] `v=BIMI1;` (empty l=, no a=) → domain explicitly opts out
- [ ] Return BimiResult::Declined

---

## 4. SVG Tiny PS Validation

### 4.1 Profile: SVG Portable/Secure

- [ ] Root element MUST be `<svg>`
- [ ] `baseProfile="tiny-ps"` attribute required
- [ ] `<title>` element required (max 65 characters)
- [ ] Square aspect ratio (1:1)
- [ ] viewBox space-delimited (NOT comma-delimited)
- [ ] Maximum size: 32KB (32,768 bytes)

### 4.2 Prohibited Elements

- [ ] `<script>` — no scripts
- [ ] External references (except XML namespace declarations)
- [ ] Animations (`<animate>`, `<animateTransform>`, etc.)
- [ ] Embedded raster images (`<image>` with base64 PNG/JPG)
- [ ] `<!ENTITY>` declarations (XXE prevention)
- [ ] `javascript:` URIs

### 4.3 Security Validation

- [ ] XML bomb detection (entity expansion depth limit)
- [ ] Size limit enforcement before parsing
- [ ] No external resource loading

---

## 5. VMC (Verified Mark Certificate) Validation

### 5.1 VMC Structure

- [ ] X.509 certificate with BIMI-specific extensions
- [ ] Extended Key Usage OID: `1.3.6.1.5.5.7.3.31` (id-kp-BrandIndicatorforMessageIdentification)
- [ ] LogoType extension (RFC 3709): contains SVG as `data:image/svg+xml;base64,<data>` URI
- [ ] Subject Alternative Names: `<selector>._bimi.<domain>` DNS names

### 5.2 VMC Validation Steps

- [ ] Parse PEM certificate chain (VMC first, then issuer chain)
- [ ] Validate certificate chain to trusted BIMI root CA
- [ ] Check validity period (not expired, not before)
- [ ] Check revocation status (CRL)
- [ ] Validate EKU contains BIMI OID
- [ ] Match SAN to `<selector>._bimi.<author-domain>`
- [ ] Extract SVG from LogoType extension
- [ ] Validate extracted SVG against SVG Tiny PS profile
- [ ] Compare logo hash: DNS-fetched logo MUST match VMC-embedded logo

### 5.3 Certificate Chain Rules

- [ ] PEM encoding required
- [ ] Order: VMC → Intermediate CA(s) → optional Root
- [ ] Out-of-order → reject
- [ ] Duplicate certificates → reject
- [ ] Multiple VMCs → reject

---

## 6. Validation Flow

```
1. Check DMARC eligibility (pass + quarantine/reject + pct=100)
2. Extract author domain from From header
3. Extract selector from BIMI-Selector header (or use "default")
4. DNS lookup: <selector>._bimi.<domain>
5. Parse BIMI record
6. If declination record → Declined
7. If a= present: fetch and validate VMC
8. Fetch logo from l= URI (caller responsibility)
9. Validate SVG Tiny PS profile
10. If VMC present: compare logo hash with VMC-embedded logo
11. Pass → add BIMI-Location and BIMI-Indicator headers
```

---

## 7. API Design

```rust
pub struct BimiVerifier<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> BimiVerifier<R> {
    /// Discover and parse BIMI record. Does NOT fetch logo or VMC.
    pub async fn discover(
        &self,
        author_domain: &str,
        selector: Option<&str>,
        dmarc_result: &DmarcResult,
    ) -> BimiValidationResult;
}

/// Validate SVG content against SVG Tiny PS profile.
pub fn validate_svg_tiny_ps(svg: &str) -> Result<(), SvgError>;

/// Parse BIMI-Selector header value.
pub fn parse_bimi_selector(header_value: &str) -> Result<BimiSelectorHeader, String>;
```

**Caller responsibilities:**
- Fetch logo SVG via HTTPS (reqwest or similar)
- Fetch VMC PEM via HTTPS
- VMC certificate chain validation (requires X.509 library)

---

## 8. Test Cases

### 8.1 Record Parsing

- [ ] Valid: `v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem;`
- [ ] Multiple logo URIs: `l=https://a.com/1.svg,https://a.com/2.svg`
- [ ] v= not first → error
- [ ] Non-HTTPS URI → error
- [ ] Unknown tags → ignored
- [ ] Declination: `v=BIMI1;` → Declined
- [ ] More than 2 URIs → error

### 8.2 DMARC Eligibility

- [ ] DMARC pass + quarantine → eligible
- [ ] DMARC pass + reject → eligible
- [ ] DMARC pass + none → NOT eligible
- [ ] DMARC fail → NOT eligible
- [ ] pct < 100 → NOT eligible (construct DmarcResult with record.percent=50, verify rejection)
- [ ] pct=100 explicit → eligible
- [ ] Alignment check: dkim_aligned=true → eligible
- [ ] Alignment check: both dkim_aligned=false and spf_aligned=false → NOT eligible (even if disposition=Pass, which shouldn't normally happen, but defensive)

### 8.3 Discovery

- [ ] Record at author domain → use it
- [ ] No record at author domain, record at org domain → use fallback
- [ ] No record anywhere → None
- [ ] DNS TempFail → TempError
- [ ] Custom selector via BIMI-Selector header
- [ ] Multiple valid BIMI records at same DNS name → Fail (not first-wins)
- [ ] One valid + one invalid record → use the valid one (invalid silently skipped)

### 8.4 SVG Validation

- [ ] Valid SVG Tiny PS → pass
- [ ] Missing baseProfile → fail
- [ ] Contains `<script>` → fail
- [ ] Exceeds 32KB → fail
- [ ] Missing `<title>` → fail
- [ ] Comma-delimited viewBox → fail
- [ ] Event handler on self-closing element: `<rect onclick="x"/>` → fail (Event::Empty, not just Event::Start)
- [ ] `javascript:` URI in href → fail
- [ ] `<animate>` element → fail
- [ ] `<image>` element → fail
- [ ] `<foreignObject>` element → fail
- [ ] Title exceeding 65 characters → fail
- [ ] Entity declaration (`<!ENTITY`) → fail (XXE prevention)

### 8.5 VMC Validation

- [ ] Valid VMC: PEM cert with BIMI EKU OID `1.3.6.1.5.5.7.3.31` → pass
- [ ] Missing BIMI EKU OID → fail
- [ ] SAN matches `<selector>._bimi.<domain>` → pass
- [ ] SAN mismatch → fail
- [ ] Expired certificate → fail
- [ ] Not-yet-valid certificate → fail
- [ ] Extract SVG from LogoType extension (RFC 3709) → validate as SVG Tiny PS
- [ ] Logo hash comparison: DNS-fetched logo matches VMC-embedded logo → pass
- [ ] Logo hash comparison: mismatch → fail
- [ ] PEM chain: VMC → Intermediate → Root, validate chain
- [ ] Out-of-order PEM chain → reject
- [ ] Multiple VMC certificates in chain → reject

### 8.6 Header Generation

- [ ] BIMI pass → `format_bimi_headers()` produces `BIMI-Location` header with logo URI
- [ ] BIMI pass with VMC → `BIMI-Indicator` header with base64-encoded SVG
- [ ] BIMI fail/none/declined → `format_bimi_headers()` returns None

### 8.7 Sender-Inserted Header Removal

- [ ] Message with pre-existing `BIMI-Location` header → header stripped before evaluation
- [ ] Message with pre-existing `BIMI-Indicator` header → header stripped before evaluation
- [ ] Message with no BIMI headers → no-op

---

## 9. Security Considerations

- [ ] Logo size limit (32KB) prevents resource exhaustion
- [ ] XXE prevention: reject `<!ENTITY>` declarations
- [ ] Script injection: reject `<script>`, `javascript:` URIs
- [ ] TLS 1.2 minimum for logo and VMC fetch
- [ ] BIMI does NOT prevent lookalike domains — separate reputation system needed
- [ ] Remove sender-inserted BIMI-Location headers before processing

---

## 10. Dependencies

- [ ] DMARC module (for eligibility check)
- [ ] DNS resolver (shared DnsResolver trait)
- [ ] XML parser (for SVG validation): `quick-xml` or similar
- [ ] X.509 library (for VMC): `x509-parser` or `webpki`
- [ ] Optional: `reqwest` for HTTPS fetching (caller can provide)

---

## 11. Implementation Learnings

### 11.1 v3 Bugs (MUST fix in v4)

#### 11.1.1 SVG Event Handler Bypass on Self-Closing Elements (SECURITY)
- `validate_svg_tiny_ps()` checked `on*` event handler attributes only on `Event::Start` elements
- Self-closing elements (`<rect onclick="alert(1)"/>`) emit `Event::Empty`, not `Event::Start`
- **FIX**: Add the same `on*` attribute check to the `Event::Empty` branch. Both Start and Empty must reject event handlers.

#### 11.1.2 SVG Title Max Length Off-by-One
- v3 used `MAX_TITLE_LENGTH = 64` (spec §4.1 says max 65 characters)
- **FIX**: Change constant to 65.

### 11.2 v3 Gaps (MUST implement in v4)

#### 11.2.1 SVG Validator Not Wired Into Discovery
- `validate_svg_tiny_ps()` exists as standalone function but is never called from `BimiVerifier::discover()`
- Design decision: discover() returns logo_uri, caller fetches SVG, then calls validate_svg_tiny_ps() separately
- This is correct (library doesn't do HTTP fetching), but the API should make the flow clear
- Consider adding a `validate_logo(&self, svg: &str) -> Result<(), SvgError>` convenience method on BimiVerifier

#### 11.2.2 VMC Entirely Unimplemented (~15 spec items)
- No certificate parsing, chain validation, EKU check, SAN matching, LogoType extraction, or revocation check
- Requires `x509-parser` or `webpki` crate
- This is the largest gap — BIMI without VMC is limited to domains without authority evidence
- **Recommendation**: Implement basic VMC validation (parse PEM, check EKU OID, validate chain, match SAN). CRL checking can be deferred.

#### 11.2.3 BIMI-Location/Indicator Header Generation Missing
- Spec §6 step 11 says to add `BIMI-Location` and `BIMI-Indicator` headers on pass
- v3 returns BimiValidationResult but does not generate these headers
- **FIX**: Add `fn format_bimi_headers(result: &BimiValidationResult) -> Option<(String, String)>` that produces the header values

#### 11.2.4 pct Check in DMARC Eligibility
- `check_dmarc_eligibility()` checks disposition and policy but does NOT check if DMARC pct=100
- Spec §2.2 requires pct=100 (or absent, defaulting to 100) for BIMI eligibility
- **FIX**: Access `dmarc_result.record` and check `record.percent == 100`

### 11.3 Patterns That Worked
- `quick-xml` event-based parsing for SVG validation — memory-efficient, catches prohibited elements during parse
- Declination record detection (`v=BIMI1;` with no l= or empty l=) — clean separate result variant
- DMARC eligibility as standalone function — reusable, easy to test independently
- Org-domain fallback in discovery — same pattern as DMARC record discovery

---

## Completion Checklist

- [ ] BIMI DNS record parsing (v=, l=, a= tags)
- [ ] BIMI-Selector header parsing
- [ ] Record discovery with org-domain fallback
- [ ] Multiple valid records → Fail (not first-wins)
- [ ] DMARC eligibility check (disposition + policy + pct=100 + alignment)
- [ ] SVG Tiny PS validation (size, baseProfile, prohibited elements, Event::Start AND Event::Empty)
- [ ] VMC validation (EKU OID, SAN matching, chain validation, LogoType SVG extraction, logo hash comparison)
- [ ] Declination record handling
- [ ] BIMI-Location and BIMI-Indicator header generation (`format_bimi_headers()`)
- [ ] Sender-inserted BIMI header removal
- [ ] Unit tests for: parsing, discovery (incl. multiple records), SVG validation, DMARC eligibility, VMC, header generation, header removal
