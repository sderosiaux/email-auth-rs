/// BIMI DNS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BimiRecord {
    /// Version string, MUST be "BIMI1".
    pub version: String,
    /// l= tag: 1-2 HTTPS URIs for logo SVG.
    pub logo_uris: Vec<String>,
    /// a= tag: VMC authority evidence URI (HTTPS).
    pub authority_uri: Option<String>,
}

/// BIMI-Selector header parsed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BimiSelectorHeader {
    /// Version string, MUST be "BIMI1".
    pub version: String,
    /// Selector value (default: "default").
    pub selector: String,
}

/// BIMI validation result status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BimiResult {
    /// Validated successfully.
    Pass,
    /// No BIMI record found.
    None,
    /// Validation failure.
    Fail { reason: String },
    /// DNS or fetch failure.
    TempError,
    /// DMARC not eligible.
    Skipped,
    /// Domain published declination record.
    Declined,
}

/// Complete BIMI validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BimiValidationResult {
    pub result: BimiResult,
    pub domain: String,
    pub selector: String,
    pub record: Option<BimiRecord>,
}
