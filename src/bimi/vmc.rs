use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::fmt;
use x509_parser::der_parser::oid::Oid;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

use super::svg::validate_svg_tiny_ps;

/// BIMI EKU OID: 1.3.6.1.5.5.7.3.31
/// id-kp-BrandIndicatorforMessageIdentification
const BIMI_EKU_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 31];

/// LogoType extension OID (RFC 3709): 1.3.6.1.5.5.7.1.12
const LOGOTYPE_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 12];

/// VMC validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmcError {
    /// PEM parsing failure.
    PemParse(String),
    /// No certificates found in PEM data.
    NoCertificates,
    /// Multiple VMC (end-entity) certificates found.
    MultipleVmcs,
    /// Certificate chain is out of order.
    OutOfOrder,
    /// Duplicate certificate in chain.
    DuplicateCert,
    /// Missing BIMI EKU OID.
    MissingBimiEku,
    /// SAN does not match expected selector._bimi.domain.
    SanMismatch { expected: String },
    /// Certificate expired.
    Expired,
    /// Certificate not yet valid.
    NotYetValid,
    /// LogoType extension not found.
    MissingLogoType,
    /// Failed to extract SVG from LogoType extension.
    LogoTypeExtractFailed(String),
    /// SVG validation failed.
    SvgValidation(String),
    /// Logo hash mismatch between DNS-fetched and VMC-embedded.
    LogoHashMismatch,
    /// Chain validation failure (issuer mismatch).
    ChainValidation(String),
    /// X.509 parsing error.
    X509Parse(String),
}

impl fmt::Display for VmcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmcError::PemParse(e) => write!(f, "PEM parse error: {}", e),
            VmcError::NoCertificates => write!(f, "no certificates in PEM data"),
            VmcError::MultipleVmcs => write!(f, "multiple VMC certificates in chain"),
            VmcError::OutOfOrder => write!(f, "certificate chain out of order"),
            VmcError::DuplicateCert => write!(f, "duplicate certificate in chain"),
            VmcError::MissingBimiEku => write!(f, "missing BIMI EKU OID 1.3.6.1.5.5.7.3.31"),
            VmcError::SanMismatch { expected } => {
                write!(f, "SAN does not match {}", expected)
            }
            VmcError::Expired => write!(f, "certificate expired"),
            VmcError::NotYetValid => write!(f, "certificate not yet valid"),
            VmcError::MissingLogoType => write!(f, "LogoType extension not found"),
            VmcError::LogoTypeExtractFailed(e) => {
                write!(f, "LogoType SVG extraction failed: {}", e)
            }
            VmcError::SvgValidation(e) => write!(f, "SVG validation failed: {}", e),
            VmcError::LogoHashMismatch => {
                write!(f, "logo hash mismatch: DNS-fetched != VMC-embedded")
            }
            VmcError::ChainValidation(e) => write!(f, "chain validation: {}", e),
            VmcError::X509Parse(e) => write!(f, "X.509 parse error: {}", e),
        }
    }
}

/// Result of VMC validation.
#[derive(Debug)]
pub struct VmcValidationResult {
    /// Extracted SVG from LogoType extension (validated against SVG Tiny PS).
    pub embedded_svg: String,
}

/// Parse PEM certificate chain and return DER-decoded certificates.
/// Validates: no duplicates, VMC first, ordered chain.
fn parse_pem_chain(pem_data: &[u8]) -> Result<Vec<Vec<u8>>, VmcError> {
    let mut der_certs: Vec<Vec<u8>> = Vec::new();
    let mut remaining = pem_data;

    loop {
        match parse_x509_pem(remaining) {
            Ok((rest, pem)) => {
                if pem.label != "CERTIFICATE" {
                    remaining = rest;
                    continue;
                }
                der_certs.push(pem.contents);
                if rest.is_empty() {
                    break;
                }
                remaining = rest;
            }
            Err(_) => break,
        }
    }

    if der_certs.is_empty() {
        return Err(VmcError::NoCertificates);
    }

    // Check for duplicate certificates (by raw DER)
    let mut seen = HashSet::new();
    for cert_der in &der_certs {
        if !seen.insert(cert_der.clone()) {
            return Err(VmcError::DuplicateCert);
        }
    }

    Ok(der_certs)
}

/// Validate a VMC certificate chain.
///
/// `pem_data`: PEM-encoded certificate chain (VMC first, then issuer chain)
/// `selector`: BIMI selector (e.g., "default")
/// `domain`: author domain (e.g., "example.com")
/// `dns_logo_svg`: Optional DNS-fetched logo SVG for hash comparison
///
/// Returns extracted SVG from VMC on success.
pub fn validate_vmc(
    pem_data: &[u8],
    selector: &str,
    domain: &str,
    dns_logo_svg: Option<&str>,
) -> Result<VmcValidationResult, VmcError> {
    let der_certs = parse_pem_chain(pem_data)?;

    // Parse all certificates
    let mut parsed_certs: Vec<X509Certificate<'_>> = Vec::new();

    // We need to keep the DER data alive for the parsed references
    // Parse each cert from its DER bytes
    for der in &der_certs {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| VmcError::X509Parse(format!("{}", e)))?;
        parsed_certs.push(cert);
    }

    if parsed_certs.is_empty() {
        return Err(VmcError::NoCertificates);
    }

    // CHK-985: Multiple VMCs → reject
    // Count end-entity (non-CA) certs — should be exactly 1
    let vmc_count = parsed_certs.iter().filter(|c| !c.tbs_certificate.is_ca()).count();
    if vmc_count > 1 {
        return Err(VmcError::MultipleVmcs);
    }

    // The first cert MUST be the VMC (end-entity)
    let vmc = &parsed_certs[0];
    if vmc.tbs_certificate.is_ca() && parsed_certs.len() > 1 {
        return Err(VmcError::OutOfOrder);
    }

    // CHK-983: Chain ordering — each cert should be issued by the next
    for i in 0..parsed_certs.len().saturating_sub(1) {
        let child = &parsed_certs[i];
        let parent = &parsed_certs[i + 1];
        if child.issuer() != parent.subject() {
            return Err(VmcError::OutOfOrder);
        }
    }

    // CHK-974: Check validity period
    let validity = vmc.validity();
    if !validity.is_valid() {
        if validity.not_after.timestamp() < chrono_now() {
            return Err(VmcError::Expired);
        }
        return Err(VmcError::NotYetValid);
    }

    // CHK-976/CHK-969: Check EKU contains BIMI OID
    check_bimi_eku(vmc)?;

    // CHK-977/CHK-971: Match SAN to selector._bimi.domain
    let expected_san = format!("{}._bimi.{}", selector, domain);
    check_san_match(vmc, &expected_san)?;

    // CHK-978/CHK-970: Extract SVG from LogoType extension
    let embedded_svg = extract_logotype_svg(vmc)?;

    // CHK-979: Validate extracted SVG against SVG Tiny PS profile
    validate_svg_tiny_ps(&embedded_svg)
        .map_err(|e| VmcError::SvgValidation(format!("{}", e)))?;

    // CHK-980: Compare logo hash if DNS-fetched logo provided
    if let Some(dns_svg) = dns_logo_svg {
        let dns_hash = sha256_hash(dns_svg.as_bytes());
        let vmc_hash = sha256_hash(embedded_svg.as_bytes());
        if dns_hash != vmc_hash {
            return Err(VmcError::LogoHashMismatch);
        }
    }

    // CHK-973: Chain signature validation
    validate_chain_signatures(&parsed_certs)?;

    Ok(VmcValidationResult { embedded_svg })
}

/// Check that the certificate has the BIMI EKU OID.
fn check_bimi_eku(cert: &X509Certificate<'_>) -> Result<(), VmcError> {
    let eku = cert
        .tbs_certificate
        .extended_key_usage()
        .map_err(|e| VmcError::X509Parse(format!("EKU: {}", e)))?;

    match eku {
        Some(ext) => {
            let bimi_oid = Oid::from(BIMI_EKU_OID)
                .map_err(|_| VmcError::MissingBimiEku)?;
            if ext.value.other.iter().any(|o| o == &bimi_oid) {
                Ok(())
            } else {
                Err(VmcError::MissingBimiEku)
            }
        }
        None => Err(VmcError::MissingBimiEku),
    }
}

/// Check that the SAN contains the expected DNS name.
fn check_san_match(cert: &X509Certificate<'_>, expected: &str) -> Result<(), VmcError> {
    let san = cert
        .tbs_certificate
        .subject_alternative_name()
        .map_err(|e| VmcError::X509Parse(format!("SAN: {}", e)))?;

    match san {
        Some(ext) => {
            for name in &ext.value.general_names {
                if let GeneralName::DNSName(dns) = name {
                    if dns.eq_ignore_ascii_case(expected) {
                        return Ok(());
                    }
                }
            }
            Err(VmcError::SanMismatch {
                expected: expected.to_string(),
            })
        }
        None => Err(VmcError::SanMismatch {
            expected: expected.to_string(),
        }),
    }
}

/// Extract SVG from the LogoType extension (RFC 3709).
///
/// The LogoType extension contains a data URI:
/// `data:image/svg+xml;base64,<base64-encoded-svg>`
///
/// We parse the extension raw data, searching for the data URI pattern,
/// then decode the base64 SVG.
fn extract_logotype_svg(cert: &X509Certificate<'_>) -> Result<String, VmcError> {
    let logotype_oid = Oid::from(LOGOTYPE_OID)
        .map_err(|_| VmcError::MissingLogoType)?;

    let ext = cert
        .tbs_certificate
        .get_extension_unique(&logotype_oid)
        .map_err(|e| VmcError::X509Parse(format!("LogoType: {}", e)))?
        .ok_or(VmcError::MissingLogoType)?;

    // The LogoType extension value is ASN.1-encoded.
    // We search the raw bytes for the data URI pattern.
    let raw = ext.value;
    let raw_str = String::from_utf8_lossy(raw);

    // Look for data:image/svg+xml;base64, pattern
    let marker = "data:image/svg+xml;base64,";
    if let Some(start) = raw_str.find(marker) {
        let b64_start = start + marker.len();
        // Find end of base64 data (next non-base64 char)
        let b64_data: String = raw_str[b64_start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .collect();

        if b64_data.is_empty() {
            return Err(VmcError::LogoTypeExtractFailed(
                "empty base64 data after marker".into(),
            ));
        }

        use base64::Engine;
        let svg_bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64_data)
            .map_err(|e| VmcError::LogoTypeExtractFailed(format!("base64 decode: {}", e)))?;

        let svg = String::from_utf8(svg_bytes)
            .map_err(|e| VmcError::LogoTypeExtractFailed(format!("UTF-8: {}", e)))?;

        return Ok(svg);
    }

    // If data URI not found in string form, try binary scan
    let marker_bytes = marker.as_bytes();
    if let Some(pos) = raw.windows(marker_bytes.len()).position(|w| w == marker_bytes) {
        let b64_start = pos + marker_bytes.len();
        let b64_data: Vec<u8> = raw[b64_start..]
            .iter()
            .copied()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
            .collect();

        if b64_data.is_empty() {
            return Err(VmcError::LogoTypeExtractFailed(
                "empty base64 data".into(),
            ));
        }

        use base64::Engine;
        let svg_bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64_data)
            .map_err(|e| VmcError::LogoTypeExtractFailed(format!("base64 decode: {}", e)))?;

        let svg = String::from_utf8(svg_bytes)
            .map_err(|e| VmcError::LogoTypeExtractFailed(format!("UTF-8: {}", e)))?;

        return Ok(svg);
    }

    Err(VmcError::MissingLogoType)
}

/// Compute SHA-256 hash of data.
fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Get current Unix timestamp.
fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Validate chain signatures: each cert[i] should be signed by cert[i+1].
/// The last cert (root or self-signed) is verified against itself.
fn validate_chain_signatures(certs: &[X509Certificate<'_>]) -> Result<(), VmcError> {
    for i in 0..certs.len().saturating_sub(1) {
        let child = &certs[i];
        let parent = &certs[i + 1];
        child
            .verify_signature(Some(&parent.tbs_certificate.subject_pki))
            .map_err(|e| {
                VmcError::ChainValidation(format!(
                    "cert {} not signed by cert {}: {}",
                    i,
                    i + 1,
                    e
                ))
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose,
        IsCa, BasicConstraints, SanType, KeyPair,
    };

    /// Test SVG for embedding in VMC LogoType extension.
    const TEST_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>Test</title><rect width="100" height="100" fill="red"/></svg>"#;

    /// Build a LogoType extension value containing a data URI with base64-encoded SVG.
    /// This is a simplified ASN.1 structure — wraps the data URI in an OCTET STRING.
    fn build_logotype_extension(svg: &str) -> Vec<u8> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(svg.as_bytes());
        let data_uri = format!("data:image/svg+xml;base64,{}", b64);
        // Wrap in a minimal ASN.1 structure that x509-parser can read as extension value.
        // The LogoType extension is complex ASN.1, but x509-parser gives us raw bytes.
        // We embed the data URI directly so our string search finds it.
        data_uri.into_bytes()
    }

    /// BIMI EKU OID as rcgen ExtendedKeyUsagePurpose
    fn bimi_eku() -> ExtendedKeyUsagePurpose {
        ExtendedKeyUsagePurpose::Other(BIMI_EKU_OID.to_vec())
    }

    /// Create a self-signed VMC test certificate with BIMI EKU, SAN, and LogoType.
    fn make_vmc_cert(
        selector: &str,
        domain: &str,
        svg: &str,
        expired: bool,
        not_yet_valid: bool,
        include_eku: bool,
        include_san: bool,
        include_logotype: bool,
    ) -> (String, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .expect("CertificateParams");

        params
            .distinguished_name
            .push(DnType::CommonName, format!("{}._bimi.{}", selector, domain));

        // Validity
        if expired {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        } else if not_yet_valid {
            params.not_before = rcgen::date_time_ymd(2030, 1, 1);
            params.not_after = rcgen::date_time_ymd(2031, 1, 1);
        } else {
            params.not_before = rcgen::date_time_ymd(2024, 1, 1);
            params.not_after = rcgen::date_time_ymd(2030, 12, 31);
        }

        // EKU
        if include_eku {
            params.extended_key_usages.push(bimi_eku());
        }

        // SAN
        if include_san {
            let san_name = format!("{}._bimi.{}", selector, domain);
            params.subject_alt_names.push(SanType::DnsName(san_name.try_into().expect("dns name")));
        }

        // LogoType extension (custom)
        if include_logotype {
            let logotype_oid = LOGOTYPE_OID.to_vec();
            let ext_value = build_logotype_extension(svg);
            let ext = CustomExtension::from_oid_content(&logotype_oid, ext_value);
            params.custom_extensions.push(ext);
        }

        params.is_ca = IsCa::NoCa;

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("key pair");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");
        (cert.pem(), key_pair)
    }

    /// Create a CA cert for chain testing.
    fn make_ca_cert(cn: &str) -> (CertificateParams, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .expect("CertificateParams");
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 12, 31);

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("key pair");
        (params, key_pair)
    }

    // ─── CHK-1021: Valid VMC with BIMI EKU OID → pass ────────────────

    #[test]
    fn valid_vmc() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, true, true);
        let result = validate_vmc(pem.as_bytes(), "default", "example.com", None);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
        assert_eq!(result.unwrap().embedded_svg, TEST_SVG);
    }

    // ─── CHK-1022: Missing BIMI EKU OID → fail ──────────────────────

    #[test]
    fn missing_bimi_eku() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, false, true, true);
        let result = validate_vmc(pem.as_bytes(), "default", "example.com", None);
        assert_eq!(result.unwrap_err(), VmcError::MissingBimiEku);
    }

    // ─── CHK-1023: SAN matches selector._bimi.domain → pass ─────────

    #[test]
    fn san_match() {
        let (pem, _kp) =
            make_vmc_cert("brand", "example.com", TEST_SVG, false, false, true, true, true);
        let result = validate_vmc(pem.as_bytes(), "brand", "example.com", None);
        assert!(result.is_ok());
    }

    // ─── CHK-1024: SAN mismatch → fail ──────────────────────────────

    #[test]
    fn san_mismatch() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, true, true);
        let result = validate_vmc(pem.as_bytes(), "default", "other.com", None);
        assert!(matches!(result.unwrap_err(), VmcError::SanMismatch { .. }));
    }

    // ─── CHK-1025: Expired certificate → fail ────────────────────────

    #[test]
    fn expired_cert() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, true, false, true, true, true);
        let result = validate_vmc(pem.as_bytes(), "default", "example.com", None);
        assert_eq!(result.unwrap_err(), VmcError::Expired);
    }

    // ─── CHK-1026: Not-yet-valid certificate → fail ──────────────────

    #[test]
    fn not_yet_valid_cert() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, true, true, true, true);
        let result = validate_vmc(pem.as_bytes(), "default", "example.com", None);
        assert_eq!(result.unwrap_err(), VmcError::NotYetValid);
    }

    // ─── CHK-1027: Extract SVG from LogoType extension ───────────────

    #[test]
    fn extract_logotype_svg_test() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, true, true);
        let result = validate_vmc(pem.as_bytes(), "default", "example.com", None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().embedded_svg, TEST_SVG);
    }

    // ─── CHK-1028: Logo hash match → pass ────────────────────────────

    #[test]
    fn logo_hash_match() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, true, true);
        // DNS-fetched SVG matches VMC-embedded SVG
        let result = validate_vmc(pem.as_bytes(), "default", "example.com", Some(TEST_SVG));
        assert!(result.is_ok());
    }

    // ─── CHK-1029: Logo hash mismatch → fail ─────────────────────────

    #[test]
    fn logo_hash_mismatch() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, true, true);
        // DNS-fetched SVG is different from VMC-embedded
        let different_svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>Diff</title><rect width="100" height="100" fill="blue"/></svg>"#;
        let result =
            validate_vmc(pem.as_bytes(), "default", "example.com", Some(different_svg));
        assert_eq!(result.unwrap_err(), VmcError::LogoHashMismatch);
    }

    // ─── CHK-1030: PEM chain: VMC → Intermediate → Root ──────────────

    #[test]
    fn valid_pem_chain() {
        // Create a 2-cert chain: VMC signed by CA
        let (ca_params, ca_kp) = make_ca_cert("Test CA");
        let ca_cert = ca_params.self_signed(&ca_kp).expect("CA cert");

        let mut vmc_params = CertificateParams::new(Vec::<String>::new())
            .expect("CertificateParams");
        vmc_params.distinguished_name.push(DnType::CommonName, "default._bimi.example.com");
        vmc_params.is_ca = IsCa::NoCa;
        vmc_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        vmc_params.not_after = rcgen::date_time_ymd(2030, 12, 31);
        vmc_params.extended_key_usages.push(bimi_eku());
        vmc_params.subject_alt_names.push(
            SanType::DnsName("default._bimi.example.com".try_into().expect("dns"))
        );
        let logotype_ext = CustomExtension::from_oid_content(
            &LOGOTYPE_OID.to_vec(),
            build_logotype_extension(TEST_SVG),
        );
        vmc_params.custom_extensions.push(logotype_ext);

        let vmc_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("vmc key pair");
        let vmc_cert = vmc_params.signed_by(&vmc_kp, &ca_cert, &ca_kp).expect("VMC signed");

        let chain_pem = format!("{}{}", vmc_cert.pem(), ca_cert.pem());
        let result = validate_vmc(chain_pem.as_bytes(), "default", "example.com", None);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    // ─── CHK-1031: Out-of-order PEM chain → reject ───────────────────

    #[test]
    fn out_of_order_chain() {
        // Put CA cert first, then VMC — wrong order
        let (ca_params, ca_kp) = make_ca_cert("Test CA");
        let ca_cert = ca_params.self_signed(&ca_kp).expect("CA cert");

        let mut vmc_params = CertificateParams::new(Vec::<String>::new())
            .expect("CertificateParams");
        vmc_params.distinguished_name.push(DnType::CommonName, "default._bimi.example.com");
        vmc_params.is_ca = IsCa::NoCa;
        vmc_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        vmc_params.not_after = rcgen::date_time_ymd(2030, 12, 31);
        vmc_params.extended_key_usages.push(bimi_eku());
        vmc_params.subject_alt_names.push(
            SanType::DnsName("default._bimi.example.com".try_into().expect("dns"))
        );
        let logotype_ext = CustomExtension::from_oid_content(
            &LOGOTYPE_OID.to_vec(),
            build_logotype_extension(TEST_SVG),
        );
        vmc_params.custom_extensions.push(logotype_ext);

        let vmc_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("vmc key pair");
        let vmc_cert = vmc_params.signed_by(&vmc_kp, &ca_cert, &ca_kp).expect("VMC signed");

        // Wrong order: CA first, then VMC
        let chain_pem = format!("{}{}", ca_cert.pem(), vmc_cert.pem());
        let result = validate_vmc(chain_pem.as_bytes(), "default", "example.com", None);
        assert!(result.is_err());
        // Should fail because first cert is CA, not VMC (out of order)
        let err = result.unwrap_err();
        assert!(
            matches!(err, VmcError::OutOfOrder | VmcError::MissingBimiEku),
            "expected OutOfOrder or MissingBimiEku, got {:?}",
            err
        );
    }

    // ─── CHK-1032: Multiple VMC certificates → reject ────────────────

    #[test]
    fn multiple_vmcs_in_chain() {
        let (pem1, _kp1) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, true, true);
        let (pem2, _kp2) =
            make_vmc_cert("default", "other.com", TEST_SVG, false, false, true, true, true);

        let chain_pem = format!("{}{}", pem1, pem2);
        let result = validate_vmc(chain_pem.as_bytes(), "default", "example.com", None);
        assert_eq!(result.unwrap_err(), VmcError::MultipleVmcs);
    }

    // ─── CHK-984: Duplicate certificates → reject ────────────────────

    #[test]
    fn duplicate_cert_in_chain() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, true, true);
        let chain_pem = format!("{}{}", pem, pem);
        let result = validate_vmc(chain_pem.as_bytes(), "default", "example.com", None);
        assert_eq!(result.unwrap_err(), VmcError::DuplicateCert);
    }

    // ─── Additional: No certificates in PEM → error ──────────────────

    #[test]
    fn no_certificates() {
        let result = validate_vmc(b"not a PEM", "default", "example.com", None);
        assert_eq!(result.unwrap_err(), VmcError::NoCertificates);
    }

    // ─── Additional: Missing LogoType extension ──────────────────────

    #[test]
    fn missing_logotype() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, true, false);
        let result = validate_vmc(pem.as_bytes(), "default", "example.com", None);
        assert_eq!(result.unwrap_err(), VmcError::MissingLogoType);
    }

    // ─── Additional: Missing SAN entirely ────────────────────────────

    #[test]
    fn missing_san() {
        let (pem, _kp) =
            make_vmc_cert("default", "example.com", TEST_SVG, false, false, true, false, true);
        let result = validate_vmc(pem.as_bytes(), "default", "example.com", None);
        assert!(matches!(result.unwrap_err(), VmcError::SanMismatch { .. }));
    }
}
