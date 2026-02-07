//! Combined email authentication (SPF + DKIM + DMARC).
//!
//! Provides [`EmailAuthenticator`] which runs the full authentication pipeline:
//! SPF check -> DKIM signature verification -> DMARC evaluation.

use std::net::IpAddr;

use crate::common::dns::DnsResolver;
use crate::common::domain;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{DmarcEvaluator, DmarcResult};
use crate::spf::SpfResult;

// ---------------------------------------------------------------------------
// AuthenticationResult
// ---------------------------------------------------------------------------

/// Combined result of SPF, DKIM, and DMARC authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResult {
    /// SPF check result.
    pub spf: SpfResult,
    /// DKIM verification results (one per DKIM-Signature, or a single `None`).
    pub dkim: Vec<DkimResult>,
    /// DMARC evaluation result.
    pub dmarc: DmarcResult,
    /// The RFC 5322 From domain used for DMARC alignment.
    pub from_domain: String,
    /// The MAIL FROM (envelope sender) domain used for SPF.
    pub spf_domain: String,
}

// ---------------------------------------------------------------------------
// EmailAuthenticator
// ---------------------------------------------------------------------------

/// Runs the full email authentication pipeline: SPF -> DKIM -> DMARC.
///
/// Each protocol runs independently; a failure in one does not prevent the
/// others from producing results.
pub struct EmailAuthenticator<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
    receiver: String,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            clock_skew: 300,
            receiver: "unknown".into(),
        }
    }

    /// Override the DKIM clock skew allowance (in seconds).
    pub fn clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    /// Set the receiver hostname (for SPF `%{r}` macro).
    pub fn receiver(mut self, hostname: impl Into<String>) -> Self {
        self.receiver = hostname.into();
        self
    }

    /// Authenticate a raw RFC 5322 message.
    ///
    /// - `message`: raw message bytes (headers + blank line + body)
    /// - `client_ip`: connecting client IP
    /// - `helo`: EHLO/HELO hostname
    /// - `mail_from`: MAIL FROM address (envelope sender)
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // 1. Parse message into headers + body
        let (headers, body) = parse_message(message);

        // 2. Extract RFC 5322 From domain (for DMARC)
        let from_domain = extract_from_domain(&headers).unwrap_or_else(|| {
            domain::domain_from_email(mail_from)
                .unwrap_or(helo)
                .to_string()
        });

        // 3. Determine SPF domain (envelope sender domain)
        let spf_domain = if mail_from.is_empty() || !mail_from.contains('@') {
            helo.to_string()
        } else {
            domain::domain_from_email(mail_from)
                .unwrap_or(helo)
                .to_string()
        };

        // 4. SPF
        let spf_result = crate::spf::eval::check_host(
            &self.resolver,
            client_ip,
            helo,
            mail_from,
            &spf_domain,
            &self.receiver,
        )
        .await;

        // 5. DKIM
        let headers_ref: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let dkim_results = DkimVerifier::new(&self.resolver)
            .clock_skew(self.clock_skew)
            .verify_message(&headers_ref, &body)
            .await;

        // 6. DMARC
        let dmarc_result = DmarcEvaluator::new(&self.resolver)
            .evaluate(&from_domain, &spf_result, &spf_domain, &dkim_results)
            .await;

        AuthenticationResult {
            spf: spf_result,
            dkim: dkim_results,
            dmarc: dmarc_result,
            from_domain,
            spf_domain,
        }
    }
}

// ---------------------------------------------------------------------------
// Message parsing
// ---------------------------------------------------------------------------

/// Parse a raw RFC 5322 message into (headers, body).
///
/// Headers are returned as `(name, value)` pairs where `value` is everything
/// after the colon (including leading whitespace). Folded headers (continuation
/// lines starting with SP/HTAB) are merged with `\r\n` separators.
pub(crate) fn parse_message(data: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
    let (header_end, body_start) = find_header_body_boundary(data);
    let header_text = String::from_utf8_lossy(&data[..header_end]);
    let body = data[body_start..].to_vec();
    (parse_headers(&header_text), body)
}

/// Scan for the blank line separating headers from body.
/// Returns (end_of_headers, start_of_body).
fn find_header_body_boundary(data: &[u8]) -> (usize, usize) {
    for (i, window) in data.windows(4).enumerate() {
        if window == b"\r\n\r\n" {
            return (i, i + 4);
        }
    }
    for (i, window) in data.windows(2).enumerate() {
        if window == b"\n\n" {
            return (i, i + 2);
        }
    }
    (data.len(), data.len())
}

/// Parse header text into (name, value) pairs, handling folded headers.
fn parse_headers(text: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Folded continuation — append to previous header value
            if let Some(last) = headers.last_mut() {
                let h: &mut (String, String) = last;
                h.1.push_str("\r\n");
                h.1.push_str(line);
            }
        } else if let Some(colon_pos) = line.find(':') {
            headers.push((
                line[..colon_pos].to_string(),
                line[colon_pos + 1..].to_string(),
            ));
        }
    }
    headers
}

// ---------------------------------------------------------------------------
// From header extraction
// ---------------------------------------------------------------------------

/// Extract the domain from the RFC 5322 From header.
///
/// Handles: display names, angle brackets, comments, multiple addresses
/// (uses the first), and folded headers.
fn extract_from_domain(headers: &[(String, String)]) -> Option<String> {
    let from_value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        .map(|(_, v)| v.as_str())?;

    extract_domain_from_mailbox(from_value)
}

/// Parse a mailbox value and extract the domain.
///
/// Checks for angle brackets BEFORE comma-splitting so that quoted display
/// names containing commas (e.g. `"Smith, John" <j@x.com>`) are handled.
fn extract_domain_from_mailbox(value: &str) -> Option<String> {
    // Strip RFC 5322 comments (parenthesized text)
    let clean = strip_comments(value);
    // Unfold (CRLF + WSP -> single space)
    let unfolded = clean.replace("\r\n ", " ").replace("\r\n\t", " ");

    // Try angle bracket format first — handles quoted display names with commas
    if let Some(start) = unfolded.find('<') {
        if let Some(end) = unfolded[start..].find('>') {
            let addr = unfolded[start + 1..start + end].trim();
            return domain::domain_from_email(addr).map(|d| d.to_string());
        }
    }

    // No angle brackets — try comma-split for multiple bare addresses, take first
    let first = unfolded.split(',').next().unwrap_or(&unfolded).trim();
    domain::domain_from_email(first).map(|d| d.to_string())
}

/// Remove RFC 5322 comments (text within parentheses, with nesting).
fn strip_comments(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut depth = 0u32;
    for ch in s.chars() {
        match ch {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => result.push(ch),
            _ => {}
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::{MockDnsResponse, MockResolver};
    use crate::dkim::sign::DkimSigner;
    use crate::dkim::signature::CanonicalizationMethod;
    use crate::dmarc::Disposition;

    use base64::Engine;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    fn gen_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_key = kp.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), pub_key)
    }

    /// Build a raw RFC 5322 message from headers and body.
    fn build_raw_message(headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        for (name, value) in headers {
            msg.extend_from_slice(name.as_bytes());
            msg.push(b':');
            msg.extend_from_slice(value.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(body);
        msg
    }

    /// Set up a MockResolver with SPF, DKIM key, and DMARC records.
    fn resolver_with_all(
        spf_domain: &str,
        spf_record: &str,
        dkim_selector: &str,
        dkim_domain: &str,
        dkim_pub_key: &[u8],
        dmarc_domain: &str,
        dmarc_record: &str,
    ) -> MockResolver {
        let mut r = MockResolver::new();
        r.txt.insert(
            spf_domain.into(),
            MockDnsResponse::Records(vec![spf_record.into()]),
        );
        r.txt.insert(
            format!("{dkim_selector}._domainkey.{dkim_domain}"),
            MockDnsResponse::Records(vec![format!(
                "v=DKIM1; k=ed25519; p={}",
                b64(dkim_pub_key)
            )]),
        );
        r.txt.insert(
            format!("_dmarc.{dmarc_domain}"),
            MockDnsResponse::Records(vec![dmarc_record.into()]),
        );
        r
    }

    // -----------------------------------------------------------------------
    // Unit tests: message parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_basic_message() {
        let msg = b"From: alice@example.com\r\nTo: bob@example.org\r\n\r\nHello\r\n";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "From");
        assert_eq!(headers[0].1, " alice@example.com");
        assert_eq!(headers[1].0, "To");
        assert_eq!(headers[1].1, " bob@example.org");
        assert_eq!(body, b"Hello\r\n");
    }

    #[test]
    fn parse_folded_header() {
        let msg = b"Subject: This is a\r\n    long subject\r\n\r\nbody";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Subject");
        assert_eq!(headers[0].1, " This is a\r\n    long subject");
        assert_eq!(body, b"body");
    }

    #[test]
    fn parse_no_body() {
        let msg = b"From: test@example.com\r\n";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 1);
        assert!(body.is_empty());
    }

    #[test]
    fn parse_bare_lf_message() {
        let msg = b"From: test@example.com\nTo: b@b.com\n\nbody";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(body, b"body");
    }

    // -----------------------------------------------------------------------
    // Unit tests: From domain extraction
    // -----------------------------------------------------------------------

    #[test]
    fn from_domain_simple() {
        let headers = vec![("From".into(), " alice@example.com".into())];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".into())
        );
    }

    #[test]
    fn from_domain_angle_bracket() {
        let headers = vec![("From".into(), " Alice <alice@example.com>".into())];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".into())
        );
    }

    #[test]
    fn from_domain_display_name_quoted() {
        let headers = vec![(
            "From".into(),
            " \"Alice Smith\" <alice@example.com>".into(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".into())
        );
    }

    #[test]
    fn from_domain_with_comment() {
        let headers = vec![(
            "From".into(),
            " alice@example.com (Alice Smith)".into(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".into())
        );
    }

    #[test]
    fn from_domain_multiple_addresses() {
        let headers = vec![(
            "From".into(),
            " alice@first.com, bob@second.com".into(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("first.com".into())
        );
    }

    #[test]
    fn from_domain_missing() {
        let headers = vec![("To".into(), " bob@example.com".into())];
        assert_eq!(extract_from_domain(&headers), None);
    }

    #[test]
    fn from_domain_case_insensitive() {
        let headers = vec![("FROM".into(), " alice@EXAMPLE.COM".into())];
        assert_eq!(
            extract_from_domain(&headers),
            Some("EXAMPLE.COM".into())
        );
    }

    #[test]
    fn from_domain_folded() {
        let headers = vec![(
            "From".into(),
            " Alice\r\n <alice@example.com>".into(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".into())
        );
    }

    #[test]
    fn strip_comments_nested() {
        assert_eq!(strip_comments("a (b (c) d) e"), "a  e");
        assert_eq!(strip_comments("no comments"), "no comments");
    }

    #[test]
    fn from_domain_quoted_display_name_with_comma() {
        // "Smith, John" <john@example.com> — comma must not split the address
        let headers = vec![(
            "From".into(),
            " \"Smith, John\" <john@example.com>".into(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".into())
        );
    }

    // =======================================================================
    // Ground-truth fixtures: manually constructed DKIM signatures (no DkimSigner)
    // =======================================================================
    //
    // These fixtures construct DKIM signatures directly using ring primitives
    // and canonicalization functions, bypassing DkimSigner entirely. This
    // tests the full pipeline (raw bytes -> parse -> SPF + DKIM + DMARC)
    // against independently computed signatures.

    use crate::dkim::canon::{
        canonicalize_body_relaxed, canonicalize_body_simple, canonicalize_header_relaxed,
        canonicalize_header_simple, select_headers,
    };
    use ring::digest::{digest, SHA256};

    /// Compute body hash using ring directly.
    fn compute_body_hash(body: &[u8], relaxed: bool) -> Vec<u8> {
        let canon = if relaxed {
            canonicalize_body_relaxed(body)
        } else {
            canonicalize_body_simple(body)
        };
        digest(&SHA256, &canon).as_ref().to_vec()
    }

    /// Build the header data bytes for DKIM signing, using canonicalization
    /// functions directly (replicating the verifier's logic).
    fn fixture_build_header_data(
        headers: &[(&str, &str)],
        signed_names: &[&str],
        sig_value: &str,
        relaxed: bool,
    ) -> Vec<u8> {
        let signed: Vec<String> = signed_names.iter().map(|s| s.to_string()).collect();
        let selected = select_headers(headers, &signed);

        let mut data = String::new();
        for (i, (name, value)) in selected.iter().enumerate() {
            if name.is_empty() && value.is_empty() {
                let h = &signed[i];
                let c = if relaxed {
                    canonicalize_header_relaxed(h, "")
                } else {
                    canonicalize_header_simple(h, "")
                };
                data.push_str(&c);
            } else {
                let c = if relaxed {
                    canonicalize_header_relaxed(name, value)
                } else {
                    canonicalize_header_simple(name, value)
                };
                data.push_str(&c);
            }
        }

        let dkim_canon = if relaxed {
            canonicalize_header_relaxed("DKIM-Signature", sig_value)
        } else {
            canonicalize_header_simple("DKIM-Signature", sig_value)
        };
        let dkim_canon = dkim_canon.strip_suffix("\r\n").unwrap_or(&dkim_canon);
        data.push_str(dkim_canon);
        data.into_bytes()
    }

    /// Build a complete ground-truth fixture: raw message bytes with a manually
    /// constructed Ed25519 DKIM signature + DNS mock.
    struct GroundTruthFixture {
        raw_message: Vec<u8>,
        resolver: MockResolver,
    }

    fn build_ground_truth(
        domain: &str,
        selector: &str,
        from_addr: &str,
        to_addr: &str,
        subject: &str,
        body: &[u8],
        canon: &str,
        spf_record: &str,
        dmarc_record: &str,
    ) -> GroundTruthFixture {
        let (pkcs8, pub_key) = gen_ed25519_keypair();
        let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();

        let relaxed_hdr = canon.starts_with("relaxed");
        let relaxed_body = canon.ends_with("relaxed");

        let bh = compute_body_hash(body, relaxed_body);
        let bh_b64 = b64(&bh);

        let msg_headers = vec![
            ("From", from_addr),
            ("To", to_addr),
            ("Subject", subject),
        ];
        let signed_names = ["from", "to", "subject"];

        // Build DKIM-Signature with empty b= for signing
        let sig_template = format!(
            " v=1; a=ed25519-sha256; d={domain}; s={selector}; c={canon}; h=from:to:subject; bh={bh_b64}; b="
        );

        // Compute header data to sign
        let header_data =
            fixture_build_header_data(&msg_headers, &signed_names, &sig_template, relaxed_hdr);

        // Sign with ring directly
        let signature = kp.sign(&header_data);
        let sig_b64 = b64(signature.as_ref());

        // Build real sig value with b= filled
        let real_sig = format!(
            " v=1; a=ed25519-sha256; d={domain}; s={selector}; c={canon}; h=from:to:subject; bh={bh_b64}; b={sig_b64}"
        );

        // Assemble raw message
        let mut all_headers: Vec<(&str, &str)> = vec![("DKIM-Signature", &real_sig)];
        all_headers.extend_from_slice(&msg_headers);
        let raw_message = build_raw_message(&all_headers, body);

        // Build resolver
        let mut resolver = MockResolver::new();
        // SPF
        let spf_domain = domain::domain_from_email(from_addr.trim()).unwrap_or(domain);
        resolver.txt.insert(
            spf_domain.to_string(),
            MockDnsResponse::Records(vec![spf_record.to_string()]),
        );
        // DKIM key
        resolver.txt.insert(
            format!("{selector}._domainkey.{domain}"),
            MockDnsResponse::Records(vec![format!(
                "v=DKIM1; k=ed25519; p={}",
                b64(&pub_key)
            )]),
        );
        // DMARC
        resolver.txt.insert(
            format!("_dmarc.{domain}"),
            MockDnsResponse::Records(vec![dmarc_record.to_string()]),
        );

        GroundTruthFixture {
            raw_message,
            resolver,
        }
    }

    // -----------------------------------------------------------------------
    // Ground-truth 1: Full pass via manually constructed Ed25519 signature
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ground_truth_full_pass() {
        let fixture = build_ground_truth(
            "example.com",
            "gt1",
            " alice@example.com",
            " bob@example.org",
            " Ground truth test",
            b"This is the body.\r\n",
            "relaxed/relaxed",
            "v=spf1 ip4:192.0.2.0/24 -all",
            "v=DMARC1; p=reject",
        );

        let auth = EmailAuthenticator::new(fixture.resolver);
        let result = auth
            .authenticate(
                &fixture.raw_message,
                "192.0.2.10".parse().unwrap(),
                "mail.example.com",
                "alice@example.com",
            )
            .await;

        assert_eq!(result.spf, SpfResult::Pass);
        assert_eq!(result.dkim.len(), 1);
        assert!(result.dkim[0].is_pass(), "DKIM: {:?}", result.dkim[0]);
        assert_eq!(result.dmarc.disposition, Disposition::Pass);
        assert!(result.dmarc.dkim_aligned);
        assert!(result.dmarc.spf_aligned);
        assert_eq!(result.from_domain, "example.com");
    }

    // -----------------------------------------------------------------------
    // Ground-truth 2: simple/simple canonicalization
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ground_truth_simple_simple() {
        let fixture = build_ground_truth(
            "example.com",
            "gt2",
            " sender@example.com",
            " recipient@example.org",
            " Simple canon",
            b"Simple body content\r\n",
            "simple/simple",
            "v=spf1 +all",
            "v=DMARC1; p=none",
        );

        let auth = EmailAuthenticator::new(fixture.resolver);
        let result = auth
            .authenticate(
                &fixture.raw_message,
                "10.0.0.1".parse().unwrap(),
                "helo",
                "sender@example.com",
            )
            .await;

        assert!(result.dkim[0].is_pass(), "DKIM: {:?}", result.dkim[0]);
    }

    // -----------------------------------------------------------------------
    // Ground-truth 3: Wrong signature — hand-crafted invalid sig bytes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ground_truth_invalid_signature() {
        let (_, pub_key) = gen_ed25519_keypair();
        let body = b"Test body\r\n";
        let bh = compute_body_hash(body, true);
        let bh_b64 = b64(&bh);

        // Hand-craft a DKIM-Signature with garbage b= (64 zero bytes)
        let fake_sig_b64 = b64(&[0u8; 64]);
        let sig_value = format!(
            " v=1; a=ed25519-sha256; d=example.com; s=bad; c=relaxed/relaxed; h=from:to; bh={bh_b64}; b={fake_sig_b64}"
        );

        let msg_headers: Vec<(&str, &str)> = vec![
            ("DKIM-Signature", &sig_value),
            ("From", " user@example.com"),
            ("To", " other@example.org"),
        ];
        let raw = build_raw_message(&msg_headers, body);

        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::Records(vec!["v=spf1 ip4:10.0.0.0/8 -all".into()]),
        );
        resolver.txt.insert(
            "bad._domainkey.example.com".into(),
            MockDnsResponse::Records(vec![format!(
                "v=DKIM1; k=ed25519; p={}",
                b64(&pub_key)
            )]),
        );
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec!["v=DMARC1; p=reject".into()]),
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(
                &raw,
                "10.0.0.1".parse().unwrap(),
                "helo",
                "user@example.com",
            )
            .await;

        // SPF passes (ip matches)
        assert_eq!(result.spf, SpfResult::Pass);
        // DKIM fails (wrong signature)
        assert!(
            matches!(&result.dkim[0], DkimResult::Fail { reason } if reason.contains("signature verification failed")),
            "expected Fail, got {:?}",
            result.dkim[0]
        );
        // DMARC: SPF aligned but DKIM not — still passes via SPF
        assert!(result.dmarc.spf_aligned);
        assert!(!result.dmarc.dkim_aligned);
        assert_eq!(result.dmarc.disposition, Disposition::Pass);
    }

    // -----------------------------------------------------------------------
    // Ground-truth 4: Body hash mismatch — correct sig but tampered body
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ground_truth_tampered_body() {
        // Build a valid fixture then mutate the body in the raw message
        let fixture = build_ground_truth(
            "example.com",
            "gt4",
            " alice@example.com",
            " bob@example.org",
            " Tamper test",
            b"Original body\r\n",
            "relaxed/relaxed",
            "v=spf1 +all",
            "v=DMARC1; p=reject",
        );

        // Replace body in raw message (after \r\n\r\n boundary)
        let msg = String::from_utf8_lossy(&fixture.raw_message);
        let boundary = msg.find("\r\n\r\n").unwrap();
        let mut tampered = fixture.raw_message[..boundary + 4].to_vec();
        tampered.extend_from_slice(b"Tampered body content\r\n");

        let auth = EmailAuthenticator::new(fixture.resolver);
        let result = auth
            .authenticate(
                &tampered,
                "1.2.3.4".parse().unwrap(),
                "helo",
                "alice@example.com",
            )
            .await;

        // DKIM should fail with body hash mismatch
        assert!(
            matches!(&result.dkim[0], DkimResult::Fail { reason } if reason.contains("body hash")),
            "expected body hash mismatch, got {:?}",
            result.dkim[0]
        );
    }

    // -----------------------------------------------------------------------
    // Ground-truth 5: Cross-domain — DKIM d= != From domain, DMARC fails
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ground_truth_cross_domain_dmarc_reject() {
        // DKIM signed by "other.com" but From is "example.com"
        let fixture = build_ground_truth(
            "other.com",           // DKIM domain
            "gt5",
            " alice@example.com",  // From address (different domain)
            " bob@example.org",
            " Cross-domain",
            b"Cross domain body\r\n",
            "relaxed/relaxed",
            "v=spf1 -all",         // SPF fails
            "v=DMARC1; p=none",    // DMARC for other.com
        );

        // Add DMARC record for example.com (the From domain)
        let mut resolver = fixture.resolver;
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec!["v=DMARC1; p=reject".into()]),
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(
                &fixture.raw_message,
                "192.0.2.10".parse().unwrap(),
                "helo",
                "alice@example.com",
            )
            .await;

        // DKIM passes for other.com but doesn't align with From (example.com)
        assert!(result.dkim[0].is_pass());
        assert!(!result.dmarc.dkim_aligned);
        // SPF fails
        assert!(matches!(result.spf, SpfResult::Fail { .. }));
        assert!(!result.dmarc.spf_aligned);
        // DMARC rejects
        assert_eq!(result.dmarc.disposition, Disposition::Reject);
    }

    // -----------------------------------------------------------------------
    // Integration test 1: Full pass — SPF + DKIM + DMARC
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_pass_spf_dkim_dmarc() {
        let (pkcs8, pub_key) = gen_ed25519_keypair();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to", "subject"]);

        let msg_headers = [
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " Test message"),
        ];
        let body = b"Hello, world!\r\n";

        let sig_value = signer.sign_message(&msg_headers, body).unwrap();
        let mut all_headers: Vec<(&str, &str)> =
            vec![("DKIM-Signature", &sig_value)];
        all_headers.extend_from_slice(&msg_headers);

        let raw = build_raw_message(&all_headers, body);

        let resolver = resolver_with_all(
            "example.com",
            "v=spf1 ip4:192.0.2.0/24 -all",
            "sel",
            "example.com",
            &pub_key,
            "example.com",
            "v=DMARC1; p=reject",
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(&raw, "192.0.2.10".parse().unwrap(), "mail.example.com", "alice@example.com")
            .await;

        assert_eq!(result.spf, SpfResult::Pass);
        assert_eq!(result.dkim.len(), 1);
        assert!(result.dkim[0].is_pass());
        assert_eq!(result.dmarc.disposition, Disposition::Pass);
        assert!(result.dmarc.dkim_aligned);
        assert!(result.dmarc.spf_aligned);
        assert_eq!(result.from_domain, "example.com");
        assert_eq!(result.spf_domain, "example.com");
    }

    // -----------------------------------------------------------------------
    // Integration test 2: SPF fail, DKIM pass -> DMARC pass via DKIM
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn spf_fail_dkim_pass_dmarc_via_dkim() {
        let (pkcs8, pub_key) = gen_ed25519_keypair();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to", "subject"]);

        let msg_headers = [
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " Test"),
        ];
        let body = b"Body\r\n";

        let sig_value = signer.sign_message(&msg_headers, body).unwrap();
        let mut all_headers: Vec<(&str, &str)> =
            vec![("DKIM-Signature", &sig_value)];
        all_headers.extend_from_slice(&msg_headers);

        let raw = build_raw_message(&all_headers, body);

        let resolver = resolver_with_all(
            "example.com",
            "v=spf1 ip4:10.0.0.1 -all",  // won't match 192.0.2.10
            "sel",
            "example.com",
            &pub_key,
            "example.com",
            "v=DMARC1; p=reject",
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(&raw, "192.0.2.10".parse().unwrap(), "mail.example.com", "alice@example.com")
            .await;

        assert!(matches!(result.spf, SpfResult::Fail { .. }));
        assert!(result.dkim[0].is_pass());
        assert_eq!(result.dmarc.disposition, Disposition::Pass);
        assert!(result.dmarc.dkim_aligned);
        assert!(!result.dmarc.spf_aligned);
    }

    // -----------------------------------------------------------------------
    // Integration test 3: No DKIM signature, DMARC pass via SPF
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_dkim_dmarc_pass_via_spf() {
        let msg_headers = [
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " Test"),
        ];
        let body = b"No signature\r\n";
        let raw = build_raw_message(&msg_headers, body);

        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::Records(vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]),
        );
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec!["v=DMARC1; p=reject".into()]),
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(&raw, "192.0.2.10".parse().unwrap(), "mail.example.com", "alice@example.com")
            .await;

        assert_eq!(result.spf, SpfResult::Pass);
        assert_eq!(result.dkim, vec![DkimResult::None]);
        assert_eq!(result.dmarc.disposition, Disposition::Pass);
        assert!(!result.dmarc.dkim_aligned);
        assert!(result.dmarc.spf_aligned);
    }

    // -----------------------------------------------------------------------
    // Integration test 4: DMARC reject — both SPF and DKIM fail alignment
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dmarc_reject_both_fail() {
        let msg_headers = [
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
        ];
        let body = b"Rejected\r\n";
        let raw = build_raw_message(&msg_headers, body);

        let mut resolver = MockResolver::new();
        // SPF: different domain, will fail
        resolver.txt.insert(
            "other.com".into(),
            MockDnsResponse::Records(vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]),
        );
        // DMARC: reject policy
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec!["v=DMARC1; p=reject".into()]),
        );

        let auth = EmailAuthenticator::new(resolver);
        // mail_from domain is "other.com" — SPF passes for other.com but
        // doesn't align with From domain "example.com"
        let result = auth
            .authenticate(&raw, "192.0.2.10".parse().unwrap(), "mail.example.com", "alice@other.com")
            .await;

        // SPF checks against other.com (mail_from domain)
        assert_eq!(result.spf_domain, "other.com");
        // No DKIM -> None
        assert_eq!(result.dkim, vec![DkimResult::None]);
        // DMARC: SPF domain (other.com) doesn't align with From (example.com)
        assert!(!result.dmarc.spf_aligned);
        assert!(!result.dmarc.dkim_aligned);
        assert_eq!(result.dmarc.disposition, Disposition::Reject);
    }

    // -----------------------------------------------------------------------
    // Integration test 5: Missing From header — fallback to mail_from
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn missing_from_fallback_to_mail_from() {
        let msg_headers = [
            ("To", " bob@example.org"),
            ("Subject", " No From"),
        ];
        let body = b"body\r\n";
        let raw = build_raw_message(&msg_headers, body);

        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::Records(vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]),
        );
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec!["v=DMARC1; p=none".into()]),
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(&raw, "192.0.2.10".parse().unwrap(), "mail.example.com", "alice@example.com")
            .await;

        // From domain should fall back to mail_from domain
        assert_eq!(result.from_domain, "example.com");
        assert_eq!(result.spf, SpfResult::Pass);
    }

    // -----------------------------------------------------------------------
    // Integration test 6: SPF temp error, DKIM still runs
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn spf_temperror_dkim_still_runs() {
        let (pkcs8, pub_key) = gen_ed25519_keypair();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to"]);

        let msg_headers = [
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
        ];
        let body = b"Body\r\n";

        let sig_value = signer.sign_message(&msg_headers, body).unwrap();
        let mut all_headers: Vec<(&str, &str)> =
            vec![("DKIM-Signature", &sig_value)];
        all_headers.extend_from_slice(&msg_headers);

        let raw = build_raw_message(&all_headers, body);

        let mut resolver = MockResolver::new();
        // SPF: DNS temp fail
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::TempFail("timeout".into()),
        );
        // DKIM key: available
        resolver.txt.insert(
            "sel._domainkey.example.com".into(),
            MockDnsResponse::Records(vec![format!(
                "v=DKIM1; k=ed25519; p={}",
                b64(&pub_key)
            )]),
        );
        // DMARC: available
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec!["v=DMARC1; p=reject".into()]),
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(&raw, "192.0.2.10".parse().unwrap(), "mail.example.com", "alice@example.com")
            .await;

        // SPF failed with temp error
        assert_eq!(result.spf, SpfResult::TempError);
        // DKIM still verified successfully
        assert!(result.dkim[0].is_pass());
        // DMARC passes via DKIM alignment despite SPF failure
        assert_eq!(result.dmarc.disposition, Disposition::Pass);
        assert!(result.dmarc.dkim_aligned);
    }

    // -----------------------------------------------------------------------
    // Integration test 7: From header with display name + angle brackets
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn from_with_display_name_parsed() {
        let msg_headers = [
            ("From", " \"Alice Smith\" <alice@example.com>"),
            ("To", " bob@example.org"),
        ];
        let body = b"body\r\n";
        let raw = build_raw_message(&msg_headers, body);

        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::Records(vec!["v=spf1 +all".into()]),
        );
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec!["v=DMARC1; p=none".into()]),
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(&raw, "1.2.3.4".parse().unwrap(), "helo", "alice@example.com")
            .await;

        assert_eq!(result.from_domain, "example.com");
    }

    // -----------------------------------------------------------------------
    // Integration test 8: No DMARC record — disposition None
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_dmarc_record_disposition_none() {
        let msg_headers = [
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
        ];
        let body = b"body\r\n";
        let raw = build_raw_message(&msg_headers, body);

        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "example.com".into(),
            MockDnsResponse::Records(vec!["v=spf1 +all".into()]),
        );
        // No DMARC record

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(&raw, "1.2.3.4".parse().unwrap(), "helo", "alice@example.com")
            .await;

        assert_eq!(result.spf, SpfResult::Pass);
        assert_eq!(result.dmarc.disposition, Disposition::None);
        assert!(result.dmarc.record.is_none());
    }

    // -----------------------------------------------------------------------
    // Integration test 9: Empty mail_from — SPF domain from HELO
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn empty_mail_from_uses_helo_domain() {
        let msg_headers = [
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
        ];
        let body = b"body\r\n";
        let raw = build_raw_message(&msg_headers, body);

        let mut resolver = MockResolver::new();
        resolver.txt.insert(
            "mail.example.com".into(),
            MockDnsResponse::Records(vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]),
        );
        resolver.txt.insert(
            "_dmarc.example.com".into(),
            MockDnsResponse::Records(vec!["v=DMARC1; p=none".into()]),
        );

        let auth = EmailAuthenticator::new(resolver);
        // Empty mail_from: SPF domain should be HELO domain
        let result = auth
            .authenticate(&raw, "192.0.2.10".parse().unwrap(), "mail.example.com", "")
            .await;

        assert_eq!(result.spf_domain, "mail.example.com");
        assert_eq!(result.spf, SpfResult::Pass);
    }

    // -----------------------------------------------------------------------
    // Integration test 10: DKIM with simple/simple canonicalization
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dkim_simple_canonicalization_through_pipeline() {
        let (pkcs8, pub_key) = gen_ed25519_keypair();
        let signer = DkimSigner::ed25519("example.com", "sel", &pkcs8)
            .unwrap()
            .headers(&["from", "to", "subject"])
            .canonicalization(CanonicalizationMethod::Simple, CanonicalizationMethod::Simple);

        let msg_headers = [
            ("From", " alice@example.com"),
            ("To", " bob@example.org"),
            ("Subject", " Simple test"),
        ];
        let body = b"Simple body\r\n";

        let sig_value = signer.sign_message(&msg_headers, body).unwrap();
        let mut all_headers: Vec<(&str, &str)> =
            vec![("DKIM-Signature", &sig_value)];
        all_headers.extend_from_slice(&msg_headers);

        let raw = build_raw_message(&all_headers, body);

        let resolver = resolver_with_all(
            "example.com",
            "v=spf1 +all",
            "sel",
            "example.com",
            &pub_key,
            "example.com",
            "v=DMARC1; p=reject",
        );

        let auth = EmailAuthenticator::new(resolver);
        let result = auth
            .authenticate(&raw, "1.2.3.4".parse().unwrap(), "helo", "alice@example.com")
            .await;

        assert!(result.dkim[0].is_pass());
        assert_eq!(result.dmarc.disposition, Disposition::Pass);
    }
}
