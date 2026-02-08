use std::net::IpAddr;

use crate::common::dns::DnsResolver;
use crate::common::domain;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{DmarcEvaluator, DmarcResult};
use crate::spf::{self, SpfResult};

/// Combined authentication result from SPF, DKIM, and DMARC.
#[derive(Debug)]
pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub from_domain: String,
    pub spf_domain: String,
}

/// Combined email authenticator running SPF, DKIM, and DMARC in sequence.
pub struct EmailAuthenticator<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
    receiver: String,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub fn new(resolver: R, receiver: impl Into<String>) -> Self {
        Self {
            resolver,
            clock_skew: 300,
            receiver: receiver.into(),
        }
    }

    pub fn with_clock_skew(mut self, skew: u64) -> Self {
        self.clock_skew = skew;
        self
    }

    /// Authenticate a raw RFC 5322 message.
    ///
    /// - `message`: raw RFC 5322 bytes
    /// - `client_ip`: connecting client IP
    /// - `helo`: EHLO/HELO identity
    /// - `mail_from`: MAIL FROM address (envelope sender)
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> Result<AuthenticationResult, AuthError> {
        // 1. Parse message into headers + body
        let (headers, body) = split_message(message);
        let parsed_headers = parse_headers(&headers);

        // 2. Extract From domain
        let from_domain = extract_from_domain(&parsed_headers)
            .ok_or(AuthError::NoFromDomain)?;

        // 3. Determine SPF domain (MAIL FROM domain, or HELO if empty)
        let spf_domain = if mail_from.is_empty() || !mail_from.contains('@') {
            helo.to_string()
        } else {
            domain::domain_from_email(mail_from)
                .unwrap_or(helo)
                .to_string()
        };

        // 4. Run SPF
        let spf_result = spf::check_host(
            &self.resolver,
            client_ip,
            helo,
            mail_from,
            &spf_domain,
            &self.receiver,
        )
        .await;

        // 5. Run DKIM
        let header_pairs: Vec<(&str, &str)> = parsed_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let dkim_verifier = DkimVerifier::new(&self.resolver)
            .clock_skew(self.clock_skew);
        let dkim_results = dkim_verifier.verify_message(&header_pairs, body).await;

        // 6. Run DMARC
        let dmarc_evaluator = DmarcEvaluator::new(&self.resolver);
        let dmarc_result = dmarc_evaluator
            .evaluate(&from_domain, &spf_result, &spf_domain, &dkim_results)
            .await;

        Ok(AuthenticationResult {
            spf: spf_result,
            dkim: dkim_results,
            dmarc: dmarc_result,
            from_domain,
            spf_domain,
        })
    }
}

/// Error from authentication pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No RFC 5322 From header with a valid domain found.
    NoFromDomain,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::NoFromDomain => write!(f, "no From domain found in message"),
        }
    }
}

impl std::error::Error for AuthError {}

// --- Message parsing ---

/// Split raw message bytes into (headers_bytes, body_bytes).
/// Splits at `\r\n\r\n` (preferred) or `\n\n` (fallback).
fn split_message(message: &[u8]) -> (&[u8], &[u8]) {
    // Look for \r\n\r\n first
    if let Some(pos) = find_bytes(message, b"\r\n\r\n") {
        return (&message[..pos], &message[pos + 4..]);
    }
    // Fallback: \n\n
    if let Some(pos) = find_bytes(message, b"\n\n") {
        return (&message[..pos], &message[pos + 2..]);
    }
    // No body separator — entire message is headers
    (message, b"")
}

/// Find a byte pattern in a byte slice.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Parse raw header bytes into (name, value) pairs.
/// Handles folded headers (lines starting with SP/HTAB are continuations).
fn parse_headers(header_bytes: &[u8]) -> Vec<(String, String)> {
    // Convert to string, handling non-UTF-8 gracefully at the byte level.
    // Headers are ASCII per RFC 5322 — parse as bytes, find colons.
    let mut headers: Vec<(String, String)> = Vec::new();

    // Split into lines, preserving CRLF semantics
    let text = String::from_utf8_lossy(header_bytes);
    let mut lines: Vec<&str> = Vec::new();

    // Split on \r\n first, then on bare \n for remaining
    let mut remaining = text.as_ref();
    while !remaining.is_empty() {
        if let Some(pos) = remaining.find("\r\n") {
            lines.push(&remaining[..pos]);
            remaining = &remaining[pos + 2..];
        } else if let Some(pos) = remaining.find('\n') {
            lines.push(&remaining[..pos]);
            remaining = &remaining[pos + 1..];
        } else {
            lines.push(remaining);
            break;
        }
    }

    // Group folded lines
    let mut current_line = String::new();
    for line in &lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation — append with original folding whitespace
            if !current_line.is_empty() {
                current_line.push_str("\r\n");
                current_line.push_str(line);
            }
        } else {
            // New header — flush previous
            if !current_line.is_empty() {
                if let Some((name, value)) = split_header(&current_line) {
                    headers.push((name, value));
                }
            }
            current_line = line.to_string();
        }
    }
    // Flush last header
    if !current_line.is_empty() {
        if let Some((name, value)) = split_header(&current_line) {
            headers.push((name, value));
        }
    }

    headers
}

/// Split a header line into (name, value) at the first colon.
fn split_header(line: &str) -> Option<(String, String)> {
    let pos = line.find(':')?;
    let name = line[..pos].to_string();
    let value = line[pos + 1..].to_string();
    Some((name, value))
}

/// Extract the From domain from parsed headers.
/// Handles RFC 5322 comments, angle brackets, and display names.
fn extract_from_domain(headers: &[(String, String)]) -> Option<String> {
    // Find the From header
    let from_value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))?;

    let value = &from_value.1;

    // Unfold (replace \r\n + WSP with single space)
    let unfolded = unfold(value);

    // Strip RFC 5322 comments (parenthesized, possibly nested)
    let stripped = strip_comments(&unfolded);

    // Extract email address
    let email = extract_email_address(&stripped)?;

    // Get domain from email
    let domain = domain::domain_from_email(&email)?;
    Some(domain.to_lowercase())
}

/// Unfold header value: replace \r\n followed by SP/HTAB with single space.
fn unfold(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next(); // consume \n
                if matches!(chars.peek(), Some(' ' | '\t')) {
                    result.push(' ');
                    chars.next(); // consume the WSP
                } else {
                    result.push('\r');
                    result.push('\n');
                }
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Strip RFC 5322 comments (parenthesized text with nesting support).
fn strip_comments(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut depth = 0u32;
    let mut escaped = false;

    for c in value.chars() {
        if escaped {
            if depth == 0 {
                result.push(c);
            }
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            if depth == 0 {
                result.push(c);
            }
            continue;
        }
        if c == '(' {
            depth += 1;
            continue;
        }
        if c == ')' && depth > 0 {
            depth -= 1;
            continue;
        }
        if depth == 0 {
            result.push(c);
        }
    }
    result
}

/// Extract an email address from a From header value.
/// Checks for angle brackets first (handles display names, commas in quoted strings).
/// Falls back to bare address.
fn extract_email_address(value: &str) -> Option<String> {
    let trimmed = value.trim();

    // Check for angle-bracket form: ... <addr>
    if let Some(start) = trimmed.rfind('<') {
        if let Some(end) = trimmed[start..].find('>') {
            let addr = trimmed[start + 1..start + end].trim();
            if !addr.is_empty() && addr.contains('@') {
                return Some(addr.to_string());
            }
        }
    }

    // Bare address form
    let addr = trimmed.trim();
    if addr.contains('@') {
        return Some(addr.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::{DnsError, MxRecord};
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- MockResolver for integration tests ---
    #[derive(Clone)]
    struct MockResolver {
        txt: HashMap<String, Vec<String>>,
        a: HashMap<String, Vec<Ipv4Addr>>,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                txt: HashMap::new(),
                a: HashMap::new(),
            }
        }

        fn add_txt(&mut self, name: &str, records: Vec<&str>) {
            self.txt
                .insert(name.to_string(), records.into_iter().map(String::from).collect());
        }

    }

    impl DnsResolver for MockResolver {
        async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
            self.txt
                .get(name)
                .cloned()
                .ok_or(DnsError::NxDomain)
        }
        async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
            self.a
                .get(name)
                .cloned()
                .ok_or(DnsError::NxDomain)
        }
        async fn query_aaaa(&self, _name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
            Err(DnsError::NxDomain)
        }
        async fn query_mx(&self, _name: &str) -> Result<Vec<MxRecord>, DnsError> {
            Err(DnsError::NxDomain)
        }
        async fn query_ptr(&self, _ip: &IpAddr) -> Result<Vec<String>, DnsError> {
            Err(DnsError::NxDomain)
        }
        async fn query_exists(&self, name: &str) -> Result<bool, DnsError> {
            Ok(self.a.contains_key(name))
        }
    }

    // --- Message parsing unit tests ---

    #[test]
    fn split_message_crlf() {
        let msg = b"From: test@example.com\r\nSubject: hi\r\n\r\nBody here";
        let (headers, body) = split_message(msg);
        assert_eq!(headers, b"From: test@example.com\r\nSubject: hi");
        assert_eq!(body, b"Body here");
    }

    #[test]
    fn split_message_lf_fallback() {
        let msg = b"From: test@example.com\nSubject: hi\n\nBody here";
        let (headers, body) = split_message(msg);
        assert_eq!(headers, b"From: test@example.com\nSubject: hi");
        assert_eq!(body, b"Body here");
    }

    #[test]
    fn split_message_no_body() {
        let msg = b"From: test@example.com\r\nSubject: hi";
        let (headers, body) = split_message(msg);
        assert_eq!(headers, b"From: test@example.com\r\nSubject: hi");
        assert_eq!(body, b"");
    }

    #[test]
    fn parse_headers_simple() {
        let raw = b"From: alice@example.com\r\nSubject: Hello";
        let headers = parse_headers(raw);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "From");
        assert_eq!(headers[0].1, " alice@example.com");
        assert_eq!(headers[1].0, "Subject");
        assert_eq!(headers[1].1, " Hello");
    }

    #[test]
    fn parse_headers_folded() {
        let raw = b"Subject: This is a long\r\n subject line\r\nFrom: test@example.com";
        let headers = parse_headers(raw);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "Subject");
        assert!(headers[0].1.contains("long"));
        assert!(headers[0].1.contains("subject line"));
        assert_eq!(headers[1].0, "From");
    }

    #[test]
    fn parse_headers_bare_lf() {
        let raw = b"From: alice@example.com\nSubject: Hello";
        let headers = parse_headers(raw);
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn extract_from_angle_brackets() {
        let headers = vec![
            ("From".to_string(), " \"John Smith\" <john@example.com>".to_string()),
        ];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_from_bare_address() {
        let headers = vec![
            ("From".to_string(), " alice@example.org".to_string()),
        ];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.org".to_string())
        );
    }

    #[test]
    fn extract_from_with_comment() {
        let headers = vec![
            ("From".to_string(), " alice(comment)@example.com".to_string()),
        ];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_from_nested_comments() {
        let headers = vec![
            ("From".to_string(), " alice(nested (comment))@example.com".to_string()),
        ];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_from_display_name_with_comma() {
        // "Smith, John" <j@example.com> — comma must not split
        let headers = vec![
            ("From".to_string(), " \"Smith, John\" <j@example.com>".to_string()),
        ];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_from_case_insensitive() {
        let headers = vec![
            ("from".to_string(), " alice@EXAMPLE.COM".to_string()),
        ];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_from_missing() {
        let headers = vec![
            ("Subject".to_string(), " Hello".to_string()),
        ];
        assert_eq!(extract_from_domain(&headers), None);
    }

    #[test]
    fn extract_from_no_at() {
        let headers = vec![
            ("From".to_string(), " invalid-address".to_string()),
        ];
        assert_eq!(extract_from_domain(&headers), None);
    }

    #[test]
    fn strip_comments_basic() {
        assert_eq!(strip_comments("alice(test)@example.com"), "alice@example.com");
    }

    #[test]
    fn strip_comments_nested() {
        assert_eq!(
            strip_comments("alice(a (b) c)@example.com"),
            "alice@example.com"
        );
    }

    #[test]
    fn strip_comments_escaped_paren() {
        assert_eq!(strip_comments("alice(\\))@example.com"), "alice@example.com");
    }

    #[test]
    fn unfold_crlf_sp() {
        assert_eq!(unfold("hello\r\n world"), "hello world");
    }

    #[test]
    fn unfold_crlf_tab() {
        assert_eq!(unfold("hello\r\n\tworld"), "hello world");
    }

    #[test]
    fn unfold_no_fold() {
        assert_eq!(unfold("hello world"), "hello world");
    }

    // --- Integration tests ---

    #[tokio::test]
    async fn authenticate_full_pipeline() {
        let mut resolver = MockResolver::new();

        // SPF record for example.com: allow 192.0.2.1
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.1 -all"]);

        // DMARC record
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject; adkim=r; aspf=r"]);

        let message = b"From: sender@example.com\r\nSubject: Test\r\n\r\nBody";

        let auth = EmailAuthenticator::new(resolver, "mx.receiver.com");
        let result = auth
            .authenticate(
                message,
                "192.0.2.1".parse().unwrap(),
                "mail.example.com",
                "sender@example.com",
            )
            .await
            .unwrap();

        assert_eq!(result.from_domain, "example.com");
        assert_eq!(result.spf_domain, "example.com");
        assert!(matches!(result.spf, SpfResult::Pass));
        // No DKIM signatures → DkimResult::None
        assert_eq!(result.dkim.len(), 1);
        assert!(matches!(result.dkim[0], DkimResult::None));
    }

    #[tokio::test]
    async fn authenticate_no_from_header() {
        let resolver = MockResolver::new();
        let message = b"Subject: No from\r\n\r\nBody";
        let auth = EmailAuthenticator::new(resolver, "mx.receiver.com");
        let result = auth
            .authenticate(
                message,
                "192.0.2.1".parse().unwrap(),
                "mail.example.com",
                "sender@example.com",
            )
            .await;
        assert!(matches!(result, Err(AuthError::NoFromDomain)));
    }

    #[tokio::test]
    async fn authenticate_empty_mail_from_uses_helo() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("mail.example.com", vec!["v=spf1 ip4:192.0.2.1 -all"]);
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=none"]);

        let message = b"From: sender@example.com\r\n\r\nBody";

        let auth = EmailAuthenticator::new(resolver, "mx.receiver.com");
        let result = auth
            .authenticate(
                message,
                "192.0.2.1".parse().unwrap(),
                "mail.example.com",
                "", // empty MAIL FROM
            )
            .await
            .unwrap();

        // SPF domain should be HELO domain
        assert_eq!(result.spf_domain, "mail.example.com");
    }

    #[tokio::test]
    async fn authenticate_spf_fail_dmarc_reject() {
        let mut resolver = MockResolver::new();
        // SPF: only allow 10.0.0.1
        resolver.add_txt("example.com", vec!["v=spf1 ip4:10.0.0.1 -all"]);
        // DMARC: reject policy
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject"]);

        let message = b"From: sender@example.com\r\n\r\nBody";

        let auth = EmailAuthenticator::new(resolver, "mx.receiver.com");
        let result = auth
            .authenticate(
                message,
                "192.0.2.99".parse().unwrap(), // not authorized
                "mail.example.com",
                "sender@example.com",
            )
            .await
            .unwrap();

        assert!(matches!(result.spf, SpfResult::Fail { .. }));
        // DMARC should apply reject since SPF failed and no DKIM
        assert!(matches!(
            result.dmarc.disposition,
            crate::dmarc::Disposition::Reject
        ));
    }

    #[tokio::test]
    async fn authenticate_folded_from_header() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.1 -all"]);
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=none"]);

        // From header is folded across lines
        let message = b"From: \"Very Long\r\n Display Name\" <sender@example.com>\r\nSubject: Test\r\n\r\nBody";

        let auth = EmailAuthenticator::new(resolver, "mx.receiver.com");
        let result = auth
            .authenticate(
                message,
                "192.0.2.1".parse().unwrap(),
                "mail.example.com",
                "sender@example.com",
            )
            .await
            .unwrap();

        assert_eq!(result.from_domain, "example.com");
    }

    #[tokio::test]
    async fn authenticate_from_with_rfc5322_comment() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.1 -all"]);
        resolver.add_txt("_dmarc.example.com", vec!["v=DMARC1; p=none"]);

        let message = b"From: sender(comment)@example.com\r\n\r\nBody";

        let auth = EmailAuthenticator::new(resolver, "mx.receiver.com");
        let result = auth
            .authenticate(
                message,
                "192.0.2.1".parse().unwrap(),
                "mail.example.com",
                "sender@example.com",
            )
            .await
            .unwrap();

        assert_eq!(result.from_domain, "example.com");
    }
}
