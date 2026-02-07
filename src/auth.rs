use crate::common::dns::DnsResolver;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{self, DmarcResult};
use crate::spf::{self, SpfResult};
use std::net::IpAddr;

/// Combined result of SPF + DKIM + DMARC authentication.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
}

/// Parameters for email authentication that aren't in the message itself.
pub struct AuthParams<'a> {
    /// IP address of the sending MTA
    pub client_ip: IpAddr,
    /// HELO/EHLO identity
    pub helo: &'a str,
    /// MAIL FROM (envelope sender), empty string if null sender
    pub mail_from: &'a str,
    /// Hostname of the receiving MTA (for SPF %{r} macro)
    pub receiver: &'a str,
}

/// Authenticate an email message by running SPF, DKIM, and DMARC.
///
/// `raw_message` is the full RFC 5322 message bytes (headers + body).
pub async fn authenticate<R: DnsResolver>(
    resolver: &R,
    params: &AuthParams<'_>,
    raw_message: &[u8],
) -> AuthResult {
    // Parse message into headers + body
    let (headers, body) = parse_message(raw_message);

    // Extract From domain for DMARC
    let from_domain = extract_from_domain(&headers).unwrap_or_default();

    // SPF domain: MAIL FROM domain, fallback to HELO
    let spf_domain = if params.mail_from.is_empty() || !params.mail_from.contains('@') {
        params.helo.to_string()
    } else {
        crate::common::domain::domain_from_email(params.mail_from)
            .unwrap_or(params.helo)
            .to_string()
    };

    // Run SPF
    let spf_result = spf::check_host(
        resolver,
        params.client_ip,
        params.helo,
        params.mail_from,
        &spf_domain,
        params.receiver,
    )
    .await;

    // Run DKIM
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let verifier = DkimVerifier::new(resolver);
    let dkim_results = verifier.verify_message(&header_refs, &body).await;

    // Run DMARC
    let dmarc_result = dmarc::eval::evaluate(
        resolver,
        &from_domain,
        &spf_result,
        &spf_domain,
        &dkim_results,
    )
    .await;

    AuthResult {
        spf: spf_result,
        dkim: dkim_results,
        dmarc: dmarc_result,
    }
}

/// Parse raw RFC 5322 message bytes into (headers, body).
///
/// Headers are split at the first blank line (CRLF CRLF).
/// Returns Vec of (name, value) pairs where value includes folding whitespace.
/// Body is everything after the blank line separator.
pub fn parse_message(raw: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
    // Find header/body boundary: first occurrence of CRLFCRLF or LFLF
    let (header_bytes, body) = split_header_body(raw);

    let headers = parse_headers(header_bytes);
    (headers, body)
}

/// Split raw message into header bytes and body bytes.
fn split_header_body(raw: &[u8]) -> (&[u8], Vec<u8>) {
    // Try CRLF CRLF first
    if let Some(pos) = find_bytes(raw, b"\r\n\r\n") {
        let header_bytes = &raw[..pos];
        let body = raw[pos + 4..].to_vec();
        return (header_bytes, body);
    }
    // Fallback: LF LF (bare LF)
    if let Some(pos) = find_bytes(raw, b"\n\n") {
        let header_bytes = &raw[..pos];
        let body = raw[pos + 2..].to_vec();
        return (header_bytes, body);
    }
    // No body separator found — entire message is headers
    (raw, Vec::new())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Parse header block bytes into (name, value) pairs.
/// Handles folded headers (continuation lines starting with SP/HTAB).
fn parse_headers(header_bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(header_bytes);
    let mut headers = Vec::new();
    let mut current_name = String::new();
    let mut current_value = String::new();

    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);

        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header (folded)
            if !current_name.is_empty() {
                current_value.push_str("\r\n");
                current_value.push_str(line);
            }
        } else if let Some(colon_pos) = line.find(':') {
            // New header — flush previous
            if !current_name.is_empty() {
                headers.push((current_name, current_value));
            }
            current_name = line[..colon_pos].to_string();
            current_value = line[colon_pos + 1..].to_string();
        } else if line.is_empty() {
            // Shouldn't reach here since we split at boundary, but handle gracefully
            continue;
        }
        // Ignore malformed lines that don't have a colon and aren't continuation
    }

    // Flush last header
    if !current_name.is_empty() {
        headers.push((current_name, current_value));
    }

    headers
}

/// Extract the domain from the RFC 5322 From header.
/// Handles multiple From addresses (takes first), angle brackets, display names,
/// and RFC 5322 comments.
fn extract_from_domain(headers: &[(String, String)]) -> Option<String> {
    // Find the From header (last occurrence per RFC, but typically only one)
    let from_value = headers
        .iter()
        .rev()
        .find(|(name, _)| name.eq_ignore_ascii_case("From"))
        .map(|(_, value)| value.as_str())?;

    // Strip RFC 5322 comments
    let stripped = strip_comments(from_value);

    // Extract email address
    extract_email_domain(&stripped)
}

/// Strip RFC 5322 comments (parenthesized, possibly nested).
fn strip_comments(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut depth = 0u32;
    let mut escaped = false;

    for c in s.chars() {
        if escaped {
            if depth == 0 {
                result.push(c);
            }
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                if depth == 0 {
                    result.push(c);
                }
            }
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => result.push(c),
            _ => {} // inside comment, skip
        }
    }
    result
}

/// Extract domain from a potentially decorated email address.
/// Handles: `<user@domain>`, `Display Name <user@domain>`, `user@domain`, group syntax.
fn extract_email_domain(s: &str) -> Option<String> {
    let s = s.trim();

    // If there are multiple addresses (comma-separated), take the first
    let first = if s.contains(',') {
        s.split(',').next().unwrap_or(s).trim()
    } else {
        s
    };

    // Try angle-bracket form first
    if let Some(start) = first.find('<') {
        if let Some(end) = first[start..].find('>') {
            let addr = &first[start + 1..start + end];
            return domain_from_addr(addr);
        }
    }

    // Bare address
    domain_from_addr(first)
}

fn domain_from_addr(addr: &str) -> Option<String> {
    let addr = addr.trim();
    if let Some(at_pos) = addr.rfind('@') {
        let domain = addr[at_pos + 1..].trim();
        if !domain.is_empty() {
            return Some(domain.to_ascii_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    #[test]
    fn test_parse_message_crlf() {
        let msg = b"From: user@example.com\r\nTo: other@example.com\r\n\r\nHello body";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "From");
        assert_eq!(headers[0].1, " user@example.com");
        assert_eq!(body, b"Hello body");
    }

    #[test]
    fn test_parse_message_lf() {
        let msg = b"From: user@example.com\nTo: other@example.com\n\nHello body";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(body, b"Hello body");
    }

    #[test]
    fn test_parse_folded_headers() {
        let msg = b"Subject: This is a\r\n very long subject\r\nFrom: user@example.com\r\n\r\nbody";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "Subject");
        assert!(headers[0].1.contains("very long subject"));
        assert_eq!(body, b"body");
    }

    #[test]
    fn test_parse_no_body() {
        let msg = b"From: user@example.com\r\nTo: other@example.com";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 2);
        assert!(body.is_empty());
    }

    #[test]
    fn test_extract_from_domain_simple() {
        let headers = vec![
            ("From".to_string(), " user@example.com".to_string()),
        ];
        assert_eq!(extract_from_domain(&headers), Some("example.com".into()));
    }

    #[test]
    fn test_extract_from_domain_angle_brackets() {
        let headers = vec![
            ("From".to_string(), " John Doe <john@example.com>".to_string()),
        ];
        assert_eq!(extract_from_domain(&headers), Some("example.com".into()));
    }

    #[test]
    fn test_extract_from_domain_with_comment() {
        let headers = vec![
            ("From".to_string(), " user@example.com (Comment)".to_string()),
        ];
        assert_eq!(extract_from_domain(&headers), Some("example.com".into()));
    }

    #[test]
    fn test_extract_from_domain_nested_comments() {
        let headers = vec![
            ("From".to_string(), " (outer (inner)) user@example.com".to_string()),
        ];
        assert_eq!(extract_from_domain(&headers), Some("example.com".into()));
    }

    #[test]
    fn test_extract_from_domain_multiple() {
        let headers = vec![
            ("From".to_string(), " a@first.com, b@second.com".to_string()),
        ];
        assert_eq!(extract_from_domain(&headers), Some("first.com".into()));
    }

    #[test]
    fn test_extract_from_domain_case_insensitive() {
        let headers = vec![
            ("From".to_string(), " user@EXAMPLE.COM".to_string()),
        ];
        assert_eq!(extract_from_domain(&headers), Some("example.com".into()));
    }

    #[test]
    fn test_strip_comments_basic() {
        assert_eq!(strip_comments("hello (comment) world"), "hello  world");
    }

    #[test]
    fn test_strip_comments_nested() {
        assert_eq!(strip_comments("a (b (c) d) e"), "a  e");
    }

    #[test]
    fn test_strip_comments_escaped() {
        assert_eq!(strip_comments("a (b\\)c) d"), "a  d");
    }

    #[tokio::test]
    async fn test_authenticate_full() {
        let resolver = MockResolver::new()
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject"])
            .with_txt("example.com", vec!["v=spf1 ip4:192.0.2.1 -all"]);

        let msg = b"From: user@example.com\r\nTo: other@test.com\r\nSubject: Test\r\n\r\nHello";

        let params = AuthParams {
            client_ip: "192.0.2.1".parse().unwrap(),
            helo: "mail.example.com",
            mail_from: "user@example.com",
            receiver: "mx.test.com",
        };

        let result = authenticate(&resolver, &params, msg).await;

        assert_eq!(result.spf, SpfResult::Pass);
        assert_eq!(result.dkim.len(), 1);
        assert_eq!(result.dkim[0], DkimResult::None);
        // DMARC: SPF passes and aligns (relaxed), so should pass
        assert_eq!(result.dmarc.disposition, crate::dmarc::Disposition::Pass);
        assert!(result.dmarc.spf_aligned);
    }

    #[tokio::test]
    async fn test_authenticate_fail() {
        let resolver = MockResolver::new()
            .with_txt("_dmarc.example.com", vec!["v=DMARC1; p=reject"])
            .with_txt("example.com", vec!["v=spf1 ip4:192.0.2.1 -all"]);

        let msg = b"From: user@example.com\r\nTo: other@test.com\r\n\r\nHello";

        let params = AuthParams {
            client_ip: "10.0.0.1".parse().unwrap(), // wrong IP
            helo: "mail.other.com",
            mail_from: "user@other.com", // different domain
            receiver: "mx.test.com",
        };

        let result = authenticate(&resolver, &params, msg).await;

        // SPF fails (wrong IP)
        assert!(matches!(result.spf, SpfResult::Fail { .. }) || result.spf == SpfResult::None);
        // DMARC: neither aligned
        assert!(!result.dmarc.spf_aligned);
        assert!(!result.dmarc.dkim_aligned);
    }

    #[test]
    fn test_parse_message_binary_body() {
        // Verify we handle non-UTF8 body bytes correctly
        let mut msg = b"From: user@example.com\r\n\r\n".to_vec();
        msg.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x01]);
        let (headers, body) = parse_message(&msg);
        assert_eq!(headers.len(), 1);
        assert_eq!(body, &[0xFF, 0xFE, 0x00, 0x01]);
    }

    #[test]
    fn test_parse_message_empty_body() {
        let msg = b"From: user@example.com\r\n\r\n";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 1);
        assert!(body.is_empty());
    }
}
