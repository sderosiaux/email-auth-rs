use std::net::IpAddr;

use crate::common::dns::DnsResolver;
use crate::common::domain;
use crate::dkim::{DkimResult, DkimVerifier};
use crate::dmarc::{DmarcEvaluator, DmarcResult};
use crate::spf::{self, SpfResult};

/// Combined email authentication result.
#[derive(Debug)]
pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub from_domain: String,
    pub spf_domain: String,
}

/// Combined email authenticator. Runs SPF, DKIM, and DMARC checks.
pub struct EmailAuthenticator<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
    receiver: String,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub fn new(resolver: R, receiver: &str) -> Self {
        Self {
            resolver,
            clock_skew: 300,
            receiver: receiver.to_string(),
        }
    }

    pub fn clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    /// Authenticate an email message.
    /// `message` is the raw RFC 5322 message bytes.
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // Parse message into headers and body
        let (headers, body) = parse_message(message);

        // Extract From domain
        let from_domain = extract_from_domain(&headers)
            .unwrap_or_else(|| {
                domain::domain_from_email(mail_from)
                    .unwrap_or("unknown")
                    .to_string()
            });

        // Determine SPF domain (MAIL FROM domain, or HELO if empty)
        let spf_domain = if mail_from.is_empty() || !mail_from.contains('@') {
            helo.to_string()
        } else {
            domain::domain_from_email(mail_from)
                .unwrap_or(helo)
                .to_string()
        };

        // Run SPF
        let spf_result = spf::check_host(
            &self.resolver,
            client_ip,
            helo,
            mail_from,
            &spf_domain,
            &self.receiver,
        )
        .await;

        // Run DKIM
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let dkim_verifier = DkimVerifier::new(&self.resolver).clock_skew(self.clock_skew);
        let dkim_results = dkim_verifier.verify_message(&header_refs, &body).await;

        // Run DMARC
        let dmarc_evaluator = DmarcEvaluator::new(&self.resolver);
        let dmarc_result = dmarc_evaluator
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

/// Parse a raw message into (headers, body).
/// Headers are returned as (name, value) pairs.
fn parse_message(message: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
    let msg = String::from_utf8_lossy(message);

    // Split at first \r\n\r\n or \n\n
    let (header_section, body) = if let Some(pos) = msg.find("\r\n\r\n") {
        (&msg[..pos], msg[pos + 4..].as_bytes().to_vec())
    } else if let Some(pos) = msg.find("\n\n") {
        (&msg[..pos], msg[pos + 2..].as_bytes().to_vec())
    } else {
        (msg.as_ref(), Vec::new())
    };

    // Parse headers, handling folded lines
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_section.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header
            if let Some(last) = headers.last_mut() {
                last.1.push_str("\r\n");
                last.1.push_str(line);
            }
        } else if let Some(colon) = line.find(':') {
            let name = line[..colon].to_string();
            let value = line[colon + 1..].to_string();
            headers.push((name, value));
        }
    }

    (headers, body)
}

/// Extract the From domain from parsed headers.
fn extract_from_domain(headers: &[(String, String)]) -> Option<String> {
    let from_header = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))?;

    let value = &from_header.1;
    // Unfold
    let unfolded = value.replace("\r\n ", " ").replace("\r\n\t", " ");
    // Strip RFC 5322 comments (parenthesized text)
    let no_comments = strip_comments(&unfolded);

    extract_email_domain(&no_comments)
}

/// Strip RFC 5322 comments (parenthesized text with nesting).
fn strip_comments(s: &str) -> String {
    let mut result = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => result.push(c),
            _ => {}
        }
    }
    result
}

/// Extract email domain from a potentially complex From header value.
fn extract_email_domain(value: &str) -> Option<String> {
    let value = value.trim();

    // Check for angle brackets first (handles "Name" <addr> format)
    if let Some(start) = value.find('<') {
        if let Some(end) = value[start..].find('>') {
            let addr = &value[start + 1..start + end];
            return domain::domain_from_email(addr).map(|d| d.to_string());
        }
    }

    // No angle brackets — try the whole value as an address
    // For multiple addresses, comma-separated, take the first
    let first = value.split(',').next()?;
    let first = first.trim();
    domain::domain_from_email(first).map(|d| d.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_message() {
        let msg = b"From: user@example.com\r\nTo: other@example.com\r\n\r\nBody here";
        let (headers, body) = parse_message(msg);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "From");
        assert_eq!(body, b"Body here");
    }

    #[test]
    fn test_parse_folded_header() {
        let msg = b"DKIM-Signature: v=1;\r\n a=rsa-sha256\r\nFrom: user@example.com\r\n\r\nbody";
        let (headers, _) = parse_message(msg);
        assert_eq!(headers.len(), 2);
        assert!(headers[0].1.contains("a=rsa-sha256"));
    }

    #[test]
    fn test_extract_from_simple() {
        let headers = vec![("From".to_string(), " user@example.com".to_string())];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_from_angle_brackets() {
        let headers = vec![("From".to_string(), " \"John Doe\" <john@example.com>".to_string())];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_from_comma_in_name() {
        let headers = vec![(
            "From".to_string(),
            " \"Last, First\" <user@example.com>".to_string(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_from_with_comment() {
        let headers = vec![(
            "From".to_string(),
            " user@example.com (Comment)".to_string(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_strip_comments() {
        assert_eq!(strip_comments("hello (world) there"), "hello  there");
        assert_eq!(strip_comments("a (b (c) d) e"), "a  e");
    }
}
