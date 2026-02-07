use std::net::IpAddr;

use crate::common::dns::DnsResolver;
use crate::common::domain::{domain_from_email, normalize_domain};
use crate::dkim::signature::DkimResult;
use crate::dkim::verify::DkimVerifier;
use crate::dmarc::eval::{DmarcEvaluator, DmarcResult};
use crate::spf::eval::check_host;
use crate::spf::record::SpfResult;

// ---------------------------------------------------------------------------
// AuthenticationResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub from_domain: String,
    pub spf_domain: String,
}

// ---------------------------------------------------------------------------
// EmailAuthenticator
// ---------------------------------------------------------------------------

pub struct EmailAuthenticator<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            clock_skew: 300,
        }
    }

    pub fn clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew = seconds;
        self
    }

    /// Full authentication pipeline: SPF + DKIM + DMARC.
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult {
        // 1. Parse message
        let msg_str = String::from_utf8_lossy(message);
        let (headers, body) = parse_message_from_str(&msg_str, message);

        // 2. Extract From domain
        let from_domain = extract_from_domain(&headers).unwrap_or_default();

        // 3. SPF domain: domain from MAIL FROM, or helo if empty
        let spf_domain = if mail_from.is_empty() {
            normalize_domain(helo)
        } else {
            domain_from_email(mail_from)
                .map(|d| normalize_domain(d))
                .unwrap_or_else(|| normalize_domain(helo))
        };

        // 4. SPF
        let spf_result = check_host(
            &self.resolver,
            client_ip,
            helo,
            mail_from,
            &spf_domain,
            "localhost",
        )
        .await;

        // 5. DKIM
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let dkim_results = DkimVerifier::new(&self.resolver)
            .clock_skew(self.clock_skew)
            .verify_message(&header_refs, body)
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
/// Headers are returned as `(name, value)` pairs where the value is everything
/// after the colon (including leading whitespace). Folded headers (continuation
/// lines starting with SP/TAB) are unfolded by appending to the previous header
/// value.
///
/// The body is the portion of the raw bytes after the header/body separator
/// (`\r\n\r\n` or `\n\n`).
pub fn parse_message(raw: &[u8]) -> (Vec<(&str, &str)>, &[u8]) {
    // RFC 5322 headers are 7-bit ASCII, so from_utf8 is appropriate.
    // Falls back to empty on invalid UTF-8.
    let text = std::str::from_utf8(raw).unwrap_or("");

    let (header_end, sep_len) = if let Some(pos) = text.find("\r\n\r\n") {
        (pos, 4)
    } else if let Some(pos) = text.find("\n\n") {
        (pos, 2)
    } else {
        (text.len(), 0)
    };

    let header_section = &text[..header_end];
    let body = if sep_len > 0 && header_end + sep_len <= raw.len() {
        &raw[header_end + sep_len..]
    } else {
        &[]
    };

    let headers = parse_header_section_borrowed(header_section);
    (headers, body)
}

/// Internal: parse message from pre-computed string + original bytes.
/// Returns owned header pairs + body slice from original bytes.
fn parse_message_from_str<'a>(
    text: &'a str,
    raw: &'a [u8],
) -> (Vec<(String, String)>, &'a [u8]) {
    let (header_end, sep_len) = if let Some(pos) = text.find("\r\n\r\n") {
        (pos, 4)
    } else if let Some(pos) = text.find("\n\n") {
        (pos, 2)
    } else {
        (text.len(), 0)
    };

    let header_section = &text[..header_end];
    let headers = parse_header_section(header_section);

    let body = if sep_len > 0 && header_end + sep_len <= raw.len() {
        &raw[header_end + sep_len..]
    } else {
        &[]
    };

    (headers, body)
}

/// Parse header section into owned (name, value) pairs, handling folded headers.
fn parse_header_section(section: &str) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in split_lines(section) {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line: append to previous header value
            if let Some(last) = headers.last_mut() {
                last.1.push('\r');
                last.1.push('\n');
                last.1.push_str(line);
            }
        } else if let Some(colon_pos) = line.find(':') {
            let name = &line[..colon_pos];
            let value = &line[colon_pos + 1..];
            headers.push((name.to_string(), value.to_string()));
        }
    }
    headers
}

/// Parse header section into borrowed (name, value) pairs, handling folded headers.
/// This only works when the entire header section is a contiguous &str slice.
fn parse_header_section_borrowed(section: &str) -> Vec<(&str, &str)> {
    let mut headers: Vec<(&str, &str)> = Vec::new();

    // For borrowed parsing, we track start/end positions in the section string.
    // Since folded headers span multiple lines, the value spans from after the
    // colon to the end of the last continuation line.
    let lines = split_line_ranges(section);

    let mut i = 0;
    while i < lines.len() {
        let (start, end) = lines[i];
        let line = &section[start..end];
        if line.is_empty() {
            i += 1;
            continue;
        }

        if let Some(colon_pos) = line.find(':') {
            let name = &section[start..start + colon_pos];
            let value_start = start + colon_pos + 1;
            let mut value_end = end;

            // Absorb continuation lines
            while i + 1 < lines.len() {
                let (next_start, next_end) = lines[i + 1];
                let next_line = &section[next_start..next_end];
                if !next_line.is_empty()
                    && (next_line.starts_with(' ') || next_line.starts_with('\t'))
                {
                    value_end = next_end;
                    i += 1;
                } else {
                    break;
                }
            }

            // The value spans from after the colon to end of last continuation
            // line. For folded headers, the original \r\n between lines is part
            // of the section string, so the slice naturally includes them.
            let value = &section[value_start..value_end];
            headers.push((name, value));
        }
        i += 1;
    }
    headers
}

/// Split a header section into lines, handling both CRLF and bare LF.
fn split_lines(section: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = section.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'\r' && i + 1 < len && bytes[i + 1] == b'\n' {
            lines.push(&section[start..i]);
            i += 2;
            start = i;
        } else if bytes[i] == b'\n' {
            lines.push(&section[start..i]);
            i += 1;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < len {
        lines.push(&section[start..]);
    }
    lines
}

/// Split into (start, end) byte ranges for each line.
fn split_line_ranges(section: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    let bytes = section.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'\r' && i + 1 < len && bytes[i + 1] == b'\n' {
            ranges.push((start, i));
            i += 2;
            start = i;
        } else if bytes[i] == b'\n' {
            ranges.push((start, i));
            i += 1;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < len {
        ranges.push((start, len));
    }
    ranges
}

// ---------------------------------------------------------------------------
// From header extraction
// ---------------------------------------------------------------------------

/// Extract the domain from the RFC 5322 From header.
pub fn extract_from_domain(headers: &[(impl AsRef<str>, impl AsRef<str>)]) -> Option<String> {
    // Find From header (case-insensitive)
    let from_value = headers
        .iter()
        .find(|(name, _)| name.as_ref().eq_ignore_ascii_case("from"))
        .map(|(_, v)| v.as_ref())?;

    // Extract email address
    let addr = if let Some(start) = from_value.rfind('<') {
        if let Some(end) = from_value[start..].find('>') {
            &from_value[start + 1..start + end]
        } else {
            from_value.trim()
        }
    } else {
        // No angle brackets — trim whitespace and strip any trailing comment
        let trimmed = from_value.trim();
        // Handle "user@example.com (Name)" form
        if let Some(paren) = trimmed.find('(') {
            trimmed[..paren].trim()
        } else {
            trimmed
        }
    };

    // Extract domain after @
    let domain = addr.rsplit_once('@').map(|(_, d)| d)?;
    Some(normalize_domain(domain))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;
    use crate::dkim::signature::DkimResult;
    use crate::dmarc::eval::Disposition;
    use crate::spf::record::SpfResult;

    // -- parse_message tests --------------------------------------------------

    #[test]
    fn parse_message_basic() {
        let raw = b"From: user@example.com\r\nTo: other@example.com\r\n\r\nHello body";
        let (headers, body) = parse_message(raw);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "From");
        assert_eq!(headers[0].1, " user@example.com");
        assert_eq!(headers[1].0, "To");
        assert_eq!(headers[1].1, " other@example.com");
        assert_eq!(body, b"Hello body");
    }

    #[test]
    fn parse_message_folded_headers() {
        let raw = b"Subject: This is\r\n a long subject\r\nFrom: user@example.com\r\n\r\nbody";
        let (headers, body) = parse_message(raw);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "Subject");
        assert!(headers[0].1.contains("a long subject"));
        assert_eq!(headers[1].0, "From");
        assert_eq!(body, b"body");
    }

    #[test]
    fn parse_message_lf_only() {
        let raw = b"From: user@example.com\nTo: other@example.com\n\nbody here";
        let (headers, body) = parse_message(raw);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "From");
        assert_eq!(body, b"body here");
    }

    #[test]
    fn parse_message_empty_body() {
        let raw = b"From: user@example.com\r\nTo: other@example.com\r\n\r\n";
        let (headers, body) = parse_message(raw);
        assert_eq!(headers.len(), 2);
        assert_eq!(body, b"");
    }

    // -- extract_from_domain tests --------------------------------------------

    #[test]
    fn extract_from_simple() {
        let headers = vec![("From".to_string(), " user@example.com".to_string())];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_from_angle_brackets() {
        let headers = vec![(
            "From".to_string(),
            " \"User Name\" <user@example.com>".to_string(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_from_missing() {
        let headers: Vec<(String, String)> = vec![("To".to_string(), " other@example.com".to_string())];
        assert_eq!(extract_from_domain(&headers), None);
    }

    #[test]
    fn extract_from_with_comment() {
        let headers = vec![(
            "From".to_string(),
            " user@example.com (John)".to_string(),
        )];
        assert_eq!(
            extract_from_domain(&headers),
            Some("example.com".to_string())
        );
    }

    // -- integration test -----------------------------------------------------

    #[tokio::test]
    async fn authenticate_integration() {
        let resolver = MockResolver::new();

        // SPF record for example.com allowing 192.0.2.1
        resolver.add_txt(
            "example.com",
            vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
        );
        // A record for example.com (needed by SPF a mechanism, but we use ip4 here)
        resolver.add_a("example.com", vec!["192.0.2.1".parse().unwrap()]);
        // DMARC record
        resolver.add_txt(
            "_dmarc.example.com",
            vec!["v=DMARC1; p=reject;".to_string()],
        );

        // Build a raw message
        let raw = b"From: sender@example.com\r\n\
                     To: recipient@other.com\r\n\
                     Subject: Test\r\n\
                     \r\n\
                     Hello, world!\r\n";

        let authenticator = EmailAuthenticator::new(resolver);
        let result = authenticator
            .authenticate(
                raw,
                "192.0.2.1".parse().unwrap(),
                "mail.example.com",
                "sender@example.com",
            )
            .await;

        // SPF should pass (IP is in the allowed range)
        assert_eq!(result.spf, SpfResult::Pass);

        // DKIM: no DKIM-Signature header, so should be DkimResult::None
        assert_eq!(result.dkim, vec![DkimResult::None]);

        // From domain extracted correctly
        assert_eq!(result.from_domain, "example.com");
        assert_eq!(result.spf_domain, "example.com");

        // DMARC: SPF passes and is aligned (example.com == example.com),
        // so DMARC should pass even without DKIM
        assert_eq!(result.dmarc.disposition, Disposition::Pass);
        assert!(result.dmarc.spf_aligned);
    }
}
