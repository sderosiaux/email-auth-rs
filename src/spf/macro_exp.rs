//! SPF macro expansion (RFC 7208 Section 7).
//!
//! Macros appear in domain-specs and exp= explanation strings. The syntax is:
//!   %{letter [digits] [r] [delimiters]}
//! Plus escapes: %%, %_, %-

use std::net::IpAddr;

/// Context required for macro expansion.
#[derive(Debug, Clone)]
pub struct MacroContext {
    /// The full sender identity (local-part@domain or postmaster@domain).
    pub sender: String,
    /// The local-part of the sender (left of @).
    pub local_part: String,
    /// The domain of the sender (right of @), or the HELO identity.
    pub domain: String,
    /// Client (connecting) IP address.
    pub client_ip: IpAddr,
    /// HELO/EHLO domain.
    pub helo: String,
    /// Receiving mail server's domain/hostname (for %{r}).
    pub receiver: String,
}

/// Error during macro expansion.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MacroError {
    #[error("invalid macro syntax: {0}")]
    InvalidSyntax(String),
    #[error("macro letter '{0}' is only valid in exp= context")]
    ExplanationOnly(char),
    #[error("unknown macro letter: {0}")]
    UnknownLetter(char),
    #[error("unterminated macro expression")]
    Unterminated,
}

/// Expand all macros in `input` using the given context.
///
/// `is_exp` controls whether explanation-only macro letters (c, r, t) are allowed.
/// In non-exp contexts (domain-spec in mechanisms/redirect), c/r/t produce an error.
pub fn expand(input: &str, ctx: &MacroContext, is_exp: bool) -> Result<String, MacroError> {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'%' {
            if i + 1 >= len {
                return Err(MacroError::InvalidSyntax(
                    "trailing % at end of string".into(),
                ));
            }
            match bytes[i + 1] {
                b'%' => {
                    result.push('%');
                    i += 2;
                }
                b'_' => {
                    result.push(' ');
                    i += 2;
                }
                b'-' => {
                    result.push_str("%20");
                    i += 2;
                }
                b'{' => {
                    // Find closing '}'
                    let start = i + 2;
                    let close = bytes[start..]
                        .iter()
                        .position(|&b| b == b'}')
                        .map(|p| start + p)
                        .ok_or(MacroError::Unterminated)?;
                    let spec = &input[start..close];
                    let expanded = expand_macro_spec(spec, ctx, is_exp)?;
                    result.push_str(&expanded);
                    i = close + 1;
                }
                other => {
                    return Err(MacroError::InvalidSyntax(format!(
                        "unexpected character after %: '{}'",
                        other as char
                    )));
                }
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    Ok(result)
}

/// Expand a single macro spec (the content between %{ and }).
/// Format: letter [digits] [r] [delimiters]
fn expand_macro_spec(
    spec: &str,
    ctx: &MacroContext,
    is_exp: bool,
) -> Result<String, MacroError> {
    if spec.is_empty() {
        return Err(MacroError::InvalidSyntax("empty macro spec".into()));
    }

    let bytes = spec.as_bytes();
    let letter = bytes[0] as char;
    let letter_lower = letter.to_ascii_lowercase();
    let is_upper = letter.is_ascii_uppercase();

    // Validate letter
    let raw_value = resolve_letter(letter_lower, ctx, is_exp)?;

    // Parse remainder: [digits][r][delimiters]
    let rest = &spec[1..];
    let (digits, rest) = parse_digits(rest);
    let (reverse, rest) = parse_reverse(rest);
    let delimiters = if rest.is_empty() {
        vec!['.']
    } else {
        parse_delimiters(rest)?
    };

    // Split by delimiters
    let parts = split_by_delimiters(&raw_value, &delimiters);

    // Apply reverse
    let parts = if reverse {
        parts.into_iter().rev().collect::<Vec<_>>()
    } else {
        parts
    };

    // Apply digit truncation (rightmost N)
    let parts = if let Some(n) = digits {
        if n == 0 {
            // 0 means all parts per RFC
            parts
        } else {
            let skip = parts.len().saturating_sub(n);
            parts.into_iter().skip(skip).collect()
        }
    } else {
        parts
    };

    // Rejoin with '.'
    let expanded = parts.join(".");

    // Uppercase letter -> URL-encode
    if is_upper {
        Ok(url_encode(&expanded))
    } else {
        Ok(expanded)
    }
}

/// Resolve a macro letter to its raw string value.
fn resolve_letter(
    letter: char,
    ctx: &MacroContext,
    is_exp: bool,
) -> Result<String, MacroError> {
    match letter {
        's' => Ok(ctx.sender.clone()),
        'l' => Ok(ctx.local_part.clone()),
        'o' => Ok(ctx.domain.clone()),
        'd' => Ok(ctx.domain.clone()),
        'i' => Ok(ip_to_macro_string(&ctx.client_ip)),
        'v' => Ok(match ctx.client_ip {
            IpAddr::V4(_) => "in-addr".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        }),
        'h' => Ok(ctx.helo.clone()),
        'p' => {
            // PTR validated domain. Stub with "unknown" per spec allowance.
            Ok("unknown".to_string())
        }
        'c' | 'r' | 't' => {
            if !is_exp {
                return Err(MacroError::ExplanationOnly(letter));
            }
            match letter {
                'c' => Ok(ctx.client_ip.to_string()),
                'r' => Ok(ctx.receiver.clone()),
                't' => Ok(current_timestamp().to_string()),
                _ => unreachable!(),
            }
        }
        _ => Err(MacroError::UnknownLetter(letter)),
    }
}

/// Convert IP to macro string. IPv4 is dotted decimal. IPv6 is dot-separated nibbles.
fn ip_to_macro_string(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut nibbles = Vec::with_capacity(32);
            for octet in &octets {
                nibbles.push(format!("{:x}", octet >> 4));
                nibbles.push(format!("{:x}", octet & 0x0f));
            }
            nibbles.join(".")
        }
    }
}

/// Parse leading digits from a spec remainder. Returns (Some(n), rest) or (None, rest).
fn parse_digits(s: &str) -> (Option<usize>, &str) {
    let end = s
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    if end == 0 {
        return (None, s);
    }
    let n = s[..end].parse::<usize>().ok();
    (n, &s[end..])
}

/// Parse an optional 'r' (reverse) flag.
fn parse_reverse(s: &str) -> (bool, &str) {
    if s.starts_with('r') || s.starts_with('R') {
        (true, &s[1..])
    } else {
        (false, s)
    }
}

/// Parse delimiter characters. Valid delimiters: . - + , / _ =
fn parse_delimiters(s: &str) -> Result<Vec<char>, MacroError> {
    let mut delims = Vec::new();
    for ch in s.chars() {
        match ch {
            '.' | '-' | '+' | ',' | '/' | '_' | '=' => delims.push(ch),
            _ => {
                return Err(MacroError::InvalidSyntax(format!(
                    "invalid delimiter character: '{ch}'"
                )));
            }
        }
    }
    if delims.is_empty() {
        return Err(MacroError::InvalidSyntax("empty delimiter set".into()));
    }
    Ok(delims)
}

/// Split a string by any of the given delimiter characters.
fn split_by_delimiters(s: &str, delimiters: &[char]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    for ch in s.chars() {
        if delimiters.contains(&ch) {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

/// URL-encode a string per RFC 3986. Unreserved chars are not encoded.
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        if is_unreserved(byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{:02X}", byte));
        }
    }
    result
}

/// RFC 3986 unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
}

/// Get current Unix timestamp. Separated for testability.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_ctx() -> MacroContext {
        MacroContext {
            sender: "strong-bad@email.example.com".into(),
            local_part: "strong-bad".into(),
            domain: "email.example.com".into(),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
            helo: "mail.example.com".into(),
            receiver: "mx.example.org".into(),
        }
    }

    fn test_ctx_v6() -> MacroContext {
        MacroContext {
            sender: "strong-bad@email.example.com".into(),
            local_part: "strong-bad".into(),
            domain: "email.example.com".into(),
            client_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xcb01)),
            helo: "mail.example.com".into(),
            receiver: "mx.example.org".into(),
        }
    }

    // ---- Escapes ----

    #[test]
    fn escape_percent() {
        assert_eq!(expand("100%%", &test_ctx(), false).unwrap(), "100%");
    }

    #[test]
    fn escape_space() {
        assert_eq!(expand("a%_b", &test_ctx(), false).unwrap(), "a b");
    }

    #[test]
    fn escape_url_space() {
        assert_eq!(expand("a%-b", &test_ctx(), false).unwrap(), "a%20b");
    }

    // ---- Basic macro letters ----

    #[test]
    fn macro_s_sender() {
        assert_eq!(
            expand("%{s}", &test_ctx(), false).unwrap(),
            "strong-bad@email.example.com"
        );
    }

    #[test]
    fn macro_l_local() {
        assert_eq!(
            expand("%{l}", &test_ctx(), false).unwrap(),
            "strong-bad"
        );
    }

    #[test]
    fn macro_o_domain() {
        assert_eq!(
            expand("%{o}", &test_ctx(), false).unwrap(),
            "email.example.com"
        );
    }

    #[test]
    fn macro_d_domain() {
        assert_eq!(
            expand("%{d}", &test_ctx(), false).unwrap(),
            "email.example.com"
        );
    }

    #[test]
    fn macro_i_ipv4() {
        assert_eq!(expand("%{i}", &test_ctx(), false).unwrap(), "192.0.2.3");
    }

    #[test]
    fn macro_v_ipv4() {
        assert_eq!(expand("%{v}", &test_ctx(), false).unwrap(), "in-addr");
    }

    #[test]
    fn macro_v_ipv6() {
        assert_eq!(expand("%{v}", &test_ctx_v6(), false).unwrap(), "ip6");
    }

    #[test]
    fn macro_h_helo() {
        assert_eq!(
            expand("%{h}", &test_ctx(), false).unwrap(),
            "mail.example.com"
        );
    }

    // ---- IPv6 %{i} as dot-separated nibbles ----

    #[test]
    fn macro_i_ipv6_nibbles() {
        let result = expand("%{i}", &test_ctx_v6(), false).unwrap();
        // 2001:0db8:0000:0000:0000:0000:0000:cb01
        // -> 2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1
        assert_eq!(
            result,
            "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1"
        );
    }

    // ---- Transformers ----

    #[test]
    fn macro_d_reverse() {
        // %{dr} -> reverse domain parts: "com.example.email"
        assert_eq!(
            expand("%{dr}", &test_ctx(), false).unwrap(),
            "com.example.email"
        );
    }

    #[test]
    fn macro_d_rightmost_2() {
        // %{d2} -> rightmost 2 labels: "example.com"
        assert_eq!(
            expand("%{d2}", &test_ctx(), false).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn macro_d_rightmost_1() {
        assert_eq!(expand("%{d1}", &test_ctx(), false).unwrap(), "com");
    }

    #[test]
    fn macro_d_reverse_and_truncate() {
        // %{d1r} -> reverse then take rightmost 1: "email"
        assert_eq!(expand("%{d1r}", &test_ctx(), false).unwrap(), "email");
    }

    // ---- Custom delimiters ----

    #[test]
    fn macro_l_with_hyphen_delimiter() {
        // %{l-} splits "strong-bad" by '-' -> ["strong", "bad"] -> "strong.bad"
        assert_eq!(
            expand("%{l-}", &test_ctx(), false).unwrap(),
            "strong.bad"
        );
    }

    #[test]
    fn macro_l_reverse_with_hyphen() {
        // %{lr-} -> split by '-', reverse, rejoin with '.'
        assert_eq!(
            expand("%{lr-}", &test_ctx(), false).unwrap(),
            "bad.strong"
        );
    }

    // ---- Uppercase -> URL encode ----

    #[test]
    fn macro_uppercase_url_encodes() {
        // %{S} should URL-encode the sender
        let result = expand("%{S}", &test_ctx(), false).unwrap();
        assert_eq!(result, "strong-bad%40email.example.com");
    }

    #[test]
    fn macro_uppercase_l() {
        // %{L} -> URL-encode local part (hyphens are unreserved, so no change)
        let result = expand("%{L}", &test_ctx(), false).unwrap();
        assert_eq!(result, "strong-bad");
    }

    // ---- PTR letter p ----

    #[test]
    fn macro_p_stub() {
        assert_eq!(expand("%{p}", &test_ctx(), false).unwrap(), "unknown");
    }

    // ---- Explanation-only letters ----

    #[test]
    fn macro_c_in_exp_context() {
        let result = expand("%{c}", &test_ctx(), true).unwrap();
        assert_eq!(result, "192.0.2.3");
    }

    #[test]
    fn macro_r_in_exp_context() {
        let result = expand("%{r}", &test_ctx(), true).unwrap();
        assert_eq!(result, "mx.example.org");
    }

    #[test]
    fn macro_t_in_exp_context() {
        let result = expand("%{t}", &test_ctx(), true);
        // Just verify it's a number and doesn't error
        assert!(result.is_ok());
        let ts: u64 = result.unwrap().parse().unwrap();
        assert!(ts > 1_000_000_000); // after ~2001
    }

    #[test]
    fn macro_c_in_non_exp_errors() {
        let err = expand("%{c}", &test_ctx(), false).unwrap_err();
        assert!(matches!(err, MacroError::ExplanationOnly('c')));
    }

    #[test]
    fn macro_r_in_non_exp_errors() {
        let err = expand("%{r}", &test_ctx(), false).unwrap_err();
        assert!(matches!(err, MacroError::ExplanationOnly('r')));
    }

    #[test]
    fn macro_t_in_non_exp_errors() {
        let err = expand("%{t}", &test_ctx(), false).unwrap_err();
        assert!(matches!(err, MacroError::ExplanationOnly('t')));
    }

    // ---- Unknown letter ----

    #[test]
    fn macro_unknown_letter() {
        let err = expand("%{x}", &test_ctx(), false).unwrap_err();
        assert!(matches!(err, MacroError::UnknownLetter('x')));
    }

    // ---- Unterminated ----

    #[test]
    fn macro_unterminated() {
        let err = expand("%{s", &test_ctx(), false).unwrap_err();
        assert!(matches!(err, MacroError::Unterminated));
    }

    // ---- No macros (passthrough) ----

    #[test]
    fn no_macros_passthrough() {
        assert_eq!(
            expand("example.com", &test_ctx(), false).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn empty_string() {
        assert_eq!(expand("", &test_ctx(), false).unwrap(), "");
    }

    // ---- Complex / RFC 7208 Section 7.4 examples ----

    #[test]
    fn rfc_example_ir_reverse_ip() {
        // %{ir}.%{v}._spf.%{d2}
        // ip=192.0.2.3 -> reversed: 3.2.0.192
        // v=in-addr, d2=example.com
        let result = expand(
            "%{ir}.%{v}._spf.%{d2}",
            &test_ctx(),
            false,
        )
        .unwrap();
        assert_eq!(result, "3.2.0.192.in-addr._spf.example.com");
    }

    #[test]
    fn rfc_example_ir_ipv6() {
        // With IPv6 2001:db8::cb01
        // %{ir} should reverse the nibbles
        let result = expand("%{ir}.%{v}._spf.%{d2}", &test_ctx_v6(), false).unwrap();
        // nibbles: 2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1
        // reversed: 1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
        assert_eq!(
            result,
            "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
        );
    }

    #[test]
    fn rfc_example_l_o_d() {
        // %{l}@%{o} should reconstruct the sender parts
        let result = expand("%{l}@%{o}", &test_ctx(), false).unwrap();
        assert_eq!(result, "strong-bad@email.example.com");
    }

    #[test]
    fn mixed_text_and_macros() {
        let result = expand(
            "prefix.%{d}.suffix",
            &test_ctx(),
            false,
        )
        .unwrap();
        assert_eq!(result, "prefix.email.example.com.suffix");
    }

    // ---- Digits = 0 means all ----

    #[test]
    fn macro_d0_means_all() {
        assert_eq!(
            expand("%{d0}", &test_ctx(), false).unwrap(),
            "email.example.com"
        );
    }

    // ---- Multiple macros in one string ----

    #[test]
    fn multiple_macros() {
        let result = expand("%{l}.%{d}", &test_ctx(), false).unwrap();
        assert_eq!(result, "strong-bad.email.example.com");
    }

    // ---- Invalid after % ----

    #[test]
    fn invalid_percent_sequence() {
        let err = expand("%z", &test_ctx(), false).unwrap_err();
        assert!(matches!(err, MacroError::InvalidSyntax(_)));
    }

    #[test]
    fn trailing_percent() {
        let err = expand("foo%", &test_ctx(), false).unwrap_err();
        assert!(matches!(err, MacroError::InvalidSyntax(_)));
    }

    // ---- Uppercase with transform ----

    #[test]
    fn uppercase_with_reverse() {
        // %{Dr} -> reverse domain, URL-encode (no special chars so same)
        let result = expand("%{Dr}", &test_ctx(), false).unwrap();
        assert_eq!(result, "com.example.email");
    }

    // ---- Empty macro spec ----

    #[test]
    fn empty_macro_spec() {
        let err = expand("%{}", &test_ctx(), false).unwrap_err();
        assert!(matches!(err, MacroError::InvalidSyntax(_)));
    }
}
