use std::net::IpAddr;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// All inputs needed to expand SPF macros (RFC 7208 Section 7).
#[derive(Debug, Clone)]
pub struct MacroContext {
    /// Full sender address (local-part@domain).
    pub sender: String,
    /// Local-part of the sender address.
    pub local_part: String,
    /// Domain portion of the sender address.
    pub sender_domain: String,
    /// IP address of the connecting SMTP client.
    pub client_ip: IpAddr,
    /// HELO/EHLO identity.
    pub helo: String,
    /// Current domain being evaluated (changes on include/redirect).
    pub domain: String,
    /// Receiving mail server's domain name (for `%{r}`).
    pub receiver: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Expand SPF macros in `input` according to RFC 7208 Section 7.
///
/// When `allow_exp_macros` is true the explanation-only letters (`c`, `r`, `t`)
/// are permitted; otherwise encountering them returns `Err(())`.
pub fn expand(input: &str, ctx: &MacroContext, allow_exp_macros: bool) -> Result<String, ()> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] != b'%' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        // We saw '%'. Need at least one more byte.
        i += 1;
        if i >= len {
            return Err(());
        }

        match bytes[i] {
            b'%' => {
                out.push('%');
                i += 1;
            }
            b'_' => {
                out.push(' ');
                i += 1;
            }
            b'-' => {
                out.push_str("%20");
                i += 1;
            }
            b'{' => {
                i += 1; // skip '{'
                let start = i;
                // Find closing '}'.
                while i < len && bytes[i] != b'}' {
                    i += 1;
                }
                if i >= len {
                    return Err(());
                }
                let spec = &input[start..i];
                i += 1; // skip '}'
                let expanded = expand_macro_spec(spec, ctx, allow_exp_macros)?;
                out.push_str(&expanded);
            }
            _ => {
                return Err(());
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Macro spec parser & expander
// ---------------------------------------------------------------------------

/// Parse and expand a single macro spec (the content between `%{` and `}`).
///
/// Grammar: `<letter> [<digits>] [r] [<delimiters>]`
fn expand_macro_spec(
    spec: &str,
    ctx: &MacroContext,
    allow_exp_macros: bool,
) -> Result<String, ()> {
    if spec.is_empty() {
        return Err(());
    }

    let bytes = spec.as_bytes();
    let mut pos = 0;

    // --- letter ---
    let letter = bytes[pos] as char;
    pos += 1;

    let letter_lower = letter.to_ascii_lowercase();
    let url_encode = letter.is_ascii_uppercase();

    // --- optional digit string (0-128 would be absurd but spec says digits) ---
    let digit_start = pos;
    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
        pos += 1;
    }
    let digit_count: usize = if digit_start == pos {
        0 // means "all"
    } else {
        spec[digit_start..pos].parse().map_err(|_| ())?
    };

    // --- optional 'r' ---
    let reverse = if pos < bytes.len() && (bytes[pos] == b'r' || bytes[pos] == b'R') {
        pos += 1;
        true
    } else {
        false
    };

    // --- optional delimiters (any of: . - + , / _ =) ---
    let delimiters: Vec<char> = if pos < bytes.len() {
        let delim_str = &spec[pos..];
        let mut ds = Vec::new();
        for ch in delim_str.chars() {
            match ch {
                '.' | '-' | '+' | ',' | '/' | '_' | '=' => ds.push(ch),
                _ => return Err(()),
            }
        }
        if ds.is_empty() {
            return Err(());
        }
        ds
    } else {
        vec!['.']
    };

    // --- resolve the macro letter ---
    let raw_value = match letter_lower {
        's' => ctx.sender.clone(),
        'l' => ctx.local_part.clone(),
        'o' => ctx.sender_domain.clone(),
        'd' => ctx.domain.clone(),
        'i' => expand_ip(ctx.client_ip),
        'p' => "unknown".to_string(),
        'v' => match ctx.client_ip {
            IpAddr::V4(_) => "in-addr".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        },
        'h' => ctx.helo.clone(),
        'c' | 'r' | 't' => {
            if !allow_exp_macros {
                return Err(());
            }
            match letter_lower {
                'c' => ctx.client_ip.to_string(),
                'r' => ctx.receiver.clone(),
                't' => {
                    let ts = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    ts.to_string()
                }
                _ => unreachable!(),
            }
        }
        _ => return Err(()),
    };

    // --- apply transformers: split, reverse, take rightmost N ---
    let parts = split_by_delimiters(&raw_value, &delimiters);

    let parts = if reverse {
        parts.into_iter().rev().collect::<Vec<_>>()
    } else {
        parts
    };

    let parts = if digit_count == 0 {
        parts
    } else if digit_count >= parts.len() {
        parts
    } else {
        // Take rightmost N parts.
        parts[parts.len() - digit_count..].to_vec()
    };

    let result = parts.join(".");

    if url_encode {
        Ok(url_encode_value(&result))
    } else {
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Expand an IP address to the SPF `%{i}` format.
///
/// IPv4: dotted-decimal as-is (e.g. `1.2.3.4`).
/// IPv6: fully expanded dot-separated nibbles (e.g. `2.0.0.1.0.d.b.8...`).
fn expand_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut nibbles = String::with_capacity(63); // 32 hex chars + 31 dots
            for (idx, &octet) in octets.iter().enumerate() {
                let hi = octet >> 4;
                let lo = octet & 0x0f;
                if idx > 0 {
                    nibbles.push('.');
                }
                nibbles.push(char::from_digit(hi as u32, 16).unwrap());
                nibbles.push('.');
                nibbles.push(char::from_digit(lo as u32, 16).unwrap());
            }
            nibbles
        }
    }
}

/// Split a string on any character present in `delimiters`.
fn split_by_delimiters<'a>(s: &'a str, delimiters: &[char]) -> Vec<&'a str> {
    if delimiters.is_empty() {
        return vec![s];
    }
    s.split(|c: char| delimiters.contains(&c))
        .filter(|part| !part.is_empty())
        .collect()
}

/// RFC 3986 percent-encoding: encode everything except unreserved characters.
/// Unreserved: A-Z a-z 0-9 - . _ ~
fn url_encode_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'.'
            || byte == b'_'
            || byte == b'~'
        {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(char::from_digit((byte >> 4) as u32, 16).unwrap().to_ascii_uppercase());
            out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap().to_ascii_uppercase());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx_v4() -> MacroContext {
        MacroContext {
            sender: "user@example.com".into(),
            local_part: "user".into(),
            sender_domain: "example.com".into(),
            client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            helo: "mail.example.com".into(),
            domain: "sub.example.com".into(),
            receiver: "mx.receiver.org".into(),
        }
    }

    fn ctx_v6() -> MacroContext {
        MacroContext {
            sender: "user@example.com".into(),
            local_part: "user".into(),
            sender_domain: "example.com".into(),
            client_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
            helo: "mail.example.com".into(),
            domain: "sub.example.com".into(),
            receiver: "mx.receiver.org".into(),
        }
    }

    // -- basic macro letters --------------------------------------------------

    #[test]
    fn sender() {
        assert_eq!(expand("%{s}", &ctx_v4(), false).unwrap(), "user@example.com");
    }

    #[test]
    fn local_part() {
        assert_eq!(expand("%{l}", &ctx_v4(), false).unwrap(), "user");
    }

    #[test]
    fn sender_domain() {
        assert_eq!(expand("%{o}", &ctx_v4(), false).unwrap(), "example.com");
    }

    #[test]
    fn current_domain() {
        assert_eq!(expand("%{d}", &ctx_v4(), false).unwrap(), "sub.example.com");
    }

    #[test]
    fn ip_v4() {
        assert_eq!(expand("%{i}", &ctx_v4(), false).unwrap(), "1.2.3.4");
    }

    #[test]
    fn ip_v6_nibbles() {
        let result = expand("%{i}", &ctx_v6(), false).unwrap();
        assert_eq!(
            result,
            "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1"
        );
    }

    #[test]
    fn version_v4() {
        assert_eq!(expand("%{v}", &ctx_v4(), false).unwrap(), "in-addr");
    }

    #[test]
    fn version_v6() {
        assert_eq!(expand("%{v}", &ctx_v6(), false).unwrap(), "ip6");
    }

    #[test]
    fn helo_domain() {
        assert_eq!(expand("%{h}", &ctx_v4(), false).unwrap(), "mail.example.com");
    }

    #[test]
    fn ptr_always_unknown() {
        assert_eq!(expand("%{p}", &ctx_v4(), false).unwrap(), "unknown");
    }

    // -- transformers: reverse ------------------------------------------------

    #[test]
    fn ip_reversed() {
        assert_eq!(expand("%{ir}", &ctx_v4(), false).unwrap(), "4.3.2.1");
    }

    #[test]
    fn ip_v6_reversed() {
        let result = expand("%{ir}", &ctx_v6(), false).unwrap();
        assert_eq!(
            result,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
        );
    }

    // -- transformers: digit (rightmost N) ------------------------------------

    #[test]
    fn domain_rightmost_2() {
        assert_eq!(expand("%{d2}", &ctx_v4(), false).unwrap(), "example.com");
    }

    #[test]
    fn domain_rightmost_1_reversed() {
        // %{d1r}: reverse sub.example.com -> com.example.sub, take rightmost 1 -> sub
        assert_eq!(expand("%{d1r}", &ctx_v4(), false).unwrap(), "sub");
    }

    #[test]
    fn domain_0_means_all() {
        assert_eq!(expand("%{d0}", &ctx_v4(), false).unwrap(), "sub.example.com");
    }

    // -- transformers: custom delimiters --------------------------------------

    #[test]
    fn local_part_hyphen_delimiter() {
        let mut ctx = ctx_v4();
        ctx.local_part = "foo-bar".into();
        ctx.sender = "foo-bar@example.com".into();
        // %{l-} splits local-part on '-', yielding ["foo", "bar"], joined by '.'
        assert_eq!(expand("%{l-}", &ctx, false).unwrap(), "foo.bar");
    }

    #[test]
    fn sender_domain_hyphen_delimiter() {
        let mut ctx = ctx_v4();
        ctx.sender_domain = "a-b.example.com".into();
        // %{o-} splits on '-': ["a", "b.example.com"], joined with '.'
        assert_eq!(expand("%{o-}", &ctx, false).unwrap(), "a.b.example.com");
    }

    // -- URL encoding (uppercase letter) --------------------------------------

    #[test]
    fn url_encode_sender() {
        // %{S}: sender "user@example.com" URL-encoded -> "user%40example.com"
        assert_eq!(
            expand("%{S}", &ctx_v4(), false).unwrap(),
            "user%40example.com"
        );
    }

    #[test]
    fn url_encode_local_part() {
        let mut ctx = ctx_v4();
        ctx.local_part = "a b".into();
        assert_eq!(expand("%{L}", &ctx, false).unwrap(), "a%20b");
    }

    // -- explanation-only macros (%{c}, %{r}, %{t}) ---------------------------

    #[test]
    fn exp_c_allowed() {
        let result = expand("%{c}", &ctx_v4(), true).unwrap();
        assert_eq!(result, "1.2.3.4");
    }

    #[test]
    fn exp_c_v6_allowed() {
        let result = expand("%{c}", &ctx_v6(), true).unwrap();
        assert_eq!(result, "2001:db8::1");
    }

    #[test]
    fn exp_r_allowed() {
        assert_eq!(expand("%{r}", &ctx_v4(), true).unwrap(), "mx.receiver.org");
    }

    #[test]
    fn exp_t_allowed() {
        let result = expand("%{t}", &ctx_v4(), true).unwrap();
        // Must be a numeric string.
        assert!(result.parse::<u64>().is_ok(), "timestamp must be numeric: {result}");
        // Sanity: after 2020-01-01.
        let ts: u64 = result.parse().unwrap();
        assert!(ts > 1_577_836_800, "timestamp looks too old: {ts}");
    }

    #[test]
    fn exp_c_disallowed() {
        assert!(expand("%{c}", &ctx_v4(), false).is_err());
    }

    #[test]
    fn exp_r_disallowed() {
        assert!(expand("%{r}", &ctx_v4(), false).is_err());
    }

    #[test]
    fn exp_t_disallowed() {
        assert!(expand("%{t}", &ctx_v4(), false).is_err());
    }

    // -- escapes --------------------------------------------------------------

    #[test]
    fn escape_percent() {
        assert_eq!(expand("100%%", &ctx_v4(), false).unwrap(), "100%");
    }

    #[test]
    fn escape_space() {
        assert_eq!(expand("a%_b", &ctx_v4(), false).unwrap(), "a b");
    }

    #[test]
    fn escape_url_space() {
        assert_eq!(expand("a%-b", &ctx_v4(), false).unwrap(), "a%20b");
    }

    // -- combined / real-world patterns ---------------------------------------

    #[test]
    fn reversed_ip_in_domain() {
        assert_eq!(
            expand("%{ir}.origin.example.com", &ctx_v4(), false).unwrap(),
            "4.3.2.1.origin.example.com"
        );
    }

    #[test]
    fn exists_pattern() {
        assert_eq!(
            expand("%{ir}.%{v}._spf.%{d}", &ctx_v4(), false).unwrap(),
            "4.3.2.1.in-addr._spf.sub.example.com"
        );
    }

    #[test]
    fn no_macros() {
        assert_eq!(
            expand("plain.example.com", &ctx_v4(), false).unwrap(),
            "plain.example.com"
        );
    }

    #[test]
    fn empty_input() {
        assert_eq!(expand("", &ctx_v4(), false).unwrap(), "");
    }

    // -- error cases ----------------------------------------------------------

    #[test]
    fn unknown_macro_letter() {
        assert!(expand("%{x}", &ctx_v4(), false).is_err());
    }

    #[test]
    fn unterminated_macro() {
        assert!(expand("%{s", &ctx_v4(), false).is_err());
    }

    #[test]
    fn trailing_percent() {
        assert!(expand("foo%", &ctx_v4(), false).is_err());
    }

    #[test]
    fn invalid_percent_sequence() {
        // %z is not a valid escape
        assert!(expand("%z", &ctx_v4(), false).is_err());
    }
}
