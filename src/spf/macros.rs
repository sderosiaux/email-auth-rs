use std::net::IpAddr;

/// Context for SPF macro expansion (RFC 7208 Section 7).
#[derive(Debug, Clone)]
pub struct MacroContext {
    /// Full sender address (local-part@domain), or postmaster@helo.
    pub sender: String,
    /// Local-part of sender.
    pub local_part: String,
    /// Domain part of sender.
    pub sender_domain: String,
    /// Client IP address.
    pub client_ip: IpAddr,
    /// HELO/EHLO identity.
    pub helo: String,
    /// Current domain being evaluated (changes during include/redirect).
    pub domain: String,
    /// Receiving MTA domain name (for %{r} macro, exp-only).
    pub receiver: String,
}

/// Expand SPF macros in a string.
///
/// `exp_context` controls whether explanation-only macros (%{c}, %{r}, %{t}) are allowed.
/// Returns Err if an exp-only macro is used in non-exp context, or on malformed macro syntax.
pub fn expand(input: &str, ctx: &MacroContext, exp_context: bool) -> Result<String, String> {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'%' {
            if i + 1 >= len {
                return Err("trailing % in macro string".into());
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
                    let end = match bytes[start..].iter().position(|&b| b == b'}') {
                        Some(pos) => start + pos,
                        None => return Err("unclosed macro expression".into()),
                    };
                    let macro_body = &input[start..end];
                    let expanded = expand_macro_body(macro_body, ctx, exp_context)?;
                    result.push_str(&expanded);
                    i = end + 1;
                }
                _ => {
                    return Err(format!("invalid macro escape: %{}", input.as_bytes()[i + 1] as char));
                }
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    Ok(result)
}

/// Expand a macro body (the part inside %{ ... }).
/// Format: <letter>[<digits>][r][<delimiters>]
fn expand_macro_body(body: &str, ctx: &MacroContext, exp_context: bool) -> Result<String, String> {
    if body.is_empty() {
        return Err("empty macro expression".into());
    }

    let mut chars = body.chars();
    let letter = chars.next().unwrap();
    let rest: String = chars.collect();

    let lowercase_letter = letter.to_ascii_lowercase();
    let url_encode = letter.is_ascii_uppercase();

    // Get the raw value for this macro letter
    let raw_value = get_macro_value(lowercase_letter, ctx, exp_context)?;

    // Parse transformers: [digits][r][delimiters]
    let (digits, reverse, delimiters) = parse_transformers(&rest)?;

    // Apply transformers
    let transformed = apply_transformers(&raw_value, digits, reverse, &delimiters);

    // Apply URL encoding if uppercase letter
    if url_encode {
        Ok(url_encode_str(&transformed))
    } else {
        Ok(transformed)
    }
}

/// Get the raw value for a macro letter.
fn get_macro_value(letter: char, ctx: &MacroContext, exp_context: bool) -> Result<String, String> {
    match letter {
        's' => Ok(ctx.sender.clone()),
        'l' => Ok(ctx.local_part.clone()),
        'o' => Ok(ctx.sender_domain.clone()),
        'd' => Ok(ctx.domain.clone()),
        'i' => Ok(format_ip_for_macro(ctx.client_ip)),
        'p' => Ok("unknown".into()), // PTR stub — spec says this is acceptable
        'v' => Ok(match ctx.client_ip {
            IpAddr::V4(_) => "in-addr".into(),
            IpAddr::V6(_) => "ip6".into(),
        }),
        'h' => Ok(ctx.helo.clone()),
        // Explanation-only macros
        'c' | 'r' | 't' => {
            if !exp_context {
                return Err(format!("macro %{{{}}} only allowed in exp= context", letter));
            }
            match letter {
                'c' => Ok(ctx.client_ip.to_string()),
                'r' => Ok(ctx.receiver.clone()),
                't' => Ok(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_else(|_| "0".into())),
                _ => unreachable!(),
            }
        }
        _ => Err(format!("unknown macro letter: {}", letter)),
    }
}

/// Format IP address for %{i} macro.
/// IPv4: dotted decimal (e.g., "192.0.2.1")
/// IPv6: dot-separated nibbles, 32 hex chars (e.g., "2.0.0.1.0.d.b.8....")
fn format_ip_for_macro(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut nibbles = String::with_capacity(63); // 32 hex chars + 31 dots
            for (seg_idx, segment) in segments.iter().enumerate() {
                for nibble_idx in (0..4).rev() {
                    let nibble = (segment >> (nibble_idx * 4)) & 0xf;
                    if !nibbles.is_empty() {
                        nibbles.push('.');
                    }
                    nibbles.push(char::from_digit(nibble as u32, 16).unwrap());
                }
                let _ = seg_idx; // suppress unused
            }
            nibbles
        }
    }
}

/// Parse transformer string: [digits][r][delimiters]
fn parse_transformers(rest: &str) -> Result<(Option<usize>, bool, String), String> {
    if rest.is_empty() {
        return Ok((None, false, ".".into()));
    }

    let mut chars = rest.chars().peekable();

    // Parse optional digits
    let mut digit_str = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            digit_str.push(c);
            chars.next();
        } else {
            break;
        }
    }
    let digits = if digit_str.is_empty() {
        None
    } else {
        let n: usize = digit_str.parse().map_err(|_| "invalid digit in macro")?;
        Some(n)
    };

    // Parse optional 'r' for reverse
    let reverse = if let Some(&'r') = chars.peek() {
        chars.next();
        true
    } else if let Some(&'R') = chars.peek() {
        chars.next();
        true
    } else {
        false
    };

    // Remaining chars are delimiter characters
    let delimiters: String = chars.collect();
    let delimiters = if delimiters.is_empty() {
        ".".into()
    } else {
        delimiters
    };

    Ok((digits, reverse, delimiters))
}

/// Apply transformers: split by delimiters, optionally reverse, take rightmost N.
fn apply_transformers(value: &str, digits: Option<usize>, reverse: bool, delimiters: &str) -> String {
    // If no transformers at all (no digits, no reverse, default delimiter), return as-is
    if digits.is_none() && !reverse && delimiters == "." {
        return value.to_string();
    }

    // Split by any delimiter character
    let parts: Vec<&str> = split_by_delimiters(value, delimiters);

    let mut parts: Vec<&str> = parts;

    // Reverse if requested
    if reverse {
        parts.reverse();
    }

    // Take rightmost N parts (0 means all)
    if let Some(n) = digits {
        if n > 0 && n < parts.len() {
            parts = parts[parts.len() - n..].to_vec();
        }
        // n == 0 means all parts
    }

    // Rejoin with dots (always dots, regardless of original delimiter)
    parts.join(".")
}

/// Split a string by any character in the delimiter set.
fn split_by_delimiters<'a>(s: &'a str, delimiters: &str) -> Vec<&'a str> {
    if delimiters.is_empty() || delimiters == "." {
        return s.split('.').collect();
    }
    let delim_chars: Vec<char> = delimiters.chars().collect();
    s.split(|c: char| delim_chars.contains(&c)).collect()
}

/// URL-encode a string (percent-encode non-unreserved characters).
fn url_encode_str(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_ctx_v4() -> MacroContext {
        MacroContext {
            sender: "user@example.com".into(),
            local_part: "user".into(),
            sender_domain: "example.com".into(),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            helo: "mail.example.com".into(),
            domain: "example.com".into(),
            receiver: "mta.receiver.example".into(),
        }
    }

    fn test_ctx_v6() -> MacroContext {
        MacroContext {
            sender: "user@example.com".into(),
            local_part: "user".into(),
            sender_domain: "example.com".into(),
            client_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            helo: "mail.example.com".into(),
            domain: "example.com".into(),
            receiver: "mta.receiver.example".into(),
        }
    }

    // CHK-216: %{s} sender
    #[test]
    fn macro_s_sender() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{s}", &ctx, false).unwrap(), "user@example.com");
    }

    // CHK-217: %{l} local-part, %{o} domain
    #[test]
    fn macro_l_o() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{l}", &ctx, false).unwrap(), "user");
        assert_eq!(expand("%{o}", &ctx, false).unwrap(), "example.com");
    }

    // CHK-218: %{d} current domain
    #[test]
    fn macro_d() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{d}", &ctx, false).unwrap(), "example.com");
    }

    // CHK-219: %{i} IP expansion
    #[test]
    fn macro_i_ipv4() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{i}", &ctx, false).unwrap(), "192.0.2.1");
    }

    #[test]
    fn macro_i_ipv6() {
        let ctx = test_ctx_v6();
        let result = expand("%{i}", &ctx, false).unwrap();
        // 2001:0db8:0000:0000:0000:0000:0000:0001
        // -> 2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1
        assert_eq!(result, "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1");
        assert_eq!(result.chars().filter(|c| *c == '.').count(), 31);
    }

    // CHK-220: %{v} IP version
    #[test]
    fn macro_v_ipv4() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{v}", &ctx, false).unwrap(), "in-addr");
    }

    #[test]
    fn macro_v_ipv6() {
        let ctx = test_ctx_v6();
        assert_eq!(expand("%{v}", &ctx, false).unwrap(), "ip6");
    }

    // CHK-221: %{h} HELO domain
    #[test]
    fn macro_h() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{h}", &ctx, false).unwrap(), "mail.example.com");
    }

    // CHK-222: %{p} → "unknown"
    #[test]
    fn macro_p_unknown() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{p}", &ctx, false).unwrap(), "unknown");
    }

    // CHK-223: %{ir} reversed IP
    #[test]
    fn macro_ir_reversed_v4() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{ir}", &ctx, false).unwrap(), "1.2.0.192");
    }

    #[test]
    fn macro_ir_reversed_v6() {
        let ctx = test_ctx_v6();
        let result = expand("%{ir}", &ctx, false).unwrap();
        assert!(result.starts_with("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"));
    }

    // CHK-224: %{d2} rightmost 2 labels, %{d1r} reversed first label
    #[test]
    fn macro_d2() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{d2}", &ctx, false).unwrap(), "example.com");
    }

    #[test]
    fn macro_d1r() {
        // d = "example.com" → split by "." → ["example", "com"]
        // 1 rightmost → ["com"], then reversed → ["com"]
        // But actually: d1 takes rightmost 1 = "com", r reverses parts
        // %{d1r}: split "example.com" → ["example","com"], reverse → ["com","example"], take 1 → ["example"]
        let ctx = test_ctx_v4();
        let result = expand("%{d1r}", &ctx, false).unwrap();
        // reverse first, then take rightmost 1
        // split: ["example", "com"], reverse: ["com", "example"], take 1: ["example"]
        assert_eq!(result, "example");
    }

    // CHK-225: %{l-} local-part with hyphen delimiter
    #[test]
    fn macro_l_hyphen_delimiter() {
        let mut ctx = test_ctx_v4();
        ctx.local_part = "user-name".into();
        ctx.sender = "user-name@example.com".into();
        let result = expand("%{l-}", &ctx, false).unwrap();
        // Split "user-name" by '-' → ["user", "name"], rejoin with '.' → "user.name"
        assert_eq!(result, "user.name");
    }

    // CHK-226: %{S} URL-encode sender
    #[test]
    fn macro_s_url_encode() {
        let ctx = test_ctx_v4();
        let result = expand("%{S}", &ctx, false).unwrap();
        // "user@example.com" → "user%40example.com"
        assert_eq!(result, "user%40example.com");
    }

    // CHK-227: c/r/t in exp context → succeed
    #[test]
    fn macro_c_in_exp() {
        let ctx = test_ctx_v4();
        let result = expand("%{c}", &ctx, true).unwrap();
        assert_eq!(result, "192.0.2.1");
    }

    #[test]
    fn macro_r_in_exp() {
        let ctx = test_ctx_v4();
        let result = expand("%{r}", &ctx, true).unwrap();
        assert_eq!(result, "mta.receiver.example");
    }

    #[test]
    fn macro_t_in_exp() {
        let ctx = test_ctx_v4();
        let result = expand("%{t}", &ctx, true).unwrap();
        // Should be a valid unix timestamp (numeric string)
        let ts: u64 = result.parse().expect("timestamp should be numeric");
        assert!(ts > 1_000_000_000); // after 2001
    }

    // CHK-228: Reject c/r/t outside exp context
    #[test]
    fn macro_c_rejected_non_exp() {
        let ctx = test_ctx_v4();
        assert!(expand("%{c}", &ctx, false).is_err());
    }

    #[test]
    fn macro_r_rejected_non_exp() {
        let ctx = test_ctx_v4();
        assert!(expand("%{r}", &ctx, false).is_err());
    }

    #[test]
    fn macro_t_rejected_non_exp() {
        let ctx = test_ctx_v4();
        assert!(expand("%{t}", &ctx, false).is_err());
    }

    // CHK-229: Escapes
    #[test]
    fn macro_escapes() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%%", &ctx, false).unwrap(), "%");
        assert_eq!(expand("%_", &ctx, false).unwrap(), " ");
        assert_eq!(expand("%-", &ctx, false).unwrap(), "%20");
    }

    #[test]
    fn macro_mixed_escapes() {
        let ctx = test_ctx_v4();
        assert_eq!(
            expand("hello%_world%%foo%-bar", &ctx, false).unwrap(),
            "hello world%foo%20bar"
        );
    }

    // CHK-230: %{d0} entire domain (0 means all parts)
    #[test]
    fn macro_d0_entire_domain() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("%{d0}", &ctx, false).unwrap(), "example.com");
    }

    // Additional: complex macro string with multiple macros
    #[test]
    fn macro_complex_string() {
        let ctx = test_ctx_v4();
        let result = expand("%{ir}.%{v}.arpa", &ctx, false).unwrap();
        assert_eq!(result, "1.2.0.192.in-addr.arpa");
    }

    // Additional: no macros in string
    #[test]
    fn macro_no_macros() {
        let ctx = test_ctx_v4();
        assert_eq!(expand("plain.example.com", &ctx, false).unwrap(), "plain.example.com");
    }

    // Additional: unknown macro letter
    #[test]
    fn macro_unknown_letter() {
        let ctx = test_ctx_v4();
        assert!(expand("%{x}", &ctx, false).is_err());
    }
}
