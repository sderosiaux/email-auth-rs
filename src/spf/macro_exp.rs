use std::net::IpAddr;

/// Context for SPF macro expansion.
pub struct MacroContext<'a> {
    pub sender: &'a str,
    pub local_part: &'a str,
    pub sender_domain: &'a str,
    pub client_ip: IpAddr,
    pub helo: &'a str,
    pub domain: &'a str,
    pub receiver: &'a str,
}

/// Expand SPF macros in a domain-spec string.
/// `allow_exp_macros`: true when expanding in exp= TXT context (allows c, r, t).
pub fn expand(spec: &str, ctx: &MacroContext, allow_exp_macros: bool) -> Result<String, String> {
    let mut result = String::new();
    let mut chars = spec.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '%' {
            result.push(c);
            continue;
        }
        match chars.peek() {
            Some('%') => {
                chars.next();
                result.push('%');
            }
            Some('_') => {
                chars.next();
                result.push(' ');
            }
            Some('-') => {
                chars.next();
                result.push_str("%20");
            }
            Some('{') => {
                chars.next();
                let mut macro_body = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(ch) => macro_body.push(ch),
                        None => return Err("unterminated macro".into()),
                    }
                }
                let expanded = expand_macro_body(&macro_body, ctx, allow_exp_macros)?;
                result.push_str(&expanded);
            }
            _ => {
                result.push('%');
            }
        }
    }

    Ok(result)
}

fn expand_macro_body(
    body: &str,
    ctx: &MacroContext,
    allow_exp_macros: bool,
) -> Result<String, String> {
    if body.is_empty() {
        return Err("empty macro body".into());
    }

    let mut chars = body.chars();
    let letter = chars.next().unwrap();
    let is_upper = letter.is_ascii_uppercase();
    let letter_lower = letter.to_ascii_lowercase();

    // Get raw value for the macro letter
    let raw_value = match letter_lower {
        's' => ctx.sender.to_string(),
        'l' => ctx.local_part.to_string(),
        'o' => ctx.sender_domain.to_string(),
        'd' => ctx.domain.to_string(),
        'i' => expand_ip(ctx.client_ip),
        'p' => "unknown".to_string(),
        'v' => match ctx.client_ip {
            IpAddr::V4(_) => "in-addr".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        },
        'h' => ctx.helo.to_string(),
        'c' => {
            if !allow_exp_macros {
                return Err("macro %{c} only allowed in exp= context".into());
            }
            ctx.client_ip.to_string()
        }
        'r' => {
            if !allow_exp_macros {
                return Err("macro %{r} only allowed in exp= context".into());
            }
            ctx.receiver.to_string()
        }
        't' => {
            if !allow_exp_macros {
                return Err("macro %{t} only allowed in exp= context".into());
            }
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string()
        }
        _ => return Err(format!("unknown macro letter: {letter}")),
    };

    // Parse optional digit count and transformers
    let rest: String = chars.collect();
    let (digits, reverse, delimiters) = parse_transformers(&rest)?;

    // Apply transformers
    let delims = if delimiters.is_empty() {
        ".".to_string()
    } else {
        delimiters
    };

    // Split by delimiters
    let parts: Vec<&str> = split_by_delimiters(&raw_value, &delims);

    let mut parts: Vec<String> = parts.into_iter().map(String::from).collect();

    // Reverse if requested
    if reverse {
        parts.reverse();
    }

    // Take rightmost N parts (0 means all)
    if digits > 0 && parts.len() > digits as usize {
        let start = parts.len() - digits as usize;
        parts = parts[start..].to_vec();
    }

    let expanded = parts.join(".");

    // URL-encode if uppercase letter
    if is_upper {
        Ok(url_encode(&expanded))
    } else {
        Ok(expanded)
    }
}

fn expand_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            // Dot-separated nibbles: 32 hex chars separated by dots
            let segments = v6.segments();
            let mut nibbles = Vec::with_capacity(32);
            for seg in segments {
                nibbles.push(format!("{:x}", (seg >> 12) & 0xf));
                nibbles.push(format!("{:x}", (seg >> 8) & 0xf));
                nibbles.push(format!("{:x}", (seg >> 4) & 0xf));
                nibbles.push(format!("{:x}", seg & 0xf));
            }
            nibbles.join(".")
        }
    }
}

fn parse_transformers(s: &str) -> Result<(u32, bool, String), String> {
    let mut digits: u32 = 0;
    let mut reverse = false;
    let mut delimiters = String::new();
    let mut chars = s.chars().peekable();

    // Parse digits
    let mut digit_str = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            digit_str.push(c);
            chars.next();
        } else {
            break;
        }
    }
    if !digit_str.is_empty() {
        digits = digit_str
            .parse()
            .map_err(|_| "invalid digit in macro".to_string())?;
    }

    // Check for 'r' reverse
    if let Some(&'r') = chars.peek() {
        reverse = true;
        chars.next();
    }

    // Rest are delimiter characters
    for c in chars {
        match c {
            '.' | '-' | '+' | ',' | '/' | '_' | '=' => delimiters.push(c),
            _ => return Err(format!("invalid delimiter: {c}")),
        }
    }

    Ok((digits, reverse, delimiters))
}

fn split_by_delimiters<'a>(s: &'a str, delims: &str) -> Vec<&'a str> {
    let mut parts = vec![s];
    for delim in delims.chars() {
        let mut new_parts = Vec::new();
        for part in parts {
            for sub in part.split(delim) {
                new_parts.push(sub);
            }
        }
        parts = new_parts;
    }
    parts
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_ctx() -> MacroContext<'static> {
        MacroContext {
            sender: "user@example.com",
            local_part: "user",
            sender_domain: "example.com",
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            helo: "mail.example.com",
            domain: "example.com",
            receiver: "receiver.example.com",
        }
    }

    #[test]
    fn test_sender() {
        let ctx = test_ctx();
        assert_eq!(expand("%{s}", &ctx, false).unwrap(), "user@example.com");
    }

    #[test]
    fn test_local_part() {
        let ctx = test_ctx();
        assert_eq!(expand("%{l}", &ctx, false).unwrap(), "user");
    }

    #[test]
    fn test_domain() {
        let ctx = test_ctx();
        assert_eq!(expand("%{d}", &ctx, false).unwrap(), "example.com");
        assert_eq!(expand("%{o}", &ctx, false).unwrap(), "example.com");
    }

    #[test]
    fn test_ip_v4() {
        let ctx = test_ctx();
        assert_eq!(expand("%{i}", &ctx, false).unwrap(), "192.0.2.1");
    }

    #[test]
    fn test_ip_v6() {
        let ctx = MacroContext {
            client_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ..test_ctx()
        };
        assert_eq!(
            expand("%{i}", &ctx, false).unwrap(),
            "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1"
        );
    }

    #[test]
    fn test_ip_version() {
        let ctx = test_ctx();
        assert_eq!(expand("%{v}", &ctx, false).unwrap(), "in-addr");

        let ctx6 = MacroContext {
            client_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ..test_ctx()
        };
        assert_eq!(expand("%{v}", &ctx6, false).unwrap(), "ip6");
    }

    #[test]
    fn test_helo() {
        let ctx = test_ctx();
        assert_eq!(expand("%{h}", &ctx, false).unwrap(), "mail.example.com");
    }

    #[test]
    fn test_p_unknown() {
        let ctx = test_ctx();
        assert_eq!(expand("%{p}", &ctx, false).unwrap(), "unknown");
    }

    #[test]
    fn test_reversed_ip() {
        let ctx = test_ctx();
        assert_eq!(
            expand("%{ir}.origin.example.com", &ctx, false).unwrap(),
            "1.2.0.192.origin.example.com"
        );
    }

    #[test]
    fn test_rightmost_labels() {
        let ctx = test_ctx();
        assert_eq!(expand("%{d2}", &ctx, false).unwrap(), "example.com");
    }

    #[test]
    fn test_d1r() {
        let ctx = test_ctx();
        assert_eq!(expand("%{d1r}", &ctx, false).unwrap(), "example");
    }

    #[test]
    fn test_local_part_hyphen_delimiter() {
        let ctx = MacroContext {
            local_part: "foo-bar",
            ..test_ctx()
        };
        assert_eq!(expand("%{l-}", &ctx, false).unwrap(), "foo.bar");
    }

    #[test]
    fn test_uppercase_url_encode() {
        let ctx = test_ctx();
        assert_eq!(
            expand("%{S}", &ctx, false).unwrap(),
            "user%40example.com"
        );
    }

    #[test]
    fn test_exp_macros_allowed() {
        let ctx = test_ctx();
        assert!(expand("%{c}", &ctx, true).is_ok());
        assert!(expand("%{r}", &ctx, true).is_ok());
        assert!(expand("%{t}", &ctx, true).is_ok());
    }

    #[test]
    fn test_exp_macros_rejected() {
        let ctx = test_ctx();
        assert!(expand("%{c}", &ctx, false).is_err());
        assert!(expand("%{r}", &ctx, false).is_err());
        assert!(expand("%{t}", &ctx, false).is_err());
    }

    #[test]
    fn test_escapes() {
        let ctx = test_ctx();
        assert_eq!(expand("%%", &ctx, false).unwrap(), "%");
        assert_eq!(expand("%_", &ctx, false).unwrap(), " ");
        assert_eq!(expand("%-", &ctx, false).unwrap(), "%20");
    }

    #[test]
    fn test_d0_means_all() {
        let ctx = test_ctx();
        assert_eq!(expand("%{d0}", &ctx, false).unwrap(), "example.com");
    }
}
