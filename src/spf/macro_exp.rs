use std::net::IpAddr;

/// Context for macro expansion
pub struct MacroContext<'a> {
    pub sender: &'a str,      // local-part@domain or postmaster@domain
    pub domain: &'a str,      // current domain being evaluated
    pub client_ip: IpAddr,    // connecting server IP
    pub helo: &'a str,        // HELO/EHLO domain
    pub receiver: &'a str,    // receiving domain (for %{r})
    pub is_exp: bool,         // true if expanding exp= TXT (allows c, r, t)
}

/// Expand SPF macros in a domain-spec string
pub fn expand_macros(input: &str, ctx: &MacroContext) -> Result<String, String> {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('%') => result.push('%'),
                Some('_') => result.push(' '),
                Some('-') => result.push_str("%20"),
                Some('{') => {
                    // Parse macro: %{<letter><digits>r<delimiters>}
                    let mut macro_spec = String::new();
                    while let Some(&mc) = chars.peek() {
                        if mc == '}' {
                            chars.next();
                            break;
                        }
                        macro_spec.push(chars.next().unwrap());
                    }
                    let expanded = expand_macro_spec(&macro_spec, ctx)?;
                    result.push_str(&expanded);
                }
                Some(other) => {
                    return Err(format!("invalid macro: %{}", other));
                }
                None => {
                    return Err("incomplete macro at end of string".to_string());
                }
            }
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

fn expand_macro_spec(spec: &str, ctx: &MacroContext) -> Result<String, String> {
    if spec.is_empty() {
        return Err("empty macro spec".to_string());
    }

    let mut chars = spec.chars().peekable();
    let letter = chars.next().unwrap();
    let is_uppercase = letter.is_uppercase();
    let letter_lower = letter.to_ascii_lowercase();

    // Parse optional digit count
    let mut digit_str = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            digit_str.push(chars.next().unwrap());
        } else {
            break;
        }
    }
    let take_right: Option<usize> = if digit_str.is_empty() {
        None
    } else {
        Some(
            digit_str
                .parse()
                .map_err(|_| format!("invalid digit in macro: {}", digit_str))?,
        )
    };

    // Check for 'r' (reverse)
    let reverse = if chars.peek() == Some(&'r') || chars.peek() == Some(&'R') {
        chars.next();
        true
    } else {
        false
    };

    // Remaining chars are delimiters (default ".")
    let delimiters: String = chars.collect();
    let delimiters = if delimiters.is_empty() {
        ".".to_string()
    } else {
        delimiters
    };

    // Get the base value
    let value = match letter_lower {
        's' => ctx.sender.to_string(),
        'l' => {
            // local-part of sender
            ctx.sender
                .rfind('@')
                .map(|pos| &ctx.sender[..pos])
                .unwrap_or("postmaster")
                .to_string()
        }
        'o' => {
            // domain of sender
            ctx.sender
                .rfind('@')
                .map(|pos| &ctx.sender[pos + 1..])
                .unwrap_or(ctx.sender)
                .to_string()
        }
        'd' => ctx.domain.to_string(),
        'i' => expand_ip(ctx.client_ip),
        'p' => {
            // Validated domain of client IP - we just return "unknown" since
            // proper implementation requires PTR lookup and validation
            "unknown".to_string()
        }
        'v' => {
            if ctx.client_ip.is_ipv4() {
                "in-addr".to_string()
            } else {
                "ip6".to_string()
            }
        }
        'h' => ctx.helo.to_string(),
        'c' => {
            if !ctx.is_exp {
                return Err("macro %{c} only allowed in exp".to_string());
            }
            ctx.client_ip.to_string()
        }
        'r' => {
            if !ctx.is_exp {
                return Err("macro %{r} only allowed in exp".to_string());
            }
            ctx.receiver.to_string()
        }
        't' => {
            if !ctx.is_exp {
                return Err("macro %{t} only allowed in exp".to_string());
            }
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().to_string())
                .unwrap_or_else(|_| "0".to_string())
        }
        _ => {
            return Err(format!("unknown macro letter: {}", letter));
        }
    };

    // Apply transformations
    let transformed = transform_value(&value, &delimiters, reverse, take_right);

    // URL-encode if uppercase
    if is_uppercase {
        Ok(url_encode(&transformed))
    } else {
        Ok(transformed)
    }
}

fn expand_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            // Dotted decimal
            v4.to_string()
        }
        IpAddr::V6(v6) => {
            // Dot-separated nibbles
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

fn transform_value(
    value: &str,
    delimiters: &str,
    reverse: bool,
    take_right: Option<usize>,
) -> String {
    // Split by any delimiter character
    let parts: Vec<&str> = value
        .split(|c: char| delimiters.contains(c))
        .collect();

    let mut parts = if reverse {
        parts.into_iter().rev().collect::<Vec<_>>()
    } else {
        parts
    };

    if let Some(n) = take_right {
        if n < parts.len() {
            parts = parts[parts.len() - n..].to_vec();
        }
    }

    parts.join(".")
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ctx() -> MacroContext<'static> {
        MacroContext {
            sender: "strong-bad@email.example.com",
            domain: "email.example.com",
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
            helo: "mx.example.org",
            receiver: "receiver.example.com",
            is_exp: false,
        }
    }

    #[test]
    fn test_simple_macros() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{s}", &ctx).unwrap(), "strong-bad@email.example.com");
        assert_eq!(expand_macros("%{l}", &ctx).unwrap(), "strong-bad");
        assert_eq!(expand_macros("%{o}", &ctx).unwrap(), "email.example.com");
        assert_eq!(expand_macros("%{d}", &ctx).unwrap(), "email.example.com");
        assert_eq!(expand_macros("%{i}", &ctx).unwrap(), "192.0.2.3");
        assert_eq!(expand_macros("%{h}", &ctx).unwrap(), "mx.example.org");
    }

    #[test]
    fn test_reverse_macro() {
        let ctx = test_ctx();
        // Reverse domain
        assert_eq!(
            expand_macros("%{dr}", &ctx).unwrap(),
            "com.example.email"
        );
    }

    #[test]
    fn test_take_right() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{d2}", &ctx).unwrap(), "example.com");
        assert_eq!(expand_macros("%{d1}", &ctx).unwrap(), "com");
    }

    #[test]
    fn test_literals() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%%", &ctx).unwrap(), "%");
        assert_eq!(expand_macros("%_", &ctx).unwrap(), " ");
        assert_eq!(expand_macros("%-", &ctx).unwrap(), "%20");
    }

    #[test]
    fn test_exp_only_macros() {
        let mut ctx = test_ctx();
        assert!(expand_macros("%{c}", &ctx).is_err());
        assert!(expand_macros("%{r}", &ctx).is_err());
        assert!(expand_macros("%{t}", &ctx).is_err());

        ctx.is_exp = true;
        assert!(expand_macros("%{c}", &ctx).is_ok());
        assert!(expand_macros("%{r}", &ctx).is_ok());
        assert!(expand_macros("%{t}", &ctx).is_ok());
    }
}
