//! SPF macro expansion (RFC 7208 Section 7).

use std::net::IpAddr;

/// Context for SPF macro expansion.
pub struct MacroContext<'a> {
    pub sender: &'a str,     // MAIL FROM
    pub domain: &'a str,     // Current domain being evaluated
    pub client_ip: IpAddr,
    pub helo: &'a str,
    pub receiver: &'a str,   // Receiving MTA
    /// Whether this is for exp= expansion (allows c, r, t macros)
    pub is_exp: bool,
}

impl<'a> MacroContext<'a> {
    pub fn new(
        sender: &'a str,
        domain: &'a str,
        client_ip: IpAddr,
        helo: &'a str,
        receiver: &'a str,
    ) -> Self {
        Self {
            sender,
            domain,
            client_ip,
            helo,
            receiver,
            is_exp: false,
        }
    }

    pub fn with_exp(mut self) -> Self {
        self.is_exp = true;
        self
    }
}

/// Expand SPF macros in a domain-spec string.
pub fn expand(spec: &str, ctx: &MacroContext) -> Result<String, String> {
    let mut result = String::new();
    let mut chars = spec.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '%' {
            result.push(c);
            continue;
        }

        match chars.next() {
            Some('%') => result.push('%'),
            Some('_') => result.push(' '),
            Some('-') => result.push_str("%20"),
            Some('{') => {
                // Parse macro: %{letter[digits][r][delimiters]}
                let macro_str: String = chars.by_ref().take_while(|&c| c != '}').collect();
                let expanded = expand_macro(&macro_str, ctx)?;
                result.push_str(&expanded);
            }
            Some(other) => {
                return Err(format!("invalid macro escape: %{}", other));
            }
            None => {
                return Err("unexpected end after %".into());
            }
        }
    }

    Ok(result)
}

fn expand_macro(macro_str: &str, ctx: &MacroContext) -> Result<String, String> {
    if macro_str.is_empty() {
        return Err("empty macro".into());
    }

    let mut chars = macro_str.chars();
    let letter = chars.next().unwrap();
    let url_encode = letter.is_uppercase();
    let letter_lower = letter.to_ascii_lowercase();

    // Parse optional digits, 'r', and delimiters
    let rest: String = chars.collect();
    let (digits, reverse, delimiters) = parse_transformers(&rest)?;

    // Get the base value
    let value = match letter_lower {
        's' => ctx.sender.to_string(),
        'l' => {
            // local-part of sender
            ctx.sender
                .rsplit_once('@')
                .map(|(l, _)| l.to_string())
                .unwrap_or_else(|| "postmaster".to_string())
        }
        'o' => {
            // domain of sender
            ctx.sender
                .rsplit_once('@')
                .map(|(_, d)| d.to_string())
                .unwrap_or_else(|| ctx.sender.to_string())
        }
        'd' => ctx.domain.to_string(),
        'i' => expand_ip(ctx.client_ip),
        'p' => {
            // Validated domain name of client IP (PTR)
            // For simplicity, return "unknown" - full impl would do PTR lookup
            "unknown".to_string()
        }
        'v' => match ctx.client_ip {
            IpAddr::V4(_) => "in-addr".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        },
        'h' => ctx.helo.to_string(),
        // Explanation-only macros
        'c' => {
            if !ctx.is_exp {
                return Err("macro %c only valid in exp=".into());
            }
            ctx.client_ip.to_string()
        }
        'r' => {
            if !ctx.is_exp {
                return Err("macro %r only valid in exp=".into());
            }
            ctx.receiver.to_string()
        }
        't' => {
            if !ctx.is_exp {
                return Err("macro %t only valid in exp=".into());
            }
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().to_string())
                .unwrap_or_else(|_| "0".to_string())
        }
        _ => return Err(format!("unknown macro letter: {}", letter)),
    };

    // Apply transformers
    let transformed = apply_transformers(&value, &delimiters, reverse, digits);

    // URL-encode if uppercase
    if url_encode {
        Ok(url_encode_string(&transformed))
    } else {
        Ok(transformed)
    }
}

fn parse_transformers(s: &str) -> Result<(Option<usize>, bool, String), String> {
    let mut chars = s.chars().peekable();
    let mut digits_str = String::new();
    let mut reverse = false;
    let mut delimiters = String::new();

    // Parse digits
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            digits_str.push(chars.next().unwrap());
        } else {
            break;
        }
    }

    // Parse 'r'
    if let Some(&'r') = chars.peek() {
        reverse = true;
        chars.next();
    }

    // Rest is delimiters
    delimiters = chars.collect();

    let digits = if digits_str.is_empty() {
        None
    } else {
        Some(digits_str.parse().map_err(|_| "invalid digits")?)
    };

    Ok((digits, reverse, delimiters))
}

fn expand_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string().replace('.', "."), // Keep dots
        IpAddr::V6(v6) => {
            // Expand to dot-separated nibbles
            let segments = v6.segments();
            let mut nibbles = Vec::new();
            for segment in segments {
                for shift in (0..16).step_by(4).rev() {
                    nibbles.push(format!("{:x}", (segment >> shift) & 0xf));
                }
            }
            nibbles.join(".")
        }
    }
}

fn apply_transformers(value: &str, delimiters: &str, reverse: bool, digits: Option<usize>) -> String {
    let delims = if delimiters.is_empty() {
        "."
    } else {
        delimiters
    };

    // Split by delimiters
    let parts: Vec<&str> = value
        .split(|c| delims.contains(c))
        .filter(|s| !s.is_empty())
        .collect();

    let parts = if reverse {
        parts.into_iter().rev().collect::<Vec<_>>()
    } else {
        parts
    };

    // Take rightmost N if digits specified
    let parts = match digits {
        Some(n) if n < parts.len() => parts[parts.len() - n..].to_vec(),
        _ => parts,
    };

    parts.join(".")
}

fn url_encode_string(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            result.push(c);
        } else {
            for byte in c.to_string().as_bytes() {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_ctx<'a>() -> MacroContext<'a> {
        MacroContext::new(
            "user@example.com",
            "example.com",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            "client.example.org",
            "receiver.example.net",
        )
    }

    #[test]
    fn test_simple_macros() {
        let ctx = make_ctx();
        assert_eq!(expand("%{s}", &ctx).unwrap(), "user@example.com");
        assert_eq!(expand("%{d}", &ctx).unwrap(), "example.com");
        assert_eq!(expand("%{l}", &ctx).unwrap(), "user");
        assert_eq!(expand("%{o}", &ctx).unwrap(), "example.com");
        assert_eq!(expand("%{h}", &ctx).unwrap(), "client.example.org");
    }

    #[test]
    fn test_ip_macro() {
        let ctx = make_ctx();
        assert_eq!(expand("%{i}", &ctx).unwrap(), "192.0.2.1");
        assert_eq!(expand("%{v}", &ctx).unwrap(), "in-addr");
    }

    #[test]
    fn test_ipv6_expansion() {
        let ctx = MacroContext::new(
            "user@example.com",
            "example.com",
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            "client.example.org",
            "receiver.example.net",
        );
        let expanded = expand("%{i}", &ctx).unwrap();
        assert!(expanded.contains('.'));
        assert_eq!(expand("%{v}", &ctx).unwrap(), "ip6");
    }

    #[test]
    fn test_reverse_macro() {
        let ctx = make_ctx();
        // %{ir} reverses IP: 192.0.2.1 -> 1.2.0.192
        assert_eq!(expand("%{ir}", &ctx).unwrap(), "1.2.0.192");
    }

    #[test]
    fn test_escape_sequences() {
        let ctx = make_ctx();
        assert_eq!(expand("%%", &ctx).unwrap(), "%");
        assert_eq!(expand("%_", &ctx).unwrap(), " ");
        assert_eq!(expand("%-", &ctx).unwrap(), "%20");
    }

    #[test]
    fn test_url_encoding() {
        let ctx = make_ctx();
        // Uppercase triggers URL encoding
        assert_eq!(expand("%{S}", &ctx).unwrap(), "user%40example.com");
    }

    #[test]
    fn test_exp_only_macros() {
        let ctx = make_ctx();
        assert!(expand("%{c}", &ctx).is_err());
        assert!(expand("%{r}", &ctx).is_err());
        assert!(expand("%{t}", &ctx).is_err());

        let exp_ctx = ctx.with_exp();
        assert!(expand("%{c}", &exp_ctx).is_ok());
        assert!(expand("%{r}", &exp_ctx).is_ok());
        assert!(expand("%{t}", &exp_ctx).is_ok());
    }
}
