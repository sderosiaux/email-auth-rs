//! SPF macro expansion (RFC 7208 Section 7)

use std::net::IpAddr;

/// Context for macro expansion
pub struct MacroContext<'a> {
    pub sender: &'a str,       // local-part@domain (s)
    pub domain: &'a str,       // current domain being evaluated (d)
    pub client_ip: IpAddr,     // connecting IP (i)
    pub helo: &'a str,         // HELO/EHLO domain (h)
    pub receiver: Option<&'a str>, // receiving domain (r) - only in exp
    pub is_exp: bool,          // whether this is for exp= expansion
}

impl<'a> MacroContext<'a> {
    /// Get local-part of sender
    pub fn local_part(&self) -> &str {
        self.sender
            .split('@')
            .next()
            .unwrap_or("postmaster")
    }

    /// Get domain of sender
    pub fn sender_domain(&self) -> &str {
        self.sender
            .split('@')
            .nth(1)
            .unwrap_or(self.domain)
    }

    /// Get IP in SPF format (dotted for v4, dot-separated nibbles for v6)
    pub fn ip_spf_format(&self) -> String {
        match self.client_ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => {
                // Convert to dot-separated nibbles (reversed for DNS)
                let segments = v6.segments();
                let mut nibbles = Vec::with_capacity(32);
                for segment in segments {
                    nibbles.push(format!("{:x}", (segment >> 12) & 0xf));
                    nibbles.push(format!("{:x}", (segment >> 8) & 0xf));
                    nibbles.push(format!("{:x}", (segment >> 4) & 0xf));
                    nibbles.push(format!("{:x}", segment & 0xf));
                }
                nibbles.join(".")
            }
        }
    }

    /// Get IP version string
    pub fn ip_version(&self) -> &'static str {
        match self.client_ip {
            IpAddr::V4(_) => "in-addr",
            IpAddr::V6(_) => "ip6",
        }
    }
}

/// Expand macros in a domain-spec string
pub fn expand_macros(template: &str, ctx: &MacroContext) -> Result<String, MacroError> {
    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

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
                // Parse macro: {<letter>[<digits>][r][<delimiters>]}
                let mut macro_spec = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(c) => macro_spec.push(c),
                        None => return Err(MacroError::UnclosedMacro),
                    }
                }
                let expanded = expand_single_macro(&macro_spec, ctx)?;
                result.push_str(&expanded);
            }
            Some(c) => {
                return Err(MacroError::InvalidMacro(format!("unexpected char after %: {}", c)));
            }
            None => {
                return Err(MacroError::InvalidMacro("trailing %".to_string()));
            }
        }
    }

    Ok(result)
}

fn expand_single_macro(spec: &str, ctx: &MacroContext) -> Result<String, MacroError> {
    if spec.is_empty() {
        return Err(MacroError::InvalidMacro("empty macro".to_string()));
    }

    let mut chars = spec.chars();
    let letter = chars.next().unwrap();
    let rest: String = chars.collect();

    // Parse optional digits, 'r', and delimiters
    let (digits, reverse, delimiters) = parse_macro_modifiers(&rest)?;

    // Get the base value
    let value = match letter.to_ascii_lowercase() {
        's' => ctx.sender.to_string(),
        'l' => ctx.local_part().to_string(),
        'o' => ctx.sender_domain().to_string(),
        'd' => ctx.domain.to_string(),
        'i' => ctx.ip_spf_format(),
        'h' => ctx.helo.to_string(),
        'v' => ctx.ip_version().to_string(),
        'p' => {
            // PTR validated domain - we return "unknown" as placeholder
            // Real implementation would do PTR lookup
            "unknown".to_string()
        }
        'c' | 'r' | 't' => {
            // Explanation-only macros
            if !ctx.is_exp {
                return Err(MacroError::ExpOnlyMacro(letter));
            }
            match letter.to_ascii_lowercase() {
                'c' => ctx.client_ip.to_string(),
                'r' => ctx.receiver.unwrap_or("unknown").to_string(),
                't' => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_else(|_| "0".to_string()),
                _ => unreachable!(),
            }
        }
        _ => return Err(MacroError::UnknownMacro(letter)),
    };

    // Apply transformations
    let delims: Vec<char> = if delimiters.is_empty() {
        vec!['.']
    } else {
        delimiters.chars().collect()
    };

    let mut parts: Vec<&str> = value
        .split(|c| delims.contains(&c))
        .collect();

    if reverse {
        parts.reverse();
    }

    if let Some(n) = digits {
        if n > 0 && parts.len() > n {
            let skip_count = parts.len() - n;
            parts = parts.into_iter().skip(skip_count).collect();
        }
    }

    let result = parts.join(".");

    // URL-encode if uppercase letter
    if letter.is_uppercase() {
        Ok(url_encode(&result))
    } else {
        Ok(result)
    }
}

fn parse_macro_modifiers(s: &str) -> Result<(Option<usize>, bool, String), MacroError> {
    let mut chars = s.chars().peekable();
    let mut digits = String::new();
    let mut reverse = false;
    let mut delimiters = String::new();

    // Parse digits
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            digits.push(chars.next().unwrap());
        } else {
            break;
        }
    }

    // Parse 'r' for reverse
    if let Some(&'r') = chars.peek() {
        reverse = true;
        chars.next();
    }

    // Rest is delimiters
    delimiters = chars.collect();

    let digits = if digits.is_empty() {
        None
    } else {
        Some(digits.parse().map_err(|_| MacroError::InvalidMacro("invalid digit count".to_string()))?)
    };

    Ok((digits, reverse, delimiters))
}

fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            result.push(c);
        } else {
            for b in c.to_string().as_bytes() {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

#[derive(Debug, thiserror::Error)]
pub enum MacroError {
    #[error("unclosed macro")]
    UnclosedMacro,
    #[error("invalid macro: {0}")]
    InvalidMacro(String),
    #[error("unknown macro letter: {0}")]
    UnknownMacro(char),
    #[error("macro {0} only valid in exp= context")]
    ExpOnlyMacro(char),
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
            receiver: Some("receiver.example.com"),
            is_exp: false,
        }
    }

    #[test]
    fn test_expand_sender() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{s}", &ctx).unwrap(), "strong-bad@email.example.com");
    }

    #[test]
    fn test_expand_local_part() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{l}", &ctx).unwrap(), "strong-bad");
    }

    #[test]
    fn test_expand_domain() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{d}", &ctx).unwrap(), "email.example.com");
    }

    #[test]
    fn test_expand_ip() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{i}", &ctx).unwrap(), "192.0.2.3");
    }

    #[test]
    fn test_expand_reversed() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{ir}", &ctx).unwrap(), "3.2.0.192");
    }

    #[test]
    fn test_expand_with_digits() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{d2}", &ctx).unwrap(), "example.com");
    }

    #[test]
    fn test_expand_reversed_with_digits() {
        let ctx = test_ctx();
        // d = "email.example.com" -> split: ["email","example","com"]
        // reverse: ["com","example","email"]
        // take rightmost 1: ["email"]
        // join: "email"
        assert_eq!(expand_macros("%{d1r}", &ctx).unwrap(), "email");
    }

    #[test]
    fn test_literals() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%%", &ctx).unwrap(), "%");
        assert_eq!(expand_macros("%_", &ctx).unwrap(), " ");
        assert_eq!(expand_macros("%-", &ctx).unwrap(), "%20");
    }

    #[test]
    fn test_url_encoding() {
        let ctx = test_ctx();
        // Uppercase letter triggers URL encoding
        assert_eq!(expand_macros("%{S}", &ctx).unwrap(), "strong-bad%40email.example.com");
    }

    #[test]
    fn test_exp_only_macro_rejected() {
        let ctx = test_ctx();
        assert!(expand_macros("%{c}", &ctx).is_err());
    }

    #[test]
    fn test_exp_only_macro_allowed() {
        let mut ctx = test_ctx();
        ctx.is_exp = true;
        assert!(expand_macros("%{c}", &ctx).is_ok());
    }
}
