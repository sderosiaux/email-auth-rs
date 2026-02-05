use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MacroError {
    #[error("invalid macro: {0}")]
    InvalidMacro(String),
    #[error("exp-only macro used outside exp context: {0}")]
    ExpOnlyMacro(char),
}

/// Context for macro expansion
pub struct MacroContext<'a> {
    pub sender: &'a str,        // Full sender email
    pub domain: &'a str,        // Current domain being evaluated
    pub client_ip: IpAddr,      // Client IP
    pub helo: &'a str,          // HELO/EHLO domain
    pub validated_domain: Option<&'a str>, // PTR-validated domain (for %{p})
    pub receiver_domain: Option<&'a str>,  // Receiving MTA domain (for %{r}, exp only)
    pub is_exp_context: bool,   // Whether in exp= context (allows c, r, t macros)
}

impl<'a> MacroContext<'a> {
    pub fn new(sender: &'a str, domain: &'a str, client_ip: IpAddr, helo: &'a str) -> Self {
        Self {
            sender,
            domain,
            client_ip,
            helo,
            validated_domain: None,
            receiver_domain: None,
            is_exp_context: false,
        }
    }

    /// Set PTR-validated domain
    pub fn with_validated_domain(mut self, domain: &'a str) -> Self {
        self.validated_domain = Some(domain);
        self
    }

    /// Enable exp context for exp-only macros
    pub fn with_exp_context(mut self, receiver: &'a str) -> Self {
        self.is_exp_context = true;
        self.receiver_domain = Some(receiver);
        self
    }
}

/// Expand macros in a string
pub fn expand_macros(s: &str, ctx: &MacroContext) -> Result<String, MacroError> {
    let mut result = String::with_capacity(s.len() * 2);
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('{') => {
                    // Full macro: %{letter[transformers]}
                    let mut macro_str = String::new();
                    for mc in chars.by_ref() {
                        if mc == '}' {
                            break;
                        }
                        macro_str.push(mc);
                    }
                    result.push_str(&expand_full_macro(&macro_str, ctx)?);
                }
                Some('%') => result.push('%'),
                Some('_') => result.push(' '),
                Some('-') => result.push_str("%20"),
                Some(c) => {
                    return Err(MacroError::InvalidMacro(format!("%{}", c)));
                }
                None => {
                    return Err(MacroError::InvalidMacro("%".to_string()));
                }
            }
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

fn expand_full_macro(macro_str: &str, ctx: &MacroContext) -> Result<String, MacroError> {
    if macro_str.is_empty() {
        return Err(MacroError::InvalidMacro("empty macro".to_string()));
    }

    let mut chars = macro_str.chars();
    let letter = chars.next().unwrap();
    let rest: String = chars.collect();

    // Check if uppercase (URL encoding required)
    let url_encode = letter.is_uppercase();
    let letter_lower = letter.to_ascii_lowercase();

    // Get base value for letter
    let value = get_macro_value(letter_lower, ctx)?;

    // Parse transformers: digit* 'r'? delimiter*
    let (digit_count, reverse, delimiters) = parse_transformers(&rest)?;

    // Apply transformations
    let transformed = apply_transformers(&value, digit_count, reverse, &delimiters);

    // URL encode if uppercase
    if url_encode {
        Ok(url_encode_str(&transformed))
    } else {
        Ok(transformed)
    }
}

fn get_macro_value(letter: char, ctx: &MacroContext) -> Result<String, MacroError> {
    match letter {
        's' => Ok(ctx.sender.to_string()),
        'l' => {
            // Local part of sender
            Ok(ctx
                .sender
                .rsplit_once('@')
                .map(|(l, _)| l)
                .unwrap_or("postmaster")
                .to_string())
        }
        'o' => {
            // Domain of sender
            Ok(ctx
                .sender
                .rsplit_once('@')
                .map(|(_, d)| d)
                .unwrap_or(ctx.domain)
                .to_string())
        }
        'd' => Ok(ctx.domain.to_string()),
        'i' => Ok(format_ip(ctx.client_ip)),
        'p' => {
            // Validated domain name of client IP
            Ok(ctx
                .validated_domain
                .unwrap_or("unknown")
                .to_string())
        }
        'v' => {
            // IP version string
            Ok(match ctx.client_ip {
                IpAddr::V4(_) => "in-addr".to_string(),
                IpAddr::V6(_) => "ip6".to_string(),
            })
        }
        'h' => Ok(ctx.helo.to_string()),
        // Exp-only macros
        'c' => {
            if !ctx.is_exp_context {
                return Err(MacroError::ExpOnlyMacro('c'));
            }
            Ok(ctx.client_ip.to_string())
        }
        'r' => {
            if !ctx.is_exp_context {
                return Err(MacroError::ExpOnlyMacro('r'));
            }
            Ok(ctx.receiver_domain.unwrap_or("unknown").to_string())
        }
        't' => {
            if !ctx.is_exp_context {
                return Err(MacroError::ExpOnlyMacro('t'));
            }
            Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .to_string())
        }
        _ => Err(MacroError::InvalidMacro(format!("unknown letter: {}", letter))),
    }
}

fn format_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string().replace('.', "."),
        IpAddr::V6(v6) => {
            // Convert to dot-separated nibbles
            let octets = v6.octets();
            let mut nibbles = Vec::with_capacity(32);
            for octet in octets {
                nibbles.push(format!("{:x}", octet >> 4));
                nibbles.push(format!("{:x}", octet & 0x0f));
            }
            nibbles.join(".")
        }
    }
}

fn parse_transformers(s: &str) -> Result<(Option<usize>, bool, Vec<char>), MacroError> {
    let mut chars = s.chars().peekable();
    let mut digit_str = String::new();
    let mut reverse = false;
    let mut delimiters = Vec::new();

    // Parse leading digits
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            digit_str.push(chars.next().unwrap());
        } else {
            break;
        }
    }

    let digit_count = if digit_str.is_empty() {
        None
    } else {
        Some(digit_str.parse().map_err(|_| MacroError::InvalidMacro(s.to_string()))?)
    };

    // Check for 'r' (reverse)
    if let Some(&'r') = chars.peek() {
        reverse = true;
        chars.next();
    }

    // Rest are delimiters (default is '.')
    for c in chars {
        if matches!(c, '.' | '-' | '+' | ',' | '/' | '_' | '=') {
            delimiters.push(c);
        } else {
            return Err(MacroError::InvalidMacro(format!("invalid delimiter: {}", c)));
        }
    }

    Ok((digit_count, reverse, delimiters))
}

fn apply_transformers(value: &str, digit_count: Option<usize>, reverse: bool, delimiters: &[char]) -> String {
    // Use '.' as default delimiter for splitting
    let split_delims: &[char] = if delimiters.is_empty() {
        &['.']
    } else {
        delimiters
    };

    // Split by delimiters
    let mut parts: Vec<&str> = value.split(|c| split_delims.contains(&c)).collect();

    // Reverse if requested
    if reverse {
        parts.reverse();
    }

    // Take last N parts if digit specified
    if let Some(n) = digit_count {
        if n < parts.len() {
            parts = parts[parts.len() - n..].to_vec();
        }
    }

    // Join with first delimiter (or '.')
    let join_delim = delimiters.first().copied().unwrap_or('.');
    parts.join(&join_delim.to_string())
}

fn url_encode_str(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            result.push(c);
        } else {
            for b in c.to_string().bytes() {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> MacroContext<'static> {
        MacroContext::new(
            "user@example.com",
            "example.com",
            "192.168.1.1".parse().unwrap(),
            "mail.example.com",
        )
    }

    #[test]
    fn test_expand_simple_macros() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{s}", &ctx).unwrap(), "user@example.com");
        assert_eq!(expand_macros("%{l}", &ctx).unwrap(), "user");
        assert_eq!(expand_macros("%{o}", &ctx).unwrap(), "example.com");
        assert_eq!(expand_macros("%{d}", &ctx).unwrap(), "example.com");
        assert_eq!(expand_macros("%{h}", &ctx).unwrap(), "mail.example.com");
    }

    #[test]
    fn test_expand_ip_macro() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{i}", &ctx).unwrap(), "192.168.1.1");
        assert_eq!(expand_macros("%{v}", &ctx).unwrap(), "in-addr");
    }

    #[test]
    fn test_expand_reverse() {
        let ctx = test_ctx();
        // %{ir} reverses the IP octets
        assert_eq!(expand_macros("%{ir}", &ctx).unwrap(), "1.1.168.192");
    }

    #[test]
    fn test_expand_literals() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%%", &ctx).unwrap(), "%");
        assert_eq!(expand_macros("%_", &ctx).unwrap(), " ");
        assert_eq!(expand_macros("%-", &ctx).unwrap(), "%20");
    }

    #[test]
    fn test_expand_url_encoding() {
        let ctx = test_ctx();
        // Uppercase letter triggers URL encoding
        assert_eq!(expand_macros("%{S}", &ctx).unwrap(), "user%40example.com");
    }

    #[test]
    fn test_exp_only_macros_rejected() {
        let ctx = test_ctx();
        assert!(expand_macros("%{c}", &ctx).is_err());
        assert!(expand_macros("%{r}", &ctx).is_err());
        assert!(expand_macros("%{t}", &ctx).is_err());
    }

    #[test]
    fn test_exp_only_macros_allowed_in_exp() {
        let ctx = test_ctx().with_exp_context("receiver.example.com");
        assert!(expand_macros("%{c}", &ctx).is_ok());
        assert!(expand_macros("%{r}", &ctx).is_ok());
        assert!(expand_macros("%{t}", &ctx).is_ok());
    }
}
