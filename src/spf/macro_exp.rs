use std::net::IpAddr;

/// Context for macro expansion
pub struct MacroContext<'a> {
    /// Sender email (local-part@domain)
    pub sender: &'a str,
    /// Current domain being evaluated
    pub domain: &'a str,
    /// Client IP address
    pub client_ip: IpAddr,
    /// HELO/EHLO domain
    pub helo: &'a str,
    /// Receiving domain (for %{r} macro)
    pub receiver: Option<&'a str>,
    /// Whether this is an exp= context (allows %{c}, %{r}, %{t})
    pub is_exp_context: bool,
}

impl<'a> MacroContext<'a> {
    /// Expand macros in a domain-spec string
    pub fn expand(&self, input: &str) -> Result<String, String> {
        let mut result = String::with_capacity(input.len() * 2);
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                match chars.next() {
                    Some('%') => result.push('%'),
                    Some('_') => result.push(' '),
                    Some('-') => result.push_str("%20"),
                    Some('{') => {
                        let macro_body = Self::read_until(&mut chars, '}')?;
                        let expanded = self.expand_macro(&macro_body)?;
                        result.push_str(&expanded);
                    }
                    Some(other) => {
                        return Err(format!("invalid macro escape: %{}", other));
                    }
                    None => {
                        return Err("unexpected end of string after %".to_string());
                    }
                }
            } else {
                result.push(c);
            }
        }

        Ok(result)
    }

    fn read_until(chars: &mut std::iter::Peekable<std::str::Chars>, end: char) -> Result<String, String> {
        let mut result = String::new();
        while let Some(c) = chars.next() {
            if c == end {
                return Ok(result);
            }
            result.push(c);
        }
        Err(format!("unterminated macro (missing {})", end))
    }

    fn expand_macro(&self, spec: &str) -> Result<String, String> {
        if spec.is_empty() {
            return Err("empty macro".to_string());
        }

        let mut chars = spec.chars();
        let letter = chars.next().unwrap();
        let is_uppercase = letter.is_uppercase();
        let letter_lower = letter.to_ascii_lowercase();

        // Parse transformers: digits, 'r', delimiters
        let rest: String = chars.collect();
        let (digits, reverse, delimiters) = self.parse_transformers(&rest)?;

        // Get base value
        let value = match letter_lower {
            's' => self.sender.to_string(),
            'l' => self.local_part().to_string(),
            'o' => self.sender_domain().to_string(),
            'd' => self.domain.to_string(),
            'i' => self.format_ip(),
            'p' => {
                // PTR validated domain - expensive, return "unknown" for now
                // Full implementation would require reverse DNS lookup
                "unknown".to_string()
            }
            'v' => match self.client_ip {
                IpAddr::V4(_) => "in-addr".to_string(),
                IpAddr::V6(_) => "ip6".to_string(),
            },
            'h' => self.helo.to_string(),
            'c' | 'r' | 't' => {
                if !self.is_exp_context {
                    return Err(format!("macro %{{{}}} only allowed in exp= context", letter_lower));
                }
                match letter_lower {
                    'c' => self.client_ip.to_string(),
                    'r' => self.receiver.unwrap_or("unknown").to_string(),
                    't' => std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs().to_string())
                        .unwrap_or_else(|_| "0".to_string()),
                    _ => unreachable!(),
                }
            }
            _ => return Err(format!("unknown macro letter: {}", letter)),
        };

        // Apply transformers
        let transformed = self.apply_transformers(&value, digits, reverse, &delimiters);

        // URL encode if uppercase
        if is_uppercase {
            Ok(Self::url_encode(&transformed))
        } else {
            Ok(transformed)
        }
    }

    fn parse_transformers(&self, rest: &str) -> Result<(Option<usize>, bool, String), String> {
        let mut chars = rest.chars().peekable();
        let mut digits = None;
        let mut reverse = false;
        let mut delimiters = ".".to_string();

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
            digits = Some(digit_str.parse().map_err(|_| "invalid digit")?);
        }

        // Parse 'r' for reverse
        if chars.peek() == Some(&'r') || chars.peek() == Some(&'R') {
            reverse = true;
            chars.next();
        }

        // Rest is delimiters
        let custom_delims: String = chars.collect();
        if !custom_delims.is_empty() {
            delimiters = custom_delims;
        }

        Ok((digits, reverse, delimiters))
    }

    fn apply_transformers(&self, value: &str, digits: Option<usize>, reverse: bool, delimiters: &str) -> String {
        // Split by delimiters
        let parts: Vec<&str> = if delimiters == "." {
            value.split('.').collect()
        } else {
            // Split by any delimiter character
            let mut parts = Vec::new();
            let mut current = String::new();
            for c in value.chars() {
                if delimiters.contains(c) {
                    if !current.is_empty() {
                        parts.push(current.clone());
                        current.clear();
                    }
                } else {
                    current.push(c);
                }
            }
            if !current.is_empty() {
                parts.push(current);
            }
            // Convert to &str - need owned data
            return self.apply_transformers_owned(parts, digits, reverse);
        };

        let mut parts: Vec<&str> = parts;

        if reverse {
            parts.reverse();
        }

        if let Some(n) = digits {
            // Take rightmost n parts
            if n < parts.len() {
                parts = parts[parts.len() - n..].to_vec();
            }
        }

        parts.join(".")
    }

    fn apply_transformers_owned(&self, mut parts: Vec<String>, digits: Option<usize>, reverse: bool) -> String {
        if reverse {
            parts.reverse();
        }

        if let Some(n) = digits {
            if n < parts.len() {
                parts = parts[parts.len() - n..].to_vec();
            }
        }

        parts.join(".")
    }

    fn local_part(&self) -> &str {
        self.sender
            .rsplit_once('@')
            .map(|(local, _)| local)
            .unwrap_or("postmaster")
    }

    fn sender_domain(&self) -> &str {
        self.sender
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or(self.domain)
    }

    fn format_ip(&self) -> String {
        match self.client_ip {
            IpAddr::V4(ip) => {
                // Dotted notation as-is
                ip.to_string()
            }
            IpAddr::V6(ip) => {
                // Dot-separated nibbles
                let segments = ip.segments();
                let mut result = String::with_capacity(63);
                for (i, seg) in segments.iter().enumerate() {
                    if i > 0 {
                        result.push('.');
                    }
                    result.push_str(&format!(
                        "{:x}.{:x}.{:x}.{:x}",
                        (seg >> 12) & 0xf,
                        (seg >> 8) & 0xf,
                        (seg >> 4) & 0xf,
                        seg & 0xf
                    ));
                }
                result
            }
        }
    }

    fn url_encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 3);
        for c in s.chars() {
            if c.is_ascii_alphanumeric() || "-_.~".contains(c) {
                result.push(c);
            } else {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_context<'a>(sender: &'a str, domain: &'a str, ip: IpAddr) -> MacroContext<'a> {
        MacroContext {
            sender,
            domain,
            client_ip: ip,
            helo: "mail.example.com",
            receiver: Some("mta.example.net"),
            is_exp_context: false,
        }
    }

    #[test]
    fn test_sender_macro() {
        let ctx = make_context("user@example.com", "example.com", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(ctx.expand("%{s}").unwrap(), "user@example.com");
    }

    #[test]
    fn test_domain_macro() {
        let ctx = make_context("user@example.com", "example.com", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(ctx.expand("%{d}").unwrap(), "example.com");
    }

    #[test]
    fn test_ip_macro_v4() {
        let ctx = make_context("user@example.com", "example.com", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(ctx.expand("%{i}").unwrap(), "192.0.2.1");
    }

    #[test]
    fn test_ip_macro_v6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ctx = make_context("user@example.com", "example.com", ip);
        let result = ctx.expand("%{i}").unwrap();
        assert!(result.contains('.'));
    }

    #[test]
    fn test_reverse_ip() {
        let ctx = make_context("user@example.com", "example.com", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let result = ctx.expand("%{ir}").unwrap();
        assert_eq!(result, "1.2.0.192");
    }

    #[test]
    fn test_url_encode() {
        let ctx = make_context("user name@example.com", "example.com", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let result = ctx.expand("%{S}").unwrap();
        assert!(result.contains("%20")); // space encoded
    }

    #[test]
    fn test_literal_percent() {
        let ctx = make_context("user@example.com", "example.com", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(ctx.expand("%%").unwrap(), "%");
        assert_eq!(ctx.expand("%_").unwrap(), " ");
        assert_eq!(ctx.expand("%-").unwrap(), "%20");
    }

    #[test]
    fn test_exp_only_macros() {
        let mut ctx = make_context("user@example.com", "example.com", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));

        // Should fail outside exp context
        assert!(ctx.expand("%{c}").is_err());

        // Should succeed in exp context
        ctx.is_exp_context = true;
        assert!(ctx.expand("%{c}").is_ok());
    }
}
