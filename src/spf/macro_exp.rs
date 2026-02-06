use std::net::IpAddr;

pub struct MacroContext<'a> {
    pub sender: &'a str,
    pub domain: &'a str,
    pub ip: IpAddr,
    pub helo: &'a str,
}

impl<'a> MacroContext<'a> {
    fn local_part(&self) -> &str {
        self.sender
            .split('@')
            .next()
            .unwrap_or("postmaster")
    }

    fn sender_domain(&self) -> &str {
        self.sender
            .split('@')
            .nth(1)
            .unwrap_or(self.domain)
    }

    fn ip_string(&self) -> String {
        match self.ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => {
                // For IPv6 in SPF, use dotted nibble format
                let segments = v6.segments();
                let mut result = String::new();
                for segment in segments {
                    for nibble in [(segment >> 12) & 0xf, (segment >> 8) & 0xf, (segment >> 4) & 0xf, segment & 0xf] {
                        if !result.is_empty() {
                            result.push('.');
                        }
                        result.push_str(&format!("{:x}", nibble));
                    }
                }
                result
            }
        }
    }

    fn ip_version(&self) -> &'static str {
        match self.ip {
            IpAddr::V4(_) => "in-addr",
            IpAddr::V6(_) => "ip6",
        }
    }
}

pub fn expand_macros(template: &str, ctx: &MacroContext) -> String {
    let mut result = String::new();
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('%') => result.push('%'),
                Some('_') => result.push(' '),
                Some('-') => result.push_str("%20"),
                Some('{') => {
                    let mut macro_spec = String::new();
                    for mc in chars.by_ref() {
                        if mc == '}' {
                            break;
                        }
                        macro_spec.push(mc);
                    }
                    let expanded = expand_macro_spec(&macro_spec, ctx);
                    result.push_str(&expanded);
                }
                Some(other) => {
                    result.push('%');
                    result.push(other);
                }
                None => result.push('%'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

fn expand_macro_spec(spec: &str, ctx: &MacroContext) -> String {
    if spec.is_empty() {
        return String::new();
    }

    let mut chars = spec.chars();
    let letter = match chars.next() {
        Some(c) => c.to_ascii_lowercase(),
        None => return String::new(),
    };

    let rest: String = chars.collect();

    let value = match letter {
        's' => ctx.sender.to_string(),
        'l' => ctx.local_part().to_string(),
        'o' => ctx.sender_domain().to_string(),
        'd' => ctx.domain.to_string(),
        'i' => ctx.ip_string(),
        'p' => "unknown".to_string(), // PTR validation is expensive, use placeholder
        'v' => ctx.ip_version().to_string(),
        'h' => ctx.helo.to_string(),
        _ => return String::new(),
    };

    let (transform_count, reverse, delimiters) = parse_transformers(&rest);

    apply_transformers(&value, transform_count, reverse, &delimiters)
}

fn parse_transformers(spec: &str) -> (Option<usize>, bool, String) {
    let mut count = None;
    let mut reverse = false;
    let mut delimiters = String::new();

    let mut chars = spec.chars().peekable();

    // Parse optional digit count
    let mut num_str = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            num_str.push(c);
            chars.next();
        } else {
            break;
        }
    }
    if !num_str.is_empty() {
        count = num_str.parse().ok();
    }

    // Parse optional 'r' for reverse
    if chars.peek() == Some(&'r') || chars.peek() == Some(&'R') {
        reverse = true;
        chars.next();
    }

    // Rest is delimiters
    for c in chars {
        if c == '.' || c == '-' || c == '+' || c == ',' || c == '/' || c == '_' || c == '=' {
            delimiters.push(c);
        }
    }

    (count, reverse, delimiters)
}

fn apply_transformers(value: &str, count: Option<usize>, reverse: bool, delimiters: &str) -> String {
    let delims = if delimiters.is_empty() { "." } else { delimiters };

    let parts: Vec<&str> = value
        .split(|c| delims.contains(c))
        .filter(|s| !s.is_empty())
        .collect();

    let parts = if reverse {
        parts.into_iter().rev().collect::<Vec<_>>()
    } else {
        parts
    };

    let parts = if let Some(n) = count {
        if n < parts.len() {
            parts[parts.len() - n..].to_vec()
        } else {
            parts
        }
    } else {
        parts
    };

    parts.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> MacroContext<'static> {
        MacroContext {
            sender: "user@example.com",
            domain: "example.com",
            ip: "192.168.1.1".parse().unwrap(),
            helo: "mail.example.com",
        }
    }

    #[test]
    fn test_simple_macros() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{s}", &ctx), "user@example.com");
        assert_eq!(expand_macros("%{d}", &ctx), "example.com");
        assert_eq!(expand_macros("%{l}", &ctx), "user");
        assert_eq!(expand_macros("%{o}", &ctx), "example.com");
    }

    #[test]
    fn test_ip_macro() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{i}", &ctx), "192.168.1.1");
    }

    #[test]
    fn test_escape_sequences() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%%", &ctx), "%");
        assert_eq!(expand_macros("%_", &ctx), " ");
        assert_eq!(expand_macros("%-", &ctx), "%20");
    }

    #[test]
    fn test_reverse_transformer() {
        let ctx = test_ctx();
        assert_eq!(expand_macros("%{dr}", &ctx), "com.example");
    }

    #[test]
    fn test_count_transformer() {
        let ctx = MacroContext {
            sender: "user@sub.mail.example.com",
            domain: "sub.mail.example.com",
            ip: "192.168.1.1".parse().unwrap(),
            helo: "mail.example.com",
        };
        assert_eq!(expand_macros("%{d2}", &ctx), "example.com");
    }
}
