use std::net::IpAddr;

pub struct MacroContext<'a> {
    pub sender: &'a str,
    pub domain: &'a str,
    pub ip: IpAddr,
    pub helo: &'a str,
}

impl<'a> MacroContext<'a> {
    pub fn expand(&self, input: &str) -> String {
        let mut result = String::new();
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                match chars.next() {
                    Some('{') => {
                        let mut macro_spec = String::new();
                        for mc in chars.by_ref() {
                            if mc == '}' {
                                break;
                            }
                            macro_spec.push(mc);
                        }
                        result.push_str(&self.expand_macro(&macro_spec));
                    }
                    Some('%') => result.push('%'),
                    Some('_') => result.push(' '),
                    Some('-') => result.push_str("%20"),
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

    fn expand_macro(&self, spec: &str) -> String {
        let mut chars = spec.chars();
        let letter = match chars.next() {
            Some(c) => c.to_ascii_lowercase(),
            None => return String::new(),
        };

        let rest: String = chars.collect();
        let (digits, reverse, delimiters) = parse_transformers(&rest);

        let raw_value = match letter {
            's' => self.sender.to_string(),
            'l' => self.local_part(),
            'o' => self.sender_domain(),
            'd' => self.domain.to_string(),
            'i' => self.ip_expanded(),
            'p' => "unknown".to_string(), // PTR not commonly used
            'v' => match self.ip {
                IpAddr::V4(_) => "in-addr".to_string(),
                IpAddr::V6(_) => "ip6".to_string(),
            },
            'h' => self.helo.to_string(),
            _ => return String::new(),
        };

        let delims = if delimiters.is_empty() { "." } else { &delimiters };
        let parts: Vec<&str> = raw_value.split(|c| delims.contains(c)).collect();

        let parts = if reverse {
            parts.into_iter().rev().collect::<Vec<_>>()
        } else {
            parts
        };

        let parts = if let Some(n) = digits {
            let n = n as usize;
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

    fn local_part(&self) -> String {
        self.sender
            .split('@')
            .next()
            .unwrap_or("postmaster")
            .to_string()
    }

    fn sender_domain(&self) -> String {
        self.sender
            .split('@')
            .nth(1)
            .unwrap_or(self.domain)
            .to_string()
    }

    fn ip_expanded(&self) -> String {
        match self.ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                let mut nibbles = Vec::new();
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
}

fn parse_transformers(s: &str) -> (Option<u8>, bool, String) {
    let mut digits = None;
    let mut reverse = false;

    let mut chars = s.chars().peekable();

    // Parse digits
    let mut digit_str = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            digit_str.push(chars.next().unwrap());
        } else {
            break;
        }
    }
    if !digit_str.is_empty() {
        digits = digit_str.parse().ok();
    }

    // Parse 'r' for reverse
    if chars.peek() == Some(&'r') || chars.peek() == Some(&'R') {
        reverse = true;
        chars.next();
    }

    // Rest is delimiters
    let delimiters: String = chars.collect();

    (digits, reverse, delimiters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_simple_expansion() {
        let ctx = MacroContext {
            sender: "user@example.com",
            domain: "example.com",
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            helo: "mail.example.com",
        };

        assert_eq!(ctx.expand("%{s}"), "user@example.com");
        assert_eq!(ctx.expand("%{d}"), "example.com");
        assert_eq!(ctx.expand("%{l}"), "user");
        assert_eq!(ctx.expand("%{o}"), "example.com");
    }

    #[test]
    fn test_reverse() {
        let ctx = MacroContext {
            sender: "user@example.com",
            domain: "example.com",
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            helo: "mail.example.com",
        };

        assert_eq!(ctx.expand("%{dr}"), "com.example");
    }
}
