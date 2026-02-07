use std::net::IpAddr;

/// Context for SPF macro expansion.
pub struct MacroContext {
    pub sender: String,
    pub local_part: String,
    pub sender_domain: String,
    pub client_ip: IpAddr,
    pub helo: String,
    pub domain: String,
    pub receiver: String,
}

/// Expand SPF macros in a string.
/// `is_exp` controls whether explanation-only macros (c, r, t) are allowed.
pub fn expand(template: &str, ctx: &MacroContext, is_exp: bool) -> Result<String, String> {
    let mut result = String::new();
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '%' {
            i += 1;
            if i >= chars.len() {
                return Err("trailing % in macro".to_string());
            }
            match chars[i] {
                '%' => {
                    result.push('%');
                    i += 1;
                }
                '_' => {
                    result.push(' ');
                    i += 1;
                }
                '-' => {
                    result.push_str("%20");
                    i += 1;
                }
                '{' => {
                    i += 1;
                    // Parse macro: letter [digits] [r] [delimiters]
                    if i >= chars.len() {
                        return Err("unterminated macro".to_string());
                    }
                    let letter = chars[i];
                    let is_upper = letter.is_ascii_uppercase();
                    let letter_lower = letter.to_ascii_lowercase();
                    i += 1;

                    // Parse optional digits
                    let mut digits = 0u32;
                    let mut has_digits = false;
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        digits = digits * 10 + (chars[i] as u32 - '0' as u32);
                        has_digits = true;
                        i += 1;
                    }
                    if !has_digits {
                        digits = 0; // 0 means all parts
                    }

                    // Parse optional reverse flag
                    let reverse = if i < chars.len() && chars[i] == 'r' {
                        i += 1;
                        true
                    } else {
                        false
                    };

                    // Parse optional delimiters (up to closing })
                    let mut delimiters = String::new();
                    while i < chars.len() && chars[i] != '}' {
                        delimiters.push(chars[i]);
                        i += 1;
                    }
                    if i >= chars.len() || chars[i] != '}' {
                        return Err("unterminated macro".to_string());
                    }
                    i += 1; // skip }

                    if delimiters.is_empty() {
                        delimiters = ".".to_string();
                    }

                    // Expand the macro letter
                    let value = expand_letter(letter_lower, ctx, is_exp)?;

                    // Apply transformers
                    let transformed = apply_transformers(&value, digits, reverse, &delimiters);

                    // URL-encode if uppercase letter
                    if is_upper {
                        result.push_str(&url_encode(&transformed));
                    } else {
                        result.push_str(&transformed);
                    }
                }
                _ => {
                    return Err(format!("invalid macro escape: %{}", chars[i]));
                }
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    Ok(result)
}

fn expand_letter(letter: char, ctx: &MacroContext, is_exp: bool) -> Result<String, String> {
    match letter {
        's' => Ok(ctx.sender.clone()),
        'l' => Ok(ctx.local_part.clone()),
        'o' => Ok(ctx.sender_domain.clone()),
        'd' => Ok(ctx.domain.clone()),
        'i' => Ok(expand_ip(&ctx.client_ip)),
        'p' => Ok("unknown".to_string()), // PTR validation not performed
        'v' => Ok(match ctx.client_ip {
            IpAddr::V4(_) => "in-addr".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        }),
        'h' => Ok(ctx.helo.clone()),
        'c' => {
            if !is_exp {
                return Err("macro %{c} only valid in exp= context".to_string());
            }
            Ok(ctx.client_ip.to_string())
        }
        'r' => {
            if !is_exp {
                return Err("macro %{r} only valid in exp= context".to_string());
            }
            Ok(ctx.receiver.clone())
        }
        't' => {
            if !is_exp {
                return Err("macro %{t} only valid in exp= context".to_string());
            }
            Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string())
        }
        _ => Err(format!("unknown macro letter: {}", letter)),
    }
}

/// Expand IP address for %{i}: dotted for v4, dot-separated nibbles for v6.
fn expand_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut nibbles = Vec::with_capacity(32);
            for seg in &segments {
                nibbles.push(format!("{:x}", (seg >> 12) & 0xf));
                nibbles.push(format!("{:x}", (seg >> 8) & 0xf));
                nibbles.push(format!("{:x}", (seg >> 4) & 0xf));
                nibbles.push(format!("{:x}", seg & 0xf));
            }
            nibbles.join(".")
        }
    }
}

/// Apply digit truncation, reverse, and delimiter transformers.
fn apply_transformers(value: &str, digits: u32, reverse: bool, delimiters: &str) -> String {
    // Split by any delimiter character
    let parts: Vec<&str> = if delimiters == "." {
        value.split('.').collect()
    } else {
        let mut parts = Vec::new();
        let mut start = 0;
        for (i, c) in value.char_indices() {
            if delimiters.contains(c) {
                parts.push(&value[start..i]);
                start = i + c.len_utf8();
            }
        }
        parts.push(&value[start..]);
        parts
    };

    let mut parts: Vec<&str> = parts;

    // Reverse if flag set
    if reverse {
        parts.reverse();
    }

    // Truncate to rightmost N parts (0 means all)
    if digits > 0 && (digits as usize) < parts.len() {
        let skip = parts.len() - digits as usize;
        parts = parts[skip..].to_vec();
    }

    parts.join(".")
}

/// URL-encode a string per RFC 3986.
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> MacroContext {
        MacroContext {
            sender: "user@example.com".to_string(),
            local_part: "user".to_string(),
            sender_domain: "example.com".to_string(),
            client_ip: "192.0.2.1".parse().unwrap(),
            helo: "mail.example.com".to_string(),
            domain: "example.com".to_string(),
            receiver: "receiver.example.com".to_string(),
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
    }

    #[test]
    fn test_ip_v4() {
        let ctx = test_ctx();
        assert_eq!(expand("%{i}", &ctx, false).unwrap(), "192.0.2.1");
    }

    #[test]
    fn test_ip_v6_nibbles() {
        let mut ctx = test_ctx();
        ctx.client_ip = "2001:db8::1".parse().unwrap();
        let expanded = expand("%{i}", &ctx, false).unwrap();
        assert_eq!(
            expanded,
            "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1"
        );
    }

    #[test]
    fn test_v_macro() {
        let ctx = test_ctx();
        assert_eq!(expand("%{v}", &ctx, false).unwrap(), "in-addr");
        let mut ctx6 = test_ctx();
        ctx6.client_ip = "::1".parse().unwrap();
        assert_eq!(expand("%{v}", &ctx6, false).unwrap(), "ip6");
    }

    #[test]
    fn test_reverse_ip() {
        let ctx = test_ctx();
        assert_eq!(expand("%{ir}", &ctx, false).unwrap(), "1.2.0.192");
    }

    #[test]
    fn test_rightmost_labels() {
        let ctx = test_ctx();
        assert_eq!(expand("%{d2}", &ctx, false).unwrap(), "example.com");
        assert_eq!(expand("%{d1}", &ctx, false).unwrap(), "com");
    }

    #[test]
    fn test_d0_means_all() {
        let ctx = test_ctx();
        assert_eq!(expand("%{d0}", &ctx, false).unwrap(), "example.com");
    }

    #[test]
    fn test_url_encoding_uppercase() {
        let ctx = test_ctx();
        assert_eq!(
            expand("%{S}", &ctx, false).unwrap(),
            "user%40example.com"
        );
    }

    #[test]
    fn test_escapes() {
        let ctx = test_ctx();
        assert_eq!(expand("%%", &ctx, false).unwrap(), "%");
        assert_eq!(expand("%_", &ctx, false).unwrap(), " ");
        assert_eq!(expand("%-", &ctx, false).unwrap(), "%20");
    }

    #[test]
    fn test_exp_only_macros_rejected_outside_exp() {
        let ctx = test_ctx();
        assert!(expand("%{c}", &ctx, false).is_err());
        assert!(expand("%{r}", &ctx, false).is_err());
        assert!(expand("%{t}", &ctx, false).is_err());
    }

    #[test]
    fn test_exp_only_macros_accepted_in_exp() {
        let ctx = test_ctx();
        assert!(expand("%{c}", &ctx, true).is_ok());
        assert!(expand("%{r}", &ctx, true).is_ok());
        assert!(expand("%{t}", &ctx, true).is_ok());
    }

    #[test]
    fn test_hyphen_delimiter() {
        let mut ctx = test_ctx();
        ctx.local_part = "user-name-test".to_string();
        assert_eq!(expand("%{l-}", &ctx, false).unwrap(), "user.name.test");
    }

    #[test]
    fn test_reversed_first_label() {
        let ctx = test_ctx();
        // %{d1r} = reverse the labels of domain, take rightmost 1
        // domain = example.com -> split: [example, com] -> reverse: [com, example] -> take 1: [example]
        assert_eq!(expand("%{d1r}", &ctx, false).unwrap(), "example");
    }

    #[test]
    fn test_helo() {
        let ctx = test_ctx();
        assert_eq!(expand("%{h}", &ctx, false).unwrap(), "mail.example.com");
    }

    #[test]
    fn test_p_macro() {
        let ctx = test_ctx();
        assert_eq!(expand("%{p}", &ctx, false).unwrap(), "unknown");
    }
}
