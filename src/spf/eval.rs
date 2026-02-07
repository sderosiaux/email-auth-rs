use crate::common::dns::{DnsError, DnsResolver};
use super::macro_exp::{expand, MacroContext};
use super::mechanism::{Directive, Mechanism, Qualifier};
use super::record::SpfRecord;
use super::SpfResult;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::future::Future;

/// Shared mutable state across recursive SPF evaluation.
struct EvalContext {
    dns_lookups: usize,
    void_lookups: usize,
    visited_domains: HashSet<String>,
}

impl EvalContext {
    fn new() -> Self {
        Self {
            dns_lookups: 0,
            void_lookups: 0,
            visited_domains: HashSet::new(),
        }
    }

    /// Increment DNS lookup counter. Returns PermError if limit exceeded.
    fn increment_dns(&mut self) -> Result<(), SpfResult> {
        self.dns_lookups += 1;
        if self.dns_lookups > 10 {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }

    /// Increment void lookup counter. Returns PermError if limit exceeded.
    fn increment_void(&mut self) -> Result<(), SpfResult> {
        self.void_lookups += 1;
        if self.void_lookups > 2 {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }

    /// Check and mark domain as visited for cycle detection.
    fn visit_domain(&mut self, domain: &str) -> Result<(), SpfResult> {
        let normalized = domain.to_ascii_lowercase();
        if self.visited_domains.contains(&normalized) {
            return Err(SpfResult::PermError);
        }
        self.visited_domains.insert(normalized);
        Ok(())
    }
}

/// Public SPF check_host entry point (RFC 7208 Section 4).
pub async fn check_host<R: DnsResolver>(
    resolver: &R,
    ip: IpAddr,
    helo: &str,
    sender: &str,
    domain: &str,
    receiver: &str,
) -> SpfResult {
    // Empty or missing MAIL FROM: use postmaster@helo
    let (effective_sender, local_part, sender_domain) = if sender.is_empty()
        || !sender.contains('@')
    {
        let s = format!("postmaster@{helo}");
        (s.clone(), "postmaster".to_string(), helo.to_string())
    } else {
        let lp = crate::common::domain::local_part_from_email(sender).to_string();
        let sd = crate::common::domain::domain_from_email(sender)
            .unwrap_or(helo)
            .to_string();
        (sender.to_string(), lp, sd)
    };

    let mut ctx = EvalContext::new();
    check_host_inner(
        resolver,
        ip,
        helo,
        &effective_sender,
        &local_part,
        &sender_domain,
        domain,
        receiver,
        &mut ctx,
    )
    .await
}

fn check_host_inner<'a, R: DnsResolver + 'a>(
    resolver: &'a R,
    ip: IpAddr,
    helo: &'a str,
    sender: &'a str,
    local_part: &'a str,
    sender_domain: &'a str,
    domain: &'a str,
    receiver: &'a str,
    ctx: &'a mut EvalContext,
) -> Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>> {
    Box::pin(async move {
        // Query TXT records
        let txt_records = match resolver.query_txt(domain).await {
            Ok(records) => records,
            Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => return SpfResult::None,
            Err(DnsError::TempFail) => return SpfResult::TempError,
        };

        // Filter SPF records
        let spf_records: Vec<&String> = txt_records
            .iter()
            .filter(|r| {
                let lower = r.to_ascii_lowercase();
                lower == "v=spf1" || lower.starts_with("v=spf1 ")
            })
            .collect();

        match spf_records.len() {
            0 => return SpfResult::None,
            1 => {}
            _ => return SpfResult::PermError, // Multiple SPF records
        }

        let record = match SpfRecord::parse(spf_records[0]) {
            Ok(r) => r,
            Err(_) => return SpfResult::PermError,
        };

        let macro_ctx = MacroContext {
            sender,
            local_part,
            sender_domain,
            client_ip: ip,
            helo,
            domain,
            receiver,
        };

        // Evaluate directives left-to-right
        for directive in &record.directives {
            match eval_directive(resolver, &directive, ip, domain, &macro_ctx, ctx).await {
                DirectiveResult::Match(qualifier) => {
                    let result = qualifier_to_result(qualifier);
                    // If Fail and record has exp=, evaluate explanation
                    if let SpfResult::Fail { .. } = &result {
                        if let Some(ref exp_domain) = record.explanation {
                            let explanation =
                                eval_explanation(resolver, exp_domain, &macro_ctx).await;
                            return SpfResult::Fail { explanation };
                        }
                    }
                    return result;
                }
                DirectiveResult::NoMatch => continue,
                DirectiveResult::Error(e) => return e,
            }
        }

        // No directive matched. Check redirect.
        if let Some(ref redirect_domain) = record.redirect {
            ctx.increment_dns().map_err(|e| e).ok();
            if ctx.dns_lookups > 10 {
                return SpfResult::PermError;
            }

            let expanded = match expand(redirect_domain, &macro_ctx, false) {
                Ok(d) => d,
                Err(_) => return SpfResult::PermError,
            };

            if expanded.is_empty() {
                return SpfResult::PermError;
            }

            if let Err(e) = ctx.visit_domain(&expanded) {
                return e;
            }

            let result = check_host_inner(
                resolver,
                ip,
                helo,
                sender,
                local_part,
                sender_domain,
                &expanded,
                receiver,
                ctx,
            )
            .await;

            // Redirect target returning None → PermError
            if result == SpfResult::None {
                return SpfResult::PermError;
            }
            return result;
        }

        // No match, no redirect → Neutral
        SpfResult::Neutral
    })
}

enum DirectiveResult {
    Match(Qualifier),
    NoMatch,
    Error(SpfResult),
}

async fn eval_directive<R: DnsResolver>(
    resolver: &R,
    directive: &Directive,
    ip: IpAddr,
    current_domain: &str,
    macro_ctx: &MacroContext<'_>,
    ctx: &mut EvalContext,
) -> DirectiveResult {
    let matched = match &directive.mechanism {
        Mechanism::All => true,

        Mechanism::Include { domain } => {
            if let Err(e) = ctx.increment_dns() {
                return DirectiveResult::Error(e);
            }
            let expanded = match expand(domain, macro_ctx, false) {
                Ok(d) => d,
                Err(_) => return DirectiveResult::Error(SpfResult::PermError),
            };
            if let Err(e) = ctx.visit_domain(&expanded) {
                return DirectiveResult::Error(e);
            }

            // Recursive check_host
            let child_result = check_host_inner(
                resolver,
                ip,
                macro_ctx.helo,
                macro_ctx.sender,
                macro_ctx.local_part,
                macro_ctx.sender_domain,
                &expanded,
                macro_ctx.receiver,
                ctx,
            )
            .await;

            // Remove domain from visited so it can be used in other branches
            ctx.visited_domains
                .remove(&expanded.to_ascii_lowercase());

            match child_result {
                SpfResult::Pass => true,
                SpfResult::TempError => return DirectiveResult::Error(SpfResult::TempError),
                SpfResult::PermError => return DirectiveResult::Error(SpfResult::PermError),
                _ => false, // Fail, SoftFail, Neutral, None → no match
            }
        }

        Mechanism::A {
            domain,
            cidr4,
            cidr6,
        } => {
            if let Err(e) = ctx.increment_dns() {
                return DirectiveResult::Error(e);
            }
            let target = resolve_domain(domain.as_deref(), current_domain, macro_ctx);
            match eval_a_mechanism(resolver, &target, ip, *cidr4, *cidr6, ctx).await {
                Ok(matched) => matched,
                Err(e) => return DirectiveResult::Error(e),
            }
        }

        Mechanism::Mx {
            domain,
            cidr4,
            cidr6,
        } => {
            if let Err(e) = ctx.increment_dns() {
                return DirectiveResult::Error(e);
            }
            let target = resolve_domain(domain.as_deref(), current_domain, macro_ctx);
            match eval_mx_mechanism(resolver, &target, ip, *cidr4, *cidr6, ctx).await {
                Ok(matched) => matched,
                Err(e) => return DirectiveResult::Error(e),
            }
        }

        Mechanism::Ptr { domain } => {
            if let Err(e) = ctx.increment_dns() {
                return DirectiveResult::Error(e);
            }
            let target = domain
                .as_deref()
                .unwrap_or(current_domain)
                .to_string();
            match eval_ptr_mechanism(resolver, &target, ip, ctx).await {
                Ok(matched) => matched,
                Err(e) => return DirectiveResult::Error(e),
            }
        }

        Mechanism::Ip4 { addr, prefix } => {
            if let IpAddr::V4(client) = ip {
                let pfx = prefix.unwrap_or(32);
                ip4_in_network(client, *addr, pfx)
            } else {
                false // IPv6 client never matches ip4
            }
        }

        Mechanism::Ip6 { addr, prefix } => {
            if let IpAddr::V6(client) = ip {
                let pfx = prefix.unwrap_or(128);
                ip6_in_network(client, *addr, pfx)
            } else {
                false // IPv4 client never matches ip6
            }
        }

        Mechanism::Exists { domain } => {
            if let Err(e) = ctx.increment_dns() {
                return DirectiveResult::Error(e);
            }
            let expanded = match expand(domain, macro_ctx, false) {
                Ok(d) => d,
                Err(_) => return DirectiveResult::Error(SpfResult::PermError),
            };
            match resolver.query_exists(&expanded).await {
                Ok(exists) => exists,
                Err(DnsError::TempFail) => {
                    return DirectiveResult::Error(SpfResult::TempError)
                }
                Err(_) => false,
            }
        }
    };

    if matched {
        DirectiveResult::Match(directive.qualifier)
    } else {
        DirectiveResult::NoMatch
    }
}

fn resolve_domain(
    explicit: Option<&str>,
    current: &str,
    macro_ctx: &MacroContext,
) -> String {
    match explicit {
        Some(d) => expand(d, macro_ctx, false).unwrap_or_else(|_| current.to_string()),
        None => current.to_string(),
    }
}

async fn eval_a_mechanism<R: DnsResolver>(
    resolver: &R,
    domain: &str,
    ip: IpAddr,
    cidr4: Option<u8>,
    cidr6: Option<u8>,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    match ip {
        IpAddr::V4(client) => {
            let pfx = cidr4.unwrap_or(32);
            match resolver.query_a(domain).await {
                Ok(addrs) => Ok(addrs.iter().any(|a| ip4_in_network(client, *a, pfx))),
                Err(DnsError::NxDomain) => {
                    ctx.increment_void()?;
                    Ok(false)
                }
                Err(DnsError::NoRecords) => {
                    ctx.increment_void()?;
                    Ok(false)
                }
                Err(DnsError::TempFail) => Err(SpfResult::TempError),
            }
        }
        IpAddr::V6(client) => {
            let pfx = cidr6.unwrap_or(128);
            match resolver.query_aaaa(domain).await {
                Ok(addrs) => Ok(addrs.iter().any(|a| ip6_in_network(client, *a, pfx))),
                Err(DnsError::NxDomain) => {
                    ctx.increment_void()?;
                    Ok(false)
                }
                Err(DnsError::NoRecords) => {
                    ctx.increment_void()?;
                    Ok(false)
                }
                Err(DnsError::TempFail) => Err(SpfResult::TempError),
            }
        }
    }
}

async fn eval_mx_mechanism<R: DnsResolver>(
    resolver: &R,
    domain: &str,
    ip: IpAddr,
    cidr4: Option<u8>,
    cidr6: Option<u8>,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    let mut mx_records = match resolver.query_mx(domain).await {
        Ok(records) => records,
        Err(DnsError::NxDomain) => {
            ctx.increment_void()?;
            return Ok(false);
        }
        Err(DnsError::NoRecords) => return Ok(false),
        Err(DnsError::TempFail) => return Err(SpfResult::TempError),
    };

    mx_records.sort_by_key(|r| r.preference);
    let mx_records: Vec<_> = mx_records.into_iter().take(10).collect();

    for mx in &mx_records {
        match ip {
            IpAddr::V4(client) => {
                let pfx = cidr4.unwrap_or(32);
                if let Ok(addrs) = resolver.query_a(&mx.exchange).await {
                    if addrs.iter().any(|a| ip4_in_network(client, *a, pfx)) {
                        return Ok(true);
                    }
                }
            }
            IpAddr::V6(client) => {
                let pfx = cidr6.unwrap_or(128);
                if let Ok(addrs) = resolver.query_aaaa(&mx.exchange).await {
                    if addrs.iter().any(|a| ip6_in_network(client, *a, pfx)) {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

async fn eval_ptr_mechanism<R: DnsResolver>(
    resolver: &R,
    target_domain: &str,
    ip: IpAddr,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    let hostnames = match resolver.query_ptr(ip).await {
        Ok(names) => names,
        Err(DnsError::NxDomain) => {
            ctx.increment_void()?;
            return Ok(false);
        }
        Err(DnsError::NoRecords) => return Ok(false),
        Err(DnsError::TempFail) => return Err(SpfResult::TempError),
    };

    // Limit to 10 PTR names
    for hostname in hostnames.iter().take(10) {
        // Forward lookup to validate
        let confirmed = match ip {
            IpAddr::V4(v4) => resolver
                .query_a(hostname)
                .await
                .map(|addrs| addrs.contains(&v4))
                .unwrap_or(false),
            IpAddr::V6(v6) => resolver
                .query_aaaa(hostname)
                .await
                .map(|addrs| addrs.contains(&v6))
                .unwrap_or(false),
        };

        if confirmed {
            let h_lower = hostname.to_ascii_lowercase();
            let t_lower = target_domain.to_ascii_lowercase();
            if h_lower == t_lower || h_lower.ends_with(&format!(".{t_lower}")) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

async fn eval_explanation<R: DnsResolver>(
    resolver: &R,
    exp_domain: &str,
    macro_ctx: &MacroContext<'_>,
) -> Option<String> {
    let expanded_domain = expand(exp_domain, macro_ctx, false).ok()?;
    let txt_records = resolver.query_txt(&expanded_domain).await.ok()?;
    let txt = txt_records.first()?;
    // Expand macros in explanation TXT (allowing exp-only macros c, r, t)
    expand(txt, macro_ctx, true).ok()
}

fn qualifier_to_result(q: Qualifier) -> SpfResult {
    match q {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail { explanation: None },
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

fn ip4_in_network(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = !0u32 << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ip6_in_network(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let mask = !0u128 << (128 - prefix);
    (u128::from(ip) & mask) == (u128::from(network) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::MockResolver;

    fn resolver_basic() -> MockResolver {
        MockResolver::new()
            .with_txt(
                "example.com",
                vec!["v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 include:_spf.example.com -all"],
            )
            .with_txt("_spf.example.com", vec!["v=spf1 ip4:203.0.113.0/24 ~all"])
            .with_txt("redirect.example.com", vec!["v=spf1 redirect=example.com"])
            .with_txt(
                "loop.example.com",
                vec!["v=spf1 include:loop2.example.com -all"],
            )
            .with_txt(
                "loop2.example.com",
                vec!["v=spf1 include:loop.example.com -all"],
            )
            .with_txt(
                "exp.example.com",
                vec!["v=spf1 -all exp=explain.example.com"],
            )
            .with_txt(
                "explain.example.com",
                vec!["Access denied for %{i} sending from %{d}"],
            )
            .with_txt(
                "multi-spf.example.com",
                vec!["v=spf1 +all", "v=spf1 -all"],
            )
            .with_nxdomain("nonexistent.example.com")
            .with_a("example.com", vec!["192.0.2.1".parse().unwrap()])
            .with_aaaa("example.com", vec!["2001:db8::1".parse().unwrap()])
            .with_mx(
                "example.com",
                vec![crate::common::MxRecord {
                    preference: 10,
                    exchange: "mx1.example.com".into(),
                }],
            )
            .with_a("mx1.example.com", vec!["192.0.2.10".parse().unwrap()])
            .with_ptr(
                "192.0.2.1",
                vec!["mail.example.com"],
            )
            .with_a("mail.example.com", vec!["192.0.2.1".parse().unwrap()])
    }

    #[tokio::test]
    async fn test_simple_pass() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "192.0.2.1".parse().unwrap(),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "receiver.example.com",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_simple_fail() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "receiver.example.com",
        )
        .await;
        assert!(matches!(result, SpfResult::Fail { .. }));
    }

    #[tokio::test]
    async fn test_include_pass() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "203.0.113.1".parse().unwrap(),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "receiver.example.com",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_include_child_none() {
        // include child returning None → no match in parent
        let r = MockResolver::new()
            .with_txt("parent.com", vec!["v=spf1 include:nospf.com -all"])
            .with_nxdomain("nospf.com");
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@parent.com",
            "parent.com",
            "r",
        )
        .await;
        assert!(matches!(result, SpfResult::Fail { .. }));
    }

    #[tokio::test]
    async fn test_include_child_temperror() {
        let r = MockResolver::new()
            .with_txt("parent.com", vec!["v=spf1 include:temp.com -all"])
            .with_txt_err("temp.com", DnsError::TempFail);
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@parent.com",
            "parent.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::TempError);
    }

    #[tokio::test]
    async fn test_redirect() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "192.0.2.1".parse().unwrap(),
            "mail.example.com",
            "user@redirect.example.com",
            "redirect.example.com",
            "receiver.example.com",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_redirect_to_no_spf() {
        let r = MockResolver::new()
            .with_txt("redir.com", vec!["v=spf1 redirect=nospf.com"])
            .with_nxdomain("nospf.com");
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@redir.com",
            "redir.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::PermError);
    }

    #[tokio::test]
    async fn test_circular_include() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail.example.com",
            "user@loop.example.com",
            "loop.example.com",
            "receiver.example.com",
        )
        .await;
        assert_eq!(result, SpfResult::PermError);
    }

    #[tokio::test]
    async fn test_no_spf_record() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@nonexistent.example.com",
            "nonexistent.example.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::None);
    }

    #[tokio::test]
    async fn test_multiple_spf_records() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@multi-spf.example.com",
            "multi-spf.example.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::PermError);
    }

    #[tokio::test]
    async fn test_exp_explanation() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail.example.com",
            "user@exp.example.com",
            "exp.example.com",
            "receiver.example.com",
        )
        .await;
        if let SpfResult::Fail { explanation } = result {
            let exp = explanation.unwrap();
            assert!(exp.contains("10.0.0.1"));
            assert!(exp.contains("exp.example.com"));
        } else {
            panic!("expected Fail with explanation, got: {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_dns_lookup_limit() {
        // Build a chain of 11 includes
        let mut r = MockResolver::new();
        r.txt.insert(
            "start.com".into(),
            Ok(vec!["v=spf1 include:chain1.com -all".into()]),
        );
        for i in 1..=11 {
            let domain = format!("chain{i}.com");
            let next = format!("chain{}.com", i + 1);
            r.txt.insert(
                domain,
                Ok(vec![format!("v=spf1 include:{next} -all")]),
            );
        }
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@start.com",
            "start.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::PermError);
    }

    #[tokio::test]
    async fn test_void_lookup_limit() {
        let r = MockResolver::new().with_txt(
            "void.com",
            vec!["v=spf1 a:nx1.void.com a:nx2.void.com a:nx3.void.com -all"],
        )
        .with_a_err("nx1.void.com", DnsError::NxDomain)
        .with_a_err("nx2.void.com", DnsError::NxDomain)
        .with_a_err("nx3.void.com", DnsError::NxDomain);
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@void.com",
            "void.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::PermError);
    }

    #[tokio::test]
    async fn test_empty_mail_from() {
        let r = MockResolver::new()
            .with_txt("helo.com", vec!["v=spf1 ip4:10.0.0.1 -all"]);
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "helo.com",
            "",
            "helo.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_ipv6_with_ip6_mechanism() {
        let r = MockResolver::new()
            .with_txt("v6.com", vec!["v=spf1 ip6:2001:db8::/32 -all"]);
        let result = check_host(
            &r,
            "2001:db8::1".parse().unwrap(),
            "mail",
            "user@v6.com",
            "v6.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_ipv4_skips_ip6() {
        let r = MockResolver::new()
            .with_txt("v6only.com", vec!["v=spf1 ip6:2001:db8::/32 -all"]);
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@v6only.com",
            "v6only.com",
            "r",
        )
        .await;
        assert!(matches!(result, SpfResult::Fail { .. }));
    }

    #[tokio::test]
    async fn test_mx_mechanism() {
        let r = resolver_basic();
        let result = check_host(
            &r,
            "192.0.2.10".parse().unwrap(),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "receiver.example.com",
        )
        .await;
        // 192.0.2.10 matches the ip4 range 192.0.2.0/24
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_a_mechanism_with_cidr() {
        let r = MockResolver::new()
            .with_txt("atest.com", vec!["v=spf1 a:atest.com/24 -all"])
            .with_a("atest.com", vec!["192.168.1.1".parse().unwrap()]);
        let result = check_host(
            &r,
            "192.168.1.100".parse().unwrap(),
            "mail",
            "user@atest.com",
            "atest.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_exists_mechanism() {
        let r = MockResolver::new()
            .with_txt("ex.com", vec!["v=spf1 exists:%{ir}.sbl.ex.com -all"])
            .with_a("1.0.0.10.sbl.ex.com", vec!["127.0.0.2".parse().unwrap()]);
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@ex.com",
            "ex.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_ptr_mechanism() {
        let r = resolver_basic();
        // ptr:example.com — check if 192.0.2.1 PTR validates to subdomain of example.com
        let r = r.with_txt("ptrtest.com", vec!["v=spf1 ptr:example.com -all"]);
        let result = check_host(
            &r,
            "192.0.2.1".parse().unwrap(),
            "mail",
            "user@ptrtest.com",
            "ptrtest.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn test_dns_tempfail() {
        let r = MockResolver::new()
            .with_txt_err("tempfail.com", DnsError::TempFail);
        let result = check_host(
            &r,
            "10.0.0.1".parse().unwrap(),
            "mail",
            "user@tempfail.com",
            "tempfail.com",
            "r",
        )
        .await;
        assert_eq!(result, SpfResult::TempError);
    }

    #[test]
    fn test_cidr_matching() {
        assert!(ip4_in_network(
            "192.168.1.100".parse().unwrap(),
            "192.168.1.0".parse().unwrap(),
            24
        ));
        assert!(!ip4_in_network(
            "192.168.2.1".parse().unwrap(),
            "192.168.1.0".parse().unwrap(),
            24
        ));
        assert!(ip4_in_network(
            "10.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            0
        ));

        assert!(ip6_in_network(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32
        ));
        assert!(!ip6_in_network(
            "2001:db9::1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32
        ));
    }
}
