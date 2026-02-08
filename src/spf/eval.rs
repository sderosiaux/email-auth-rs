use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use crate::common::cidr::{ip4_in_network, ip6_in_network};
use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain;

use super::lookup::lookup_spf;
use super::macros::{self, MacroContext};
use super::types::{Directive, Mechanism, Qualifier, SpfResult};

/// Shared mutable evaluation context for DNS/void limit tracking and cycle detection.
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

    /// Increment DNS lookup counter. Returns PermError if limit (10) exceeded.
    fn increment_dns(&mut self) -> Result<(), SpfResult> {
        self.dns_lookups += 1;
        if self.dns_lookups > 10 {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }

    /// Increment void lookup counter. Returns PermError if limit (2) exceeded.
    fn increment_void(&mut self) -> Result<(), SpfResult> {
        self.void_lookups += 1;
        if self.void_lookups > 2 {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }

    /// Check and add domain to visited set. Returns PermError if cycle detected.
    fn check_visited(&mut self, domain: &str) -> Result<(), SpfResult> {
        let normalized = domain::normalize(domain);
        if !self.visited_domains.insert(normalized) {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }
}

/// Public SPF check_host entry point (RFC 7208 Section 4).
///
/// DNS caching is the caller's responsibility.
pub async fn check_host<R: DnsResolver + Send + Sync>(
    resolver: &R,
    ip: IpAddr,
    helo: &str,
    sender: &str,
    domain: &str,
    receiver: &str,
) -> SpfResult {
    // Input handling: empty or no-@ MAIL FROM → postmaster@helo
    let effective_sender = if sender.is_empty() || !sender.contains('@') {
        format!("postmaster@{}", helo)
    } else {
        sender.to_string()
    };

    let local_part = domain::local_part_from_email(&effective_sender).to_string();
    let sender_domain = domain::domain_from_email(&effective_sender)
        .unwrap_or(helo)
        .to_string();

    let macro_ctx = MacroContext {
        sender: effective_sender,
        local_part,
        sender_domain,
        client_ip: ip,
        helo: helo.to_string(),
        domain: domain.to_string(),
        receiver: receiver.to_string(),
    };

    let mut ctx = EvalContext::new();
    // Add initial domain to visited set
    let _ = ctx.check_visited(domain);

    check_host_inner(resolver, ip, domain, &macro_ctx, &mut ctx).await
}

/// Inner recursive evaluation. Uses Pin<Box> for async recursion.
fn check_host_inner<'a, R: DnsResolver + Send + Sync + 'a>(
    resolver: &'a R,
    ip: IpAddr,
    domain: &'a str,
    macro_ctx: &'a MacroContext,
    ctx: &'a mut EvalContext,
) -> Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>> {
    Box::pin(async move {
        // Look up SPF record
        let record = match lookup_spf(resolver, domain).await {
            Ok(r) => r,
            Err(result) => return result,
        };

        // Build macro context with current domain
        let mut local_ctx = macro_ctx.clone();
        local_ctx.domain = domain.to_string();

        // Evaluate directives left-to-right
        for directive in &record.directives {
            match eval_directive(resolver, ip, directive, &local_ctx, ctx).await {
                Ok(true) => {
                    let result = qualifier_to_result(directive.qualifier);
                    // If Fail with exp=, fetch explanation
                    if let SpfResult::Fail { .. } = &result {
                        if let Some(ref exp_domain) = record.explanation {
                            let explanation = fetch_explanation(
                                resolver, exp_domain, &local_ctx,
                            ).await;
                            return SpfResult::Fail { explanation };
                        }
                    }
                    return result;
                }
                Ok(false) => continue,
                Err(result) => return result,
            }
        }

        // No directive matched
        if let Some(ref redirect_domain) = record.redirect {
            return eval_redirect(resolver, ip, redirect_domain, &local_ctx, ctx).await;
        }

        SpfResult::Neutral
    })
}

/// Evaluate a single directive. Returns Ok(true) for match, Ok(false) for no match,
/// Err(SpfResult) for terminal error.
async fn eval_directive<R: DnsResolver + Send + Sync>(
    resolver: &R,
    ip: IpAddr,
    directive: &Directive,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    match &directive.mechanism {
        Mechanism::All => Ok(true),
        Mechanism::Include { domain } => {
            eval_include(resolver, ip, domain, macro_ctx, ctx).await
        }
        Mechanism::A { domain, cidr4, cidr6 } => {
            eval_a(resolver, ip, domain.as_deref(), *cidr4, *cidr6, macro_ctx, ctx).await
        }
        Mechanism::Mx { domain, cidr4, cidr6 } => {
            eval_mx(resolver, ip, domain.as_deref(), *cidr4, *cidr6, macro_ctx, ctx).await
        }
        Mechanism::Ptr { domain } => {
            eval_ptr(resolver, ip, domain.as_deref(), macro_ctx, ctx).await
        }
        Mechanism::Ip4 { addr, prefix } => {
            let prefix = prefix.unwrap_or(32);
            match ip {
                IpAddr::V4(client) => Ok(ip4_in_network(client, *addr, prefix)),
                IpAddr::V6(_) => Ok(false), // cross-family: never matches
            }
        }
        Mechanism::Ip6 { addr, prefix } => {
            let prefix = prefix.unwrap_or(128);
            match ip {
                IpAddr::V6(client) => Ok(ip6_in_network(client, *addr, prefix)),
                IpAddr::V4(_) => Ok(false), // cross-family: never matches
            }
        }
        Mechanism::Exists { domain } => {
            eval_exists(resolver, domain, macro_ctx, ctx).await
        }
    }
}

/// Evaluate `include:<domain>` mechanism.
async fn eval_include<R: DnsResolver + Send + Sync>(
    resolver: &R,
    ip: IpAddr,
    domain_spec: &str,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let expanded = macros::expand(domain_spec, macro_ctx, false)
        .map_err(|_| SpfResult::PermError)?;

    ctx.check_visited(&expanded)?;

    let child_result = check_host_inner(resolver, ip, &expanded, macro_ctx, ctx).await;

    match child_result {
        SpfResult::Pass => Ok(true),
        SpfResult::Fail { .. } | SpfResult::SoftFail | SpfResult::Neutral | SpfResult::None => {
            Ok(false)
        }
        SpfResult::TempError => Err(SpfResult::TempError),
        SpfResult::PermError => Err(SpfResult::PermError),
    }
}

/// Evaluate `a` / `a:<domain>` mechanism.
async fn eval_a<R: DnsResolver + Send + Sync>(
    resolver: &R,
    ip: IpAddr,
    domain_spec: Option<&str>,
    cidr4: Option<u8>,
    cidr6: Option<u8>,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let target = match domain_spec {
        Some(d) => macros::expand(d, macro_ctx, false).map_err(|_| SpfResult::PermError)?,
        None => macro_ctx.domain.clone(),
    };

    match ip {
        IpAddr::V4(client_v4) => {
            let prefix = cidr4.unwrap_or(32);
            match resolver.query_a(&target).await {
                Ok(addrs) => {
                    Ok(addrs.iter().any(|a| ip4_in_network(client_v4, *a, prefix)))
                }
                Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                    ctx.increment_void()?;
                    Ok(false)
                }
                Err(DnsError::TempFail) => Err(SpfResult::TempError),
            }
        }
        IpAddr::V6(client_v6) => {
            let prefix = cidr6.unwrap_or(128);
            match resolver.query_aaaa(&target).await {
                Ok(addrs) => {
                    Ok(addrs.iter().any(|a| ip6_in_network(client_v6, *a, prefix)))
                }
                Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
                    ctx.increment_void()?;
                    Ok(false)
                }
                Err(DnsError::TempFail) => Err(SpfResult::TempError),
            }
        }
    }
}

/// Evaluate `mx` / `mx:<domain>` mechanism.
async fn eval_mx<R: DnsResolver + Send + Sync>(
    resolver: &R,
    ip: IpAddr,
    domain_spec: Option<&str>,
    cidr4: Option<u8>,
    cidr6: Option<u8>,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let target = match domain_spec {
        Some(d) => macros::expand(d, macro_ctx, false).map_err(|_| SpfResult::PermError)?,
        None => macro_ctx.domain.clone(),
    };

    let mut mx_records = match resolver.query_mx(&target).await {
        Ok(records) => records,
        Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
            ctx.increment_void()?;
            return Ok(false);
        }
        Err(DnsError::TempFail) => return Err(SpfResult::TempError),
    };

    // Sort by preference, limit to 10
    mx_records.sort_by_key(|mx| mx.preference);
    mx_records.truncate(10);

    for mx in &mx_records {
        match ip {
            IpAddr::V4(client_v4) => {
                let prefix = cidr4.unwrap_or(32);
                if let Ok(addrs) = resolver.query_a(&mx.exchange).await {
                    if addrs.iter().any(|a| ip4_in_network(client_v4, *a, prefix)) {
                        return Ok(true);
                    }
                }
                // DNS errors on individual MX hosts: skip
            }
            IpAddr::V6(client_v6) => {
                let prefix = cidr6.unwrap_or(128);
                if let Ok(addrs) = resolver.query_aaaa(&mx.exchange).await {
                    if addrs.iter().any(|a| ip6_in_network(client_v6, *a, prefix)) {
                        return Ok(true);
                    }
                }
                // DNS errors on individual MX hosts: skip
            }
        }
    }

    Ok(false)
}

/// Evaluate `ptr` / `ptr:<domain>` mechanism.
async fn eval_ptr<R: DnsResolver + Send + Sync>(
    resolver: &R,
    ip: IpAddr,
    domain_spec: Option<&str>,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let target = match domain_spec {
        Some(d) => macros::expand(d, macro_ctx, false).map_err(|_| SpfResult::PermError)?,
        None => macro_ctx.domain.clone(),
    };

    // Reverse lookup
    let ptr_names = match resolver.query_ptr(&ip).await {
        Ok(names) => names,
        Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => {
            ctx.increment_void()?;
            return Ok(false);
        }
        Err(DnsError::TempFail) => return Err(SpfResult::TempError),
    };

    // Limit to 10 PTR names
    let ptr_names: Vec<&str> = ptr_names.iter().map(|s| s.as_str()).take(10).collect();

    for name in ptr_names {
        // Forward confirm: look up the PTR name and check if our IP is in the results
        let confirmed = match ip {
            IpAddr::V4(v4) => {
                resolver.query_a(name).await
                    .map(|addrs| addrs.contains(&v4))
                    .unwrap_or(false)
            }
            IpAddr::V6(v6) => {
                resolver.query_aaaa(name).await
                    .map(|addrs| addrs.contains(&v6))
                    .unwrap_or(false)
            }
        };

        if confirmed {
            // Check if validated hostname matches target domain
            let name_lower = name.to_ascii_lowercase();
            let target_lower = target.to_ascii_lowercase();
            if name_lower == target_lower || domain::is_subdomain_of(&name_lower, &target_lower) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Evaluate `exists:<domain>` mechanism.
async fn eval_exists<R: DnsResolver + Send + Sync>(
    resolver: &R,
    domain_spec: &str,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let expanded = macros::expand(domain_spec, macro_ctx, false)
        .map_err(|_| SpfResult::PermError)?;

    match resolver.query_a(&expanded).await {
        Ok(addrs) => Ok(!addrs.is_empty()),
        Err(DnsError::NxDomain) | Err(DnsError::NoRecords) => Ok(false),
        Err(DnsError::TempFail) => Err(SpfResult::TempError),
    }
}

/// Evaluate `redirect=<domain>` modifier.
async fn eval_redirect<R: DnsResolver + Send + Sync>(
    resolver: &R,
    ip: IpAddr,
    domain_spec: &str,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> SpfResult {
    if let Err(e) = ctx.increment_dns() {
        return e;
    }

    let expanded = match macros::expand(domain_spec, macro_ctx, false) {
        Ok(d) => d,
        Err(_) => return SpfResult::PermError,
    };

    if expanded.is_empty() {
        return SpfResult::PermError;
    }

    if let Err(e) = ctx.check_visited(&expanded) {
        return e;
    }

    let result = check_host_inner(resolver, ip, &expanded, macro_ctx, ctx).await;

    // Redirect target returning None → PermError
    match result {
        SpfResult::None => SpfResult::PermError,
        other => other,
    }
}

/// Fetch explanation for exp= modifier. Returns None on any failure.
async fn fetch_explanation<R: DnsResolver + Send + Sync>(
    resolver: &R,
    exp_domain: &str,
    macro_ctx: &MacroContext,
) -> Option<String> {
    let expanded_domain = macros::expand(exp_domain, macro_ctx, false).ok()?;
    let txt_records = resolver.query_txt(&expanded_domain).await.ok()?;
    let txt = txt_records.into_iter().next()?;
    macros::expand(&txt, macro_ctx, true).ok()
}

/// Map a qualifier to its corresponding SpfResult.
fn qualifier_to_result(q: Qualifier) -> SpfResult {
    match q {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail { explanation: None },
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;
    use crate::common::dns::MxRecord;

    fn setup_resolver_with_spf(domain: &str, spf: &str) -> MockResolver {
        let mut resolver = MockResolver::new();
        resolver.add_txt(domain, vec![spf.to_string()]);
        resolver
    }

    // CHK-195: Simple pass — IP in ip4 range
    #[tokio::test]
    async fn simple_pass() {
        let resolver = setup_resolver_with_spf("example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-196: Simple fail — IP not in range
    #[tokio::test]
    async fn simple_fail() {
        let resolver = setup_resolver_with_spf("example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        let result = check_host(
            &resolver, "10.0.0.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // CHK-197: Include pass — nested lookup passes
    #[tokio::test]
    async fn include_pass() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.example.com -all".into()]);
        resolver.add_txt("_spf.example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-198: Include fail — nested lookup fails → no match, continue to -all
    #[tokio::test]
    async fn include_fail() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.example.com -all".into()]);
        resolver.add_txt("_spf.example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]);
        let result = check_host(
            &resolver, "10.0.0.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        // include child returns Fail → no match → parent continues to -all → Fail
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // CHK-199: Include TempError propagation
    #[tokio::test]
    async fn include_temperror_propagates() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.example.com -all".into()]);
        resolver.add_txt_err("_spf.example.com", DnsError::TempFail);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::TempError);
    }

    // CHK-200: Include PermError propagation
    #[tokio::test]
    async fn include_permerror_propagates() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.example.com -all".into()]);
        resolver.add_txt("_spf.example.com", vec!["v=spf1 badmech -all".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::PermError);
    }

    // CHK-201: Include None → no match (continue)
    #[tokio::test]
    async fn include_none_no_match() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:_spf.example.com ip4:192.0.2.0/24 -all".into()]);
        // _spf.example.com has no SPF record → None
        resolver.add_txt("_spf.example.com", vec!["not-an-spf-record".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        // Include returns None → no match → continue → ip4 matches → Pass
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-202: MX mechanism
    #[tokio::test]
    async fn mx_mechanism() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 mx -all".into()]);
        resolver.add_mx("example.com", vec![
            MxRecord { preference: 10, exchange: "mail.example.com".into() },
        ]);
        resolver.add_a("mail.example.com", vec!["192.0.2.1".parse().unwrap()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-203: A mechanism with CIDR
    #[tokio::test]
    async fn a_with_cidr() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 a/24 -all".into()]);
        resolver.add_a("example.com", vec!["192.0.2.0".parse().unwrap()]);
        let result = check_host(
            &resolver, "192.0.2.100".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-204: PTR mechanism
    #[tokio::test]
    async fn ptr_mechanism() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 ptr -all".into()]);
        resolver.add_ptr("192.0.2.1", vec!["mail.example.com".into()]);
        resolver.add_a("mail.example.com", vec!["192.0.2.1".parse().unwrap()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-205: Redirect modifier
    #[tokio::test]
    async fn redirect_modifier() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 redirect=_spf.example.com".into()]);
        resolver.add_txt("_spf.example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-206: Redirect to domain without SPF → PermError
    #[tokio::test]
    async fn redirect_no_spf_permerror() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 redirect=nospf.example.com".into()]);
        resolver.add_txt("nospf.example.com", vec!["not-an-spf-record".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::PermError);
    }

    // CHK-207: DNS lookup limit (11th lookup → PermError)
    #[tokio::test]
    async fn dns_limit_exceeded() {
        let mut resolver = MockResolver::new();
        // Chain 11 includes to exceed limit
        let spf = "v=spf1 include:a1.com include:a2.com include:a3.com include:a4.com include:a5.com include:a6.com include:a7.com include:a8.com include:a9.com include:a10.com include:a11.com -all";
        resolver.add_txt("example.com", vec![spf.into()]);
        for i in 1..=11 {
            resolver.add_txt(&format!("a{}.com", i), vec!["v=spf1 -all".into()]);
        }
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::PermError);
    }

    // CHK-208: Void lookup limit (3rd void → PermError)
    #[tokio::test]
    async fn void_limit_exceeded() {
        let mut resolver = MockResolver::new();
        // 3 A mechanisms pointing to NxDomain
        resolver.add_txt("example.com", vec!["v=spf1 a:nope1.com a:nope2.com a:nope3.com -all".into()]);
        // All three return NxDomain → void lookups
        // nope1/2/3.com not added → NxDomain by default
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::PermError);
    }

    // CHK-209: Circular include → PermError
    #[tokio::test]
    async fn circular_include() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 include:other.com -all".into()]);
        resolver.add_txt("other.com", vec!["v=spf1 include:example.com -all".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::PermError);
    }

    // CHK-210: exp= explanation attached to Fail
    #[tokio::test]
    async fn exp_explanation() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 -all exp=explain.example.com".into()]);
        resolver.add_txt("explain.example.com", vec!["You are not authorized to send from %{d}".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Fail {
            explanation: Some("You are not authorized to send from example.com".into())
        });
    }

    // CHK-211: exp= failure → Fail without explanation (graceful)
    #[tokio::test]
    async fn exp_failure_graceful() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 -all exp=explain.example.com".into()]);
        resolver.add_txt_err("explain.example.com", DnsError::TempFail);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // CHK-212: Empty MAIL FROM → postmaster@helo
    #[tokio::test]
    async fn empty_mail_from() {
        let resolver = setup_resolver_with_spf("mail.example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "", "mail.example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-213: IPv6 with ip6 mechanism
    #[tokio::test]
    async fn ipv6_with_ip6() {
        let resolver = setup_resolver_with_spf("example.com", "v=spf1 ip6:2001:db8::/32 -all");
        let result = check_host(
            &resolver, "2001:db8::1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // CHK-214: IPv4 client skips ip6 mechanism
    #[tokio::test]
    async fn ipv4_skips_ip6() {
        let resolver = setup_resolver_with_spf("example.com", "v=spf1 ip6:2001:db8::/32 -all");
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // CHK-215: exists mechanism with macro expansion
    #[tokio::test]
    async fn exists_with_macros() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 exists:%{i}.sbl.example.com -all".into()]);
        resolver.add_a("192.0.2.1.sbl.example.com", vec!["127.0.0.2".parse().unwrap()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // Additional: no match, no redirect → Neutral
    #[tokio::test]
    async fn no_match_neutral() {
        let resolver = setup_resolver_with_spf("example.com", "v=spf1 ip4:10.0.0.0/8");
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Neutral);
    }

    // Additional: MAIL FROM without @ → postmaster@helo
    #[tokio::test]
    async fn mail_from_no_at() {
        let resolver = setup_resolver_with_spf("mail.example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "noreply", "mail.example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Pass);
    }

    // Additional: softfail qualifier
    #[tokio::test]
    async fn softfail_qualifier() {
        let resolver = setup_resolver_with_spf("example.com", "v=spf1 ~all");
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::SoftFail);
    }

    // Additional: neutral qualifier
    #[tokio::test]
    async fn neutral_qualifier() {
        let resolver = setup_resolver_with_spf("example.com", "v=spf1 ?all");
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::Neutral);
    }

    // Additional: no SPF record → None
    #[tokio::test]
    async fn no_spf_record_none() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["not-spf".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::None);
    }

    // Additional: empty redirect domain → PermError
    #[tokio::test]
    async fn redirect_empty_domain_permerror() {
        let mut resolver = MockResolver::new();
        resolver.add_txt("example.com", vec!["v=spf1 redirect=".into()]);
        let result = check_host(
            &resolver, "192.0.2.1".parse().unwrap(),
            "mail.example.com", "user@example.com", "example.com", "receiver.example",
        ).await;
        assert_eq!(result, SpfResult::PermError);
    }
}
