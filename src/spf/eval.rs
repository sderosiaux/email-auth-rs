use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain::{is_subdomain_of, normalize_domain};
use crate::spf::macro_exp::{expand, MacroContext};
use crate::spf::record::{Mechanism, Qualifier, SpfRecord, SpfResult};

// ---------------------------------------------------------------------------
// Constants (RFC 7208 Section 4.6.4 / 11.1)
// ---------------------------------------------------------------------------

const MAX_DNS_LOOKUPS: usize = 10;
const MAX_VOID_LOOKUPS: usize = 2;
const MAX_MX_TARGETS: usize = 10;
const MAX_PTR_NAMES: usize = 10;

// ---------------------------------------------------------------------------
// EvalContext — shared mutable state threaded through recursion
// ---------------------------------------------------------------------------

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

    fn increment_dns(&mut self) -> Result<(), SpfResult> {
        self.dns_lookups += 1;
        if self.dns_lookups > MAX_DNS_LOOKUPS {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }

    fn increment_void(&mut self) -> Result<(), SpfResult> {
        self.void_lookups += 1;
        if self.void_lookups > MAX_VOID_LOOKUPS {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// CIDR matching
// ---------------------------------------------------------------------------

fn ip4_in_network(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ip6_in_network(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let ip_bits = u128::from(ip);
    let net_bits = u128::from(network);
    let mask = u128::MAX << (128 - prefix);
    (ip_bits & mask) == (net_bits & mask)
}

// ---------------------------------------------------------------------------
// Qualifier → SpfResult
// ---------------------------------------------------------------------------

fn qualifier_to_result(q: Qualifier) -> SpfResult {
    match q {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail { explanation: None },
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Evaluate the SPF check_host() function per RFC 7208 Section 4.
pub async fn check_host<R: DnsResolver>(
    resolver: &R,
    ip: IpAddr,
    helo: &str,
    sender: &str,
    domain: &str,
    receiver: &str,
) -> SpfResult {
    // Determine effective sender: empty or missing '@' → postmaster@helo
    let effective_sender = if sender.is_empty() || !sender.contains('@') {
        format!("postmaster@{helo}")
    } else {
        sender.to_string()
    };

    let norm_domain = normalize_domain(domain);

    let mut ctx = EvalContext::new();
    check_host_inner(resolver, ip, helo, &effective_sender, &norm_domain, receiver, &mut ctx)
        .await
}

// ---------------------------------------------------------------------------
// Recursive inner implementation
// ---------------------------------------------------------------------------

fn check_host_inner<'a, R: DnsResolver + 'a>(
    resolver: &'a R,
    ip: IpAddr,
    helo: &'a str,
    sender: &'a str,
    domain: &'a str,
    receiver: &'a str,
    ctx: &'a mut EvalContext,
) -> Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>> {
    Box::pin(async move {
        // --- 1. Build macro context ---
        let (local_part, sender_domain) = match sender.rsplit_once('@') {
            Some((l, d)) => (l.to_string(), d.to_string()),
            None => ("postmaster".to_string(), sender.to_string()),
        };

        let macro_ctx = MacroContext {
            sender: sender.to_string(),
            local_part,
            sender_domain,
            client_ip: ip,
            helo: helo.to_string(),
            domain: domain.to_string(),
            receiver: receiver.to_string(),
        };

        // --- 2. Query TXT records ---
        let txt_records = match resolver.query_txt(domain).await {
            Ok(recs) => recs,
            Err(DnsError::TempFail) => return SpfResult::TempError,
            Err(DnsError::NxDomain | DnsError::NoRecords) => return SpfResult::None,
        };

        // --- 3. Filter SPF records ---
        let spf_records: Vec<&str> = txt_records
            .iter()
            .map(|s| s.as_str())
            .filter(|s| is_spf_record(s))
            .collect();

        match spf_records.len() {
            0 => return SpfResult::None,
            1 => {}
            _ => return SpfResult::PermError,
        }

        // --- 4. Parse the single SPF record ---
        let record = match SpfRecord::parse(spf_records[0]) {
            Ok(r) => r,
            Err(_) => return SpfResult::PermError,
        };

        // --- 5. Evaluate directives left-to-right ---
        let mut matched = false;
        let mut final_result = SpfResult::Neutral;

        for directive in &record.directives {
            let mechanism_matches = match eval_mechanism(
                &directive.mechanism,
                resolver,
                ip,
                domain,
                &macro_ctx,
                ctx,
            )
            .await
            {
                Ok(m) => m,
                Err(result) => return result,
            };

            if mechanism_matches {
                matched = true;
                final_result = qualifier_to_result(directive.qualifier);
                break;
            }
        }

        // --- 6. If no directive matched, check redirect ---
        if !matched {
            if let Some(ref redirect_domain) = record.redirect {
                if let Err(result) = ctx.increment_dns() {
                    return result;
                }

                let expanded = match expand(redirect_domain, &macro_ctx, false) {
                    Ok(d) => normalize_domain(&d),
                    Err(()) => return SpfResult::PermError,
                };

                if expanded.is_empty() {
                    return SpfResult::PermError;
                }

                // Cycle check
                if !ctx.visited_domains.insert(expanded.clone()) {
                    return SpfResult::PermError;
                }

                let redirect_result = check_host_inner(
                    resolver, ip, helo, sender, &expanded, receiver, ctx,
                )
                .await;

                // RFC 7208 Section 6.1: redirect target returning None → PermError
                return match redirect_result {
                    SpfResult::None => SpfResult::PermError,
                    other => other,
                };
            }
            // No redirect → Neutral
            return SpfResult::Neutral;
        }

        // --- 7. Handle exp= modifier on Fail ---
        if let SpfResult::Fail { explanation: None } = &final_result {
            if let Some(ref exp_domain_spec) = record.explanation {
                let explanation = resolve_explanation(resolver, exp_domain_spec, &macro_ctx).await;
                if let Some(text) = explanation {
                    return SpfResult::Fail {
                        explanation: Some(text),
                    };
                }
            }
        }

        final_result
    })
}

/// Check whether a TXT record string is an SPF record:
/// starts with "v=spf1" (case-insensitive) followed by a space or end-of-string.
fn is_spf_record(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 6 {
        return false;
    }
    if !s[..6].eq_ignore_ascii_case("v=spf1") {
        return false;
    }
    s.len() == 6 || s.as_bytes()[6].is_ascii_whitespace()
}

// ---------------------------------------------------------------------------
// Explanation resolution (exp= modifier)
// ---------------------------------------------------------------------------

/// Resolve the exp= modifier: expand macro in domain spec, query TXT, expand
/// macros in the TXT body. Returns None on any failure (silently).
async fn resolve_explanation<R: DnsResolver>(
    resolver: &R,
    exp_domain_spec: &str,
    macro_ctx: &MacroContext,
) -> Option<String> {
    let domain = expand(exp_domain_spec, macro_ctx, false).ok()?;
    let domain = normalize_domain(&domain);
    if domain.is_empty() {
        return None;
    }

    let txt_records = resolver.query_txt(&domain).await.ok()?;
    if txt_records.len() != 1 {
        return None;
    }

    expand(&txt_records[0], macro_ctx, true).ok()
}

// ---------------------------------------------------------------------------
// Mechanism evaluation
// ---------------------------------------------------------------------------

async fn eval_mechanism<R: DnsResolver>(
    mechanism: &Mechanism,
    resolver: &R,
    ip: IpAddr,
    current_domain: &str,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    match mechanism {
        Mechanism::All => Ok(true),

        Mechanism::Include { domain } => eval_include(
            domain, resolver, ip, current_domain, macro_ctx, ctx,
        )
        .await,

        Mechanism::A {
            domain,
            cidr4,
            cidr6,
        } => {
            eval_a(domain.as_deref(), *cidr4, *cidr6, resolver, ip, current_domain, macro_ctx, ctx)
                .await
        }

        Mechanism::Mx {
            domain,
            cidr4,
            cidr6,
        } => {
            eval_mx(domain.as_deref(), *cidr4, *cidr6, resolver, ip, current_domain, macro_ctx, ctx)
                .await
        }

        Mechanism::Ptr { domain } => {
            eval_ptr(domain.as_deref(), resolver, ip, current_domain, macro_ctx, ctx).await
        }

        Mechanism::Ip4 { addr, prefix } => Ok(eval_ip4(ip, *addr, *prefix)),

        Mechanism::Ip6 { addr, prefix } => Ok(eval_ip6(ip, *addr, *prefix)),

        Mechanism::Exists { domain } => {
            eval_exists(domain, resolver, macro_ctx, ctx).await
        }
    }
}

// ---------------------------------------------------------------------------
// include
// ---------------------------------------------------------------------------

async fn eval_include<R: DnsResolver>(
    domain_spec: &str,
    resolver: &R,
    ip: IpAddr,
    _current_domain: &str,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let expanded = expand(domain_spec, macro_ctx, false).map_err(|()| SpfResult::PermError)?;
    let target = normalize_domain(&expanded);
    if target.is_empty() {
        return Err(SpfResult::PermError);
    }

    // Cycle check
    if !ctx.visited_domains.insert(target.clone()) {
        return Err(SpfResult::PermError);
    }

    let child_sender = &macro_ctx.sender;
    let child_result = check_host_inner(
        resolver,
        ip,
        &macro_ctx.helo,
        child_sender,
        &target,
        &macro_ctx.receiver,
        ctx,
    )
    .await;

    // Remove from visited so other branches can visit it
    // Actually per RFC 7208, the visited set prevents infinite loops within
    // a single evaluation path. We keep it in ctx across the whole evaluation.
    // But we need to allow the same domain to be visited in sibling paths.
    // The simplest correct approach: don't remove it. The spec says "check_host()
    // is called" - if there's a cycle, it's PermError. For non-cyclic cases
    // where the same domain appears in different branches, the visited set
    // should NOT block them. However, the ctx is shared mutably, so once we
    // recurse into domain A and return, if domain A appears again in a
    // sibling include, it will be blocked. This is conservative and prevents
    // exponential blowup. RFC 7208 Section 4.6.4 supports this interpretation
    // since the DNS lookup count already limits total work.
    //
    // Actually, let's remove it after returning so sibling includes work.
    ctx.visited_domains.remove(&target);

    match child_result {
        SpfResult::Pass => Ok(true),
        SpfResult::Fail { .. } | SpfResult::SoftFail | SpfResult::Neutral => Ok(false),
        SpfResult::None => Ok(false),
        SpfResult::TempError => Err(SpfResult::TempError),
        SpfResult::PermError => Err(SpfResult::PermError),
    }
}

// ---------------------------------------------------------------------------
// a mechanism
// ---------------------------------------------------------------------------

async fn eval_a<R: DnsResolver>(
    domain_spec: Option<&str>,
    cidr4: Option<u8>,
    cidr6: Option<u8>,
    resolver: &R,
    ip: IpAddr,
    current_domain: &str,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let target = resolve_target_domain(domain_spec, current_domain, macro_ctx)?;

    match ip {
        IpAddr::V4(client_v4) => {
            let prefix = cidr4.unwrap_or(32);
            match resolver.query_a(&target).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if ip4_in_network(client_v4, addr, prefix) {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
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
        IpAddr::V6(client_v6) => {
            let prefix = cidr6.unwrap_or(128);
            match resolver.query_aaaa(&target).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if ip6_in_network(client_v6, addr, prefix) {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
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

// ---------------------------------------------------------------------------
// mx mechanism
// ---------------------------------------------------------------------------

async fn eval_mx<R: DnsResolver>(
    domain_spec: Option<&str>,
    cidr4: Option<u8>,
    cidr6: Option<u8>,
    resolver: &R,
    ip: IpAddr,
    current_domain: &str,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let target = resolve_target_domain(domain_spec, current_domain, macro_ctx)?;

    let mut mx_records = match resolver.query_mx(&target).await {
        Ok(recs) => recs,
        Err(DnsError::NxDomain) => {
            ctx.increment_void()?;
            return Ok(false);
        }
        Err(DnsError::NoRecords) => {
            ctx.increment_void()?;
            return Ok(false);
        }
        Err(DnsError::TempFail) => return Err(SpfResult::TempError),
    };

    // Sort by preference, then limit to first 10
    mx_records.sort_by_key(|r| r.preference);
    mx_records.truncate(MAX_MX_TARGETS);

    for mx in &mx_records {
        let host = normalize_domain(&mx.exchange);
        match ip {
            IpAddr::V4(client_v4) => {
                let prefix = cidr4.unwrap_or(32);
                // DNS errors on individual MX hosts are not fatal — skip
                if let Ok(addrs) = resolver.query_a(&host).await {
                    for addr in addrs {
                        if ip4_in_network(client_v4, addr, prefix) {
                            return Ok(true);
                        }
                    }
                }
            }
            IpAddr::V6(client_v6) => {
                let prefix = cidr6.unwrap_or(128);
                if let Ok(addrs) = resolver.query_aaaa(&host).await {
                    for addr in addrs {
                        if ip6_in_network(client_v6, addr, prefix) {
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

// ---------------------------------------------------------------------------
// ptr mechanism
// ---------------------------------------------------------------------------

async fn eval_ptr<R: DnsResolver>(
    domain_spec: Option<&str>,
    resolver: &R,
    ip: IpAddr,
    current_domain: &str,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let target = match domain_spec {
        Some(spec) => {
            let expanded = expand(spec, macro_ctx, false).map_err(|()| SpfResult::PermError)?;
            normalize_domain(&expanded)
        }
        None => current_domain.to_string(),
    };

    // Reverse lookup
    let ptr_names = match resolver.query_ptr(ip).await {
        Ok(names) => names,
        Err(_) => return Ok(false),
    };

    // Limit to first 10 PTR names
    let ptr_names: Vec<&str> = ptr_names.iter().take(MAX_PTR_NAMES).map(|s| s.as_str()).collect();

    // Forward-confirm each PTR name
    for name in ptr_names {
        let normalized_name = normalize_domain(name);
        let confirmed = match ip {
            IpAddr::V4(v4) => {
                resolver
                    .query_a(&normalized_name)
                    .await
                    .map(|addrs| addrs.contains(&v4))
                    .unwrap_or(false)
            }
            IpAddr::V6(v6) => {
                resolver
                    .query_aaaa(&normalized_name)
                    .await
                    .map(|addrs| addrs.contains(&v6))
                    .unwrap_or(false)
            }
        };

        if confirmed && is_subdomain_of(&normalized_name, &target) {
            return Ok(true);
        }
    }

    Ok(false)
}

// ---------------------------------------------------------------------------
// ip4 mechanism
// ---------------------------------------------------------------------------

fn eval_ip4(client: IpAddr, network: Ipv4Addr, prefix: Option<u8>) -> bool {
    match client {
        IpAddr::V4(v4) => ip4_in_network(v4, network, prefix.unwrap_or(32)),
        IpAddr::V6(_) => false, // Cross-family: no match, not error
    }
}

// ---------------------------------------------------------------------------
// ip6 mechanism
// ---------------------------------------------------------------------------

fn eval_ip6(client: IpAddr, network: Ipv6Addr, prefix: Option<u8>) -> bool {
    match client {
        IpAddr::V6(v6) => ip6_in_network(v6, network, prefix.unwrap_or(128)),
        IpAddr::V4(_) => false, // Cross-family: no match, not error
    }
}

// ---------------------------------------------------------------------------
// exists mechanism
// ---------------------------------------------------------------------------

async fn eval_exists<R: DnsResolver>(
    domain_spec: &str,
    resolver: &R,
    macro_ctx: &MacroContext,
    ctx: &mut EvalContext,
) -> Result<bool, SpfResult> {
    ctx.increment_dns()?;

    let expanded = expand(domain_spec, macro_ctx, false).map_err(|()| SpfResult::PermError)?;
    let target = normalize_domain(&expanded);
    if target.is_empty() {
        return Err(SpfResult::PermError);
    }

    match resolver.query_exists(&target).await {
        Ok(exists) => Ok(exists),
        Err(DnsError::TempFail) => Err(SpfResult::TempError),
        Err(DnsError::NxDomain | DnsError::NoRecords) => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the target domain for A/MX mechanisms: expand macro if domain_spec
/// is provided, otherwise use current_domain.
fn resolve_target_domain(
    domain_spec: Option<&str>,
    current_domain: &str,
    macro_ctx: &MacroContext,
) -> Result<String, SpfResult> {
    match domain_spec {
        Some(spec) => {
            let expanded = expand(spec, macro_ctx, false).map_err(|()| SpfResult::PermError)?;
            Ok(normalize_domain(&expanded))
        }
        None => Ok(current_domain.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::mock::MockResolver;
    use crate::common::dns::MxRecord;
    #[allow(unused_imports)]
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -- 1. Simple pass: IP in ip4 range --

    #[tokio::test]
    async fn simple_pass_ip4_in_range() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]);

        let result = check_host(
            &r,
            IpAddr::V4("192.0.2.1".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 2. Simple fail: IP not in range, ends -all --

    #[tokio::test]
    async fn simple_fail_ip4_not_in_range() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 ip4:192.0.2.0/24 -all".into()]);

        let result = check_host(
            &r,
            IpAddr::V4("10.0.0.1".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // -- 3. Include pass: nested lookup passes --

    #[tokio::test]
    async fn include_pass() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 include:_spf.example.com -all".into()],
        );
        r.add_txt(
            "_spf.example.com",
            vec!["v=spf1 ip4:10.0.0.0/8 -all".into()],
        );

        let result = check_host(
            &r,
            IpAddr::V4("10.1.2.3".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 4. Include fail: nested lookup fails, continues to -all --

    #[tokio::test]
    async fn include_fail_continues() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 include:_spf.example.com -all".into()],
        );
        r.add_txt(
            "_spf.example.com",
            vec!["v=spf1 ip4:10.0.0.0/8 -all".into()],
        );

        let result = check_host(
            &r,
            IpAddr::V4("192.168.1.1".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // -- 5. Include propagation: child TempError propagates --

    #[tokio::test]
    async fn include_propagates_temperror() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 include:child.example.com -all".into()],
        );
        r.add_txt_err("child.example.com", DnsError::TempFail);

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::TempError);
    }

    // -- 6. Include: child None means no match, continues --

    #[tokio::test]
    async fn include_child_none_continues() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 include:nospf.example.com ~all".into()],
        );
        // nospf.example.com has TXT but no SPF record
        r.add_txt("nospf.example.com", vec!["not-an-spf-record".into()]);

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        // child returns None → include treats as no-match → falls through to ~all
        assert_eq!(result, SpfResult::SoftFail);
    }

    // -- 7. MX mechanism: IP matches MX host A record --

    #[tokio::test]
    async fn mx_mechanism_matches() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 mx -all".into()]);
        r.add_mx(
            "example.com",
            vec![MxRecord {
                preference: 10,
                exchange: "mail.example.com".into(),
            }],
        );
        r.add_a("mail.example.com", vec!["192.0.2.10".parse().unwrap()]);

        let result = check_host(
            &r,
            IpAddr::V4("192.0.2.10".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 8. A mechanism with CIDR /24 --

    #[tokio::test]
    async fn a_mechanism_cidr24() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 a/24 -all".into()]);
        r.add_a("example.com", vec!["192.0.2.1".parse().unwrap()]);

        // 192.0.2.100 is in the /24 of 192.0.2.1
        let result = check_host(
            &r,
            IpAddr::V4("192.0.2.100".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 9. PTR mechanism validation --

    #[tokio::test]
    async fn ptr_mechanism_validates() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 ptr -all".into()]);
        let client_ip: IpAddr = "192.0.2.1".parse().unwrap();
        r.add_ptr(client_ip, vec!["mail.example.com".into()]);
        r.add_a("mail.example.com", vec!["192.0.2.1".parse().unwrap()]);

        let result = check_host(
            &r,
            client_ip,
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 10. Redirect modifier --

    #[tokio::test]
    async fn redirect_modifier() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 redirect=other.example.com".into()]);
        r.add_txt(
            "other.example.com",
            vec!["v=spf1 ip4:10.0.0.0/8 -all".into()],
        );

        let result = check_host(
            &r,
            IpAddr::V4("10.1.1.1".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 11. Redirect to domain without SPF record → PermError --

    #[tokio::test]
    async fn redirect_no_spf_permerror() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 redirect=nospf.example.com".into()]);
        r.add_txt("nospf.example.com", vec!["not-spf".into()]);

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::PermError);
    }

    // -- 12. DNS lookup limit (11 includes → PermError) --

    #[tokio::test]
    async fn dns_lookup_limit_permerror() {
        let r = MockResolver::new();
        // Build a chain: example.com includes i0..i10 (11 includes = 11 DNS lookups > 10)
        let mut spf = "v=spf1".to_string();
        for i in 0..11 {
            spf.push_str(&format!(" include:i{i}.example.com"));
        }
        spf.push_str(" -all");
        r.add_txt("example.com", vec![spf]);

        for i in 0..11 {
            r.add_txt(
                &format!("i{i}.example.com"),
                vec!["v=spf1 ip4:127.0.0.1 -all".into()],
            );
        }

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::PermError);
    }

    // -- 13. Void lookup limit (3 NxDomain lookups → PermError) --

    #[tokio::test]
    async fn void_lookup_limit_permerror() {
        let r = MockResolver::new();
        // 3 A mechanisms that all result in NxDomain (void lookups)
        r.add_txt(
            "example.com",
            vec!["v=spf1 a:nx1.example.com a:nx2.example.com a:nx3.example.com -all".into()],
        );
        // nx1, nx2, nx3 are not in the mock → default NxDomain

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::PermError);
    }

    // -- 14. Circular include between 2 domains → PermError --

    #[tokio::test]
    async fn circular_include_permerror() {
        let r = MockResolver::new();
        r.add_txt(
            "a.example.com",
            vec!["v=spf1 include:b.example.com -all".into()],
        );
        r.add_txt(
            "b.example.com",
            vec!["v=spf1 include:a.example.com -all".into()],
        );

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@a.example.com",
            "a.example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::PermError);
    }

    // -- 15. exp= explanation attached to Fail --

    #[tokio::test]
    async fn exp_explanation_on_fail() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 -all exp=explain.example.com".into()],
        );
        r.add_txt(
            "explain.example.com",
            vec!["You are not authorized to send mail for %{d}".into()],
        );

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(
            result,
            SpfResult::Fail {
                explanation: Some(
                    "You are not authorized to send mail for example.com".into()
                ),
            }
        );
    }

    // -- 16. exp= failure → Fail without explanation --

    #[tokio::test]
    async fn exp_failure_silent() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 -all exp=explain.example.com".into()],
        );
        // explain.example.com has no TXT records → NxDomain → exp silently fails
        // (not added to mock, so query returns NxDomain)

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // -- 17. Empty MAIL FROM → postmaster@helo --

    #[tokio::test]
    async fn empty_mail_from_uses_postmaster_helo() {
        let r = MockResolver::new();
        r.add_txt("mail.example.com", vec!["v=spf1 ip4:1.2.3.4 -all".into()]);

        // Empty sender: domain is derived from helo parameter
        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "",
            "mail.example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 18. IPv6 client with ip6 mechanism --

    #[tokio::test]
    async fn ipv6_client_ip6_mechanism() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 ip6:2001:db8::/32 -all".into()],
        );

        let result = check_host(
            &r,
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 19. IPv4 client skips ip6 → no match --

    #[tokio::test]
    async fn ipv4_client_skips_ip6() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 ip6:2001:db8::/32 -all".into()],
        );

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        // ip6 doesn't match v4 client, falls through to -all
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // -- 20. exists mechanism with macro expansion --

    #[tokio::test]
    async fn exists_mechanism_with_macros() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec!["v=spf1 exists:%{ir}.sbl.example.com -all".into()],
        );
        // For IP 1.2.3.4, %{ir} expands to "4.3.2.1"
        r.add_exists("4.3.2.1.sbl.example.com", true);

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- 21. No SPF record → None --

    #[tokio::test]
    async fn no_spf_record_none() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["not-an-spf-record".into()]);

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::None);
    }

    // -- 22. Multiple SPF records → PermError --

    #[tokio::test]
    async fn multiple_spf_records_permerror() {
        let r = MockResolver::new();
        r.add_txt(
            "example.com",
            vec![
                "v=spf1 ip4:1.2.3.4 -all".into(),
                "v=spf1 ip4:5.6.7.8 -all".into(),
            ],
        );

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::PermError);
    }

    // -- 23. DNS TempFail on TXT query → TempError --

    #[tokio::test]
    async fn dns_tempfail_on_txt_temperror() {
        let r = MockResolver::new();
        r.add_txt_err("example.com", DnsError::TempFail);

        let result = check_host(
            &r,
            IpAddr::V4("1.2.3.4".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::TempError);
    }

    // -- 24. CIDR /0 matches any IP --

    #[tokio::test]
    async fn cidr_0_matches_any_ip() {
        let r = MockResolver::new();
        r.add_txt("example.com", vec!["v=spf1 ip4:0.0.0.0/0 -all".into()]);

        let result = check_host(
            &r,
            IpAddr::V4("255.255.255.255".parse().unwrap()),
            "mail.example.com",
            "user@example.com",
            "example.com",
            "mx.receiver.org",
        )
        .await;

        assert_eq!(result, SpfResult::Pass);
    }

    // -- Unit tests for CIDR matching functions --

    #[test]
    fn cidr4_exact_match() {
        assert!(ip4_in_network(
            "192.0.2.1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            32,
        ));
    }

    #[test]
    fn cidr4_subnet_match() {
        assert!(ip4_in_network(
            "192.0.2.100".parse().unwrap(),
            "192.0.2.0".parse().unwrap(),
            24,
        ));
    }

    #[test]
    fn cidr4_no_match() {
        assert!(!ip4_in_network(
            "192.0.3.1".parse().unwrap(),
            "192.0.2.0".parse().unwrap(),
            24,
        ));
    }

    #[test]
    fn cidr4_zero_matches_all() {
        assert!(ip4_in_network(
            "255.255.255.255".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            0,
        ));
    }

    #[test]
    fn cidr4_over_32_never_matches() {
        assert!(!ip4_in_network(
            "1.2.3.4".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
            33,
        ));
    }

    #[test]
    fn cidr6_exact_match() {
        assert!(ip6_in_network(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            128,
        ));
    }

    #[test]
    fn cidr6_subnet_match() {
        assert!(ip6_in_network(
            "2001:db8::ffff".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32,
        ));
    }

    #[test]
    fn cidr6_no_match() {
        assert!(!ip6_in_network(
            "2001:db9::1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32,
        ));
    }

    #[test]
    fn cidr6_zero_matches_all() {
        assert!(ip6_in_network(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
            "::".parse().unwrap(),
            0,
        ));
    }

    #[test]
    fn cidr6_over_128_never_matches() {
        assert!(!ip6_in_network(
            "::1".parse().unwrap(),
            "::1".parse().unwrap(),
            129,
        ));
    }
}
