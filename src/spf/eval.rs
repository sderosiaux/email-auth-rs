//! SPF evaluation engine (RFC 7208 Section 4).
//!
//! Implements `check_host` with full mechanism evaluation, DNS lookup limits,
//! void lookup limits, include/redirect recursion, and exp= explanation.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use crate::common::dns::{DnsError, DnsResolver};
use crate::common::domain;
use crate::spf::macro_exp::{self, MacroContext};
use crate::spf::mechanism::{DualCidr, Mechanism, Qualifier};
use crate::spf::record::SpfRecord;
use crate::spf::SpfResult;

/// Maximum DNS-querying mechanism lookups per check_host evaluation.
const DNS_LOOKUP_LIMIT: usize = 10;
/// Maximum void (NxDomain / empty) DNS lookups before PermError.
const VOID_LOOKUP_LIMIT: usize = 2;
/// Maximum MX hosts to resolve A/AAAA records for.
const MX_HOST_LIMIT: usize = 10;
/// Maximum PTR names to validate.
const PTR_NAME_LIMIT: usize = 10;

/// Mutable evaluation context shared across recursive check_host calls.
struct EvalContext {
    dns_lookups: usize,
    void_lookups: usize,
}

impl EvalContext {
    fn new() -> Self {
        Self {
            dns_lookups: 0,
            void_lookups: 0,
        }
    }

    /// Increment DNS lookup counter. Returns Err(PermError) if limit exceeded.
    fn inc_dns(&mut self) -> Result<(), SpfResult> {
        self.dns_lookups += 1;
        if self.dns_lookups > DNS_LOOKUP_LIMIT {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }

    /// Track a void lookup. Returns Err(PermError) if limit exceeded.
    fn inc_void(&mut self) -> Result<(), SpfResult> {
        self.void_lookups += 1;
        if self.void_lookups > VOID_LOOKUP_LIMIT {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }
}

/// Entry point for SPF evaluation. Creates context and delegates to inner eval.
pub async fn check_host<R: DnsResolver>(
    resolver: &R,
    ip: IpAddr,
    helo: &str,
    sender: &str,
    domain: &str,
    receiver: &str,
) -> SpfResult {
    // Empty MAIL FROM: use postmaster@<helo>
    let sender = if sender.is_empty() || !sender.contains('@') {
        format!("postmaster@{helo}")
    } else {
        sender.to_string()
    };

    let mut ctx = EvalContext::new();
    check_host_inner(resolver, &mut ctx, ip, helo, &sender, domain, receiver).await
}

/// Inner recursive check_host. Shared EvalContext across include/redirect.
/// Uses Box::pin to allow async recursion (include/redirect chains).
fn check_host_inner<'a, R: DnsResolver>(
    resolver: &'a R,
    ctx: &'a mut EvalContext,
    ip: IpAddr,
    helo: &'a str,
    sender: &'a str,
    domain: &'a str,
    receiver: &'a str,
) -> Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>> {
    Box::pin(async move {
        // Fetch SPF record for domain
        let record = match fetch_spf_record(resolver, ctx, domain, true).await {
            Ok(r) => r,
            Err(result) => return result,
        };

        let macro_ctx = build_macro_context(sender, ip, helo, domain, receiver);

        // Evaluate directives left to right
        for directive in &record.directives {
            let matched = match eval_mechanism(
                resolver, ctx, &directive.mechanism, ip, &macro_ctx, domain,
            )
            .await
            {
                Ok(m) => m,
                Err(result) => return result,
            };

            if let Some(did_match) = matched {
                if did_match {
                    let result = qualifier_to_result(directive.qualifier);
                    return maybe_attach_explanation(
                        resolver, &record, &macro_ctx, result,
                    )
                    .await;
                }
            }
        }

        // No directive matched. Check redirect.
        if let Some(ref redirect_domain) = record.redirect {
            if ctx.inc_dns().is_err() {
                return SpfResult::PermError;
            }

            let expanded = match macro_ctx_expand(redirect_domain, &macro_ctx, false) {
                Ok(d) => d,
                Err(_) => return SpfResult::PermError,
            };

            if expanded.is_empty() {
                return SpfResult::PermError;
            }

            let result = check_host_inner(
                resolver, ctx, ip, helo, sender, &expanded, receiver,
            )
            .await;

            if matches!(result, SpfResult::None) {
                return SpfResult::PermError;
            }
            return result;
        }

        // No match, no redirect -> Neutral
        SpfResult::Neutral
    })
}

/// Fetch and parse the SPF record for a domain.
/// `is_initial` controls whether "no record" returns None vs PermError.
async fn fetch_spf_record<R: DnsResolver>(
    resolver: &R,
    ctx: &mut EvalContext,
    domain: &str,
    is_initial: bool,
) -> Result<SpfRecord, SpfResult> {
    let txt_records = match resolver.query_txt(domain).await {
        Ok(records) => records,
        Err(DnsError::NxDomain) => {
            ctx.inc_void().map_err(|_| SpfResult::PermError)?;
            return Err(SpfResult::None);
        }
        Err(DnsError::NoRecords) => {
            return Err(SpfResult::None);
        }
        Err(DnsError::TempFail(_)) => {
            return Err(SpfResult::TempError);
        }
    };

    // Filter for SPF records (start with "v=spf1" case-insensitive, followed by space or end)
    let spf_texts: Vec<&String> = txt_records
        .iter()
        .filter(|txt| {
            let lower = txt.to_ascii_lowercase();
            lower == "v=spf1" || lower.starts_with("v=spf1 ")
        })
        .collect();

    match spf_texts.len() {
        0 => {
            if is_initial {
                Err(SpfResult::None)
            } else {
                Err(SpfResult::PermError)
            }
        }
        1 => SpfRecord::parse(spf_texts[0]).map_err(|_| SpfResult::PermError),
        _ => Err(SpfResult::PermError), // multiple SPF records
    }
}

/// Evaluate a single mechanism. Returns:
/// - Ok(Some(true))  -> mechanism matched
/// - Ok(Some(false)) -> mechanism did not match
/// - Err(SpfResult)  -> propagate this result immediately (TempError/PermError from include)
async fn eval_mechanism<R: DnsResolver>(
    resolver: &R,
    ctx: &mut EvalContext,
    mechanism: &Mechanism,
    ip: IpAddr,
    macro_ctx: &MacroContext,
    current_domain: &str,
) -> Result<Option<bool>, SpfResult> {
    match mechanism {
        Mechanism::All => Ok(Some(true)),

        Mechanism::Include(domain_spec) => {
            ctx.inc_dns()?;
            let expanded = macro_ctx_expand(domain_spec, macro_ctx, false)
                .map_err(|_| SpfResult::PermError)?;
            let child_result = check_host_inner(
                resolver,
                ctx,
                ip,
                &macro_ctx.helo,
                &macro_ctx.sender,
                &expanded,
                &macro_ctx.receiver,
            )
            .await;
            match child_result {
                SpfResult::Pass => Ok(Some(true)),
                SpfResult::Fail { .. }
                | SpfResult::SoftFail
                | SpfResult::Neutral => Ok(Some(false)),
                SpfResult::TempError => Err(SpfResult::TempError),
                SpfResult::PermError => Err(SpfResult::PermError),
                SpfResult::None => Err(SpfResult::PermError),
            }
        }

        Mechanism::A { domain, cidr } => {
            ctx.inc_dns()?;
            let target = resolve_domain(domain.as_deref(), current_domain, macro_ctx)?;
            let matched = match_a_records(resolver, ctx, &target, ip, cidr).await?;
            Ok(Some(matched))
        }

        Mechanism::Mx { domain, cidr } => {
            ctx.inc_dns()?;
            let target = resolve_domain(domain.as_deref(), current_domain, macro_ctx)?;
            let matched = match_mx_records(resolver, ctx, &target, ip, cidr).await?;
            Ok(Some(matched))
        }

        Mechanism::Ptr(domain) => {
            ctx.inc_dns()?;
            let target = match domain {
                Some(d) => macro_ctx_expand(d, macro_ctx, false)
                    .map_err(|_| SpfResult::PermError)?,
                None => current_domain.to_string(),
            };
            let matched = match_ptr(resolver, ctx, ip, &target).await?;
            Ok(Some(matched))
        }

        Mechanism::Ip4 { addr, prefix_len } => {
            let matched = match ip {
                IpAddr::V4(client_v4) => ip4_in_network(client_v4, *addr, *prefix_len),
                IpAddr::V6(_) => false,
            };
            Ok(Some(matched))
        }

        Mechanism::Ip6 { addr, prefix_len } => {
            let matched = match ip {
                IpAddr::V6(client_v6) => ip6_in_network(client_v6, *addr, *prefix_len),
                IpAddr::V4(_) => false,
            };
            Ok(Some(matched))
        }

        Mechanism::Exists(domain_spec) => {
            ctx.inc_dns()?;
            let expanded = macro_ctx_expand(domain_spec, macro_ctx, false)
                .map_err(|_| SpfResult::PermError)?;
            let matched = match resolver.query_exists(&expanded).await {
                Ok(exists) => exists,
                Err(DnsError::NxDomain | DnsError::NoRecords) => false,
                Err(DnsError::TempFail(_)) => return Err(SpfResult::TempError),
            };
            Ok(Some(matched))
        }
    }
}

// ---------------------------------------------------------------------------
// A/AAAA matching
// ---------------------------------------------------------------------------

async fn match_a_records<R: DnsResolver>(
    resolver: &R,
    ctx: &mut EvalContext,
    domain: &str,
    ip: IpAddr,
    cidr: &DualCidr,
) -> Result<bool, SpfResult> {
    match ip {
        IpAddr::V4(client_v4) => {
            match resolver.query_a(domain).await {
                Ok(addrs) => {
                    for addr in &addrs {
                        if ip4_in_network(client_v4, *addr, cidr.v4) {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                Err(DnsError::NxDomain) => {
                    ctx.inc_void()?;
                    Ok(false)
                }
                Err(DnsError::NoRecords) => Ok(false),
                Err(DnsError::TempFail(_)) => Err(SpfResult::TempError),
            }
        }
        IpAddr::V6(client_v6) => {
            match resolver.query_aaaa(domain).await {
                Ok(addrs) => {
                    for addr in &addrs {
                        if ip6_in_network(client_v6, *addr, cidr.v6) {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                Err(DnsError::NxDomain) => {
                    ctx.inc_void()?;
                    Ok(false)
                }
                Err(DnsError::NoRecords) => Ok(false),
                Err(DnsError::TempFail(_)) => Err(SpfResult::TempError),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MX matching
// ---------------------------------------------------------------------------

async fn match_mx_records<R: DnsResolver>(
    resolver: &R,
    ctx: &mut EvalContext,
    domain: &str,
    ip: IpAddr,
    cidr: &DualCidr,
) -> Result<bool, SpfResult> {
    let mut mx_records = match resolver.query_mx(domain).await {
        Ok(records) => records,
        Err(DnsError::NxDomain) => {
            ctx.inc_void()?;
            return Ok(false);
        }
        Err(DnsError::NoRecords) => return Ok(false),
        Err(DnsError::TempFail(_)) => return Err(SpfResult::TempError),
    };

    // Sort by preference, take first 10
    mx_records.sort_by_key(|mx| mx.preference);
    mx_records.truncate(MX_HOST_LIMIT);

    for mx in &mx_records {
        let exchange = &mx.exchange;
        match ip {
            IpAddr::V4(client_v4) => {
                if let Ok(addrs) = resolver.query_a(exchange).await {
                    for addr in &addrs {
                        if ip4_in_network(client_v4, *addr, cidr.v4) {
                            return Ok(true);
                        }
                    }
                }
            }
            IpAddr::V6(client_v6) => {
                if let Ok(addrs) = resolver.query_aaaa(exchange).await {
                    for addr in &addrs {
                        if ip6_in_network(client_v6, *addr, cidr.v6) {
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
// PTR matching
// ---------------------------------------------------------------------------

async fn match_ptr<R: DnsResolver>(
    resolver: &R,
    ctx: &mut EvalContext,
    ip: IpAddr,
    target_domain: &str,
) -> Result<bool, SpfResult> {
    let ptr_names = match resolver.query_ptr(ip).await {
        Ok(names) => names,
        Err(DnsError::NxDomain) => {
            ctx.inc_void()?;
            return Ok(false);
        }
        Err(DnsError::NoRecords) => return Ok(false),
        Err(DnsError::TempFail(_)) => return Err(SpfResult::TempError),
    };

    // Limit to first 10 PTR names
    let names: Vec<&String> = ptr_names.iter().take(PTR_NAME_LIMIT).collect();

    for name in names {
        // Forward-confirm: look up the PTR name and check if the IP appears
        let confirmed = match ip {
            IpAddr::V4(client_v4) => {
                if let Ok(addrs) = resolver.query_a(name).await {
                    addrs.contains(&client_v4)
                } else {
                    false
                }
            }
            IpAddr::V6(client_v6) => {
                if let Ok(addrs) = resolver.query_aaaa(name).await {
                    addrs.contains(&client_v6)
                } else {
                    false
                }
            }
        };

        if confirmed && domain::is_subdomain_of(name, target_domain) {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// CIDR matching helpers
// ---------------------------------------------------------------------------

fn ip4_in_network(client: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    let client_bits = u32::from(client);
    let network_bits = u32::from(network);
    let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
    (client_bits & mask) == (network_bits & mask)
}

fn ip6_in_network(client: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 128 {
        return false;
    }
    let client_bits = u128::from(client);
    let network_bits = u128::from(network);
    let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
    (client_bits & mask) == (network_bits & mask)
}

// ---------------------------------------------------------------------------
// Explanation (exp=) handling
// ---------------------------------------------------------------------------

async fn maybe_attach_explanation<R: DnsResolver>(
    resolver: &R,
    record: &SpfRecord,
    macro_ctx: &MacroContext,
    result: SpfResult,
) -> SpfResult {
    // Only attach explanation to Fail results
    if !matches!(result, SpfResult::Fail { .. }) {
        return result;
    }

    let exp_domain = match record.explanation {
        Some(ref domain) => domain,
        None => return result,
    };

    // Expand macros in the exp= domain
    let expanded_domain = match macro_ctx_expand(exp_domain, macro_ctx, false) {
        Ok(d) => d,
        Err(_) => return result, // silently ignore exp errors
    };

    // Query TXT for the explanation domain
    let txt_records = match resolver.query_txt(&expanded_domain).await {
        Ok(records) => records,
        Err(_) => return result, // silently ignore DNS errors for exp
    };

    if txt_records.is_empty() {
        return result;
    }

    // Use the first TXT record, expand macros (with is_exp=true for c, r, t)
    let explanation_template = &txt_records[0];
    let explanation = match macro_exp::expand(explanation_template, macro_ctx, true) {
        Ok(expanded) => expanded,
        Err(_) => return result,
    };

    SpfResult::Fail {
        explanation: Some(explanation),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn qualifier_to_result(qualifier: Qualifier) -> SpfResult {
    match qualifier {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail { explanation: None },
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

fn build_macro_context(
    sender: &str,
    ip: IpAddr,
    helo: &str,
    domain: &str,
    receiver: &str,
) -> MacroContext {
    let local = domain::local_part_from_email(sender).to_string();
    let sender_domain = domain::domain_from_email(sender)
        .unwrap_or(domain)
        .to_string();
    MacroContext {
        sender: sender.to_string(),
        local_part: local,
        domain: sender_domain,
        client_ip: ip,
        helo: helo.to_string(),
        receiver: receiver.to_string(),
    }
}

/// Resolve the target domain for A/MX mechanisms. If the mechanism has an explicit
/// domain-spec, expand it. Otherwise, use the current domain being evaluated.
fn resolve_domain(
    explicit: Option<&str>,
    current_domain: &str,
    macro_ctx: &MacroContext,
) -> Result<String, SpfResult> {
    match explicit {
        Some(spec) => {
            macro_ctx_expand(spec, macro_ctx, false).map_err(|_| SpfResult::PermError)
        }
        None => Ok(current_domain.to_string()),
    }
}

fn macro_ctx_expand(
    input: &str,
    ctx: &MacroContext,
    is_exp: bool,
) -> Result<String, macro_exp::MacroError> {
    macro_exp::expand(input, ctx, is_exp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dns::{MockDnsResponse, MockResolver, MxRecord};

    fn mock_spf(resolver: &mut MockResolver, domain: &str, record: &str) {
        resolver.txt.insert(
            domain.to_string(),
            MockDnsResponse::Records(vec![record.to_string()]),
        );
    }

    async fn eval(resolver: &MockResolver, ip: IpAddr, domain: &str) -> SpfResult {
        check_host(resolver, ip, "ehlo.example.com", "user@example.com", domain, "mx.example.org").await
    }

    async fn eval_full(
        resolver: &MockResolver,
        ip: IpAddr,
        helo: &str,
        sender: &str,
        domain: &str,
    ) -> SpfResult {
        check_host(resolver, ip, helo, sender, domain, "mx.example.org").await
    }

    // -----------------------------------------------------------------------
    // Basic results
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pass_via_ip4_match() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn fail_via_dash_all() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 ip4:10.0.0.1 -all");
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    #[tokio::test]
    async fn softfail_via_tilde_all() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 ~all");
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::SoftFail);
    }

    #[tokio::test]
    async fn neutral_via_question_all() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 ?all");
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Neutral);
    }

    #[tokio::test]
    async fn no_spf_record_returns_none() {
        let r = MockResolver::new();
        // No TXT records at all -> NxDomain -> None
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::None);
    }

    #[tokio::test]
    async fn multiple_spf_records_returns_permerror() {
        let mut r = MockResolver::new();
        r.txt.insert(
            "example.com".to_string(),
            MockDnsResponse::Records(vec![
                "v=spf1 ip4:10.0.0.1 -all".to_string(),
                "v=spf1 ip4:10.0.0.2 -all".to_string(),
            ]),
        );
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::PermError);
    }

    // -----------------------------------------------------------------------
    // include: mechanism
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn include_pass_propagation() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 include:other.com -all");
        mock_spf(&mut r, "other.com", "v=spf1 ip4:192.0.2.0/24 -all");
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn include_child_fail_no_match_in_parent() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 include:other.com ?all");
        mock_spf(&mut r, "other.com", "v=spf1 ip4:10.0.0.1 -all");
        // Child returns Fail (ip doesn't match 10.0.0.1, hits -all)
        // include maps child Fail -> no match -> continue -> ?all -> Neutral
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Neutral);
    }

    #[tokio::test]
    async fn include_child_temperror_propagates() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 include:other.com -all");
        r.txt.insert(
            "other.com".to_string(),
            MockDnsResponse::TempFail("timeout".into()),
        );
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::TempError);
    }

    #[tokio::test]
    async fn include_child_permerror_propagates() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 include:other.com -all");
        // other.com has two SPF records -> PermError
        r.txt.insert(
            "other.com".to_string(),
            MockDnsResponse::Records(vec![
                "v=spf1 -all".into(),
                "v=spf1 +all".into(),
            ]),
        );
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::PermError);
    }

    #[tokio::test]
    async fn include_child_none_becomes_permerror() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 include:nonexistent.com -all");
        // nonexistent.com has no SPF record -> child returns None -> include maps to PermError
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::PermError);
    }

    // -----------------------------------------------------------------------
    // redirect= modifier
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn redirect_basic() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 redirect=other.com");
        mock_spf(&mut r, "other.com", "v=spf1 ip4:192.0.2.0/24 -all");
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn redirect_target_no_spf_returns_permerror() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 redirect=nospf.com");
        // nospf.com has no SPF record -> None -> redirect maps to PermError
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::PermError);
    }

    #[tokio::test]
    async fn redirect_ignored_when_directive_matches() {
        let mut r = MockResolver::new();
        // redirect should only apply if NO directive matched
        mock_spf(&mut r, "example.com", "v=spf1 ip4:192.0.2.0/24 redirect=other.com");
        mock_spf(&mut r, "other.com", "v=spf1 -all");
        // IP matches ip4 directive -> Pass, redirect not used
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Pass);
    }

    // -----------------------------------------------------------------------
    // DNS lookup limit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dns_lookup_limit_exceeded_permerror() {
        let mut r = MockResolver::new();
        // Build a chain of 11 includes. Each include costs 1 DNS lookup.
        // Plus the initial domain fetch doesn't count toward mechanism lookups,
        // but each include: mechanism does.
        mock_spf(
            &mut r,
            "example.com",
            "v=spf1 include:d1.com include:d2.com include:d3.com include:d4.com include:d5.com include:d6.com include:d7.com include:d8.com include:d9.com include:d10.com include:d11.com -all",
        );
        // Each child returns SoftFail (no match for include), so we keep going
        for i in 1..=11 {
            mock_spf(&mut r, &format!("d{i}.com"), "v=spf1 ~all");
        }
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::PermError);
    }

    // -----------------------------------------------------------------------
    // Void lookup limit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn void_lookup_limit_exceeded_permerror() {
        let mut r = MockResolver::new();
        // Use A mechanisms that query NxDomain domains -> void lookups
        mock_spf(
            &mut r,
            "example.com",
            "v=spf1 a:nx1.com a:nx2.com a:nx3.com -all",
        );
        // nx1, nx2, nx3 are not in the resolver -> NxDomain -> void
        // void limit is 2, third void should trigger PermError
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::PermError);
    }

    // -----------------------------------------------------------------------
    // A mechanism
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn a_mechanism_with_cidr_matching() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 a:mail.example.com/24 -all");
        r.a.insert(
            "mail.example.com".to_string(),
            MockDnsResponse::Records(vec![Ipv4Addr::new(192, 0, 2, 1)]),
        );
        // Client 192.0.2.50 should match 192.0.2.1/24
        let result = eval(&r, "192.0.2.50".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Pass);

        // Client 10.0.0.1 should NOT match
        let result2 = eval(&r, "10.0.0.1".parse().unwrap(), "example.com").await;
        assert_eq!(result2, SpfResult::Fail { explanation: None });
    }

    #[tokio::test]
    async fn a_mechanism_bare_uses_current_domain() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 a -all");
        r.a.insert(
            "example.com".to_string(),
            MockDnsResponse::Records(vec![Ipv4Addr::new(192, 0, 2, 1)]),
        );
        let result = eval(&r, "192.0.2.1".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Pass);
    }

    // -----------------------------------------------------------------------
    // MX mechanism
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mx_mechanism_basic() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 mx -all");
        r.mx.insert(
            "example.com".to_string(),
            MockDnsResponse::Records(vec![MxRecord {
                preference: 10,
                exchange: "mail.example.com".to_string(),
            }]),
        );
        r.a.insert(
            "mail.example.com".to_string(),
            MockDnsResponse::Records(vec![Ipv4Addr::new(192, 0, 2, 1)]),
        );
        let result = eval(&r, "192.0.2.1".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Pass);
    }

    // -----------------------------------------------------------------------
    // PTR mechanism
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ptr_mechanism_basic() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 ptr:example.com -all");

        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        r.ptr.insert(
            "192.0.2.1".to_string(),
            MockDnsResponse::Records(vec!["mail.example.com".to_string()]),
        );
        // Forward-confirm: mail.example.com -> 192.0.2.1
        r.a.insert(
            "mail.example.com".to_string(),
            MockDnsResponse::Records(vec![Ipv4Addr::new(192, 0, 2, 1)]),
        );

        let result = eval(&r, ip, "example.com").await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn ptr_mechanism_forward_confirm_fails() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 ptr:example.com -all");

        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        r.ptr.insert(
            "192.0.2.1".to_string(),
            MockDnsResponse::Records(vec!["mail.example.com".to_string()]),
        );
        // Forward lookup returns different IP -> no forward-confirm
        r.a.insert(
            "mail.example.com".to_string(),
            MockDnsResponse::Records(vec![Ipv4Addr::new(10, 0, 0, 1)]),
        );

        let result = eval(&r, ip, "example.com").await;
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // -----------------------------------------------------------------------
    // exists mechanism
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn exists_mechanism_match() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 exists:exists.example.com -all");
        r.a.insert(
            "exists.example.com".to_string(),
            MockDnsResponse::Records(vec![Ipv4Addr::new(127, 0, 0, 1)]),
        );
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn exists_mechanism_no_match() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 exists:nope.example.com -all");
        // nope.example.com not in resolver -> NxDomain -> no match -> -all -> Fail
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // -----------------------------------------------------------------------
    // exp= explanation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn exp_explanation_attached_to_fail() {
        let mut r = MockResolver::new();
        mock_spf(
            &mut r,
            "example.com",
            "v=spf1 -all exp=explain.example.com",
        );
        r.txt.insert(
            "explain.example.com".to_string(),
            MockDnsResponse::Records(vec![
                "You are not authorized to send from %{d}".to_string(),
            ]),
        );
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(
            result,
            SpfResult::Fail {
                explanation: Some(
                    "You are not authorized to send from example.com".to_string()
                ),
            }
        );
    }

    #[tokio::test]
    async fn exp_not_attached_to_non_fail() {
        let mut r = MockResolver::new();
        mock_spf(
            &mut r,
            "example.com",
            "v=spf1 ~all exp=explain.example.com",
        );
        r.txt.insert(
            "explain.example.com".to_string(),
            MockDnsResponse::Records(vec!["Explanation text".to_string()]),
        );
        // ~all -> SoftFail, exp should NOT be attached
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::SoftFail);
    }

    // -----------------------------------------------------------------------
    // Empty MAIL FROM -> postmaster@helo
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn empty_mail_from_defaults_to_postmaster() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "ehlo.example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        // Empty sender: should use postmaster@ehlo.example.com
        // Domain from sender becomes ehlo.example.com
        let result = eval_full(
            &r,
            "192.0.2.10".parse().unwrap(),
            "ehlo.example.com",
            "",
            "ehlo.example.com",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    // -----------------------------------------------------------------------
    // No match, no redirect -> Neutral
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_match_no_redirect_returns_neutral() {
        let mut r = MockResolver::new();
        // Record with only ip4, no catch-all, no redirect
        mock_spf(&mut r, "example.com", "v=spf1 ip4:10.0.0.1");
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::Neutral);
    }

    // -----------------------------------------------------------------------
    // IPv6 tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ip6_mechanism_match() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 ip6:2001:db8::/32 -all");
        let result = eval(
            &r,
            "2001:db8::1".parse().unwrap(),
            "example.com",
        )
        .await;
        assert_eq!(result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn ip6_mechanism_no_match() {
        let mut r = MockResolver::new();
        mock_spf(&mut r, "example.com", "v=spf1 ip6:2001:db8::/32 -all");
        let result = eval(
            &r,
            "2001:db9::1".parse().unwrap(),
            "example.com",
        )
        .await;
        assert_eq!(result, SpfResult::Fail { explanation: None });
    }

    // -----------------------------------------------------------------------
    // CIDR helpers
    // -----------------------------------------------------------------------

    #[test]
    fn cidr_v4_matching() {
        let net = Ipv4Addr::new(192, 168, 1, 0);
        assert!(ip4_in_network(Ipv4Addr::new(192, 168, 1, 100), net, 24));
        assert!(ip4_in_network(Ipv4Addr::new(192, 168, 1, 0), net, 24));
        assert!(ip4_in_network(Ipv4Addr::new(192, 168, 1, 255), net, 24));
        assert!(!ip4_in_network(Ipv4Addr::new(192, 168, 2, 0), net, 24));
        assert!(ip4_in_network(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(0, 0, 0, 0), 0));
    }

    #[test]
    fn cidr_v6_matching() {
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        let in_range: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let out_of_range: Ipv6Addr = "2001:db9::1".parse().unwrap();
        assert!(ip6_in_network(in_range, net, 32));
        assert!(!ip6_in_network(out_of_range, net, 32));
        assert!(ip6_in_network(out_of_range, net, 0)); // /0 matches everything
    }

    // -----------------------------------------------------------------------
    // DNS TempFail -> TempError
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dns_tempfail_returns_temperror() {
        let mut r = MockResolver::new();
        r.txt.insert(
            "example.com".to_string(),
            MockDnsResponse::TempFail("timeout".into()),
        );
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        assert_eq!(result, SpfResult::TempError);
    }

    // -----------------------------------------------------------------------
    // Redirect counts as DNS lookup
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn redirect_counts_as_dns_lookup() {
        let mut r = MockResolver::new();
        // 10 includes (each a DNS lookup) + redirect (1 more) = 11 -> PermError
        mock_spf(
            &mut r,
            "example.com",
            "v=spf1 include:d1.com include:d2.com include:d3.com include:d4.com include:d5.com include:d6.com include:d7.com include:d8.com include:d9.com include:d10.com redirect=other.com",
        );
        for i in 1..=10 {
            mock_spf(&mut r, &format!("d{i}.com"), "v=spf1 ~all");
        }
        mock_spf(&mut r, "other.com", "v=spf1 +all");
        let result = eval(&r, "192.0.2.10".parse().unwrap(), "example.com").await;
        // 10 includes use up the limit, then redirect is the 11th -> PermError
        assert_eq!(result, SpfResult::PermError);
    }
}
