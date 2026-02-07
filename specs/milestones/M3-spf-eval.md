# M3: SPF Evaluation
Scope: src/spf/eval.rs, src/spf/mod.rs (SpfVerifier)
Depends on: M2
RFC: 7208 Sections 4, 5

## Contracts
- check_host(ip, domain, sender, helo, receiver) -> SpfResult
- DNS lookup limit: max 10 across entire evaluation (include, redirect, a, mx, ptr, exists count; ip4, ip6, all do NOT)
- Void lookup limit: max 2 (NxDomain or empty responses) -> PermError
- Empty MAIL FROM: use postmaster@<helo_domain> as sender
- Left-to-right directive evaluation, first match wins
- No match + no redirect: Neutral
- redirect= modifier: only if no directive matched, target None -> PermError, counts as DNS lookup

## EvalContext design
Evaluation state must be threaded through recursive calls. Use a mutable context struct:
```rust
struct EvalContext {
    dns_lookup_count: u32,     // Max 10, shared across recursion
    void_lookup_count: u32,    // Max 2
    visited_domains: HashSet<String>,  // Circular include/redirect detection
}
```

### Circular include/redirect detection (CRITICAL)
v1 relied only on the 10-DNS-lookup limit as a safety net. This is insufficient — a 2-domain cycle could execute 5 times before hitting the limit, wasting resources and potentially causing confusing results.

**Required**: Track visited domains in a `HashSet<String>`. Before processing an `include:` or `redirect=` target:
1. Normalize the domain (lowercase, strip trailing dot)
2. Check if already in `visited_domains`
3. If present: return `SpfResult::PermError` immediately with "circular include/redirect" reason
4. If not: insert and proceed with recursive evaluation
5. Do NOT remove after return (the set is append-only for the entire evaluation)

### Async recursion pattern
`check_host_inner` is recursive (via include/redirect). Rust async recursion requires boxing:
```rust
fn check_host_inner<'a>(
    &'a self,
    ctx: &'a mut EvalContext,
    domain: &'a str,
    // ...
) -> Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>> {
    Box::pin(async move {
        // ... evaluation logic
    })
}
```
The `Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>>` return type is required. Using `async fn` directly causes infinite type recursion.

## Mechanism evaluation
- all: always matches
- include: recursive check_host, map child Pass->match, Fail/SoftFail/Neutral/None->no match, TempError/PermError propagate
- a/mx: macro expand domain, query A (if client v4) or AAAA (if v6), CIDR match. MX limited to first 10 hosts.
- ptr: reverse lookup -> forward confirm -> domain suffix check. Limit to 10 PTR names. Deprecated but must support.
- ip4/ip6: CIDR match, no DNS lookup
- exists: macro expand domain, A query, any result=match, NxDomain=no match

### CIDR matching implementation
For `a` and `mx` mechanisms with CIDR:
```rust
// For IPv4
fn cidr_match_v4(client: Ipv4Addr, record: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 { return true; }
    let mask = !0u32 << (32 - prefix_len);
    (u32::from(client) & mask) == (u32::from(record) & mask)
}

// For IPv6
fn cidr_match_v6(client: Ipv6Addr, record: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 { return true; }
    let mask = !0u128 << (128 - prefix_len);
    (u128::from(client) & mask) == (u128::from(record) & mask)
}
```

### MX mechanism evaluation
1. Query MX records for domain
2. Sort by preference (lowest first)
3. Limit to first 10 MX hosts (per RFC)
4. For each MX host: query A or AAAA (matching client IP version)
5. Each A/AAAA query counts as a DNS lookup
6. CIDR match client IP against each resolved address
7. Any match -> mechanism matches

### DNS lookup counting
Mechanisms that increment the counter: `include`, `a`, `mx`, `ptr`, `exists`, `redirect`
Mechanisms that do NOT: `all`, `ip4`, `ip6`

For `mx`: the MX lookup itself counts as 1. Each subsequent A/AAAA lookup for MX hosts also counts. Total for one MX mechanism can be 1 + N where N is number of MX hosts resolved.

### Void lookup counting
A void lookup is a DNS query that returns either NXDOMAIN or an empty answer (no records). Increment void counter for each. When void_lookup_count > 2, return PermError.

## exp= modifier evaluation
- Only when result is Fail
- Query TXT at expanded exp domain
- Expand macros in TXT result (including c, r, t explanation-only macros)
- Attach explanation string to Fail result

## Review kill patterns
- exp= parsed but never evaluated during check_host
- DNS lookup counter not incremented for some mechanisms (especially exists, ptr)
- Void lookup counter absent or not enforced
- Multiple SPF records accepted instead of PermError
- include child PermError/TempError not propagated
- MX mechanism not limited to 10 hosts
- No circular include/redirect detection (only DNS limit as safety net)
- Async recursion without Box::pin (compile error or stack overflow)
- EvalContext not shared across recursive calls (each level has fresh counters)
- CIDR matching with wrong bit direction (shifting right instead of left)
- MX host A/AAAA lookups not counted toward DNS limit
