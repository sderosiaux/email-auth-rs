# M9: DMARC Evaluation
Scope: src/dmarc/mod.rs, src/dmarc/eval.rs
Depends on: M3 (SpfResult), M6 (DkimResult), M8 (DmarcRecord)
RFC: 7489 Sections 3, 4, 6; RFC 9091

## Scope boundary
This milestone implements DMARC policy evaluation ONLY. Report generation (aggregate and forensic) is explicitly OUT OF SCOPE for this library.

## DNS discovery contracts
- Extract domain from RFC5322.From header
- Query _dmarc.<from_domain> TXT
- If no record and from_domain != org_domain: fallback to _dmarc.<org_domain>
- Multiple TXT records: use first valid DMARC record
- No record: DmarcResult with disposition=None, no policy

### CRITICAL: DNS TempFail during discovery
v1 bug: `Err(_) => return None` in DNS discovery silently swallowed TempFail as "no record". This means a DNS outage causes messages to bypass DMARC entirely — a security vulnerability.

**Required behavior**: If DNS TXT lookup returns TempFail:
1. Do NOT treat as "no record"
2. Return `DmarcResult` with `disposition = Disposition::TempFail`
3. The caller can then decide to defer delivery (421) rather than accept

```rust
match resolver.query_txt(&dmarc_domain).await {
    Ok(records) => { /* parse and continue */ },
    Err(DnsError::NxDomain | DnsError::NoRecords) => { /* no policy, try org domain fallback */ },
    Err(DnsError::TempFail(msg)) => {
        return DmarcResult {
            disposition: Disposition::TempFail,
            reason: format!("DNS failure looking up {}: {}", dmarc_domain, msg),
            ..Default::default()
        };
    },
}
```

### DMARC record filtering from DNS
- DNS TXT may return multiple records
- Filter to records starting with `v=DMARC1;` (or `v=DMARC1` at end of string)
- 0 valid records: no policy
- 1 valid record: use it
- 2+ valid records: no policy (ambiguous, per RFC)

## Alignment contracts
- DKIM alignment: for each DkimResult::Pass, compare signature d= with From domain
  - Strict: exact match (case-insensitive)
  - Relaxed: organizational_domain(d=) == organizational_domain(from)
  - ANY passing+aligned signature -> DKIM alignment passes
- SPF alignment: SPF must have passed AND spf_domain aligns with From domain
  - Strict: exact match
  - Relaxed: org domain match
- DMARC passes if DKIM alignment OR SPF alignment passes

### organizational_domain for alignment
Use `psl::domain_str()` for both domains being compared. Both inputs must be normalized to lowercase before calling psl.

## Policy evaluation contracts
- Pass -> disposition Pass
- Fail -> select applicable policy:
  - From domain == record domain (org domain): use p=
  - From domain is existing subdomain: use sp= (fallback to p=)
  - From domain is non-existent subdomain (RFC 9091): use np= (fallback to sp=, then p=)
- Non-existent subdomain detection: DNS query for From domain A, AAAA, MX. If NxDomain for all three -> non-existent.
- pct= sampling: if pct < 100, randomly sample. Non-sampled failures -> disposition None (monitoring mode).

### Non-existent subdomain detection
Must query A, AAAA, and MX for the From domain. If ALL three return NxDomain -> domain is non-existent -> use np= policy.

**Parallelize with tokio::join!**:
```rust
let (a_result, aaaa_result, mx_result) = tokio::join!(
    resolver.query_a(from_domain),
    resolver.query_aaaa(from_domain),
    resolver.query_mx(from_domain),
);
let is_nonexistent = matches!(
    (&a_result, &aaaa_result, &mx_result),
    (Err(DnsError::NxDomain), Err(DnsError::NxDomain), Err(DnsError::NxDomain))
);
```

v1 made these 3 queries sequentially — parallelize them.

If ANY query returns TempFail, treat as "existence unknown" and fall back to sp= policy (not np=).

### pct= sampling implementation
For deterministic testing, use a seedable RNG or threshold comparison:
```rust
// Production
use rand::Rng;
let sample: u32 = rand::random_range(1..=100);  // rand 0.9 API
let apply_policy = sample <= pct;

// Testing: inject the random value or use a seeded RNG
```

**rand 0.9 API**: `random_range(1..=100)`, NOT `gen_range` (that's rand 0.8).

## DnsResolver sharing
DmarcEvaluator receives a resolver that is also used by SpfVerifier and DkimVerifier. Use the blanket `impl DnsResolver for &R` from M1:
```rust
pub struct DmarcEvaluator<R: DnsResolver> {
    resolver: R,  // Can be &HickoryResolver when called from EmailAuthenticator
}
```

## Message parsing for From header extraction
DmarcEvaluator needs the RFC5322.From domain. Parsing rules:
1. Split message at first `\r\n\r\n` to get headers
2. Find `From:` header (case-insensitive, handle folded continuation lines)
3. Extract email address: check for angle brackets FIRST (`<addr>`), THEN fall back to bare address
4. If multiple addresses (comma-separated), use the first one
5. Extract domain from the address (part after `@`)

**Gotcha from v1**: splitting by comma before checking angle brackets breaks addresses like `"Last, First" <user@example.com>`. Check angle brackets FIRST.

## Result contracts
- DmarcResult must carry: disposition (Pass/Quarantine/Reject/None/TempFail), dkim_alignment (Pass/Fail), spf_alignment (Pass/Fail), applied_policy, record (if found)
- Not a flat enum — structured with all evaluation details

## Review kill patterns
- np= parsed in M8 but never referenced during policy selection
- Non-existent subdomain detection absent (no DNS A/AAAA/MX probe)
- pct sampling always applies policy (ignores pct field)
- Alignment uses == instead of org_domain comparison for relaxed mode
- DmarcResult is flat enum without alignment/disposition details
- Fallback chain sp->p or np->sp->p not implemented
- DNS TempFail during record discovery treated as "no record" (SECURITY BUG)
- Non-existent subdomain queries made sequentially instead of parallel
- From header extraction splits by comma before checking angle brackets
- rand 0.8 API used (gen_range) instead of rand 0.9 (random_range)
- pct= sampling not testable (no way to inject deterministic random value)
- DnsResolver ownership prevents sharing across sub-verifiers (missing &R blanket impl)
