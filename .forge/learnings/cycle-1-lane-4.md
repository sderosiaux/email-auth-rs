# Learnings — Cycle 1, Lane 4: spf-evaluation

## FRICTION
- **DnsResolver trait `Send` bounds**: `async fn in trait` doesn't guarantee `Send` futures, which is required for `Pin<Box<dyn Future + Send>>` in `check_host_inner`. Had to change trait from `async fn` to `fn(...) -> impl Future<...> + Send`. This propagated through the blanket impl and MockResolver (src/common/dns.rs:39-48).
- **Void lookup propagation**: Spec learning §9.4 warned about `let _ = ctx.increment_void()` silently discarding errors. Used `ctx.increment_void()?` consistently in all mechanism evaluators (src/spf/eval.rs:230, 240, 279, 344).
- **Async recursion lifetime bounds**: `check_host_inner` needs `'a` lifetime on all parameters and `Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>>` return type. The `Box::pin(async move { ... })` pattern works cleanly (src/spf/eval.rs:103-108).

## GAP
- Spec doesn't clarify whether `check_host` should add the initial domain to the visited set before starting evaluation. Added it to prevent `redirect=same-domain` infinite loops (src/spf/eval.rs:95).
- Spec doesn't specify what happens if macro expansion fails in a mechanism domain-spec. Treated as PermError (consistent with "syntax error in domain" interpretation).
- Spec doesn't explicitly say whether `include:` child returning `None` maps to no-match or error. Learning §9.7 clarifies: `None` = no match (domain has no SPF, but that's not the parent's error).

## DECISION
- **`impl Future + Send` trait methods**: Chose over `async_trait` crate. More idiomatic Rust, avoids allocation overhead of `async_trait`'s `Box::pin` on every call. Trade-off: slightly more verbose trait definition.
- **Mechanism evaluators return `Result<bool, SpfResult>`**: `Ok(true)` = match, `Ok(false)` = no match, `Err(SpfResult)` = terminal error. This pattern cleanly separates match/no-match from error propagation, as confirmed by spec learning §9.8.2.
- **Counter increment BEFORE DNS query**: Spec learning §9.2 says increment first, check limit, then query. Implemented consistently in all DNS-querying mechanisms.
- **MX host DNS errors → skip, not fail**: Spec §3.6 says individual MX host resolution failures should not fail the entire mechanism. Used `if let Ok(addrs) = ...` pattern (src/spf/eval.rs:276-285).
- **exp= fetch is best-effort**: Any failure (DNS, macro expansion) silently returns `None`. Never promotes explanation fetch failure to a different result.

## SURPRISE
- `include:` child returning `Fail` maps to **no match** in the parent (not propagated as `Fail`). Only `Pass` from a child is a match. This is counterintuitive but correct per RFC 7208 §5.2.
- The `void_limit_exceeded` test was subtle: 3 `a:nope.com` mechanisms where nope.com doesn't exist → 3 DNS lookups (within limit) but 3 void lookups (exceeds limit of 2). The 3rd void lookup triggers PermError.
- Empty `redirect=` (no domain after `=`) correctly parsed by the parser, then caught in eval as empty expanded domain → PermError (src/spf/eval.rs:313).

## DEBT
- PTR mechanism doesn't count forward-confirmation lookups toward the DNS limit. RFC 7208 is ambiguous on this — the PTR mechanism itself counts as 1 DNS lookup, but the forward confirmations are part of that mechanism's internal operation. This matches common implementations.
- No explicit test for MX host DNS error → skip behavior. The MX test passes because the happy path works; a dedicated test with partial MX resolution failure would be ideal.
