# Learnings — Cycle 1, Lane 10: dmarc-evaluation

## FRICTION
- **`rand` 0.9 API**: `rand::rng().random_range(0u8..100)` — the 0.9 API changed from `thread_rng().gen_range()` to `rng().random_range()`. Had to check crate docs.
- **`Policy::None` vs `Option::None`**: Continued from lane 9. In eval.rs, `Option::None` must be written explicitly in return positions where the type is `Option<Policy>`. Affects ~10 call sites in DmarcResult construction.

## GAP
- **Spec doesn't clarify TempFail on subdomain query vs org query**: If `_dmarc.sub.example.com` returns TempFail, should we fall back to org domain? Chose NO — TempFail on the first query immediately returns TempFail disposition. Rationale: spec §6.6.3 says DNS TempFail must not be treated as "no record", and falling through would violate this. The subdomain might have its own stricter policy.
- **`is_non_existent_domain` with TempFail**: If A returns TempFail but AAAA/MX return NxDomain, the domain is NOT considered non-existent (conservative). Only all-three-NxDomain triggers the non-existent path. This is spec-compliant: "any other result → domain exists."

## DECISION
- **`evaluate_with_roll` for deterministic testing**: Public `evaluate()` generates random roll internally. Test-visible `pub(crate) evaluate_with_roll()` accepts `Option<u8>`. This avoids exposing test internals in the public API while enabling deterministic pct= tests.
- **`_is_org_domain_record` tracked but unused**: The discovery result tracks whether the record came from org-domain fallback. Currently unused but will be needed by reporting (lane 11) to determine the effective domain. Prefixed with `_` to suppress warning.
- **`tokio::join!` for non-existent detection**: Three DNS queries (A, AAAA, MX) run in parallel via `tokio::join!`. MockResolver handles this trivially since it's synchronous underneath, but real resolvers benefit from parallelism.

## SURPRISE
- The evaluator is clean — all domain utilities (`organizational_domain`, `domains_equal`, `is_subdomain_of`) were already battle-tested from lane 1. Zero bugs in alignment logic on first pass.
- `DmarcRecord::parse` from lane 9 integrated without any changes. The parser's defaults (sp= defaults to p=, pct defaults to 100) mean the evaluator has minimal defaulting logic.

## DEBT
- None. All 50 async tests + 10 sync tests pass. The evaluator handles all spec-mandated flows: discovery with fallback, alignment (strict/relaxed for DKIM and SPF independently), policy selection (p=/sp=/np= with fallback chain), pct sampling, and TempFail security.
