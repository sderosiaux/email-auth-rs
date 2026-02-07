# M1: Common Infrastructure
Scope: src/common/, src/lib.rs
Depends on: nothing
RFCs: shared across 7208, 6376, 7489

## Contracts
- DnsResolver trait: async, Send+Sync, with query_txt, query_a, query_aaaa, query_mx, query_ptr, query_exists
- All DNS methods return Result<Vec<T>, DnsError> where DnsError distinguishes NxDomain vs NoRecords vs TempFail (timeout/servfail)
- HickoryResolver wraps hickory-resolver 0.25 (builder pattern, TokioConnectionProvider from name_server module)
- MockResolver for testing: HashMap-backed, supports configuring NxDomain/TempFail responses per query
- Domain utilities: lowercase normalization, trailing dot stripping, domain equality
- PSL: organizational_domain() using psl 2 crate (`psl::domain_str(&str)` returns `Option<&str>`)
- Shared result type shells defined here: SpfResult (7 variants), DkimResult (Pass/Fail/PermFail/TempFail/None with typed metadata), DmarcResult (structured with disposition, alignment details, policy)
- Error types: DnsError, ParseError as shared foundations
- This module is the interface contract. Once frozen, parallel milestones depend on exact signatures.

## DnsResolver trait design

### Blanket impl for references
Provide `impl<R: DnsResolver> DnsResolver for &R` so a single resolver can be shared across sub-verifiers without `Arc`. Each method delegates via UFCS to avoid infinite recursion:
```rust
impl<R: DnsResolver> DnsResolver for &R {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        <R as DnsResolver>::query_txt(self, name).await
    }
    // ... same for all methods
}
```
This pattern enables `EmailAuthenticator` to pass `&resolver` to `SpfVerifier`, `DkimVerifier`, and `DmarcEvaluator` without cloning.

### DnsError variants
```rust
pub enum DnsError {
    NxDomain,           // Domain does not exist (NXDOMAIN)
    NoRecords,          // Domain exists but no records of requested type
    TempFail(String),   // Transient failure (timeout, SERVFAIL)
}
```
The NxDomain vs NoRecords distinction matters for SPF void lookup counting (NxDomain counts, NoRecords counts, TempFail does not increment void counter but may propagate as TempError).

### DNS caching
DNS caching is explicitly CALLER responsibility, not library scope. The DnsResolver trait is stateless per query. Callers who need caching should wrap their resolver implementation.

## MockResolver design
- HashMap-backed with `MockDnsResponse<T>` enum: `Records(Vec<T>)`, `NxDomain`, `TempFail(String)`
- Missing keys default to `NxDomain` (not empty records)
- Domain normalization: lowercase + strip trailing dot before lookup
- PTR records keyed by IP address string (e.g., `"192.0.2.1"`)
- Must support all query types independently (a domain can have TXT records but NxDomain for A)

## PSL / organizational_domain
- Use `psl` crate v2 (NOT `publicsuffix` — different crate)
- API: `psl::domain_str(input)` returns `Option<&str>` — the registrable domain
- Input MUST be lowercase ASCII (normalize before calling)
- Returns `None` for TLDs themselves, IP addresses, and invalid input
- Use for DKIM relaxed alignment and DMARC relaxed alignment

## Result type design

### DkimResult typed enums
Do NOT use `Fail { reason: String }`. Use typed failure kinds:
```rust
pub enum FailureKind {
    BodyHashMismatch,
    SignatureVerificationFailed,
}

pub enum PermFailKind {
    MalformedSignature,
    KeyRevoked,
    KeyNotFound,
    ExpiredSignature,
    AlgorithmMismatch,
    HashNotPermitted,
    ServiceTypeMismatch,
    StrictModeViolation,
    DomainMismatch,
}
```
Pass variant carries: domain, selector, testing flag.
Fail variant carries: FailureKind.
PermFail variant carries: PermFailKind.

### DmarcResult Disposition
Must include `TempFail` variant for DNS failures during DMARC record discovery:
```rust
pub enum Disposition {
    Pass,
    Quarantine,
    Reject,
    None,       // No DMARC policy or monitoring mode
    TempFail,   // DNS failure during record lookup
}
```

## Key API gotchas (from v1 implementation)
- hickory 0.25: `Resolver::builder_with_config()`, not `Resolver::new()`
- hickory 0.25: `TokioConnectionProvider` from `hickory_resolver::name_server`
- hickory 0.25: NXDOMAIN detection via `e.is_nx_domain()`, NoRecords via `e.is_no_records_found()`
- hickory A/AAAA: access IP via `.0` on wrapper types
- psl 2: `psl::domain_str(&str)` returns `Option<&str>`, input must be normalized lowercase
- `#[derive(Clone)]` on HickoryResolver — the inner Resolver is cheaply cloneable
- MockResolver: use `normalize_domain()` helper that lowercases and strips trailing dot

## Review kill patterns
- Any DNS method missing from the trait that downstream milestones will need
- DnsError that doesn't distinguish NxDomain vs NoRecords vs transient failure
- Result types that are flat enums instead of carrying metadata (domain, selector, reason)
- MockResolver that can't simulate NxDomain distinctly from empty results
- DkimResult::Fail or DkimResult::PermFail using String instead of typed enum
- DmarcResult missing TempFail disposition variant
- Missing blanket `impl DnsResolver for &R`
- PSL function accepting non-normalized input without lowercasing
- MockResolver not normalizing domain case and trailing dots
