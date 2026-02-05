# email-auth Implementation Spec

Rust library for email authentication: SPF, DKIM, DMARC.

## Status

| Milestone | Status |
|-----------|--------|
| M1: Common Infrastructure | ✓ |
| M2: SPF Core | ✓ |
| M3: DKIM Verification | ✓ |
| M4: DKIM Signing | ✓ |
| M5: DMARC | ✓ |
| M6: Combined API | ✓ |

## Sub-Specs

| Milestone | Spec | Coverage |
|-----------|------|----------|
| M2: SPF Core | specs/01-SPF-RFC7208.md | ✓ |
| M3: DKIM Verification | specs/02-DKIM-RFC6376.md | ✓ |
| M4: DKIM Signing | specs/02-DKIM-RFC6376.md | ✓ |
| M5: DMARC | specs/03-DMARC-RFC7489.md | ✓ |

Coverage: `⬚` not started, `◐` partial (impl done, not verified), `✓` verified against spec

**Note**: M1 and M6 have no dedicated sub-spec (covered by main IMPL tasks).

## Crate Structure

```
email-auth/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Re-exports
│   ├── common/
│   │   ├── mod.rs
│   │   ├── dns.rs       # DnsResolver trait + hickory impl
│   │   ├── domain.rs    # Domain parsing, case normalization
│   │   └── psl.rs       # Public Suffix List (org domain)
│   ├── spf/
│   │   ├── mod.rs       # SpfVerifier, public API
│   │   ├── record.rs    # SpfRecord parsing
│   │   ├── mechanism.rs # Mechanism types
│   │   ├── macro_exp.rs # Macro expansion
│   │   └── eval.rs      # check_host() algorithm
│   ├── dkim/
│   │   ├── mod.rs       # DkimVerifier, DkimSigner
│   │   ├── signature.rs # DKIM-Signature parsing
│   │   ├── key.rs       # DNS key record parsing
│   │   ├── canon.rs     # Canonicalization (simple/relaxed)
│   │   ├── hash.rs      # Body hash, header hash
│   │   └── crypto.rs    # RSA, Ed25519 verification/signing
│   ├── dmarc/
│   │   ├── mod.rs       # DmarcVerifier
│   │   ├── record.rs    # DMARC record parsing
│   │   ├── alignment.rs # DKIM/SPF alignment checks
│   │   └── policy.rs    # Policy evaluation
│   └── auth.rs          # EmailAuthenticator (combined)
```

## Dependencies

```toml
[dependencies]
hickory-resolver = "0.25"  # NOTE: API changed from 0.24
ring = "0.17"
base64 = "0.22"
publicsuffix = "2"
thiserror = "2"
tokio = { version = "1", features = ["rt-multi-thread"] }
rand = "0.9"  # For DMARC pct sampling
```

## Milestones

### M1: Common Infrastructure
- [x] `DnsResolver` trait with `query_txt`, `query_a`, `query_mx`
- [x] `HickoryResolver` implementation
- [x] `MockResolver` for testing
- [x] Domain utilities: lowercase, trailing dot handling
- [x] PSL integration: `organizational_domain()`

### M2: SPF Core
- [x] `SpfRecord` parsing (mechanisms + modifiers)
- [x] `Mechanism` enum with qualifiers
- [x] Macro expansion (`%{s}`, `%{d}`, `%{i}`, etc.)
- [x] `check_host()` recursive evaluation
- [x] DNS lookup limits (10 total, 2 void)
- [x] All 7 result codes

### M3: DKIM Verification
- [x] `DkimSignature` parsing (all tags)
- [x] `DkimPublicKey` parsing from DNS
- [x] Simple canonicalization (header + body)
- [x] Relaxed canonicalization (header + body)
- [x] Body hash computation with `l=` limit
- [x] Header hash computation (bottom-up selection)
- [x] RSA-SHA256 verification
- [x] Ed25519-SHA256 verification
- [x] RSA-SHA1 verification (for legacy)

### M4: DKIM Signing
- [x] Private key loading (PEM, DER, PKCS8)
- [x] `DkimSigner` with `SigningConfig`
- [x] Sign and verify round-trip (RSA-SHA256, Ed25519)

### M5: DMARC
- [x] `DmarcRecord` parsing (all tags incl. `np`)
- [x] DNS discovery with org domain fallback
- [x] DKIM alignment check (strict/relaxed)
- [x] SPF alignment check (strict/relaxed)
- [x] Policy evaluation (`p`, `sp`, `np`)
- [x] `pct` sampling

### M6: Combined API
- [x] `EmailAuthenticator` struct
- [x] `authenticate()` → `AuthenticationResult`
- [x] From header extraction

## API Surface

```rust
// SPF
pub struct SpfVerifier<R: DnsResolver> { ... }
impl<R: DnsResolver> SpfVerifier<R> {
    pub async fn check_host(&self, ip: IpAddr, domain: &str, sender: &str) -> SpfResult;
}

// DKIM
pub struct DkimVerifier<R: DnsResolver> { ... }
impl<R: DnsResolver> DkimVerifier<R> {
    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult>;
}

// DMARC
pub struct DmarcVerifier<R: DnsResolver> { ... }
impl<R: DnsResolver> DmarcVerifier<R> {
    pub async fn verify(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult;
}

// Combined
pub struct EmailAuthenticator<R: DnsResolver> { ... }
impl<R: DnsResolver> EmailAuthenticator<R> {
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult;
}
```

## Implementation Notes

### Learned from M1+M2
- hickory-resolver 0.25 uses builder pattern: `Resolver::builder_with_config(...).build()`
- A/AAAA lookups return wrapper types, access via `.0`
- Use `impl Future` in trait (Rust 1.75+) instead of async-trait crate
- NXDOMAIN → SpfResult::None, other DNS errors → TempError

### Learned from M3
- ring RSA verification takes raw message (header hash), not hash of hash
- Header parsing requires careful handling of continuation lines
- b= tag removal must avoid affecting bh= tag
- Default clock skew: 5 minutes

### Learned from M5+M6
- From header extraction fallback to SPF domain
- rand crate for pct sampling

## Learnings
### Crate/API Gotchas
- hickory-resolver 0.25: use `Resolver::builder_with_config()`, not `Resolver::new()`
- hickory-resolver 0.25: `TokioConnectionProvider` import from `name_server` submodule, NOT crate root
- hickory A/AAAA: access IP via `.0` on wrapper types
- hickory Resolver implements Clone (wrap in struct and derive Clone)
- ring RSA: verify(message, signature) where message is raw data, not pre-hashed
- ring signature: use `&'static dyn VerificationAlgorithm` for generic RSA verification
- publicsuffix 2: call `list.domain()` directly, not `suffix.domain()`
- publicsuffix 2: use `and_then()` not `map().flatten()` (clippy::map_flatten)
- rand 0.9: use `rng.random_range(1..=100)` not `gen_range`

### Design Decisions
- Use `impl Future` in traits instead of async-trait crate (Rust 1.75+)
- NXDOMAIN → None result, SERVFAIL/timeout → TempError
- Recursive async requires `Box::pin()` for self-referential calls
- EmailAuthenticator requires Clone on resolver (clone for each sub-verifier)

### Patterns That Worked
- Tag-value parsing: split on `;`, then `=`, trim whitespace
- Header continuation: unfold before parsing
- b= removal: careful string iteration to avoid affecting bh= tag
- DKIM relaxed canonicalization: no space after colon per RFC 6376

### Clippy Compliance (Rust)
- Prefer `Display` trait over inherent `to_string()` methods (clippy::inherent_to_string)
- Use `for x in iter.by_ref()` not `while let Some(x) = iter.next()` (clippy::while_let_on_iterator)
- Use `and_then()` not `map().flatten()` (clippy::map_flatten)
- Use `or_else()` not `map().or()` pattern (clippy::manual_map)
- Combine identical `if/else` branches (clippy::if_same_then_else)

### Test Data Validation
- Base64 in tests must be valid (use `dGVzdA==` not `abc123==`)
- RSA keys must be valid: generate with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`
- Ed25519 keys: generate with `openssl genpkey -algorithm Ed25519`

## Spec References

- SPF details: `specs/01-SPF-RFC7208.md`
- DKIM details: `specs/02-DKIM-RFC6376.md`
- DMARC details: `specs/03-DMARC-RFC7489.md`
