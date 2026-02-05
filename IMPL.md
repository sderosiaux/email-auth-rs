# email-auth Implementation Spec

Rust library for email authentication: SPF, DKIM, DMARC.

## Status

| Milestone | Status |
|-----------|--------|
| M1: Common Infrastructure | ✅ Complete |
| M2: SPF Core | ✅ Complete |
| M3: DKIM Verification | ✅ Complete |
| M4: DKIM Signing | ⏸️ Deferred |
| M5: DMARC | ✅ Complete |
| M6: Combined API | ✅ Complete |

**75 tests passing**

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

### M1: Common Infrastructure ✅
- [x] `DnsResolver` trait with `query_txt`, `query_a`, `query_mx`
- [x] `HickoryResolver` implementation
- [x] `MockResolver` for testing
- [x] Domain utilities: lowercase, trailing dot handling
- [x] PSL integration: `organizational_domain()`

### M2: SPF Core ✅
- [x] `SpfRecord` parsing (mechanisms + modifiers)
- [x] `Mechanism` enum with qualifiers
- [x] Macro expansion (`%{s}`, `%{d}`, `%{i}`, etc.)
- [x] `check_host()` recursive evaluation
- [x] DNS lookup limits (10 total, 2 void)
- [x] All 7 result codes

### M3: DKIM Verification ✅
- [x] `DkimSignature` parsing (all tags)
- [x] `DkimPublicKey` parsing from DNS
- [x] Simple canonicalization (header + body)
- [x] Relaxed canonicalization (header + body)
- [x] Body hash computation with `l=` limit
- [x] Header hash computation (bottom-up selection)
- [x] RSA-SHA256 verification
- [x] Ed25519-SHA256 verification
- [x] RSA-SHA1 verification (for legacy)

### M4: DKIM Signing ⏸️
- [ ] Private key loading (PEM)
- [ ] `DkimSigner` with config
- [ ] Sign and verify round-trip

### M5: DMARC ✅
- [x] `DmarcRecord` parsing (all tags incl. `np`)
- [x] DNS discovery with org domain fallback
- [x] DKIM alignment check (strict/relaxed)
- [x] SPF alignment check (strict/relaxed)
- [x] Policy evaluation (`p`, `sp`, `np`)
- [x] `pct` sampling

### M6: Combined API ✅
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

## Spec References

- SPF details: `specs/01-SPF-RFC7208.md`
- DKIM details: `specs/02-DKIM-RFC6376.md`
- DMARC details: `specs/03-DMARC-RFC7489.md`
