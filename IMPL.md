# email-auth Implementation Spec

Rust library for email authentication: SPF, DKIM, DMARC.

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
hickory-resolver = "0.24"
ring = "0.17"              # RSA, Ed25519, SHA
base64 = "0.22"
publicsuffix = "2"
thiserror = "2"
tokio = { version = "1", features = ["rt-multi-thread"] }

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Milestones

### M1: Common Infrastructure
- [ ] `DnsResolver` trait with `query_txt`, `query_a`, `query_mx`
- [ ] `HickoryResolver` implementation
- [ ] `MockResolver` for testing
- [ ] Domain utilities: lowercase, trailing dot handling
- [ ] PSL integration: `organizational_domain()`

**Gate:** `cargo test common::`

### M2: SPF Core
- [ ] `SpfRecord` parsing (mechanisms + modifiers)
- [ ] `Mechanism` enum with qualifiers
- [ ] Macro expansion (`%{s}`, `%{d}`, `%{i}`, etc.)
- [ ] `check_host()` recursive evaluation
- [ ] DNS lookup limits (10 total, 2 void)
- [ ] All 7 result codes

**Gate:** `cargo test spf::` + real-world SPF records

### M3: DKIM Verification
- [ ] `DkimSignature` parsing (all tags)
- [ ] `DkimPublicKey` parsing from DNS
- [ ] Simple canonicalization (header + body)
- [ ] Relaxed canonicalization (header + body)
- [ ] Body hash computation with `l=` limit
- [ ] Header hash computation (bottom-up selection)
- [ ] RSA-SHA256 verification
- [ ] Ed25519-SHA256 verification

**Gate:** `cargo test dkim::` + verify Gmail/Microsoft signatures

### M4: DKIM Signing
- [ ] Private key loading (PEM)
- [ ] `DkimSigner` with config
- [ ] Sign and verify round-trip

**Gate:** Sign message, verify with external tool

### M5: DMARC
- [ ] `DmarcRecord` parsing (all tags incl. `np`)
- [ ] DNS discovery with org domain fallback
- [ ] DKIM alignment check (strict/relaxed)
- [ ] SPF alignment check (strict/relaxed)
- [ ] Policy evaluation (`p`, `sp`, `np`)
- [ ] `pct` sampling

**Gate:** `cargo test dmarc::` + real DMARC records

### M6: Combined API
- [ ] `EmailAuthenticator` struct
- [ ] `authenticate()` → `AuthenticationResult`
- [ ] Integration tests with real messages

**Gate:** Full SPF+DKIM+DMARC chain on test messages

## API Surface

```rust
// SPF
pub struct SpfVerifier { resolver: Arc<dyn DnsResolver> }
impl SpfVerifier {
    pub async fn check_host(&self, ip: IpAddr, domain: &str, sender: &str) -> SpfResult;
}

// DKIM
pub struct DkimVerifier { resolver: Arc<dyn DnsResolver> }
impl DkimVerifier {
    pub async fn verify(&self, message: &[u8]) -> Vec<DkimResult>;
}

pub struct DkimSigner { key: PrivateKey, config: SigningConfig }
impl DkimSigner {
    pub fn sign(&self, message: &[u8]) -> Result<String, SignError>;
}

// DMARC
pub struct DmarcVerifier { resolver: Arc<dyn DnsResolver>, psl: PublicSuffixList }
impl DmarcVerifier {
    pub async fn verify(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult;
}

// Combined
pub struct EmailAuthenticator { spf: SpfVerifier, dkim: DkimVerifier, dmarc: DmarcVerifier }
impl EmailAuthenticator {
    pub async fn authenticate(
        &self,
        message: &[u8],
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult;
}
```

## Error Strategy

- Parsing errors: `ParseError` with context
- DNS errors: `DnsError` (timeout, NXDOMAIN, SERVFAIL)
- Crypto errors: `CryptoError`
- All implement `std::error::Error`

## Test Data

Create `tests/fixtures/`:
- `spf/` — real SPF records from major providers
- `dkim/` — signed messages from Gmail, Microsoft, etc.
- `dmarc/` — real DMARC records

## Implementation Order

```
M1 → M2 → M3 → M5 → M6 → M4
     ↓         ↓
   [SPF]    [DKIM verify needed for DMARC]
```

M4 (signing) is optional, can defer.

## Spec References

- SPF details: `specs/01-SPF-RFC7208.md`
- DKIM details: `specs/02-DKIM-RFC6376.md`
- DMARC details: `specs/03-DMARC-RFC7489.md`
