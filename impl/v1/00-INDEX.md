# Email Authentication Library Specs

> Implementation specifications for RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)

## Quick Status

| Module | Parsing | Logic | Tests | Status |
|--------|---------|-------|-------|--------|
| Common | [ ] | [ ] | [ ] | Not started |
| SPF | [ ] | [ ] | [ ] | Not started |
| DKIM | [ ] | [ ] | [ ] | Not started |
| DMARC | [ ] | [ ] | [ ] | Not started |

## Specification Files

| File | RFC | Description | Est. Lines |
|------|-----|-------------|------------|
| [01-SPF-RFC7208.md](./01-SPF-RFC7208.md) | 7208 | Sender Policy Framework | ~800 |
| [02-DKIM-RFC6376.md](./02-DKIM-RFC6376.md) | 6376 | DomainKeys Identified Mail | ~1500 |
| [03-DMARC-RFC7489.md](./03-DMARC-RFC7489.md) | 7489 | DMARC Policy & Alignment | ~500 |

## Implementation Order

```
1. Common Infrastructure
   └── DNS resolver trait
   └── Domain utilities
   └── Public Suffix List

2. SPF (simplest, no crypto)
   └── Record parsing
   └── Macro expansion
   └── check_host() evaluation

3. DKIM (most complex)
   └── Signature parsing
   └── Canonicalization
   └── Crypto verification
   └── DNS key lookup

4. DMARC (ties it together)
   └── Record parsing
   └── Alignment checks
   └── Policy evaluation

5. Combined API
   └── EmailAuthenticator
   └── Full message authentication
```

## Checkpoint Progress

### Phase 1: Foundation
- [ ] Create crate structure
- [ ] Define error types
- [ ] Implement DNS resolver trait
- [ ] Implement Public Suffix List
- [ ] Add domain utilities

### Phase 2: SPF
- [ ] SPF record parsing
- [ ] SPF macro expansion
- [ ] SPF mechanism evaluation
- [ ] SPF check_host() algorithm
- [ ] SPF unit tests

### Phase 3: DKIM
- [ ] DKIM signature parsing
- [ ] DKIM key record parsing
- [ ] Simple canonicalization
- [ ] Relaxed canonicalization
- [ ] RSA-SHA256 verification
- [ ] Ed25519 verification
- [ ] DKIM signing API
- [ ] DKIM unit tests

### Phase 4: DMARC
- [ ] DMARC record parsing
- [ ] Organizational domain lookup
- [ ] DKIM alignment check
- [ ] SPF alignment check
- [ ] Policy evaluation
- [ ] DMARC unit tests

### Phase 5: Integration
- [ ] Combined EmailAuthenticator
- [ ] Integration tests
- [ ] Real-world message tests
- [ ] Documentation
- [ ] Publish to crates.io

## Key Design Decisions

### Async First
All DNS operations are async. Sync wrappers provided via `block_on`.

### Trait-Based DNS
```rust
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn query_txt(&self, domain: &str) -> Result<Vec<String>, DnsError>;
    async fn query_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError>;
    async fn query_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DnsError>;
    async fn query_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError>;
    async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError>;
}
```

### Error Handling
Each module has specific error types that impl `std::error::Error`.
Top-level `AuthError` wraps all sub-errors.

### Feature Flags
```toml
[features]
default = ["spf", "dkim", "dmarc"]
spf = []
dkim = ["dep:ring"]
dmarc = ["spf", "dkim", "dep:psl"]
signing = ["dkim"]
reporting = ["dmarc", "dep:quick-xml"]
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `hickory-resolver` | Async DNS |
| `ring` | Cryptography (RSA, Ed25519, SHA) |
| `base64` | Encoding |
| `psl` | Public Suffix List |
| `async-trait` | Async traits |
| `thiserror` | Error types |
| `quick-xml` | Report generation (optional) |
| `flate2` | Gzip compression (optional) |

## Reference Materials

- [RFC 7208 - SPF](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 6376 - DKIM](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 7489 - DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [RFC 8463 - Ed25519 for DKIM](https://datatracker.ietf.org/doc/html/rfc8463)
- [RFC 9091 - DMARC np tag](https://datatracker.ietf.org/doc/html/rfc9091)
- [Public Suffix List](https://publicsuffix.org/)
