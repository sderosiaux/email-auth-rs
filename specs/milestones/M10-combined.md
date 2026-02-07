# M10: Combined API + Integration Tests
Scope: src/auth.rs, src/lib.rs, tests/
Depends on: M3, M7, M9
RFC: all

## Combined API contracts
- EmailAuthenticator struct: holds resolver, configurable clock skew
- authenticate(message: &[u8], client_ip, helo, mail_from) -> AuthenticationResult
- Flow: extract From header -> SPF check_host -> DKIM verify all signatures -> DMARC evaluate
- From header extraction: parse message headers, find From:, extract domain. Handle malformed (missing From -> use mail_from domain as fallback).
- AuthenticationResult: spf_result, dkim_results (Vec), dmarc_result — all structured with full metadata

## Crate structure
```
email-auth/
├── src/
│   ├── lib.rs          # Re-exports only
│   ├── auth.rs         # EmailAuthenticator, AuthenticationResult
│   ├── common/
│   │   ├── mod.rs
│   │   ├── dns.rs      # DnsResolver trait, HickoryResolver, MockResolver
│   │   ├── domain.rs   # Domain utilities
│   │   └── psl.rs      # organizational_domain via psl crate
│   ├── spf/
│   │   ├── mod.rs      # SpfResult, SpfVerifier
│   │   ├── record.rs   # SpfRecord parsing
│   │   ├── mechanism.rs # Mechanism types
│   │   ├── macro_exp.rs # Macro expansion
│   │   └── eval.rs     # check_host evaluation engine
│   ├── dkim/
│   │   ├── mod.rs      # DkimResult, FailureKind, PermFailKind
│   │   ├── signature.rs # DkimSignature parsing
│   │   ├── key.rs      # DkimPublicKey parsing
│   │   ├── canon.rs    # Canonicalization
│   │   ├── verify.rs   # DkimVerifier
│   │   └── sign.rs     # DkimSigner
│   └── dmarc/
│       ├── mod.rs      # DmarcResult, Disposition
│       ├── record.rs   # DmarcRecord parsing
│       └── eval.rs     # DmarcEvaluator
├── tests/
│   └── integration.rs  # Full-stack integration tests
├── specs/              # This directory
└── Cargo.toml
```

## DnsResolver sharing pattern
EmailAuthenticator owns a single resolver instance and passes references to sub-verifiers:
```rust
pub struct EmailAuthenticator<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub async fn authenticate(&self, ...) -> AuthenticationResult {
        // &self.resolver implements DnsResolver via blanket impl
        let spf = SpfVerifier::new(&self.resolver);
        let dkim = DkimVerifier::new(&self.resolver, self.clock_skew);
        let dmarc = DmarcEvaluator::new(&self.resolver);
        // ...
    }
}
```

## From header extraction (CRITICAL)
Message parsing rules for extracting the RFC5322.From domain:

1. **Split headers from body**: find first `\r\n\r\n`. Everything before is headers, after is body.
2. **Unfold headers**: join lines where continuation starts with whitespace (SP or HTAB)
3. **Find From header**: case-insensitive match on `from:`
4. **Extract email address**:
   - Check for angle brackets `<...>` FIRST
   - If found: extract address from within angle brackets
   - If not found: use the entire value (trimmed) as the address
   - For multiple addresses (group syntax): use the FIRST address
5. **Extract domain**: part after `@`

### Gotcha: comma in display name
`"Last, First" <user@example.com>` — splitting by comma before checking angle brackets would incorrectly split the display name. Always check angle brackets FIRST.

### Fallback for missing From
If no From header found, use the MAIL FROM domain as fallback for DMARC evaluation. Log a warning but don't fail.

## Error isolation
Each protocol runs independently. A failure in one MUST NOT prevent the others from completing:
```rust
let spf_result = spf_verifier.check_host(...).await;
// SPF error does NOT stop DKIM/DMARC
let dkim_results = dkim_verifier.verify_all(...).await;
// DKIM error does NOT stop DMARC
let dmarc_result = dmarc_evaluator.evaluate(...).await;
```

If SPF returns TempError, DKIM and DMARC still run. DMARC uses whatever SPF result it got.

## Integration test contracts
- Ground-truth fixtures: real email messages with known authentication results
- Each fixture includes: raw message bytes, client_ip, helo, mail_from, expected spf/dkim/dmarc results
- Mock DNS snapshots: pre-configured resolver with all DNS records needed for each fixture
- Tests must validate: correct result type AND correct metadata (domain, selector, reason)

### Ground-truth fixture structure
Use `specs/ground-truth/dns-fixtures.json` for frozen DNS mock data. Each test case:
1. Constructs a MockResolver with the fixture DNS data
2. Constructs a raw email message (or loads from fixture)
3. Runs EmailAuthenticator::authenticate()
4. Asserts specific result variants AND metadata fields

### Required test scenarios
- SPF pass with ip4 mechanism
- SPF fail with -all
- SPF softfail
- SPF TempError (DNS failure)
- SPF PermError (circular include, >10 lookups)
- DKIM pass (RSA-SHA256, relaxed/relaxed)
- DKIM pass (Ed25519-SHA256)
- DKIM fail (body modified)
- DKIM fail (header modified)
- DKIM PermFail (key revoked)
- DKIM PermFail (expired signature)
- DMARC pass (DKIM aligned)
- DMARC pass (SPF aligned)
- DMARC fail with quarantine policy
- DMARC fail with reject policy
- DMARC none (no record)
- DMARC TempFail (DNS failure)
- Full combined: SPF+DKIM+DMARC pass
- Full combined: mixed results (SPF fail, DKIM pass, DMARC pass via DKIM)

## Re-exports (lib.rs)
- All public types accessible from crate root: SpfVerifier, DkimVerifier, DkimSigner, DmarcEvaluator, EmailAuthenticator
- Result types: SpfResult, DkimResult, DmarcResult, AuthenticationResult, Disposition
- Config types: DnsResolver, HickoryResolver
- Do NOT re-export internal parsing types (SpfRecord, DkimSignature, DkimPublicKey, DmarcRecord — these are implementation details)

## Review kill patterns
- From header parsing missing or naive (doesn't handle folded headers, comments, multiple addresses)
- AuthenticationResult missing structured fields (just wraps flat enums)
- Integration tests use sign-then-verify (self-consistent) without external fixtures
- Error in one protocol (e.g. SPF TempError) crashes entire authentication instead of partial results
- DnsResolver not shared (cloned or re-created per sub-verifier)
- From extraction splits comma before checking angle brackets
- Missing fallback for absent From header
- Re-exports expose internal parsing types
- Ground-truth DNS fixtures not used in integration tests
