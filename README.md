# email-auth

A Rust email authentication library implementing SPF, DKIM, DMARC, ARC, and BIMI.

## Current Status

**Cycle 1 — Lane 12: ARC Parsing & Validation Complete**

| Component | Status |
|-----------|--------|
| **Common** | ✅ DNS resolver trait, domain utilities (PSL integration), CIDR matching |
| **SPF** | ✅ Complete: types, parsing, macros, evaluation algorithm |
| **DKIM** | ✅ Complete: types, parsing, canonicalization, verification, signing |
| **DMARC** | ✅ Complete: evaluation, policy selection, alignment checks, sampling, aggregate/failure reporting |
| **ARC** | ✅ Complete: types, parsing, validation (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results) |
| **BIMI** | ⏳ Pending |

## Getting Started

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
email-auth = "0.1.0"
```

### Requirements

- Rust 1.63+
- Tokio async runtime
- Ring cryptography library (RSA, Ed25519, SHA)
- Hickory DNS resolver (or implement `DnsResolver` trait)

## Key Design Principles

- **Spec-driven**: Implementation derives from RFC specifications in `specs/`
- **DNS caching optional**: Caller responsibility via `DnsResolver` trait
- **No unwrap/expect in library code**: All error paths explicit
- **Ground-truth testing**: Crypto operations validated against manual computations
- **Async/await throughout**: Full async support with `tokio`

## Implemented Modules

### `common`

- `DnsResolver` trait for abstraction (async DNS queries)
- Domain utilities: normalization, organizational domain (via Public Suffix List)
- CIDR matching for IPv4/IPv6
- Mock resolver for testing

### `spf`

- Full SPF RFC 7208 implementation
- Types: `SpfRecord`, `Directive`, `Mechanism`, `SpfResult`
- Parsing with macro expansion (%{s}, %{d}, %{i}, etc.)
- `check_host()` evaluation: include/redirect, MX/A/PTR mechanisms, DNS limits, cycle detection
- 120+ test cases covering all edge cases

### `dkim`

- Types: `DkimSignature`, `DkimSigner`, `Algorithm`, `CanonicalizationMethod`, `DkimPublicKey`, `DkimResult`
- Signature header parsing (tag=value format, folding, base64)
- Key record parsing (selector._domainkey.domain DNS lookup)
- Canonicalization: simple and relaxed methods for headers and body, line-ending normalization
- Header selection (bottom-up), over-signing support, b= tag stripping
- **Signing**: RSA-SHA256 and Ed25519 key pair constructors, header selection, body hash generation, signature generation
- **Verification**: RSA-SHA256, RSA-SHA1 (verification only), Ed25519 with crypto validation via `ring`
- Body hash verification with constant-time comparison
- Expiration checks, key constraints (h=, s=, t= tags)
- Timestamp/expiration generation (t= and x= tags)

### `dmarc`

- Types: `DmarcRecord`, `Policy`, `AlignmentMode`, `FailureOption`, `ReportUri`, `DmarcResult`, `Disposition`
- DMARC record parsing: policy, subdomain policy, alignment modes, failure reporting options, report URIs
- Record discovery: DNS TXT lookup at `_dmarc.<domain>` with organizational domain fallback, TempFail disposition handling
- Policy selection with `p=` / `sp=` / `np=` (RFC 9091 non-existent subdomain policy) fallback chain
- Alignment checks: strict (exact domain match) and relaxed (organizational domain match)
- DKIM alignment: `d=` domain of passing DKIM signature against From domain
- SPF alignment: `SPF Pass` result domain against From domain
- Non-existent subdomain detection (parallel A/AAAA/MX queries)
- Percentage sampling (pct= tag): deterministic random 0-99 range, per-message evaluation
- **Reporting**: `AggregateReport` with XML serialization (RFC 7489 Appendix C schema), `FailureReport` with AFRF format
  - External report URI verification via DNS `_report._dmarc.<domain>` queries
  - `fo=` filtering: 0 (all fail), 1 (any fail), d (DKIM fail), s (SPF fail)
  - Multipart MIME assembly for failure reports

### `arc`

- Types: `ArcSet`, `ArcSeal`, `ArcMessageSignature`, `ArcAuthenticationResults`, `ArcResult`
- **Parsing**: ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results header parsing (tag=value format)
- **Validation**: Instance validation (monotonically increasing CV chain), header tag requirements
  - ARC-Seal: b= tag stripped for signature verification, no h= or body hash (unlike DKIM)
  - ARC-Message-Signature: DKIM-compatible signature format with d=, s=, and required tags
  - ARC-Authentication-Results: structured header parsing with auth method results
- **Chain Verification**: Sequential ARC-Set chain validation with instance counter checks
- Relaxed header canonicalization for ARC seals (only method supported)
- Signature verification integrated with `ring` crypto library

## Development

### Running Tests

```bash
cargo test
```

### Project Structure

```
specs/              # RFC specifications (source of truth)
src/
  lib.rs           # Library root
  common/          # Shared utilities
  spf/             # SPF module
  dkim/            # DKIM module
  dmarc/           # DMARC module
  arc/             # ARC module
.forge/
  state.yaml       # Forge build state
  lanes.yaml       # Work lane definitions
```

## Security Considerations

- **DNS validation**: Implement DNS response validation at resolver layer
- **RSA key size**: Library enforces minimum 1024-bit, recommends 2048+
- **Clock skew**: Configurable expiration tolerance for DKIM/ARC timestamps
- **BIMI SVG**: 32KB size limit, XXE prevention, script injection blocking
- **PTR verification**: Forward confirmation required (expensive — cache aggressively)

## License

Dual-licensed: MIT OR Apache-2.0
