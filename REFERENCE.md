# REFERENCE

Technical reference for the email-auth codebase.

## Architecture

```
EmailAuthenticator
  ├── SPF check_host()    ← MAIL FROM domain + client IP
  ├── DKIM verify()       ← message headers + body
  └── DMARC evaluate()    ← SPF result + DKIM result + From domain
        ├── alignment checks (strict/relaxed)
        ├── policy selection (p/sp/np)
        └── disposition (none/quarantine/reject)

Standalone:
  ├── ARC validate/seal   ← chain verification + new seal generation
  └── BIMI validate       ← DMARC eligibility + SVG/VMC validation
```

## Key Design Principles

- **Spec-driven**: Implementation derives from RFC specifications in `specs/`
- **DNS abstraction**: Caller provides `DnsResolver` trait impl (caching is caller responsibility)
- **No unwrap/expect**: All error paths explicit
- **Ground-truth testing**: Crypto operations validated against manual computations
- **Async/await throughout**: Full async support with `tokio`

## Modules

### `common`

- `DnsResolver` trait — async DNS queries abstraction
- Domain utilities — normalization, organizational domain (Public Suffix List)
- CIDR matching — IPv4/IPv6
- Mock resolver for testing

### `spf` (RFC 7208)

- Types: `SpfRecord`, `Directive`, `Mechanism`, `SpfResult`
- Parsing with macro expansion (%{s}, %{d}, %{i}, etc.)
- `check_host()` evaluation: include/redirect, MX/A/PTR mechanisms, DNS limits, cycle detection
- 120+ test cases

### `dkim` (RFC 6376)

- Types: `DkimSignature`, `DkimSigner`, `Algorithm`, `CanonicalizationMethod`, `DkimPublicKey`, `DkimResult`
- Signature header parsing (tag=value format, folding, base64)
- Key record parsing (selector._domainkey.domain DNS lookup)
- Canonicalization: simple and relaxed methods for headers and body
- Header selection (bottom-up), over-signing support, b= tag stripping
- **Signing**: RSA-SHA256 and Ed25519 key pair constructors
- **Verification**: RSA-SHA256, RSA-SHA1 (verification only), Ed25519 via `ring`
- Body hash verification with constant-time comparison
- Expiration checks, key constraints (h=, s=, t= tags)

### `dmarc` (RFC 7489)

- Types: `DmarcRecord`, `Policy`, `AlignmentMode`, `FailureOption`, `ReportUri`, `DmarcResult`, `Disposition`
- Record discovery: DNS TXT at `_dmarc.<domain>` with org-domain fallback
- Policy selection: `p=` / `sp=` / `np=` (RFC 9091) fallback chain
- Alignment: strict (exact domain) and relaxed (organizational domain) for both DKIM and SPF
- Non-existent subdomain detection (parallel A/AAAA/MX queries)
- Percentage sampling (pct= tag)
- **Reporting**: `AggregateReport` (XML, RFC 7489 Appendix C), `FailureReport` (AFRF format)
  - External report URI verification via `_report._dmarc.<domain>`
  - `fo=` filtering: 0 (all fail), 1 (any fail), d (DKIM fail), s (SPF fail)

### `arc` (RFC 8617)

- Types: `ArcSet`, `ArcSeal`, `ArcMessageSignature`, `ArcAuthenticationResults`, `ArcResult`
- Parsing: ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results (tag=value)
- Chain verification: sequential ARC-Set validation with instance counter checks
- Relaxed header canonicalization (only method supported for seals)
- **Sealing**: cv= determination (none/pass/fail), AAR+AMS+AS header construction
- Multi-hop chain roundtrips, body modification detection via oldest_pass

### `bimi`

- Types: `BimiRecord`, `BimiSelectorHeader`, `BimiResult`, `BimiValidationResult`
- Record parsing: v=, l=, a= tags, HTTPS URI enforcement
- Discovery: DNS TXT at `<selector>._bimi.<domain>` with org-domain fallback
- DMARC eligibility: enforcement policy check, pct=100, alignment verification
- SVG Tiny PS validation: baseProfile, prohibited elements (script, animations), XXE prevention, 32KB limit
- VMC certificate validation: X.509 chain, EKU OID, SAN matching, LogoType extension, logo hash

### `EmailAuthenticator` (`auth.rs`)

- Message parsing: header/body split, RFC 5322 comment stripping, folded header unfolding, bare LF handling
- From extraction: RFC 5322 address parsing (angle brackets, display names, comments)
- Combined pipeline: SPF → DKIM → DMARC
- Structured `AuthenticationResult`: individual results + extracted domains + disposition

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `ring` | Cryptography (RSA, Ed25519, SHA) |
| `hickory-resolver` | DNS resolution |
| `publicsuffix` | Organizational domain lookup |
| `base64` | DKIM/ARC signature encoding |
| `data-encoding` | Additional encoding support |
