# email-auth

A Rust library implementing email authentication protocols: SPF, DKIM, DMARC, ARC, and BIMI.

## Installation

```toml
[dependencies]
email-auth = "0.1.2"
```

Requires Rust edition 2024 (Rust 1.85+) and Tokio.

## Quick Start

```rust
use email_auth::{EmailAuthenticator, AuthenticationResult};
use email_auth::dmarc::Disposition;

// Implement DnsResolver for your DNS backend (see below)
let auth = EmailAuthenticator::new(resolver, "mx.yourhost.com");

let result = auth.authenticate(
    raw_message,             // &[u8] — raw RFC 5322 message
    "203.0.113.1".parse()?,  // IpAddr — connecting client IP
    "mail.sender.com",       // &str  — EHLO/HELO identity
    "sender@example.com",    // &str  — MAIL FROM (envelope)
).await?;

match result.dmarc.disposition {
    Disposition::Pass      => { /* deliver */ }
    Disposition::Reject    => { /* reject */ }
    Disposition::Quarantine => { /* spam folder */ }
    Disposition::None      => { /* no policy, deliver */ }
    Disposition::TempFail  => { /* retry later */ }
}
```

## DNS Resolver

The library is DNS-backend agnostic. Implement the `DnsResolver` trait:

```rust
use email_auth::common::dns::{DnsError, DnsResolver, MxRecord};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

struct MyResolver { /* ... */ }

impl DnsResolver for MyResolver {
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> { todo!() }
    async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> { todo!() }
    async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> { todo!() }
    async fn query_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError> { todo!() }
    async fn query_ptr(&self, ip: &IpAddr) -> Result<Vec<String>, DnsError> { todo!() }
    async fn query_exists(&self, name: &str) -> Result<bool, DnsError> { todo!() }
}
```

DNS caching is the caller's responsibility — implement it at the resolver layer.

## Individual Protocols

Each protocol can be used independently:

### SPF

```rust
use email_auth::spf::{check_host, SpfResult};

let result = check_host(
    &resolver,
    client_ip,
    "mail.sender.com",       // HELO
    "sender@example.com",    // MAIL FROM
    "example.com",           // domain to check
    "mx.receiver.com",       // receiver
).await;

match result {
    SpfResult::Pass    => { /* authorized */ }
    SpfResult::Fail { explanation } => { /* reject */ }
    SpfResult::SoftFail => { /* suspicious */ }
    SpfResult::Neutral  => { /* no assertion */ }
    SpfResult::None     => { /* no SPF record */ }
    SpfResult::TempError => { /* DNS failure, retry */ }
    SpfResult::PermError => { /* policy error */ }
}
```

### DKIM

```rust
use email_auth::dkim::{DkimVerifier, DkimResult};

let verifier = DkimVerifier::new(resolver);
let results = verifier.verify_message(headers, body).await;
// headers: &[(&str, &str)] — (name, value) pairs
// body:    &[u8]

for result in &results {
    match result {
        DkimResult::Pass { domain, selector } => { /* verified */ }
        DkimResult::PermFail { kind, detail }  => { /* bad signature */ }
        DkimResult::TempFail { detail }        => { /* DNS error */ }
        DkimResult::None                       => { /* no signatures */ }
    }
}
```

### DMARC

```rust
use email_auth::dmarc::DmarcEvaluator;

let evaluator = DmarcEvaluator::new(resolver);
let result = evaluator.evaluate(
    "example.com",   // RFC5322.From domain
    &spf_result,
    "example.com",   // SPF domain (MAIL FROM or HELO)
    &dkim_results,
).await;
```

### ARC

```rust
use email_auth::arc::{ArcValidator, ArcSealer};

// Validate incoming ARC chain
let validator = ArcValidator::new(resolver);
let chain_result = validator.validate(headers, body).await;

// Seal outgoing message (as intermediary)
let sealer = ArcSealer::new(private_key, "selector", "example.com");
let new_headers = sealer.seal(headers, body, &auth_results).await?;
```

### BIMI

```rust
use email_auth::bimi::BimiVerifier;

let verifier = BimiVerifier::new(resolver);
let result = verifier.discover(
    "example.com",   // author domain
    None,            // selector (None = "default")
    &dmarc_result,   // must be Pass + quarantine/reject + pct=100
).await;
```

## RFC Compliance

| Protocol | RFC | Status |
|----------|-----|--------|
| SPF      | RFC 7208 | Full — including void lookup limits, include/redirect semantics, macro expansion |
| DKIM     | RFC 6376 | Full — RSA-SHA256, Ed25519, relaxed/simple canonicalization, key revocation |
| DMARC    | RFC 7489 | Full — alignment, pct sampling, subdomain/np= policy, reporting URIs |
| ARC      | RFC 8617 | Full — chain validation, oldest-pass algorithm, sealing |
| BIMI     | draft-bimi | Record discovery, SVG Tiny PS validation, VMC certificate chain |

## Security Considerations

- **SPF**: DNS lookup limit (10) and void lookup limit (2) enforced per RFC 7208 §4.6.4
- **DKIM**: Minimum RSA key size 1024-bit; `t=s` strict mode enforced; clock skew configurable
- **DMARC**: `p=reject` outside pct sample correctly downgrades to quarantine (not none)
- **SVG**: 32KB size limit, XXE prevention via `<!ENTITY>` detection, script/event handler rejection
- **ARC**: Forward-confirmed PTR validation; chain integrity verified before oldest-pass selection

## License

Dual-licensed: MIT OR Apache-2.0
