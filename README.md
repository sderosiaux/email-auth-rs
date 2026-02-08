# email-auth

A Rust email authentication library implementing SPF, DKIM, DMARC, ARC, and BIMI.

## Installation

```toml
[dependencies]
email-auth = "0.1.0"
```

**Requirements:** Rust 1.63+, Tokio, Ring, Hickory DNS (or custom `DnsResolver` trait impl)

## Usage

```rust
use email_auth::{EmailAuthenticator, AuthenticationResult};

let authenticator = EmailAuthenticator::new(resolver);
let result = authenticator.authenticate(
    "sender@example.com",    // MAIL FROM
    "203.0.113.1",           // client IP
    raw_message.as_bytes(),  // RFC 5322 message
).await?;

// result.spf, result.dkim, result.dmarc, result.disposition
```

## Development

```bash
cargo test
```

## Project Structure

```
specs/              # RFC specifications (source of truth)
src/
  lib.rs           # Library root
  auth.rs          # EmailAuthenticator integration
  common/          # Shared utilities
  spf/             # SPF module
  dkim/            # DKIM module
  dmarc/           # DMARC module
  arc/             # ARC module
  bimi/            # BIMI module
.forge/
  state.yaml       # Forge build state
  lanes.yaml       # Work lane definitions
```

## Security Considerations

- **DNS validation**: Implement DNS response validation at resolver layer
- **RSA key size**: Library enforces minimum 1024-bit, recommends 2048+
- **Clock skew**: Configurable expiration tolerance for DKIM/ARC timestamps
- **SVG parsing**: 32KB size limit, XXE prevention, script injection detection
- **PTR verification**: Forward confirmation required (cache aggressively)

## License

Dual-licensed: MIT OR Apache-2.0
