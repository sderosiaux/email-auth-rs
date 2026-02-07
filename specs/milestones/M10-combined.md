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

## Integration test contracts
- Ground-truth fixtures: real email messages with known authentication results
- Each fixture includes: raw message bytes, client_ip, helo, mail_from, expected spf/dkim/dmarc results
- Mock DNS snapshots: pre-configured resolver with all DNS records needed for each fixture
- Tests must validate: correct result type AND correct metadata (domain, selector, reason)

## Re-exports (lib.rs)
- All public types accessible from crate root: SpfVerifier, DkimVerifier, DmarcVerifier, EmailAuthenticator
- Result types: SpfResult, DkimResult, DmarcResult, AuthenticationResult
- Config types: DnsResolver, HickoryResolver
- Do NOT re-export internal parsing types

## Review kill patterns
- From header parsing missing or naive (doesn't handle folded headers, comments, multiple addresses)
- AuthenticationResult missing structured fields (just wraps flat enums)
- Integration tests use sign-then-verify (self-consistent) without external fixtures
- Error in one protocol (e.g. SPF TempError) crashes entire authentication instead of partial results
