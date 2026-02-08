# Learnings — Cycle 1, Lane 1: common-dns-domain-psl

## FRICTION
- `psl` crate v2 uses `psl::domain_str(&str) -> Option<&str>` but the trait method is on `Psl` trait — no import needed for the free function `psl::domain_str()`, it just works directly.
- `#[cfg(feature = "test-util")]` in a crate without that feature declared in `Cargo.toml` triggers `unexpected_cfgs` warning. Kept MockResolver `#[cfg(test)]` only for now; downstream crates needing mock will need to either duplicate or we add the feature later.
- `hickory-resolver` 0.25 pulls ~100 transitive deps. Consider feature-gating the real resolver behind a feature flag in future lanes if compile time becomes an issue.

## GAP
- Spec doesn't specify whether `DnsResolver` trait should use `async_trait` macro or native async fn in trait. Chose native `async fn in trait` (Rust 1.75+) since we target modern Rust. `#[allow(async_fn_in_trait)]` suppresses the dyn-incompatibility lint.
- Spec doesn't specify `MockResolver.query_exists()` behavior — implemented as: A query → non-empty = true, NxDomain/NoRecords = false, TempFail = propagate error.
- Spec doesn't clarify whether `domain_from_email` should handle angle brackets or comments. Kept it simple — raw `@` split. RFC 5322 comment stripping will be handled in `auth.rs` (lane 17).

## DECISION
- **Native async fn in trait vs async_trait**: Chose native. No need for `dyn DnsResolver` in current design — all generic `R: DnsResolver`. If dynamic dispatch needed later, can add a wrapper.
- **MockResolver under `#[cfg(test)]` only**: Not exposed as public API. If integration tests in downstream crates need it, we'll add `feature = "test-util"` then.
- **Blanket `impl DnsResolver for &R`**: Spec learning says this is needed for `EmailAuthenticator` passing `&self.resolver` to sub-verifiers. Implemented with UFCS to avoid recursion: `<R as DnsResolver>::query_txt(self, name).await`.
- **CIDR in separate module**: `src/common/cidr.rs` — clean separation, used only by SPF mechanism evaluation.
- **`rsplit_once('@')` for email parsing**: Takes last `@` to handle edge cases like `"user@host"@domain` (though technically invalid, robust).

## SURPRISE
- `psl::domain_str("com")` returns `None` — TLD-only input has no registrable domain. Fallback to input is correct.
- `psl` crate v2.1.188 compiled instantly — it embeds the PSL as static data, no build-time generation.
- No issues with `ring` 0.17 compilation on this platform (sometimes has cc/asm issues).

## DEBT
- MockResolver stores `HashMap<String, Result<Vec<T>, DnsError>>` which requires `T: Clone`. Fine for test types (Ipv4Addr, String) but noted.
- No real `HickoryResolver` implementation yet — that's not in scope for this lane (spec says DNS resolver is abstract trait, real impl is caller's concern).
