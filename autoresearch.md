# Autoresearch: find-bugs

## Objective
Find and fix bugs in the email-auth Rust library (SPF, DKIM, DMARC, ARC, BIMI).
Two categories:
1. **Spec compliance** — implementation violates RFC specs (wrong behavior, missing edge cases)
2. **Crash/panic risks** — `unwrap()`/`expect()` in library code that can panic on bad input

Metric tracks number of passing tests: each bug fix adds a test case that catches the bug.

## Metrics
- **Primary**: passed (count, higher is better)
- **Secondary**: clippy warnings (lower is better), unwrap count in lib code (lower is better)

## How to Run
`./autoresearch.sh` outputs `METRIC passed=N`.
Log results with the autoresearch log-experiment.sh script.

## Files in Scope
- `src/spf/` — SPF evaluation, parser, macros, lookup
- `src/dkim/` — DKIM signing, verification, canonicalization, key parsing
- `src/dmarc/` — DMARC evaluation, parser, report
- `src/arc/` — ARC validation, sealing, parser
- `src/bimi/` — BIMI discovery, SVG validation, VMC
- `src/common/` — DNS resolver, CIDR, domain utilities
- `src/auth.rs` — Top-level AuthResults
- `specs/` — Source of truth (read-only, do not modify)

## Off Limits
- `specs/` files (source of truth, never modify)
- `Cargo.toml` dependencies (no adding new crates)
- Test fixtures in `specs/ground-truth/`

## Guard
`cargo test` — all tests must pass

## Constraints
- No `unwrap()`/`expect()` in library code (tests only)
- Fixes must match RFC spec behavior

## Search Space
| Dimension | Type | Range/Values | Dependencies |
|-----------|------|--------------|--------------|
| Spec compliance gaps | categorical | SPF, DKIM, DMARC, ARC, BIMI | spec checkboxes |
| Panic risks (unwrap/expect) | categorical | per file in src/ | none |
| Edge cases in parsers | categorical | per RFC section | spec |
| Clippy lints | categorical | 36 warnings | style |

**Active dimensions**: 4 | **Explored**: none | **Unexplored**: all

## Headroom Table
| Bottleneck | Count | Severity | Headroom | Priority |
|------------|-------|----------|----------|----------|
| Spec compliance gaps | 1074 unchecked | high | very high | 1 |
| unwrap/expect in lib code | ~369 total (excl. tests) | medium | high | 2 |
| Clippy warnings | 36 | low | medium | 3 |

## Profiling Notes
- Baseline: 604 tests passing
- 1074 spec checkboxes all unchecked (documentation gap, not impl gap)
- 36 clippy warnings in library code
- `unwrap()`/`expect()` widespread — most in test code, some in library code

## Problem Profile
**Bottleneck classification**: Spec compliance (gaps in RFC edge cases) + crash safety (unwraps in lib code)
**Current focus**: Spec compliance gaps -> reading specs to find unimplemented RFC requirements first.
**Pivot trigger**: If 3 discards in current focus, switch to crash/panic hunting.

## What's Been Tried
(none yet — starting fresh)
