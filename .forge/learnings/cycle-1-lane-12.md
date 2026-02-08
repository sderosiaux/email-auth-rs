# Lane 12: ARC Parsing & Validation — Learnings

## What Worked
- DKIM code reuse via `pub(crate)` — `compute_hash`, `verify_signature`, `strip_b_tag_value`, `canonicalize_header`, `select_headers` all directly applicable to ARC AMS/AS validation.
- Ed25519 real-crypto tests provide high confidence. ring's Ed25519KeyPair for sign + verify roundtrip is fast and deterministic.
- `collect_arc_sets()` parsing ARC headers from raw `(name, value)` tuples handles the grouping/ordering cleanly.

## Bugs Found & Fixed
1. **Multi-hop test indexing bug**: When building multi-hop ARC chains in tests, using `insert(0, ...)` (prepend) to build `arc_headers` shifts previous indices on each hop. Using `(prev_hop - 1) * 3` as index into this vec breaks after hop 2+. Fix: maintain a separate `ordered_sets: Vec<(aar, ams, seal)>` in instance order for seal input construction, build the prepended header list separately at the end.
2. **`subtle::ConstantTimeEq` type inference**: `ct_eq().into()` fails type inference — must use `bool::from(ct_eq())`.
3. **Case sensitivity in error messages**: Test assertions must match actual casing. Used `contains("must not")` not `contains("MUST NOT")`.
4. **Unused imports**: ARC validate module initially imported several DKIM types that weren't needed after refactoring. Keep imports minimal.

## Architecture Decisions
- ARC-Seal has NO h= tag and NO body hash — it's a pure header chain seal using relaxed canonicalization only.
- AMS validation filters ALL ARC-* headers from the header set before `select_headers()`, since AMS signs only original message headers.
- AS signature input: all ARC sets 1..i in order (AAR -> AMS -> AS per set), b= stripped from the AS being validated (last one), no trailing CRLF on last header.
- `validate_chain()` follows RFC 8617 Section 5.2 steps 1-7 exactly: collect → check cv → structure → AMS(N) → oldest-pass → all AS → pass.

## Patterns for Future Lanes
- Lane 13 (arc-sealing) will need the inverse: constructing ARC headers and signing them. The test helper `build_single_arc_set()` is a template for the sealing API.
- `lookup_key()` is identical to DKIM key lookup — could be extracted to a shared utility if needed.
- The `ordered_sets` pattern in multi-hop tests is essential — any test building iterative chain signatures must track raw headers in stable order, separate from the prepended email header order.
