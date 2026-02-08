---
verdict: VIOLATIONS
lane: 14
cycle: 1
---

## Violations

- **CHK-N/A (project rule)**: `unwrap()` in library code at `src/bimi/discovery.rs:161`
  Expected (from CLAUDE.md): "No `unwrap`/`expect` in library code. Tests only."
  Actual (in code): `1 => Ok(valid_records.into_iter().next().unwrap())` — `unwrap()` used in `lookup_bimi_record()`, which is non-test library code.
  Test gap: No test catches this because the `unwrap()` is logically safe (the match arm guarantees length == 1). However, the project rule is absolute — no `unwrap()` in library code regardless of safety. Replace with `.expect()` → still violates, or `.ok_or()` / match-destructure.

## Code Issues

- `src/bimi/discovery.rs:161`: Replace `valid_records.into_iter().next().unwrap()` with a safe alternative. Since `valid_records.len() == 1` is guaranteed by the match arm, use `valid_records.into_iter().next().ok_or(LookupError::NotFound)?` or destructure via `if let`.

## Notes (non-blocking)

- All 39 BIMI tests pass (537 total, 0 failures).
- All 67 lane-14 work items (CHK-920 through CHK-1059) are marked DONE in checkboxes.md with corresponding test names.
- Every test precisely matches its spec wording: e.g., CHK-932 (multiple valid → Fail) tests two valid records and asserts `BimiResult::Fail`, CHK-997 (pct<100 → NOT eligible) constructs pct=50 and asserts ineligibility with reason string containing "pct=50".
- `BimiValidationResult` uses `record: Option<BimiRecord>` instead of spec's individual `logo_uri`/`authority_uri`/`logo_svg` fields — functionally equivalent and arguably cleaner, not a violation since the data is fully accessible.
- HTTPS scheme check only matches `https://` and `HTTPS://`, not mixed-case like `Https://`. Acceptable strictness but worth noting.
- No clippy warnings in BIMI code. Existing clippy warnings are from prior lanes (arc, spf).
