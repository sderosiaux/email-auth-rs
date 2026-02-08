# Learnings — Cycle 1, Lane 11: dmarc-reporting

## FRICTION
- **XML generation without a crate**: Spec doesn't mandate a specific XML library. Hand-rolling XML via `std::fmt::Write` is trivial for the fixed Appendix C schema but requires manual XML escaping (`&`, `<`, `>`, `"`, `'`). quick-xml is already a dependency (for BIMI) but using it for generation would add complexity for no benefit — the schema is static.
- **`DnsError` import scope**: Removing unused imports from lib code also removed `DnsError` which tests needed. Test modules need their own imports — the `use super::*` only pulls in the module's own items.

## GAP
- **Spec doesn't define exact XML indentation or attribute ordering**: Generated XML matches the Appendix C schema structure but with minimal formatting. Production consumers parse XML structurally, not textually.
- **AFRF boundary string**: RFC 6591 doesn't specify a boundary format. Used a fixed `----=_DMARC_AFRF_Boundary` string. Production implementations would generate unique boundaries.

## DECISION
- **Hand-rolled XML over quick-xml**: The Appendix C schema is ~30 elements deep with no attributes, no namespaces, no CDATA. `std::fmt::Write` is the right tool. Zero new dependencies.
- **`verify_external_report_uri` as free async function**: Not a method on DmarcEvaluator — callers may want to verify URIs independently of evaluation. Takes a `&DnsResolver` parameter.
- **`should_generate_failure_report` as pure function**: No async, no DNS. Takes alignment booleans and fo= options, returns bool. Clean separation from report generation.
- **`ReportDisposition` separate from `Disposition`**: Aggregate reports use a 3-value disposition (none/quarantine/reject) while DMARC evaluation has 5 (adds Pass, TempFail). Separate enum prevents invalid states.

## SURPRISE
- The reporting module is entirely deterministic — no DNS queries in report building, no randomness. All async complexity is isolated to `verify_external_report_uri`. This made testing trivial.
- `fo=` filtering is simpler than expected: each option independently checks one condition, and any match triggers the report. Multiple options act as OR.

## DEBT
- None. All 23 new tests pass. Report delivery (gzip, email sending, size enforcement) is explicitly out of scope per spec §7.3.
