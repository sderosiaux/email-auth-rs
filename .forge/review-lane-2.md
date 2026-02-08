---
verdict: VIOLATIONS
lane: 2
cycle: 1
---

## Violations

- **CHK-038**: "Query DNS TXT records for domain"
  Expected (from spec): A function that queries DNS TXT records for a given domain, returning the raw TXT record strings.
  Actual (in code): No DNS query function exists in `src/spf/`. `parse_record(record: &str)` accepts a single pre-fetched string. No `lookup_spf`, `query_spf`, or equivalent.
  Test gap: No test exercises DNS query behavior. Checkbox marked DONE referencing `src/spf/parser.rs:6` which is a string parser, not a DNS caller.

- **CHK-040**: "Handle multiple TXT records: MUST be exactly one SPF record, else PermError"
  Expected (from spec): When multiple TXT records match `v=spf1`, return `SpfResult::PermError`.
  Actual (in code): No function accepts multiple TXT records. `parse_record` takes a single `&str`. No filtering or deduplication logic.
  Test gap: No test supplies multiple SPF records and asserts PermError.

- **CHK-041**: "Handle no SPF record: return None"
  Expected (from spec): When no TXT record matches `v=spf1`, return `SpfResult::None`.
  Actual (in code): No function returns `SpfResult::None` for this case. `parse_record` returns `Err(String)` for invalid input — it never produces `SpfResult::None`.
  Test gap: No test exercises the "no SPF record found" → `SpfResult::None` path.

- **CHK-042**: "DNS TempFail during TXT query: return TempError"
  Expected (from spec): DNS temporary failure during TXT lookup returns `SpfResult::TempError`.
  Actual (in code): No DNS interaction exists in the SPF module. No mapping from `DnsError::TempFail` to `SpfResult::TempError`.
  Test gap: No test exercises DNS failure → TempError.

## Notes

- All other work items (54 of 58) are correctly implemented with precise tests matching spec wording.
- Types (CHK-001 to CHK-029) are clean, well-structured, and match the spec exactly.
- Grammar parsing (CHK-043 to CHK-058) is solid — modifier/mechanism disambiguation is well-handled.
- All 14 parsing tests (CHK-181 to CHK-194) pass and correctly verify spec behavior.
- The 4 violated checkboxes all relate to a missing DNS-to-parser bridge function (`lookup_spf` or equivalent) that takes a resolver + domain, queries TXT, filters for `v=spf1`, enforces single-record constraint, and maps DNS errors to SpfResult. This is a single function gap affecting 4 checkboxes.
- No code quality issues found. No `unwrap`/`expect` in library code.
