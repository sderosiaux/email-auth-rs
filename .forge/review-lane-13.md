---
verdict: VIOLATIONS
lane: 13
cycle: 1
---

## Violations

- **CHK-865**: AMS h= tag missing DKIM-Signature headers
  Expected (from spec, `04-ARC-RFC8617.md:225-228`):
  > Select headers for h= tag:
  > - **MUST** include existing DKIM-Signature headers
  > - MUST NOT include Authentication-Results or ARC-* headers
  > - SHOULD include From, To, Subject, Date, Message-ID

  Actual (in code, `src/arc/seal.rs:305-315`):
  `default_arc_headers()` returns `["from", "to", "subject", "date", "message-id"]` — does NOT include `dkim-signature`. The `seal_message` method at `src/arc/seal.rs:112-273` uses `self.headers_to_sign` directly without auto-adding DKIM-Signature headers present in the message. The `.headers()` builder allows override, but the default violates the MUST.

  Test gap: No test verifies that DKIM-Signature headers are included in the AMS h= tag. All tests use messages without DKIM-Signature headers, so the missing default is never exercised.

- **CHK-901**: Spec expectation unreachable, test verifies different behavior
  Expected (from spec, `04-ARC-RFC8617.md:347`):
  > Multi-hop body modification: sealer 1 signs, intermediary modifies body, sealer 2 re-signs → validate_chain returns Pass for set 2 AMS but oldest_pass > 1

  Actual (in code, `src/arc/seal.rs:771-839`):
  Test `multi_hop_body_mod_cv_fail` verifies cv=fail propagation instead. Sealer 2 validates incoming chain (with modified body), AMS(1) body hash fails → chain fails → cv=fail. Final validation sees cv=fail on highest AS → immediate Fail.

  The learnings file (`cycle-1-lane-13.md`) documents this as a spec inconsistency: the spec's expectation contradicts the sealing algorithm's Step 4 (validate incoming chain). While the implementation behavior is correct per RFC 8617 §5.1, the checkbox is marked DONE when the spec-described scenario (Pass with oldest_pass > 1) is not tested. Either the spec must be updated or an alternative test path must be found.

## Code Issues

- `src/arc/seal.rs:168`: `SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)` — `unwrap_or(0)` is acceptable (not `unwrap()`), but a timestamp of 0 is a silent failure. Not blocking.
