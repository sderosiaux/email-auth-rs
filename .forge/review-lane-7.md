---
verdict: VIOLATIONS
lane: 7
cycle: 1
---

## Violations

- **CHK-482**: Valid RSA-SHA256 signature → Pass (pre-computed fixture)
  Expected (from spec): "**pre-computed fixture**: sign with `rsa` crate or openssl, embed signed message + SPKI public key in test — cannot rely on sign→verify round-trip alone" (spec 02-DKIM-RFC6376.md:462)
  Actual (in code): No RSA-SHA256 test exists at all. No fixture. Checkboxes.md records this as DONE at `src/dkim/verify.rs:1157` — but line 1157 is a comment `// CHK-534: No unwrap/expect in library code`. There is no RSA-SHA256 pass test anywhere in the file.
  Test gap: Zero RSA verification tests. The entire RSA code path (`strip_spki_wrapper`, RSA algorithm selection, `RSA_PKCS1_*` constants) is never exercised by any test.

- **CHK-483**: Valid RSA-SHA1 signature → Pass (pre-computed fixture required)
  Expected (from spec): "**pre-computed fixture required**: ring 0.17 cannot sign SHA-1. Sign once externally, embed fixture with raw message bytes + signature + public key" (spec 02-DKIM-RFC6376.md:463)
  Actual (in code): No RSA-SHA1 test exists at all. No fixture. Same phantom line reference as CHK-482.
  Test gap: RSA-SHA1 verification code path is completely untested.

- **CHK-529**: RSA-SHA256 + RSA-SHA1 + Ed25519 verification working
  Expected (from spec): "RSA-SHA256 + RSA-SHA1 + Ed25519 verification working" (spec 02-DKIM-RFC6376.md:600)
  Actual (in code): Only Ed25519 verification is tested. RSA-SHA256 and RSA-SHA1 have zero test coverage. Marked DONE at `src/dkim/verify.rs:385` — this is the `verify_signature` function definition, not a test.
  Test gap: Two of three algorithm paths untested.

- **CHK-532**: RSA-SHA1 verification tested
  Expected (from spec): "RSA-SHA1 verification tested" (spec 02-DKIM-RFC6376.md:603)
  Actual (in code): Not tested. Marked DONE at line 1157, same phantom reference.
  Test gap: Explicitly requires testing and no test exists.

## Code Issues

- `src/dkim/verify.rs:162`: `current_timestamp()` uses `.unwrap_or(0)` in library code. While not `unwrap()` per se, returning 0 on `SystemTime` failure means signatures would be treated as not-expired (0 < any_x + 300). This is a lenient failure mode that could skip expiration checks if the system clock is broken. Not blocking per spec, but notable.

- `src/dkim/verify.rs:300-305`: `compute_header_hash_input` calls `strip_b_tag_value` twice for simple canonicalization (once on line 292, result unused; again on line 301). Redundant but not incorrect.

## Summary

4 work items (CHK-482, CHK-483, CHK-529, CHK-532) are marked DONE in checkboxes.md but have **zero corresponding tests**. All four require pre-computed RSA fixtures per spec. The entire RSA verification code path — SPKI stripping, key size detection, RSA-SHA256 algorithm selection, RSA-SHA1 algorithm selection — is exercised by no test. The SPKI stripping function has only trivial passthrough tests (non-SPKI data and too-short data); no test passes actual SPKI-wrapped RSA keys through it.

71 of 75 lane-7 work items are properly covered. The 4 RSA-related test items are hard violations.
