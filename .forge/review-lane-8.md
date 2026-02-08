---
verdict: APPROVED
lane: 8
cycle: 1
---

## Summary

All 22 work items verified. 325 tests pass (0 fail). Spec compliance confirmed across all signing checkboxes.

## Coverage Matrix

| CHK-ID | Test exists | file:line recorded | Test passes | Behavior matches spec |
|--------|-------------|-------------------|-------------|----------------------|
| CHK-421 | Y | src/dkim/sign.rs:611 | Y | Y — `decode_pem` + `RsaKeyPair::from_pkcs8` |
| CHK-422 | Y | src/dkim/sign.rs:408 | Y | Y — `rsa_sha256()` constructor, 2048-bit test key |
| CHK-423 | Y | src/dkim/sign.rs:400 | Y | Y — `Ed25519KeyPair::from_pkcs8` |
| CHK-424 | Y | src/dkim/sign.rs:400 | Y | Y — ring `from_pkcs8` for both key types |
| CHK-425 | Y | src/dkim/sign.rs:415 | Y | Y — `invalid_key_fails_fast`, `invalid_pem_fails` |
| CHK-426 | Y | src/dkim/sign.rs:442 | Y | Y — `sign_without_from_fails` returns error |
| CHK-427 | Y | src/dkim/sign.rs:701 | Y | Y — `default_headers_include_recommended` checks all 7 |
| CHK-428 | Y | src/dkim/sign.rs:701 | Y | Y — asserts Received/Return-Path absent |
| CHK-429 | Y | src/dkim/sign.rs:633 | Y | Y — `over_sign_roundtrip` checks `h=from:from:to:to:subject:subject` |
| CHK-430 | Y | src/dkim/sign.rs:716 | Y | Y — `signature_has_timestamp` verifies t= is recent |
| CHK-431 | Y | src/dkim/sign.rs:582 | Y | Y — `timestamp_and_expiration_set` verifies `x == t + 3600` |
| CHK-432 | Y | src/dkim/sign.rs:461 | Y | Y — `ed25519_sign_verify_roundtrip` + `rsa_sha256_sign_verify_roundtrip` |
| CHK-433 | Y | src/dkim/verify.rs:1014 | Y | Y — ground-truth tests in verify.rs from lane 7 |
| CHK-502 | Y | src/dkim/sign.rs:461 | Y | Y — Ed25519 sign → DkimVerifier → Pass |
| CHK-503 | Y | src/dkim/sign.rs:501 | Y | Y — RSA-SHA256 sign → MockResolver → DkimVerifier → Pass |
| CHK-504 | Y | src/dkim/sign.rs:540 | Y | Y — `simple_simple_roundtrip` + default relaxed/relaxed |
| CHK-505 | Y | src/dkim/sign.rs:442 | Y | Y — `sign_without_from_fails` with h= lacking "from" |
| CHK-506 | Y | src/dkim/sign.rs:582 | Y | Y — parses t= and x= from output, asserts x = t + 3600 |
| CHK-507 | Y | src/dkim/sign.rs:611 | Y | Y — `pem_decode_rsa_key`, `pem_decode_invalid_base64`, `pem_decode_empty` |
| CHK-508 | Y | src/dkim/sign.rs:429 | Y | Y — `rsa_sha1_signing_not_constructable`: no RSA-SHA1 constructor exists |
| CHK-509 | Y | src/dkim/sign.rs:633 | Y | Y — over-sign roundtrip verifies signer/verifier agree on empty-header hash |
| CHK-530 | Y | src/dkim/sign.rs:461 | Y | Y — all signing paths tested and passing |

## Spec Compliance

- **§5.1 DkimSigner struct**: matches spec layout (key, domain, selector, algorithm, canonicalization, headers, expiration)
- **§5.2 Private Key Handling**: PEM PKCS8 via custom decoder, ring `from_pkcs8` for both key types, fail-fast at construction
- **§5.3 Headers to Sign**: From required (enforced at sign time), recommended headers in defaults, transit headers excluded, over-signing supported
- **§5.4 Signing Flow**: all 6 steps implemented correctly — body canon → bh= → template → header selection → canonicalize sig → sign → b= fill
- **§5.5 Timestamp/Expiration**: t= set to current Unix time, x= = t + configured seconds
- **§7.2 API**: constructors `rsa_sha256()` and `ed25519()` match spec. `sign_message` signature uses `&[(&str, &str)]` instead of `&str` — consistent with DkimVerifier API pattern
- **No unwrap/expect in library code**: all panic paths are in `#[cfg(test)]` only. `unreachable!()` for RsaSha1 match arm is safe by constructor design.
- **DKIM-Signature appended WITHOUT trailing CRLF**: confirmed at sign.rs:199-205

## Notes

- `wrap_pkcs1_in_spki()` (sign.rs:280) is the inverse of `strip_spki_wrapper()` in verify.rs — needed because ring's `RsaKeyPair::public()` returns PKCS#1 DER but DKIM `p=` stores SPKI. The roundtrip wrap→DNS→strip→verify is validated by the RSA-SHA256 roundtrip test.
- Ed25519 constructor takes raw PKCS8 bytes (not PEM) because ring generates Ed25519 keys as raw PKCS8. This is a practical decision documented in learnings.
- Default canonicalization is relaxed/relaxed (not simple/simple as per RFC default). This is common practice but diverges from strict RFC default. Not a blocking issue since it's configurable.
