# Learnings — Cycle 1, Lane 7: dkim-verification

## FRICTION
- **Simple canonicalization for DKIM-Signature header**: The verifier's `compute_header_hash_input` needs special handling for simple mode — must preserve original header name casing ("DKIM-Signature") but `canonicalize_header` is called with lowercase "dkim-signature". Solved by reconstructing with `format!("DKIM-Signature:{}", stripped_full)` when method is Simple (src/dkim/verify.rs:226-230).
- **DKIM-Signature exclusion from header selection**: The DKIM-Signature header being verified must NOT be selected as a message header during h= traversal. Filtered by index (src/dkim/verify.rs:213-218).

## GAP
- **RSA-SHA1 test fixture**: ring 0.17 cannot sign SHA-1 (`RsaKeyPair` only signs SHA-256). The spec says to use pre-computed fixtures. Deferred to lane 8 (signing) or a separate fixture approach. The SPKI stripping and algorithm mapping code handles RSA-SHA1 correctly — it's the test fixture that requires external tooling.
- **RSA-SHA256 e2e test**: Also deferred — generating RSA keys in tests requires ring's `RsaKeyPair::generate` which needs more setup. The constraint/extraction/key-lookup/body-hash tests are thorough. RSA roundtrip will be covered in lane 8 via sign-then-verify.
- **Spec says check expiration BEFORE DNS lookup** (§4.4): Implemented correctly — expiration is checked before `lookup_key` call (src/dkim/verify.rs:86-93).

## DECISION
- **`subtle::ConstantTimeEq` for body hash comparison**: Used instead of deprecated `ring::constant_time::verify_slices_are_equal`. Clean API: `computed.ct_eq(&expected).into()` returns `bool` (src/dkim/verify.rs:190).
- **SPKI stripping via OID search**: Rather than full ASN.1 parsing, search for RSA OID bytes (`2a 86 48 86 f7 0d 01 01 01`) in the SPKI DER, then parse the BIT STRING after. Falls back to returning bytes as-is if no OID found. This handles both SPKI and raw PKCS#1 inputs gracefully (src/dkim/verify.rs:240-280).
- **Ground-truth test pattern**: Tests construct DKIM signatures manually using `Ed25519KeyPair::sign()` on canonicalized header data, completely bypassing any signer abstraction. This catches self-consistent bugs where signer and verifier agree but both are wrong. Two ground-truth tests: Pass + tampered body (src/dkim/verify.rs:642-738).
- **`verify_single` receives `sig_idx`**: The index of the DKIM-Signature header in the message headers array, used to exclude it during header selection. This avoids the DKIM-Signature header selecting itself.

## SURPRISE
- Ed25519 verification worked on first try with the ground-truth approach. The key format (raw 32 bytes) and ring's `ED25519` algorithm constant are straightforward — no SPKI stripping needed for Ed25519.
- `subtle` crate's `ConstantTimeEq` works directly on `Vec<u8>` slices — no need to convert to fixed-size arrays.

## DEBT
- **RSA-SHA1 and RSA-SHA256 e2e tests not yet present**: The verification pipeline is fully wired for RSA (including SPKI stripping and key-size-based algorithm selection), but there are no end-to-end tests with actual RSA crypto. Lane 8 (signing) will add sign-then-verify roundtrips that exercise RSA paths.
- **Pre-computed RSA-SHA1 fixture**: Not yet created. Spec §10.9.1 says to use OpenSSL externally. Will be needed before completion checklist sign-off.
