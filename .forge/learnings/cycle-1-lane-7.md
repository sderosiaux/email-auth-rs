# Learnings — Cycle 1, Lane 7: dkim-verification

## FRICTION
- **Simple canonicalization for DKIM-Signature header**: The verifier's `compute_header_hash_input` needs special handling for simple mode — must preserve original header name casing ("DKIM-Signature") but `canonicalize_header` is called with lowercase "dkim-signature". Solved by reconstructing with `format!("DKIM-Signature:{}", stripped)` when method is Simple (src/dkim/verify.rs:299-302).
- **DKIM-Signature exclusion from header selection**: The DKIM-Signature header being verified must NOT be selected as a message header during h= traversal. Filtered by index (src/dkim/verify.rs:271-277).
- **RSA pre-computed fixture generation**: Python fixture generator initially produced wrong header hash input because it didn't strip leading WSP from header values during relaxed canonicalization. RFC 6376 §3.4.2 says "Delete any WSP characters remaining before and after the colon" — this means `dkim-signature:v=1; ...` not `dkim-signature: v=1; ...`. Fixed Python code to match Rust behavior.
- **Redundant strip_b_tag_value double-call**: `compute_header_hash_input` called `strip_b_tag_value` twice for simple canonicalization (lines 292 and 301). Refactored to call once and branch on canonicalization method.

## GAP
- **Spec says check expiration BEFORE DNS lookup** (§4.4): Implemented correctly — expiration is checked before `lookup_key` call (src/dkim/verify.rs:86-93).

## DECISION
- **`subtle::ConstantTimeEq` for body hash comparison**: Used instead of deprecated `ring::constant_time::verify_slices_are_equal`. Clean API: `computed.ct_eq(&expected).into()` returns `bool` (src/dkim/verify.rs:241).
- **SPKI stripping via OID search**: Rather than full ASN.1 parsing, search for RSA OID bytes (`2a 86 48 86 f7 0d 01 01 01`) in the SPKI DER, then parse the BIT STRING after. Falls back to returning bytes as-is if no OID found. Handles both SPKI and raw PKCS#1 inputs gracefully (src/dkim/verify.rs:316-356). **Validated** with real 2048-bit RSA SPKI key (294 bytes) — correctly strips to PKCS#1 and ring verifies successfully.
- **Ground-truth test pattern**: Tests construct DKIM signatures manually using `Ed25519KeyPair::sign()` on canonicalized header data, completely bypassing any signer abstraction. Two ground-truth tests: Pass + tampered body (src/dkim/verify.rs:1014-1129).
- **RSA fixture approach**: Used OpenSSL CLI (`openssl dgst -sha256/-sha1 -sign`) to generate pre-computed RSA-SHA256 and RSA-SHA1 fixtures externally. The same RSA-2048 key is used for both, with SPKI public key embedded as base64 constant. This is the ONLY way to test RSA-SHA1 since ring 0.17 cannot sign SHA-1.
- **`verify_single` receives `sig_idx`**: The index of the DKIM-Signature header in the message headers array, used to exclude it during header selection.

## SURPRISE
- Ed25519 verification worked on first try with the ground-truth approach. Raw 32-byte key format and ring's `ED25519` constant are straightforward.
- `subtle` crate's `ConstantTimeEq` works directly on `Vec<u8>` slices.
- SPKI stripping with real RSA keys: 294-byte SPKI → ~270-byte PKCS#1. The 256-byte key size threshold for ring algorithm selection still works correctly after stripping (stripped key is 270 bytes, ≥256 → `RSA_PKCS1_2048_8192_SHA256`).

## DEBT
- None remaining. All RSA code paths (RSA-SHA256, RSA-SHA1) now have pre-computed fixture tests. SPKI stripping tested with real DER data.
