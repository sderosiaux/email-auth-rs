# Learnings — Cycle 1, Lane 8: dkim-signing

## FRICTION
- **ring RSA public key format**: `RsaKeyPair::public().as_ref()` returns PKCS#1 RSAPublicKey DER (SEQUENCE of modulus + exponent), NOT SPKI. DKIM `p=` expects SPKI. Had to write `wrap_pkcs1_in_spki()` to construct the SPKI envelope manually: `SEQUENCE { AlgorithmIdentifier(RSA OID + NULL), BIT STRING(0x00 + PKCS#1) }` (src/dkim/sign.rs:289-315). This is the inverse of `strip_spki_wrapper()` in verify.rs.
- **ring Ed25519 `public_key()` requires `KeyPair` trait import**: `ring::signature::KeyPair` must be in scope to call `key_pair.public_key()`. Not obvious from the docs. Import: `use ring::signature::KeyPair;` (src/dkim/sign.rs:7).
- **Deprecated `public_modulus_len()`**: ring 0.17 deprecated `RsaKeyPair::public_modulus_len()` in favor of `public().modulus_len()`. Easy fix but not well-documented in migration guides (src/dkim/sign.rs:246).

## GAP
- **Spec doesn't specify `sign_message` return format**: Spec says "output complete DKIM-Signature header value" but doesn't clarify whether the return includes the "DKIM-Signature:" prefix. Chose to return just the value (everything after the colon), matching the verifier's `(name, value)` pair convention. Caller constructs the full header.
- **PEM decoding**: Spec says "PEM PKCS8" but doesn't specify whether the crate should use a PEM library. Wrote a minimal PEM decoder (find BEGIN/END markers, decode base64) rather than adding a `pem` crate dependency (src/dkim/sign.rs:326-347). Handles both "BEGIN PRIVATE KEY" and "BEGIN RSA PRIVATE KEY" markers.

## DECISION
- **No `Algorithm::RsaSha1` constructor**: Spec says RSA-SHA1 is verify-only. API enforcement: only `rsa_sha256()` and `ed25519()` constructors exist. No code path can produce `a=rsa-sha1`. Test `rsa_sha1_signing_not_constructable` verifies this (src/dkim/sign.rs:392).
- **Builder pattern with defaults**: Signer uses `Self { ..defaults }` with optional `header_canonicalization()`, `body_canonicalization()`, `headers()`, `over_sign()`, `expiration()` methods. Default canonicalization is relaxed/relaxed, matching common practice.
- **`over_sign` implementation**: When enabled, each header name appears twice in h= (e.g., `from:from:to:to`). The second occurrence selects a non-existent header, contributing an empty canonicalized line. This prevents header injection attacks. Verifier's `select_headers` handles this correctly via the existing over-signing logic (src/dkim/canon.rs).
- **RSA test key as fixture file**: ring doesn't expose RSA key generation. Used `openssl genpkey` to create `tests/fixtures/rsa2048.pem`, loaded with `include_bytes!()`. Test-only, not shipped.

## SURPRISE
- ring's `RsaKeyPair::public()` returns a type that already serializes as PKCS#1 DER via `AsRef<[u8]>`. This is the inverse direction from verification (where we strip SPKI → PKCS#1). The roundtrip works: `wrap_pkcs1_in_spki()` → DNS mock → `strip_spki_wrapper()` → ring verify.
- Ed25519 sign-then-verify roundtrip worked on first try. No SPKI wrapping needed — Ed25519 uses raw 32-byte public keys.
- Simple/simple canonicalization roundtrip also worked first try. The `DKIM-Signature:` casing in the signing path matches the verifier's `format!("DKIM-Signature:{}", stripped)` branch.

## DEBT
- None. All algorithm paths tested, sign-then-verify roundtrips pass for Ed25519, RSA-SHA256, simple/simple, and over-signing.
