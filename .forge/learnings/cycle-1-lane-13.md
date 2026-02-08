# Learnings — Cycle 1, Lane 13: arc-sealing-roundtrip

## FRICTION
- **DKIM sign primitives are private**: `DkimSigner::sign_raw()` is private. Rather than exposing it, ArcSealer duplicates the signing logic (holds its own `PrivateKey` enum, same `sign_raw()` pattern). Acceptable since ArcSealer has different construction API (no v= tag, different header format). Same for `wrap_pkcs1_in_spki()`, `decode_pem()`, `encode_asn1_length()`.
- **CHK-865 DKIM-Signature auto-inclusion in h=**: Spec requires AMS h= to include existing DKIM-Signature headers. Initial implementation used static `default_arc_headers()` without scanning for DKIM-Signature. Fix: `seal_message` counts DKIM-Signature headers in input and appends `"dkim-signature"` to h= list once per occurrence (src/arc/seal.rs:165-173). The filter that removes ARC-* headers keeps DKIM-Signature so `select_headers` can pick them up.

## GAP
- **CHK-901 body modification scenario**: Spec says "sealer 2 re-signs → validate_chain returns Pass with oldest_pass > 1". This is unreachable via the sealer path (sealer validates incoming chain → body hash mismatch → cv=fail). But the *validator* CAN return oldest_pass > 0 when given a manually constructed chain where AMS(1) body hash doesn't match but AMS(N) does and all AS are valid. Added test `oldest_pass_after_body_modification` in validate.rs that constructs a 2-hop chain with AMS(1) body hash for original body and AMS(2) for modified body, both AS valid. Validates with modified body → Pass, oldest_pass=2.

## DECISION
- **ArcSealer as independent type**: Rather than wrapping DkimSigner, ArcSealer holds its own PrivateKey. This avoids coupling ARC's API surface to DKIM's builder pattern. ARC sealing has different requirements: always relaxed/relaxed, no v= tag, instance-based, cv= tag.
- **seal_message is async**: Takes `&ArcVerifier<R>` to validate the incoming chain for cv= determination. The verifier is passed by reference to avoid moving it.
- **No RSA-SHA1 sealing**: Like DkimSigner, only `rsa_sha256()` and `ed25519()` constructors exist. SHA1 is verify-only.
- **MockResolver::clone()**: Tests need multiple verifiers (one per seal call). MockResolver must be Clone. Already is since it's `HashMap`-based.

## SURPRISE
- Multi-hop seal→validate roundtrip worked on first try (CHK-900). The `ordered_sets` pattern from lane 12 test fix wasn't needed here since `seal_message` uses `collect_arc_sets` which already handles any header ordering.
- The `collect_arc_sets` gracefully returns `Ok(vec![])` for unparseable ARC headers via `unwrap_or_default()`, which is correct for the "no existing chain" path.

## DEBT
- **Code duplication**: `wrap_pkcs1_in_spki()`, `decode_pem()`, `encode_asn1_length()` are duplicated between `src/dkim/sign.rs` and `src/arc/seal.rs`. Could be extracted to a shared `crate::common::crypto` module. Not worth it unless a third consumer appears.
