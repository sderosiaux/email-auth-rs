# M6: DKIM Verification
Scope: src/dkim/mod.rs (verify path), src/dkim/verify.rs
Depends on: M4, M5
RFC: 6376 Section 6

## Verification flow contracts
1. Find all DKIM-Signature headers in message
2. Parse each (skip malformed, report as PermFail)
3. For each valid signature:
   a. Check expiration (x= vs current time, allow configurable clock skew, default 300s)
   b. DNS lookup: <selector>._domainkey.<domain> TXT
   c. Parse key record
   d. Enforce key h= tag: if present, signature's hash algorithm must be in the list
   e. Enforce key s= tag: must include "email" or "*"
   f. Enforce key t=s flag: if set, i= domain must exactly equal d= (not subdomain)
   g. Key t=y flag: signature valid but mark as testing in result metadata
   h. Empty p= -> key revoked -> PermFail(KeyRevoked)
   i. Canonicalize body, apply l= length limit, compute body hash
   j. Compare body hash with bh= using CONSTANT-TIME comparison
   k. Canonicalize headers per h= list (bottom-up, with over-signing)
   l. Append canonicalized DKIM-Signature (b= stripped, no trailing CRLF)
   m. Verify signature: pass RAW header data to ring, NOT pre-hashed data
4. Collect results for all signatures

## Crypto contracts

### RSA key size detection
ring provides separate algorithm constants for different minimum key sizes. Detect key size from DER SubjectPublicKeyInfo byte length:

| DER bytes | RSA bits | ring algorithm constant |
|-----------|----------|------------------------|
| < 256     | 1024-bit | RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY |
| >= 256    | 2048+    | RSA_PKCS1_2048_8192_SHA256 |

Threshold: **256 bytes**. v1 used 200 which was wrong — 1024-bit keys produce ~162 byte DER, 2048-bit produce ~294 bytes. 256 is the safe midpoint.

For SHA1:
- All RSA-SHA1: use RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY (accept for verify, never for signing)
- 1024-bit RSA-SHA1: there is no 1024-bit SHA1 constant in ring. Fall back to the 2048 variant and let ring reject if too small, OR document this as unsupported.

### Algorithm mapping table
```rust
match (algorithm, is_small_key) {
    (RsaSha256, false) => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
    (RsaSha256, true)  => &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    (RsaSha1, _)       => &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    (Ed25519Sha256, _) => &ring::signature::ED25519,
}
```

### Ed25519 verification
- ring Ed25519 verification expects raw 32-byte public key
- Use `ring::signature::UnparsedPublicKey::new(&ED25519, &key_bytes)`
- key_bytes is the decoded p= value (should be exactly 32 bytes)

### ring verify API (CRITICAL — double-hash bug)
ring's `UnparsedPublicKey::verify(message, signature)` takes RAW message bytes and hashes internally. Do NOT pre-hash the canonicalized headers and pass the hash — that causes a double-hash and ALWAYS fails on real messages.

```rust
// CORRECT:
let public_key = UnparsedPublicKey::new(algorithm, &key_bytes);
public_key.verify(&canonicalized_header_data, &signature_bytes)?;

// WRONG — double hash:
let hash = ring::digest::digest(&SHA256, &canonicalized_header_data);
public_key.verify(hash.as_ref(), &signature_bytes)?;
```

### Constant-time body hash comparison
`ring::constant_time::verify_slices_are_equal` was deprecated in ring 0.17. Options:
1. Use `subtle` crate: `subtle::ConstantTimeEq` trait
2. Check if ring 0.17+ still provides the function (it may still compile with a warning)
3. Implement manually: XOR all bytes, check if OR-reduction is zero

Prefer `subtle` crate for clarity and correctness.

## Result contracts
- DkimResult::Pass must carry: signing domain (d=), selector (s=), testing flag (key t=y)
- DkimResult::Fail must carry: FailureKind enum (BodyHashMismatch, SignatureVerificationFailed)
- DkimResult::PermFail must carry: PermFailKind enum (MalformedSignature, KeyRevoked, KeyNotFound, ExpiredSignature, AlgorithmMismatch, HashNotPermitted, ServiceTypeMismatch, StrictModeViolation, DomainMismatch)
- DkimResult::TempFail must carry: reason string (DNS failures)

## Ground-truth testing (CRITICAL)
Round-trip tests (sign-then-verify) catch most bugs but NOT self-consistent bugs where sign and verify agree on the same wrong behavior.

**Required**: Build ground-truth verification tests using externally-constructed signatures:
1. Generate RSA/Ed25519 key pairs with ring
2. Manually canonicalize a test message (by hand, not using the canon module)
3. Sign the manually-canonicalized data with ring primitives directly
4. Construct a DKIM-Signature header manually
5. Feed the complete message to DkimVerifier
6. Verify it passes

This catches bugs in canonicalization that sign+verify would both miss.

## Review kill patterns
- compute_header_hash returns SHA digest, then passed to ring::verify -> DOUBLE HASH BUG
- Key h=, s=, t= parsed in key.rs but never checked in verify flow
- Body hash compared with == or != instead of constant_time_eq
- RSA_PKCS1_2048_8192 rejects 1024-bit keys without fallback algorithm
- Over-signed headers skipped during verification (empty value not contributed)
- i= domain check against d= missing during verification
- RSA key size threshold wrong (v1 used 200 bytes, correct is 256)
- Ed25519 key bytes wrapped in DER instead of raw 32 bytes
- Clock skew not configurable (hardcoded or absent)
- DNS TXT strings not concatenated before key record parsing
