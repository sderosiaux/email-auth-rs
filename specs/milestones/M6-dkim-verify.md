# M6: DKIM Verification
Scope: src/dkim/mod.rs (verify path), src/dkim/crypto.rs (verify only)
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
   h. Empty p= -> key revoked -> PermFail
   i. Canonicalize body, apply l= length limit, compute body hash
   j. Compare body hash with bh= using CONSTANT-TIME comparison
   k. Canonicalize headers per h= list (bottom-up, with over-signing)
   l. Append canonicalized DKIM-Signature (b= stripped, no trailing CRLF)
   m. Verify signature: pass RAW header data to ring, NOT pre-hashed data
4. Collect results for all signatures

## Crypto contracts
- RSA-SHA256: ring RSA_PKCS1_2048_8192_SHA256 for >=2048 bit keys. For 1024-bit legacy keys, use RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY (ring provides this).
- RSA-SHA1: ring RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY. Accept for verify, never for signing.
- Ed25519-SHA256: ring Ed25519 verification. Key is raw 32 bytes.
- ring::verify takes (public_key, MESSAGE, signature) where MESSAGE is the raw data to be hashed+verified. Do NOT hash first then pass hash — ring hashes internally. Passing a hash = double-hash = always fails on real messages.

## Result contracts
- DkimResult::Pass must carry: signing domain (d=), selector (s=), testing flag (key t=y)
- DkimResult::Fail must carry: reason enum (BodyHashMismatch, SignatureMismatch, Expired, KeyRevoked, AlgorithmMismatch, DomainMismatch, HashNotPermitted, ServiceTypeMismatch)

## Review kill patterns
- compute_header_hash returns SHA digest, then passed to ring::verify -> DOUBLE HASH BUG
- Key h=, s=, t= parsed in key.rs but never checked in verify flow
- Body hash compared with == or != instead of constant_time_eq
- RSA_PKCS1_2048_8192 rejects 1024-bit keys without fallback algorithm
- Over-signed headers skipped during verification (empty value not contributed)
- i= domain check against d= missing during verification
