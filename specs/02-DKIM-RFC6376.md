# DKIM Implementation Spec (RFC 6376)

> LLM-actionable specification for implementing DomainKeys Identified Mail

## Overview

DKIM allows a domain to cryptographically sign email messages, enabling receivers to verify that the message was authorized by the signing domain and has not been modified in transit.

---

## 1. Data Types

### 1.1 DKIM Signature Structure

- [ ] Define `DkimSignature` struct (tag-value pairs from DKIM-Signature header):
  - [ ] `version: u8` — version (must be 1)
  - [ ] `algorithm: Algorithm` — signing algorithm
  - [ ] `signature: Vec<u8>` — signature data (decoded from base64)
  - [ ] `body_hash: Vec<u8>` — body hash (decoded from base64)
  - [ ] `header_canonicalization: CanonicalizationMethod` — header canon
  - [ ] `body_canonicalization: CanonicalizationMethod` — body canon
  - [ ] `domain: String` — signing domain (SDID, d= tag)
  - [ ] `signed_headers: Vec<String>` — signed header field names (h= tag)
  - [ ] `auid: String` — agent/user identifier (i= tag, default `@<d=>`)
  - [ ] `body_length: Option<u64>` — body length limit (l= tag)
  - [ ] `selector: String` — selector (s= tag)
  - [ ] `timestamp: Option<u64>` — signature timestamp (t= tag)
  - [ ] `expiration: Option<u64>` — signature expiration (x= tag)
  - [ ] `copied_headers: Option<Vec<String>>` — copied header fields (z= tag)
  - [ ] `raw_header: String` — original header value for verification (needed for b= stripping)

### 1.2 Algorithms

- [ ] Define `Algorithm` enum:
  - [ ] `RsaSha1` — RSA with SHA-1 (MUST support for verify, MUST NOT use for signing)
  - [ ] `RsaSha256` — RSA with SHA-256 (MUST support, preferred)
  - [ ] `Ed25519Sha256` — Ed25519 (RFC 8463, modern)
- [ ] Parsing: "rsa-sha1", "rsa-sha256", "ed25519-sha256" (case-insensitive)
- [ ] Unknown algorithm → PermFail

### 1.3 Canonicalization

- [ ] Define `CanonicalizationMethod` enum:
  - [ ] `Simple` — minimal transformation
  - [ ] `Relaxed` — tolerates whitespace changes
- [ ] c= tag format: `header/body` or just `header` (body defaults to Simple)
- [ ] Default when c= absent: `simple/simple`

### 1.4 DNS Key Record

- [ ] Define `DkimPublicKey` struct (from DNS TXT record):
  - [ ] `key_type: KeyType` — key type (default "rsa")
  - [ ] `public_key: Vec<u8>` — public key data (base64 decoded)
  - [ ] `revoked: bool` — true if p= is empty
  - [ ] `hash_algorithms: Option<Vec<HashAlgorithm>>` — if present, restricts which hashes can be used
  - [ ] `service_types: Option<Vec<String>>` — service types (default "*")
  - [ ] `flags: Vec<KeyFlag>` — flags
  - [ ] `notes: Option<String>` — human-readable notes

- [ ] Define `KeyType` enum: `Rsa`, `Ed25519`
- [ ] Define `HashAlgorithm` enum: `Sha1`, `Sha256`
- [ ] Define `KeyFlag` enum: `Testing` (t=y), `Strict` (t=s)

### 1.5 Verification Result

- [ ] Define `DkimResult` enum:
  - [ ] `Pass { domain: String, selector: String, testing: bool }` — valid signature, carries signing domain, selector, and key testing flag
  - [ ] `Fail { kind: FailureKind, detail: String }` — cryptographic verification failed
  - [ ] `PermFail { kind: PermFailKind, detail: String }` — permanent structural/configuration error
  - [ ] `TempFail { reason: String }` — transient error (DNS timeout)
  - [ ] `None` — no DKIM-Signature header present

- [ ] Define `FailureKind` enum:
  - [ ] `BodyHashMismatch` — computed body hash ≠ bh= value
  - [ ] `SignatureVerificationFailed` — crypto signature check failed

- [ ] Define `PermFailKind` enum:
  - [ ] `MalformedSignature` — parse error in DKIM-Signature header
  - [ ] `KeyRevoked` — empty p= in DNS key record
  - [ ] `KeyNotFound` — DNS NXDOMAIN for key record
  - [ ] `ExpiredSignature` — past x= timestamp + clock skew
  - [ ] `AlgorithmMismatch` — key type incompatible with signature algorithm
  - [ ] `HashNotPermitted` — key h= tag rejects signature's hash
  - [ ] `ServiceTypeMismatch` — key s= tag doesn't include "email" or "*"
  - [ ] `StrictModeViolation` — key t=s but i= domain ≠ d=
  - [ ] `DomainMismatch` — i= not subdomain of d=

---

## 2. Signature Header Parsing (RFC 6376 Section 3.5)

### 2.1 DKIM-Signature Header Format

- [ ] Parse as tag=value pairs, separated by semicolons
- [ ] Handle folded headers (CRLF + whitespace)
- [ ] Strip whitespace around tags and values
- [ ] Handle base64 values with embedded whitespace (strip all whitespace before decoding)

### 2.2 Required Tags

- [ ] `v=` — version (MUST be "1", as integer)
- [ ] `a=` — algorithm (rsa-sha1, rsa-sha256, ed25519-sha256)
- [ ] `b=` — signature (base64, strip whitespace before decode)
- [ ] `bh=` — body hash (base64, strip whitespace before decode)
- [ ] `d=` — signing domain
- [ ] `h=` — signed headers (colon-separated list)
- [ ] `s=` — selector
- [ ] Missing any required tag → `PermFail { kind: MalformedSignature }`

### 2.3 Optional Tags

- [ ] `c=` — canonicalization (default: simple/simple)
  - [ ] Format: `header/body` or just `header` (body defaults to simple)
- [ ] `i=` — AUID (default: `@<d=>`)
  - [ ] Must be subdomain of or equal to `d=` → PermFail if not
- [ ] `l=` — body length (decimal, unsigned)
- [ ] `q=` — query method (default: dns/txt, only defined value)
- [ ] `t=` — timestamp (Unix epoch)
- [ ] `x=` — expiration (Unix epoch, must be >= t if both present)
- [ ] `z=` — copied headers (pipe-separated)

### 2.4 Validation Rules

- [ ] Unknown tags: ignore (forward compatibility)
- [ ] Duplicate tags: PermFail
- [ ] Missing required tags: PermFail
- [ ] `h=` must include "from" (case-insensitive) → PermFail if missing
- [ ] `i=` not subdomain of `d=` → PermFail
- [ ] Store raw header value in `DkimSignature.raw_header` for b= stripping during verification

---

## 3. Canonicalization (RFC 6376 Section 3.4)

### 3.1 Header Canonicalization

#### Simple (`simple`)
- [ ] No changes to header content
- [ ] Output: `name:value\r\n` exactly as it appears
- [ ] Header names case-preserved in output, but selected case-insensitively from message

#### Relaxed (`relaxed`)
- [ ] Convert header name to lowercase
- [ ] Unfold headers (remove CRLF before whitespace)
- [ ] Collapse sequential whitespace (SP/HTAB) to single SP
- [ ] Remove trailing whitespace from header value
- [ ] Remove whitespace before and after colon (NO space between name and value in output)
- [ ] Output: `lowercasename:trimmed_collapsed_value\r\n`

### 3.2 Body Canonicalization

#### Simple (`simple`)
- [ ] Remove all trailing empty lines at end of body
- [ ] If body is empty after stripping: treat as single CRLF (body is `\r\n`)
- [ ] Ensure body ends with CRLF

#### Relaxed (`relaxed`)
- [ ] Remove trailing whitespace (SP/HTAB) from each line
- [ ] Collapse sequential whitespace within lines to single SP
- [ ] Remove all trailing empty lines at end of body
- [ ] If body is empty after stripping: body is empty (NOT CRLF — differs from simple!)

### 3.3 Line Ending Normalization
- [ ] Convert bare LF (`\n`) to CRLF (`\r\n`) BEFORE canonicalization
- [ ] This is critical: real-world messages may have mixed line endings

### 3.4 Body Length Limit (`l=` tag)
- [ ] Truncate canonicalized body to `l=` bytes before hashing
- [ ] `l=` is a security concern (body truncation attacks) — process it but note in result

### 3.5 Header Selection (RFC 6376 Section 5.4.2)

- [ ] Headers in `h=` selected case-insensitively from message
- [ ] Multiple same-name headers: bottom-up selection (last occurrence consumed first)
- [ ] Track consumed instances per header name using a counter
- [ ] Over-signing: if `h=` lists a header name more times than it exists in message, extra entries contribute an EMPTY canonicalized header to the hash input:
  - Simple: `headername:\r\n`
  - Relaxed: `headername:\r\n`
- [ ] Over-signed headers MUST NOT be silently skipped — they are security-critical (prevent header injection)

### 3.6 b= Tag Stripping

- [ ] Remove the VALUE of the b= tag from DKIM-Signature header, keeping `b=` with empty value
- [ ] MUST NOT affect the bh= tag (careful: naive "b=" search could match "bh=")
- [ ] Implementation: find `b=` that is NOT preceded by `b` (i.e., not `bh=`), then strip value up to next `;` or end
- [ ] The DKIM-Signature header is appended to hash input WITHOUT trailing CRLF

---

## 4. Verification Algorithm (RFC 6376 Section 6)

### 4.1 Signature Extraction

- [ ] Find all DKIM-Signature headers in message (case-insensitive name match)
- [ ] Parse each signature
- [ ] Malformed signatures → PermFail with MalformedSignature kind
- [ ] Return one result per DKIM-Signature, or single `None` if no signatures present

### 4.2 DNS Key Lookup

- [ ] Construct query: `<selector>._domainkey.<domain>` TXT record
- [ ] Handle multiple TXT strings: concatenate into single string before parsing
- [ ] Handle NXDOMAIN → PermFail with KeyNotFound
- [ ] Handle TempFail → TempFail
- [ ] Empty `p=` → PermFail with KeyRevoked
- [ ] DNS caching: caller responsibility (document this)

### 4.3 Key Constraint Enforcement (ordered)

- [ ] a. Empty p= → PermFail KeyRevoked
- [ ] b. Key h= tag: if present, signature's hash algorithm must be in the list
  - rsa-sha1 → Sha1, rsa-sha256/ed25519-sha256 → Sha256
  - Not in list → PermFail HashNotPermitted
- [ ] c. Key s= tag: must include "email" or "*" → PermFail ServiceTypeMismatch
- [ ] d. Key t=s flag: i= domain must exactly equal d= (not subdomain) → PermFail StrictModeViolation
- [ ] e. Key type must match algorithm:
  - rsa-sha1/rsa-sha256 → Rsa key
  - ed25519-sha256 → Ed25519 key
  - Mismatch → PermFail AlgorithmMismatch

### 4.4 Expiration Check

- [ ] If x= present: `current_time > x + clock_skew` → PermFail ExpiredSignature
- [ ] Clock skew: configurable, default 300 seconds
- [ ] Check BEFORE DNS lookup to avoid unnecessary queries for expired signatures

### 4.5 Body Hash Verification

- [ ] Apply body canonicalization (simple or relaxed)
- [ ] Apply length limit if `l=` present (truncate canonicalized body)
- [ ] Compute hash (SHA-1 for rsa-sha1, SHA-256 for rsa-sha256/ed25519-sha256)
- [ ] Compare with `bh=` value using CONSTANT-TIME comparison
- [ ] Mismatch → Fail with BodyHashMismatch

#### Constant-Time Comparison
- [ ] Use `ring::constant_time::verify_slices_are_equal` or `subtle` crate's `ConstantTimeEq`
- [ ] ring 0.17 has deprecated `verify_slices_are_equal` — check for replacement or use `subtle` crate
- [ ] NEVER use `==` for body hash comparison (timing side-channel)

### 4.6 Header Hash Computation

- [ ] For each header name in `h=` (in order):
  - [ ] Find header in message (bottom-up: last unused occurrence)
  - [ ] Mark as consumed
  - [ ] If not found (over-signed): use empty header value
  - [ ] Canonicalize header
  - [ ] Append to hash input: `name:value\r\n`
- [ ] Append DKIM-Signature header itself:
  - [ ] Use raw_header value stored during parsing
  - [ ] Strip b= tag value (keep `b=` with empty value)
  - [ ] Canonicalize the signature header
  - [ ] Append WITHOUT trailing CRLF (last header has no CRLF)

### 4.7 Cryptographic Signature Verification

- [ ] Pass RAW header data bytes to ring — ring hashes internally
- [ ] **CRITICAL: Do NOT pre-hash the header data. ring::UnparsedPublicKey::verify(data, signature) takes the raw MESSAGE, not a digest. Pre-hashing = double-hash = always fails.**

#### RSA Key Size Detection
- [ ] ring requires different algorithm constants for different key sizes
- [ ] 1024-bit RSA: DER-encoded SubjectPublicKeyInfo is ~140-170 bytes
- [ ] 2048-bit RSA: DER-encoded SubjectPublicKeyInfo is ~290-300 bytes
- [ ] 4096-bit RSA: DER-encoded SubjectPublicKeyInfo is ~550-560 bytes
- [ ] Use threshold: `key.public_key.len() < 256` → use `_1024_8192_FOR_LEGACY_USE_ONLY` variant
- [ ] ≥256 bytes → use `_2048_8192` variant

#### Algorithm → ring constant mapping
```
RSA-SHA256, key ≥ 256 bytes: RSA_PKCS1_2048_8192_SHA256
RSA-SHA256, key < 256 bytes: RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
RSA-SHA1,   key ≥ 256 bytes: RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
RSA-SHA1,   key < 256 bytes: RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
Ed25519-SHA256:              ED25519
```

#### Ed25519 Key Format
- [ ] Ed25519 public key in DNS: raw 32-byte key, base64 encoded in p= tag
- [ ] ring expects raw 32 bytes for Ed25519 verification

### 4.8 Result Determination

- [ ] All checks pass → Pass { domain, selector, testing }
- [ ] Body hash mismatch → Fail { BodyHashMismatch }
- [ ] Crypto verification fails → Fail { SignatureVerificationFailed }
- [ ] Key not found (NXDOMAIN) → PermFail { KeyNotFound }
- [ ] Key revoked (empty p=) → PermFail { KeyRevoked }
- [ ] DNS temp failure → TempFail
- [ ] All other constraint violations → PermFail with specific kind

---

## 5. Signing Algorithm (RFC 6376 Section 5)

### 5.1 DkimSigner Configuration

```rust
pub struct DkimSigner {
    private_key: PrivateKey,  // RSA or Ed25519
    domain: String,           // d= tag
    selector: String,         // s= tag
    algorithm: Algorithm,
    header_canon: CanonicalizationMethod,
    body_canon: CanonicalizationMethod,
    headers_to_sign: Vec<String>,
    expiration_seconds: Option<u64>,
}
```

### 5.2 Private Key Handling

- [ ] Load private key: PEM format (PKCS8)
- [ ] Support RSA keys (minimum 1024-bit for verify, recommend 2048+ for signing)
- [ ] Support Ed25519 keys (PKCS8 format)
- [ ] ring: `RsaKeyPair::from_pkcs8()` for RSA, `Ed25519KeyPair::from_pkcs8()` for Ed25519
- [ ] Validate key loads successfully at signer creation time (fail fast)

### 5.3 Headers to Sign

- [ ] MUST include From
- [ ] Recommended: From, To, Subject, Date, MIME-Version, Content-Type, Message-ID
- [ ] Avoid signing: Received, Return-Path (change in transit)
- [ ] Over-signing recommended: include header names extra times to prevent injection

### 5.4 Signing Flow

1. Canonicalize body → compute hash → base64 → bh= value
2. Build DKIM-Signature header template with b= empty
3. Canonicalize signed headers (bottom-up selection) + signature header template
4. Sign the canonicalized header bytes with private key
   - ring signs raw data (hashes internally) for both RSA and Ed25519
5. Base64 encode signature → fill in b= value
6. Output complete DKIM-Signature header value

### 5.5 Timestamp and Expiration

- [ ] Set `t=` to current Unix timestamp
- [ ] If `expiration_seconds` configured: set `x=` to `t + expiration_seconds`

### 5.6 Validation

- [ ] Sign-then-verify round-trip: `sign(message) → verify(message + signature)` must Pass
- [ ] ALSO test with ground-truth fixtures that bypass DkimSigner (use ring primitives directly) to catch self-consistent bugs

---

## 6. DNS Key Record Format (RFC 6376 Section 3.6.1)

### 6.1 Record Location

- [ ] Query: `<selector>._domainkey.<domain>` TXT record
- [ ] Selector allows multiple keys per domain
- [ ] Multiple TXT strings in one record: concatenate before parsing

### 6.2 Key Record Tags

- [ ] `v=` — version (should be "DKIM1", optional — if present must be exactly "DKIM1")
- [ ] `h=` — acceptable hash algorithms (colon-separated). If present: signature's hash must be in list
- [ ] `k=` — key type (default: "rsa"). Support "rsa" and "ed25519"
- [ ] `n=` — notes (human-readable, ignored by verifier)
- [ ] `p=` — public key base64 (required, empty = key revoked)
- [ ] `s=` — service type (colon-separated, default: "*"). Must include "email" or "*"
- [ ] `t=` — flags (colon-separated):
  - [ ] `y` — testing mode (key valid, but results are informational)
  - [ ] `s` — strict mode (i= domain must exactly match d=, not subdomain)
- [ ] Unknown tags: ignore (forward compatibility)

### 6.3 Public Key Format

- [ ] RSA: SubjectPublicKeyInfo DER format, base64 encoded
- [ ] Ed25519: raw 32-byte public key, base64 encoded
- [ ] Malformed/undecodable keys → PermFail

---

## 7. API Design

### 7.1 Verification API

```rust
pub struct DkimVerifier<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,  // default 300s
}

impl<R: DnsResolver> DkimVerifier<R> {
    pub fn new(resolver: R) -> Self;
    pub fn clock_skew(self, seconds: u64) -> Self;
    pub async fn verify_message(
        &self,
        headers: &[(&str, &str)],  // (name, value) pairs
        body: &[u8],
    ) -> Vec<DkimResult>;
}
```

### 7.2 Signing API

```rust
pub struct DkimSigner { ... }

impl DkimSigner {
    pub fn rsa_sha256(domain, selector, pem_pkcs8) -> Result<Self, Error>;
    pub fn ed25519(domain, selector, pkcs8) -> Result<Self, Error>;
    pub fn sign_message(&self, headers: &str, body: &[u8]) -> Result<String, Error>;
}
```

### 7.3 Parsing API

```rust
DkimSignature::parse(header_value: &str) -> Result<DkimSignature, DkimParseError>
DkimPublicKey::parse(txt_record: &str) -> Result<DkimPublicKey, KeyParseError>
```

---

## 8. Test Cases

### 8.1 Parsing Tests

- [ ] Minimal valid signature (all required tags only)
- [ ] All optional tags present
- [ ] Folded header value (multiline with continuation)
- [ ] Base64 with embedded whitespace
- [ ] Missing required tag → PermFail
- [ ] Duplicate tag → PermFail
- [ ] Unknown tag → ignored
- [ ] Invalid algorithm → PermFail
- [ ] h= missing "from" → PermFail
- [ ] i= not subdomain of d= → PermFail
- [ ] c= parsing: "relaxed/relaxed", "simple", "relaxed" (body defaults to simple)

### 8.2 Key Record Parsing Tests

- [ ] Minimal key: `p=<base64>`
- [ ] Full key with all tags
- [ ] Revoked key: `p=` (empty)
- [ ] h= tag with sha256 only
- [ ] s= tag with "email" vs "*" vs "other"
- [ ] t= flags: testing, strict, both
- [ ] Unknown key type
- [ ] Ed25519 key (32 bytes)
- [ ] RSA 1024-bit key
- [ ] RSA 2048-bit key

### 8.3 Canonicalization Tests

- [ ] Simple header: output unchanged (preserving case)
- [ ] Relaxed header: lowercase name, collapse whitespace, remove trailing WSP, no space around colon
- [ ] Simple body: trailing blank lines removed, empty body → `\r\n`
- [ ] Relaxed body: whitespace normalized, empty body → empty (not `\r\n`)
- [ ] Body length limit truncation
- [ ] Bare LF → CRLF conversion
- [ ] Header selection: bottom-up for multiple same-name headers
- [ ] Over-signed headers: contribute empty value (not skipped)
- [ ] b= tag stripping: does NOT affect bh= tag

### 8.4 Verification Tests

- [ ] Valid Ed25519 signature → Pass
- [ ] Valid RSA-SHA256 signature → Pass
- [ ] Valid RSA-SHA1 signature → Pass (MUST test this code path)
- [ ] Tampered body → Fail (BodyHashMismatch)
- [ ] Tampered header → Fail (SignatureVerificationFailed)
- [ ] Expired signature → PermFail (ExpiredSignature)
- [ ] Key not found (NXDOMAIN) → PermFail (KeyNotFound)
- [ ] Key revoked (empty p=) → PermFail (KeyRevoked)
- [ ] Key h= rejects algorithm → PermFail (HashNotPermitted)
- [ ] Key s= rejects email → PermFail (ServiceTypeMismatch)
- [ ] Key t=s strict mode violation → PermFail (StrictModeViolation)
- [ ] Algorithm/key type mismatch → PermFail (AlgorithmMismatch)
- [ ] DNS temp failure → TempFail
- [ ] No DKIM-Signature → None
- [ ] Simple/simple canonicalization end-to-end
- [ ] Relaxed/relaxed canonicalization end-to-end

### 8.5 Ground-Truth Verification Tests

- [ ] Construct DKIM signatures manually using ring primitives (Ed25519KeyPair.sign), bypassing DkimSigner entirely
- [ ] Verify through the full DkimVerifier pipeline
- [ ] This catches self-consistent bugs where signer and verifier agree but both are wrong
- [ ] Include at minimum: Ed25519 relaxed/relaxed, Ed25519 simple/simple, tampered body, tampered headers

### 8.6 Signing Tests

- [ ] Sign and verify round-trip (Ed25519)
- [ ] Sign and verify round-trip (RSA-SHA256)
- [ ] Different canonicalization modes
- [ ] From header enforced in signed headers
- [ ] Timestamp and expiration set correctly
- [ ] PEM key loading: RSA 2048, Ed25519

---

## 9. Security Considerations

- [ ] Minimum RSA key size: 1024 bits for verification (ring handles this via algorithm selection)
- [ ] Recommended RSA key size for signing: 2048+ bits
- [ ] RSA-SHA1: accept for verification only, NEVER use for signing
- [ ] Constant-time comparison for body hash (timing attack prevention)
- [ ] Validate signature timestamps with configurable clock skew (default ±300s)
- [ ] l= body length: process but note it's a security concern (body truncation attacks)
- [ ] Verify i= domain is subdomain of d= during parsing
- [ ] Key t=s strict mode: i= domain must EXACTLY equal d=

---

## 10. Implementation Learnings (from v1)

### 10.1 ring Crate Patterns
- `UnparsedPublicKey::new(algorithm, key_bytes)` then `.verify(message, signature)`
- ring hashes internally — pass raw data, NEVER pre-hash
- Ed25519: `ring::signature::ED25519` algorithm constant
- RSA: use `_FOR_LEGACY_USE_ONLY` variants for 1024-bit and SHA-1

### 10.2 ring Constant-Time Deprecation
- `ring::constant_time::verify_slices_are_equal` is deprecated in ring 0.17
- Still functional but flagged. Consider `subtle` crate as alternative.
- Must use `#[allow(deprecated)]` if keeping ring's version

### 10.3 Base64 Handling
- DKIM signature values (b=, bh=) may contain whitespace in base64
- Strip ALL whitespace from base64 before decoding
- Use `base64::engine::general_purpose::STANDARD`

### 10.4 Header Value Storage
- Store raw header value (everything after colon) in DkimSignature for b= stripping
- The parser receives the header VALUE (after colon), not the full header line
- During verification, the b= stripping operates on this stored raw value

### 10.5 RSA Key Size Heuristic
- DER-encoded SubjectPublicKeyInfo sizes: 1024-bit ~162 bytes, 2048-bit ~294 bytes
- Threshold 256 bytes: below → 1024-bit legacy algorithm, above → 2048-bit algorithm
- For exact detection: parse DER ASN.1 to extract modulus bit length (more work, more correct)

### 10.6 Ed25519 Key Format and ring Compatibility
- Ed25519 public key: exactly 32 bytes (44 base64 chars with padding)
- Ed25519 PKCS8 private key generated by ring: 83 bytes (NOT the 48-byte openssl format)
- **CRITICAL**: ring 0.17 rejects openssl-generated Ed25519 PKCS8 keys with "VersionNotSupported"
- **MUST generate Ed25519 keys using ring itself**: `Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())`
- ring's PKCS8 format includes the public key in the structure (81 bytes = 48 + 33 for public key)
- For testing: generate key once with ring, save PEM, extract raw 32-byte public key via `key_pair.public_key().as_ref()`

### 10.7 RSA Public Key Format: SPKI vs PKCS#1 (CRITICAL)
- DKIM `p=` tag stores **SubjectPublicKeyInfo (SPKI)** DER — this is the RFC 6376 standard format
- ring's RSA `UnparsedPublicKey` expects **PKCS#1 RSAPublicKey** format (raw modulus + exponent), NOT SPKI
- SPKI wraps PKCS#1 with an AlgorithmIdentifier: `SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { RSAPublicKey } }`
- The SPKI prefix for RSA is identifiable by OID `1.2.840.113549.1.1.1` (bytes: `06 09 2a 86 48 86 f7 0d 01 01 01`)
- **MUST strip the SPKI wrapper** before passing RSA public key bytes to ring
- Parse ASN.1: outer SEQUENCE → inner SEQUENCE (AlgorithmIdentifier) → BIT STRING → skip unused-bits byte → inner bytes are PKCS#1
- If OID is absent, bytes are already PKCS#1 — use as-is (graceful fallback)
- Ed25519 keys are raw 32 bytes — no SPKI stripping needed
- After stripping: 2048-bit RSA key is ~270 bytes PKCS#1 (was ~294 SPKI). The 256-byte threshold for key size detection still works.
- **This was the root cause of 3 test failures in v2 iteration** — hash inputs were identical between signer and verifier but verification failed because ring couldn't parse the SPKI-wrapped key

### 10.8 Gotchas
- b= stripping regex must NOT match "bh=" — use lookbehind or structural parsing
- DKIM-Signature header appended to hash WITHOUT trailing CRLF (spec requirement)
- Header selection is bottom-up: if h= lists "to" twice and message has 3 To headers, first "to" in h= selects the last To header, second "to" selects second-to-last
- Over-signed headers produce empty canonicalized headers, NOT silently skipped

---

## 11. Dependencies

- [ ] Cryptography: `ring` 0.17 (RSA + Ed25519 + SHA)
- [ ] Base64: `base64` 0.22 crate
- [ ] DNS resolver: `hickory-resolver` 0.25 (shared via DnsResolver trait)

---

## 12. Completion Checklist

- [ ] All data types defined with typed enums (FailureKind, PermFailKind, not raw strings)
- [ ] Signature parsing complete with all required and optional tags
- [ ] Key record parsing complete with constraint fields (h=, s=, t=)
- [ ] Both canonicalization methods implemented (simple and relaxed, header and body)
- [ ] Header selection with bottom-up and over-signing
- [ ] Bare LF → CRLF normalization
- [ ] b= tag stripping (safe against bh=)
- [ ] Verification algorithm complete with all constraint checks
- [ ] RSA-SHA256 + RSA-SHA1 + Ed25519 verification working
- [ ] Signing algorithm complete (RSA-SHA256 + Ed25519)
- [ ] Ground-truth tests (bypass signer, construct signatures manually)
- [ ] RSA-SHA1 verification tested
- [ ] DNS key lookup working with TXT string concatenation
- [ ] No unwrap/expect in library code (tests only)
