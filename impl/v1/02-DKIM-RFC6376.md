# DKIM Implementation Spec (RFC 6376)

> LLM-actionable specification for implementing DomainKeys Identified Mail

## Overview

DKIM allows a domain to cryptographically sign email messages, enabling receivers to verify that the message was authorized by the signing domain and has not been modified in transit.

---

## 1. Data Types

### 1.1 DKIM Signature Structure

- [ ] Define `DkimSignature` struct (tag-value pairs from DKIM-Signature header):
  - [ ] `v: u8` — version (must be 1)
  - [ ] `a: Algorithm` — signing algorithm
  - [ ] `b: Vec<u8>` — signature data (decoded from base64)
  - [ ] `bh: Vec<u8>` — body hash (decoded from base64)
  - [ ] `c: Canonicalization` — canonicalization method
  - [ ] `d: String` — signing domain (SDID)
  - [ ] `h: Vec<String>` — signed header fields
  - [ ] `i: Option<String>` — agent/user identifier (AUID)
  - [ ] `l: Option<u64>` — body length limit
  - [ ] `q: QueryMethod` — query method (default dns/txt)
  - [ ] `s: String` — selector
  - [ ] `t: Option<u64>` — signature timestamp
  - [ ] `x: Option<u64>` — signature expiration
  - [ ] `z: Option<Vec<String>>` — copied header fields

### 1.2 Algorithms

- [ ] Define `Algorithm` enum:
  - [ ] `RsaSha1` — RSA with SHA-1 (MUST support for verify)
  - [ ] `RsaSha256` — RSA with SHA-256 (MUST support, preferred)
  - [ ] `Ed25519Sha256` — Ed25519 (RFC 8463, modern)

### 1.3 Canonicalization

- [ ] Define `Canonicalization` struct:
  - [ ] `header: CanonicalizationMethod`
  - [ ] `body: CanonicalizationMethod`

- [ ] Define `CanonicalizationMethod` enum:
  - [ ] `Simple` — minimal transformation
  - [ ] `Relaxed` — tolerates whitespace changes

### 1.4 DNS Key Record

- [ ] Define `DkimPublicKey` struct (from DNS TXT record):
  - [ ] `v: Option<String>` — version (should be "DKIM1")
  - [ ] `h: Option<Vec<HashAlgorithm>>` — acceptable hash algorithms (if present, restricts which signature algorithms can use this key; e.g., `h=sha256` rejects rsa-sha1 signatures)
  - [ ] `k: KeyType` — key type (default "rsa")
  - [ ] `n: Option<String>` — notes (human-readable)
  - [ ] `p: Vec<u8>` — public key data (base64 decoded, empty = revoked)
  - [ ] `s: Option<Vec<ServiceType>>` — service types (default "*")
  - [ ] `t: Option<Vec<KeyFlag>>` — flags

- [ ] Define `KeyType` enum:
  - [ ] `Rsa`
  - [ ] `Ed25519`

- [ ] Define `KeyFlag` enum:
  - [ ] `Y` — testing mode
  - [ ] `S` — same domain only (i= must match d=)

### 1.5 Verification Result

- [ ] Define `DkimResult` enum:
  - [ ] `Pass { domain: String, selector: String }` — valid signature
  - [ ] `Fail { reason: FailureReason }` — invalid signature
  - [ ] `TempFail { reason: String }` — transient error
  - [ ] `PermFail { reason: String }` — permanent error
  - [ ] `None` — no signature present

- [ ] Define `FailureReason` enum:
  - [ ] `SignatureMismatch` — crypto verification failed
  - [ ] `BodyHashMismatch` — body hash doesn't match
  - [ ] `KeyRevoked` — empty public key in DNS
  - [ ] `KeyNotFound` — DNS lookup failed
  - [ ] `ExpiredSignature` — past x= timestamp
  - [ ] `FutureSignature` — t= in future (clock skew)
  - [ ] `AlgorithmMismatch` — key doesn't support algorithm
  - [ ] `DomainMismatch` — i= not subdomain of d=

---

## 2. Signature Header Parsing (RFC 6376 Section 3.5)

### 2.1 DKIM-Signature Header Format

- [ ] Parse as tag=value pairs, separated by semicolons
- [ ] Handle folded headers (CRLF + whitespace)
- [ ] Strip whitespace around tags and values
- [ ] Handle base64 values with embedded whitespace

### 2.2 Required Tags

- [ ] `v=` — version (MUST be "1")
- [ ] `a=` — algorithm (rsa-sha1, rsa-sha256, ed25519-sha256)
- [ ] `b=` — signature (base64)
- [ ] `bh=` — body hash (base64)
- [ ] `d=` — signing domain
- [ ] `h=` — signed headers (colon-separated)
- [ ] `s=` — selector

### 2.3 Optional Tags

- [ ] `c=` — canonicalization (default: simple/simple)
  - [ ] Format: `header/body` or just `header` (body defaults to simple)
- [ ] `i=` — AUID (default: `@d`)
  - [ ] Must be subdomain of or equal to `d=`
- [ ] `l=` — body length (decimal)
- [ ] `q=` — query method (default: dns/txt)
- [ ] `t=` — timestamp (Unix epoch)
- [ ] `x=` — expiration (Unix epoch, must be >= t if both present)
- [ ] `z=` — copied headers (pipe-separated, for diagnostics)

### 2.4 Validation Rules

- [ ] Unknown tags: ignore (forward compatibility)
- [ ] Duplicate tags: PERMFAIL
- [ ] Missing required tags: PERMFAIL
- [ ] `h=` must include "from" (case-insensitive)
- [ ] `x=` < current time: signature expired
- [ ] `i=` not subdomain of `d=`: PERMFAIL

---

## 3. Canonicalization (RFC 6376 Section 3.4)

### 3.1 Header Canonicalization

#### Simple (`simple`)
- [ ] No changes to headers
- [ ] Headers used exactly as they appear
- [ ] Header names are case-sensitive (but selected case-insensitively)

#### Relaxed (`relaxed`)
- [ ] Convert header names to lowercase
- [ ] Unfold headers (remove CRLF before whitespace)
- [ ] Collapse whitespace sequences to single space
- [ ] Remove trailing whitespace from values
- [ ] Remove whitespace before and after colon

### 3.2 Body Canonicalization

#### Simple (`simple`)
- [ ] Remove all empty lines at end of body
- [ ] If body is empty, treat as single CRLF
- [ ] Ensure body ends with CRLF

#### Relaxed (`relaxed`)
- [ ] Remove trailing whitespace from each line
- [ ] Collapse whitespace sequences to single space
- [ ] Remove all empty lines at end of body
- [ ] If body is empty, treat as empty (no CRLF added)

### 3.3 Implementation

- [ ] `canonicalize_header(name: &str, value: &str, method: CanonicalizationMethod) -> String`
- [ ] `canonicalize_body(body: &[u8], method: CanonicalizationMethod) -> Vec<u8>`
- [ ] Handle body length limit (`l=` tag)
- [ ] Ensure CRLF line endings (convert LF-only if needed)

---

## 4. Verification Algorithm (RFC 6376 Section 6)

### 4.1 Signature Extraction

- [ ] Find all DKIM-Signature headers in message
- [ ] Parse each signature (skip malformed ones)
- [ ] Verify signatures in order (first valid wins for DMARC)

### 4.2 DNS Key Lookup

- [ ] Construct query: `<selector>._domainkey.<domain>`
- [ ] Query TXT record
- [ ] Parse key record tags
- [ ] Handle multiple TXT strings (concatenate)
- [ ] Handle NXDOMAIN: key not found
- [ ] Handle empty `p=`: key revoked
- [ ] Cache keys (respect TTL)

### 4.3 Body Hash Verification

- [ ] Apply body canonicalization
- [ ] Apply length limit if `l=` present
- [ ] Compute hash (SHA-1 or SHA-256 per algorithm)
- [ ] Compare with `bh=` value
- [ ] Mismatch: FAIL with BodyHashMismatch

### 4.4 Header Hash Computation

- [ ] For each header in `h=` (in order):
  - [ ] Find header in message (last occurrence if multiple)
  - [ ] Mark as used (for multiple same-name headers)
  - [ ] Canonicalize header
  - [ ] Append to hash input: `name:value\r\n`
- [ ] Append DKIM-Signature header itself:
  - [ ] Canonicalize the signature header
  - [ ] Remove `b=` value (keep `b=` tag with empty value)
  - [ ] Do NOT include trailing CRLF

### 4.5 Signature Verification

- [ ] Decode `b=` from base64
- [ ] Verify signature over header hash using public key
- [ ] RSA: PKCS#1 v1.5 signature verification
- [ ] Ed25519: EdDSA verification
- [ ] Verification failure: FAIL with SignatureMismatch

### 4.6 Result Determination

- [ ] All checks pass: PASS
- [ ] Key not found: TEMPFAIL (DNS issue) or PERMFAIL (NXDOMAIN)
- [ ] Key revoked (empty p=): PERMFAIL
- [ ] Crypto failure: FAIL
- [ ] Body hash mismatch: FAIL
- [ ] Expired signature: PERMFAIL

---

## 5. Signing Algorithm (RFC 6376 Section 5)

### 5.1 Signature Creation

- [ ] Determine headers to sign (must include From)
- [ ] Recommended headers: From, To, Subject, Date, MIME-Version, Content-Type
- [ ] Avoid signing headers that may change: Received, Return-Path

### 5.2 Body Hash Computation

- [ ] Canonicalize body
- [ ] Compute hash
- [ ] Encode as base64 → `bh=`

### 5.3 Header Hash Computation

- [ ] Build list of headers to sign → `h=`
- [ ] Canonicalize each header
- [ ] Construct DKIM-Signature header (without `b=` value)
- [ ] Append canonicalized signature header
- [ ] Compute hash

### 5.4 Signature Generation

- [ ] Sign header hash with private key
- [ ] Encode signature as base64 → `b=`
- [ ] Construct final DKIM-Signature header
- [ ] Insert as first header (or after Received)

### 5.5 Private Key Handling

- [ ] Load private key (PEM format)
- [ ] Support RSA keys (minimum 1024-bit, recommend 2048)
- [ ] Support Ed25519 keys

---

## 6. DNS Key Record Format (RFC 6376 Section 3.6.1)

### 6.1 Record Location

- [ ] Query: `<selector>._domainkey.<domain>` TXT record
- [ ] Selector allows multiple keys per domain
- [ ] Selector naming: alphanumeric, hyphens

### 6.2 Key Record Tags

- [ ] `v=` — version (should be "DKIM1", optional)
- [ ] `h=` — acceptable hashes (colon-separated, default: allow all); if present, signature's hash must be in list (e.g., `h=sha256` rejects rsa-sha1)
- [ ] `k=` — key type (default: "rsa")
- [ ] `n=` — notes (for humans)
- [ ] `p=` — public key base64 (required, empty = revoked)
- [ ] `s=` — service type (default: "*", also "email")
- [ ] `t=` — flags (colon-separated)
  - [ ] `y` — testing mode
  - [ ] `s` — strict (i= domain must exactly match d=)

### 6.3 Public Key Parsing

- [ ] RSA: SubjectPublicKeyInfo DER format (base64)
- [ ] Ed25519: raw 32-byte public key (base64)
- [ ] Handle malformed keys: PERMFAIL

---

## 7. API Design

### 7.1 Verification API

- [ ] `DkimVerifier` struct with DNS resolver
- [ ] `verify_message(headers: &str, body: &[u8]) -> Vec<DkimResult>`
- [ ] `verify_signature(sig: &DkimSignature, headers: &str, body: &[u8], key: &DkimPublicKey) -> DkimResult`

### 7.2 Signing API

- [ ] `DkimSigner` struct with private key
- [ ] `sign_message(headers: &str, body: &[u8], config: &SigningConfig) -> String`
- [ ] `SigningConfig`: domain, selector, algorithm, canonicalization, headers to sign

### 7.3 Parsing API

- [ ] `DkimSignature::parse(header_value: &str) -> Result<DkimSignature, ParseError>`
- [ ] `DkimPublicKey::parse(txt_record: &str) -> Result<DkimPublicKey, ParseError>`

---

## 8. Test Cases

### 8.1 Parsing Tests

- [ ] Minimal valid signature
- [ ] All optional tags present
- [ ] Folded header value (multiline)
- [ ] Base64 with embedded whitespace
- [ ] Missing required tag → error
- [ ] Invalid algorithm → error
- [ ] i= not subdomain of d= → error

### 8.2 Canonicalization Tests

- [ ] Simple header: unchanged
- [ ] Relaxed header: lowercase, collapse whitespace
- [ ] Simple body: trailing blank lines removed
- [ ] Relaxed body: whitespace normalized
- [ ] Empty body handling
- [ ] Body length limit truncation

### 8.3 Verification Tests

- [ ] Valid signature → Pass
- [ ] Tampered body → Fail (body hash)
- [ ] Tampered header → Fail (signature)
- [ ] Expired signature → PermFail
- [ ] Key not found → TempFail/PermFail
- [ ] Key revoked → PermFail
- [ ] Wrong algorithm → PermFail

### 8.4 Signing Tests

- [ ] Sign and verify round-trip
- [ ] RSA-SHA256 signature
- [ ] Ed25519 signature
- [ ] Different canonicalization modes

### 8.5 Real-World Messages

- [ ] Gmail-signed message
- [ ] Microsoft-signed message
- [ ] Message with multiple signatures

---

## 9. Security Considerations

- [ ] Minimum RSA key size: 1024 bits for long-lived keys (warn if smaller)
- [ ] Recommended RSA key size: 2048 bits
- [ ] Reject SHA-1 for signing (accept for verify only); signers SHOULD use rsa-sha256
- [ ] Use constant-time comparison for signature verification (timing attack prevention)
- [ ] Validate signature timestamp (allow clock skew ±300s)
- [ ] Don't trust `l=` completely (body truncation attacks)
- [ ] Verify domain in `i=` matches `d=`

---

## 10. Header Handling Details

### 10.1 Header Selection for Signing (RFC 6376 Section 5.4.2)

- [ ] Headers in `h=` selected case-insensitively
- [ ] Multiple headers with same name: each occurrence in `h=` selects from bottom-up
- [ ] Example: `h=from:to:to:subject` — first `to` selects last To header, second `to` selects second-to-last
- [ ] Over-signing: include header name more times than present to prevent header injection attacks
- [ ] Over-signed headers (not present) contribute empty value to hash

### 10.2 Header Selection for Verification (RFC 6376 Section 5.4.2)

- [ ] Same bottom-up selection logic as signing
- [ ] Headers not present in message: treat as zero-length value (not an error)
- [ ] Track which instances have been consumed
- [ ] Critical for security: prevents adding headers above signed ones

---

## 11. Dependencies

- [ ] Cryptography: `ring` or `rsa` + `ed25519-dalek`
- [ ] Base64: `base64` crate
- [ ] DNS resolver: `hickory-dns`
- [ ] SHA hashing: from crypto crate

---

## 12. Completion Checklist

- [ ] All data types defined
- [ ] Signature parsing complete
- [ ] Key record parsing complete
- [ ] Both canonicalization methods implemented
- [ ] Verification algorithm complete
- [ ] Signing algorithm complete
- [ ] RSA-SHA256 support
- [ ] Ed25519 support (RFC 8463)
- [ ] DNS key lookup working
- [ ] Unit tests passing
- [ ] Real-world message tests passing
- [ ] Documentation complete
