# M4: DKIM Parsing
Scope: src/dkim/signature.rs, src/dkim/key.rs
Depends on: M1
RFC: 6376 Sections 3.5, 3.6

## Signature parsing contracts
- Tag=value pairs separated by semicolons, whitespace tolerant
- Handle folded headers (CRLF + whitespace -> unfold before parsing)
- Handle base64 values with embedded whitespace (strip before decode)
- Required tags: v (must be 1), a, b, bh, d, s, h — missing any -> PermFail
- Duplicate tags: PermFail (not silent overwrite)
- h= must contain "from" (case-insensitive) -> PermFail if missing
- i= (AUID): if present, must be subdomain of or equal to d= -> PermFail if not
- i= default: @<d=> value
- c= default: simple/simple. Format: header/body or just header (body defaults to simple)
- x= < current time: expired (checked during verification, not parsing)
- x= and t= both present: x must be >= t
- z= (copied headers): parse as pipe-separated list, store structured
- Unknown tags: ignore (forward compatibility)

## Tag=value parsing implementation
Shared pattern for both DKIM signatures and key records:
1. Split by `;`
2. For each part: split at first `=` to get tag name and value
3. Trim whitespace from tag name and value
4. Tag names are case-sensitive (per RFC, though all defined tags are lowercase)
5. Detect duplicate tags before processing

### Base64 handling for b= and bh=
- b= and bh= values may contain embedded FWS (folding whitespace: CRLF + space/tab)
- Strip ALL whitespace (spaces, tabs, CR, LF) before base64 decode
- Use `base64::engine::general_purpose::STANDARD` for decode
- Do NOT use URL-safe base64 variant

### Header value storage
Store the original raw header value (before tag parsing) alongside parsed fields. This is needed for canonicalization during verification — the verifier needs the original DKIM-Signature header text to strip b= and canonicalize.

## Key record parsing contracts
- Tag=value from DNS TXT at <selector>._domainkey.<domain>
- v=: optional, if present must be "DKIM1"
- k=: key type, default "rsa". Support "rsa" and "ed25519"
- p=: public key base64, required. Empty = revoked.
- h=: acceptable hash algorithms (colon-separated). If present, constrains which signature algorithms can use this key.
- s=: service types (colon-separated), default "*". Must include "email" or "*".
- t=: flags (colon-separated). "y" = testing mode, "s" = strict (i= must exactly match d=)
- n=: human-readable notes, ignored
- Multiple TXT strings: concatenate before parsing (DNS TXT records can be split into 255-byte chunks)

### Key type and algorithm cross-validation
- k=rsa: valid with a=rsa-sha256 and a=rsa-sha1
- k=ed25519: valid with a=ed25519-sha256 only
- Mismatch between key type and signature algorithm -> PermFail

### Ed25519 key format
- Ed25519 public key in p= is the raw 32-byte key, base64-encoded
- NOT wrapped in SubjectPublicKeyInfo DER structure (unlike RSA)
- Decoded p= for Ed25519 should be exactly 32 bytes

### RSA key format
- RSA public key in p= is DER-encoded SubjectPublicKeyInfo
- ring accepts this format directly via `UnparsedPublicKey`
- DER sizes by key length:
  - 1024-bit: ~162 bytes
  - 2048-bit: ~294 bytes
  - 4096-bit: ~550 bytes

## Structured types for key fields
Parse into enums/vecs, not raw strings:
```rust
pub enum KeyType { Rsa, Ed25519 }
pub enum HashAlgorithm { Sha1, Sha256 }
pub enum KeyFlag { Testing, Strict }

pub struct DkimPublicKey {
    pub version: Option<String>,
    pub key_type: KeyType,
    pub public_key: Vec<u8>,          // decoded p= bytes
    pub hash_algorithms: Option<Vec<HashAlgorithm>>,
    pub service_types: Vec<String>,
    pub flags: Vec<KeyFlag>,
    pub notes: Option<String>,
}
```

## Review kill patterns
- Duplicate tag detection absent (silently overwrites)
- h= not validated to contain "from"
- i= subdomain-of-d= check missing
- Key h=, s=, t= fields parsed into raw strings instead of structured enums/vecs
- z= stored as raw string instead of parsed Vec<(String, String)>
- Base64 whitespace not stripped before decode (fails on folded headers)
- Ed25519 key treated as DER SubjectPublicKeyInfo (wrong — it's raw 32 bytes)
- Multiple DNS TXT strings not concatenated before tag parsing
- Original header value not preserved for canonicalization
