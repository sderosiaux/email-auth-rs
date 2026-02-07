# M7: DKIM Signing
Scope: src/dkim/sign.rs (or crypto.rs signing section)
Depends on: M6
RFC: 6376 Section 5

## Signing contracts
- Load private key: PEM and DER (PKCS8) format. Support RSA (>=2048 bit) and Ed25519.
- SigningConfig: domain (d=), selector (s=), algorithm, canonicalization, headers to sign, optional body length limit
- Headers to sign: must include From. Recommended: From, To, Subject, Date, MIME-Version, Content-Type, Message-ID. Avoid: Received, Return-Path.
- Body hash: canonicalize body, compute SHA-256 (or SHA-1 for legacy), base64 encode -> bh= tag
- Header hash: canonicalize each signed header (bottom-up selection), construct DKIM-Signature with b= empty, append it, compute hash over all
- Sign: apply private key to raw header data (for RSA: ring signs raw data and hashes internally; for Ed25519: same)
- Output: complete DKIM-Signature header value ready for prepending to message
- Timestamp: set t= to current time. Optionally set x= for expiration.

## Validation: round-trip
- sign(message) -> signature -> verify(message + signature) must Pass
- This validates that sign and verify agree on canonicalization, hash, and crypto
- BUT: also validate against ground-truth fixtures to avoid self-consistent bugs

## Review kill patterns
- Signing and verification use different canonicalization paths
- Private key format not validated (accepts invalid keys silently)
- b= value not properly base64 encoded (line wrapping issues)
- From header not enforced in headers-to-sign list
