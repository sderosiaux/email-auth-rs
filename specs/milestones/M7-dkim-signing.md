# M7: DKIM Signing
Scope: src/dkim/sign.rs
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

## Private key loading

### RSA keys
```rust
use ring::signature::RsaKeyPair;
// From PKCS8 DER:
let key_pair = RsaKeyPair::from_pkcs8(pkcs8_der_bytes)?;
// Signing:
let rng = ring::rand::SystemRandom::new();
let mut signature = vec![0u8; key_pair.public_modulus_len()];
key_pair.sign(&RSA_PKCS1_SHA256, &rng, &message, &mut signature)?;
```

### Ed25519 keys
```rust
use ring::signature::Ed25519KeyPair;
// From PKCS8 DER:
let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_der_bytes)?;
// Signing:
let signature = key_pair.sign(&message);
```

### PEM support
Strip PEM header/footer (`-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----`), base64-decode the middle to get DER bytes. Use the same loading path as DER.

## DKIM-Signature header construction
1. Compute body hash (canonicalize body, hash, base64)
2. Build tag=value pairs: v=1; a=<alg>; c=<canon>; d=<domain>; s=<selector>; h=<headers>; bh=<body_hash>; t=<timestamp>; b=
3. Canonicalize the signed headers (bottom-up selection, same as verification)
4. Append the incomplete DKIM-Signature header (with b= empty) to hash input WITHOUT trailing CRLF
5. Sign the complete hash input with private key
6. Base64-encode signature -> b= value
7. Insert b= value into the header

### Header line folding
- DKIM-Signature header should be folded at ~78 characters for SMTP compliance
- Fold at tag boundaries (before `;`) or within base64 values
- Use `\r\n\t` for continuation (CRLF + tab)

## Validation: round-trip
- sign(message) -> signature -> verify(message + signature) must Pass
- This validates that sign and verify agree on canonicalization, hash, and crypto
- BUT: also validate against ground-truth fixtures to avoid self-consistent bugs

### Ground-truth signing tests
In addition to round-trip, build tests that:
1. Sign a message with DkimSigner
2. Extract the canonicalized header data that was signed
3. Verify the signature using ring primitives directly (bypassing DkimVerifier)
4. Also verify the body hash independently

This catches bugs where signer and verifier agree on wrong canonicalization.

### Test matrix
- RSA-SHA256 with relaxed/relaxed
- RSA-SHA256 with simple/simple
- Ed25519-SHA256 with relaxed/relaxed
- Message with multiple headers of same name
- Message with empty body
- Message with only \n line endings (should be normalized)

## Review kill patterns
- Signing and verification use different canonicalization paths
- Private key format not validated (accepts invalid keys silently)
- b= value not properly base64 encoded (line wrapping issues)
- From header not enforced in headers-to-sign list
- ring RSA signing: must pre-allocate output buffer of `key_pair.public_modulus_len()` bytes
- ring Ed25519 signing: returns signature directly (no pre-allocation needed)
- Header hash input includes trailing CRLF on DKIM-Signature (should NOT)
- Timestamp not set (t= missing from output)
- PEM parsing doesn't handle Windows line endings in PEM file
