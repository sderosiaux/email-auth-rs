# Ground Truth Test Fixtures

## Key Pairs
- `rsa2048.pem` — RSA 2048-bit private key (PKCS8)
- `rsa1024.pem` — RSA 1024-bit private key (legacy, must verify but not sign)
- `ed25519.pem` — Ed25519 private key (PKCS8)
- `*.pub.b64` — Corresponding public keys in base64 (SubjectPublicKeyInfo DER for RSA, raw 32 bytes for Ed25519)

## DNS Mock Data
See `dns-fixtures.json` — frozen DNS responses for deterministic testing.

## Usage
Tests load these fixtures via include_bytes!/include_str! or read at test time.
The signing test (M7) signs messages with these keys, then M6 verifier must validate them.
The DNS fixtures provide mock TXT records for SPF, DKIM key, and DMARC lookups.

## Ground-truth verification strategy (CRITICAL)

### Why round-trip is insufficient
Sign-then-verify tests only prove that signer and verifier agree. If both have the same canonicalization bug, the test passes but real-world messages fail.

### Required external-construction tests
For DKIM (M6/M7), build tests that bypass the library's own code paths:

1. **Verifier ground-truth**: Manually canonicalize a message (computed by hand or with a reference implementation), sign with ring primitives directly, construct a DKIM-Signature header manually, then feed to DkimVerifier. If DkimVerifier fails, the bug is in the library's canonicalization or verification.

2. **Signer ground-truth**: Sign a message with DkimSigner, then independently verify the signature using ring primitives (bypassing DkimVerifier). Extract the canonicalized headers that DkimSigner would produce, verify the body hash independently.

### Ed25519 key format note
Ed25519 public keys in DNS p= records are raw 32-byte keys (base64-encoded), NOT wrapped in SubjectPublicKeyInfo DER. The `ed25519.pub.b64` fixture should contain the raw 32-byte key, matching what DNS would return.

RSA public keys in DNS p= records ARE DER SubjectPublicKeyInfo.

### DNS fixture design
Each entry in `dns-fixtures.json` should map a query name + type to either:
- A list of records (success)
- `"nxdomain"` marker
- `"tempfail"` marker

This enables testing all DnsError variants including TempFail (which v1 did not test for DMARC discovery).
