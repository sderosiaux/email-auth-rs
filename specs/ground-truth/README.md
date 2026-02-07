# Ground Truth Test Fixtures

## Key Pairs
- `rsa2048.pem` — RSA 2048-bit private key (PKCS8)
- `rsa1024.pem` — RSA 1024-bit private key (legacy, must verify but not sign)
- `ed25519.pem` — Ed25519 private key (PKCS8)
- `*.pub.b64` — Corresponding public keys in base64 (SubjectPublicKeyInfo DER)

## DNS Mock Data
See `dns-fixtures.json` — frozen DNS responses for deterministic testing.

## Usage
Tests load these fixtures via include_bytes!/include_str! or read at test time.
The signing test (M7) signs messages with these keys, then M6 verifier must validate them.
The DNS fixtures provide mock TXT records for SPF, DKIM key, and DMARC lookups.
