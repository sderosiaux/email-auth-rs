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

## Key record parsing contracts
- Tag=value from DNS TXT at <selector>._domainkey.<domain>
- v=: optional, if present must be "DKIM1"
- k=: key type, default "rsa". Support "rsa" and "ed25519"
- p=: public key base64, required. Empty = revoked.
- h=: acceptable hash algorithms (colon-separated). If present, constrains which signature algorithms can use this key.
- s=: service types (colon-separated), default "*". Must include "email" or "*".
- t=: flags (colon-separated). "y" = testing mode, "s" = strict (i= must exactly match d=)
- n=: human-readable notes, ignored
- Multiple TXT strings: concatenate before parsing

## Review kill patterns
- Duplicate tag detection absent (silently overwrites)
- h= not validated to contain "from"
- i= subdomain-of-d= check missing
- Key h=, s=, t= fields parsed into raw strings instead of structured enums/vecs
- z= stored as raw string instead of parsed Vec<(String, String)>
