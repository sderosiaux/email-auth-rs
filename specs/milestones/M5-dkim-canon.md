# M5: DKIM Canonicalization
Scope: src/dkim/canon.rs
Depends on: M4
RFC: 6376 Sections 3.4, 5.4

## Header canonicalization contracts
- Simple: no changes. Header names case-sensitive in output, but selected case-insensitively.
- Relaxed: lowercase header name, unfold (remove CRLF before whitespace), collapse WSP sequences to single SP, remove trailing WSP, remove WSP before and after colon (no space between name and value).

## Body canonicalization contracts
- Simple: remove all trailing empty lines. Empty body -> single CRLF. Ensure ends with CRLF.
- Relaxed: remove trailing WSP per line, collapse WSP to single SP, remove trailing empty lines. Empty body -> empty (NO CRLF added, unlike simple).
- Handle l= body length limit: truncate canonicalized body to l= bytes before hashing.
- Normalize line endings: convert bare LF to CRLF before canonicalization.

## Header selection contracts (RFC 6376 Section 5.4.2)
- Headers in h= selected case-insensitively from message
- Multiple same-name headers: bottom-up selection (last occurrence first)
- Track consumed instances per header name
- Over-signing: if h= lists a header name more times than it exists in message, the extra entries contribute an EMPTY canonicalized header (name:CRLF for simple, name:\r\n for relaxed) to the hash input. This is critical for preventing header injection attacks. Do NOT silently skip.

## b= tag stripping for verification
- Remove the value of b= tag from DKIM-Signature header (keep "b=" with empty value)
- Must not affect bh= tag (careful string handling, not naive regex)
- The DKIM-Signature header itself is appended to hash input WITHOUT trailing CRLF

## Review kill patterns
- Over-signed headers silently skipped instead of contributing empty value
- b= stripping affects bh= tag
- Relaxed header adds space after colon (RFC says no space)
- Simple body: empty body doesn't produce CRLF
- Relaxed body: empty body produces CRLF (should be empty)
- Bare LF not converted to CRLF before canonicalization
