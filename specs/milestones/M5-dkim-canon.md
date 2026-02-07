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

### Empty body edge cases (CRITICAL)
These are the most common source of bugs:
- Simple canon, empty body: output is `\r\n` (single CRLF)
- Simple canon, body is only `\r\n\r\n\r\n`: output is `\r\n` (trailing empty lines removed, but empty body gets one CRLF)
- Relaxed canon, empty body: output is `` (empty string, zero bytes)
- Relaxed canon, body is only `\r\n\r\n\r\n`: output is `` (empty string)
- Relaxed canon, body is `  \r\n  \r\n`: output is `` (trailing WSP removed -> empty lines -> removed)

## Header selection contracts (RFC 6376 Section 5.4.2)
- Headers in h= selected case-insensitively from message
- Multiple same-name headers: bottom-up selection (last occurrence first)
- Track consumed instances per header name
- Over-signing: if h= lists a header name more times than it exists in message, the extra entries contribute an EMPTY canonicalized header (name:CRLF for simple, name:\r\n for relaxed) to the hash input. This is critical for preventing header injection attacks. Do NOT silently skip.

### Header selection implementation
```
Message has: From, To, Subject, From (two From headers)
h= says: from:from:from:to:subject

Selection (bottom-up per name):
1. from -> selects 2nd From (last occurrence)
2. from -> selects 1st From
3. from -> no more From headers -> empty contribution: "from:\r\n"
4. to -> selects To
5. subject -> selects Subject
```

## b= tag stripping for verification
- Remove the value of b= tag from DKIM-Signature header (keep "b=" with empty value)
- Must not affect bh= tag (careful string handling, not naive regex)
- The DKIM-Signature header itself is appended to hash input WITHOUT trailing CRLF

### b= stripping implementation (CRITICAL gotcha from v1)
Naive approach `header.replace(b_value, "")` can corrupt bh= if b= value is a substring of bh= value. Use a targeted approach:

1. Find the b= tag position (not bh=): search for `b=` preceded by `;` or start-of-value, NOT preceded by `b` (to avoid matching `bh=`)
2. Replace from the `=` after `b` to the next `;` or end-of-value with just `=`
3. Regex pattern: `(?:^|;)\s*b\s*=\s*[^;]*` — but verify it doesn't match inside `bh=`

Safer approach: use the parsed tag positions to reconstruct the header with b= value emptied.

## Line ending normalization
- Input messages may have mixed line endings: `\r\n`, `\n`, or even `\r`
- Normalize ALL line endings to `\r\n` before canonicalization
- This applies to both headers and body

## Review kill patterns
- Over-signed headers silently skipped instead of contributing empty value
- b= stripping affects bh= tag (substring collision)
- Relaxed header adds space after colon (RFC says no space)
- Simple body: empty body doesn't produce CRLF
- Relaxed body: empty body produces CRLF (should be empty)
- Bare LF not converted to CRLF before canonicalization
- Header selection goes top-down instead of bottom-up for duplicate headers
- DKIM-Signature header appended WITH trailing CRLF (should be WITHOUT)
- l= applied before canonicalization instead of after (must canonicalize first, then truncate)
