# Learnings — Cycle 1, Lane 6: dkim-canonicalization

## FRICTION
- None significant. Canonicalization is well-specified — each rule maps directly to code.

## GAP
- Spec says relaxed body "empty → empty" but doesn't clarify what happens with a body that is only whitespace lines. Decision: whitespace-only lines become empty after WSP stripping, then get removed as trailing blank lines → result is empty. This is consistent with the spec's intent (src/dkim/canon.rs:149-153).
- Spec §3.5 says over-signed headers contribute "empty canonicalized header" but doesn't specify the exact format for simple vs relaxed. Both produce `headername:\r\n` — for relaxed, the name is lowercased. This matches RFC 6376 §5.4.2 wording (src/dkim/canon.rs:196-197).
- Spec doesn't specify behavior for lone CR (`\r` not followed by `\n`). Decision: preserve as-is since it's not a line ending. Only bare LF and CRLF are recognized as line endings (src/dkim/canon.rs:11-13).

## DECISION
- **`canonicalize_header` returns String without trailing CRLF**: Callers append CRLF themselves. This keeps the function composable — the DKIM-Signature header (last in hash input) must NOT have trailing CRLF, so the caller controls this.
- **`select_headers` returns Vec<String> with CRLF**: Each entry includes `\r\n` since all selected headers except the DKIM-Signature header need it. The caller handles the DKIM-Signature header separately.
- **`strip_b_tag_value` uses character-level structural parsing**: Checks that `b` is not preceded by an alphabetic char (avoiding `bh=`) and that the next non-whitespace char is `=`. More robust than regex approaches from prior iterations (src/dkim/canon.rs:227-257).
- **Body canonicalization splits on CRLF then reconstructs**: Rather than in-place mutation, splits into lines, processes each, strips trailing empties, then reassembles. Cleaner and easier to verify correctness.

## SURPRISE
- b= stripping was simpler than expected. The spec warns about bh= false matches, but the structural parsing approach (check previous char isn't alpha) handles it cleanly without regex complexity.
- Simple body canonicalization of content without trailing CRLF correctly adds one — the spec says "ensure body ends with CRLF" which applies even to bodies that don't end with a newline.

## DEBT
- None. Clean implementation matching spec exactly.
