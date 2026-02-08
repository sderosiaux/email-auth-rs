# Learnings — Cycle 1, Lane 17: email-authenticator-integration

## FRICTION
- **DkimVerifier `clock_skew` method name**: API is `clock_skew(seconds)` not `with_clock_skew(seconds)`. Builder pattern uses bare name (src/dkim/verify.rs:32). Had to verify exact method name.
- **`from_utf8_lossy` trade-off**: REFLECTION-v2 flagged this as medium risk (src/auth.rs:151). Headers are ASCII per RFC 5322, so lossy conversion is acceptable for parsing. Body is passed as raw `&[u8]` directly to DKIM verifier — no lossy conversion on body.

## GAP
- **Spec doesn't define error behavior for missing From header**: Chose to return `Err(AuthError::NoFromDomain)` rather than proceeding with empty domain. Rationale: DMARC alignment requires a From domain — without one, the entire authentication pipeline is meaningless.
- **Multiple From headers not addressed**: RFC 5322 allows only one From header, but malformed messages may have multiples. Current impl takes the first one found. Spec is silent on this.

## DECISION
- **`split_message` byte-level splitting**: Split at `\r\n\r\n` (preferred) or `\n\n` (fallback) on raw bytes. Headers then converted to string via `from_utf8_lossy`. Body stays as `&[u8]` — DKIM verifier handles it natively. This avoids the REFLECTION-v2 concern about corrupting body content (src/auth.rs:122-133).
- **`extract_email_address` uses `rfind('<')` not `find('<')`**: Handles edge case where display name contains `<` character in quoted string. Last `<` is the start of the actual address.
- **MockResolver per-test**: Rather than reusing a shared mock module, auth tests define their own local MockResolver. This is simpler and avoids coupling to internal test infrastructure in other modules.
- **`unfold` preserves non-folding CRLF**: Only CRLF followed by SP/HTAB is unfolded. CRLF without continuation is preserved as-is. This matches RFC 5322 §2.2.3 exactly.

## SURPRISE
- The entire SPF→DKIM→DMARC pipeline composed cleanly on first try. The `&R` blanket DnsResolver impl (from lane 1) made sharing the resolver trivial — `DkimVerifier::new(&self.resolver)` and `DmarcEvaluator::new(&self.resolver)` just work.
- No async compilation issues. All sub-verifiers accept `&R` where `R: DnsResolver`, so no ownership conflicts.

## DEBT
- None. The authenticator is minimal: message parsing + orchestration. All heavy lifting delegated to SPF/DKIM/DMARC modules.
