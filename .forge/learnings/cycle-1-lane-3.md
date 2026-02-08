# Learnings — Cycle 1, Lane 3: spf-macros

## FRICTION
- IPv6 dot-separated nibble formatting for `%{i}`: must produce 32 hex chars separated by 31 dots (e.g., `2.0.0.1.0.d.b.8...`). Iterate over 8 segments × 4 nibbles each, extracting nibbles from high to low with bitshift (src/spf/macros.rs:132-145).
- Transformer ordering: spec says `{letter}{digits}{r}{delimiters}` — the digit count and reverse flag apply to split parts. Digits=N means "take rightmost N" (not leftmost). 0 means all. Reverse happens before digit selection (src/spf/macros.rs:190-208).
- `%{d1r}` semantics: split "example.com" → ["example","com"], reverse → ["com","example"], take rightmost 1 → ["example"]. The reverse happens first, then digit truncation. This is consistent with RFC 7208 §7.3.

## GAP
- Spec doesn't clarify transformer application order precisely for edge cases like `%{d0r}`. Decided: 0 means all, so `%{d0r}` = split, reverse all, keep all = reversed domain. Matches RFC intent.
- Spec says `%{i}` for IPv6 produces "dot-separated nibbles" but doesn't specify case. Used lowercase hex, consistent with RFC 7208 §7.3 examples.
- Spec doesn't say what happens with empty macro body `%{}`. Treated as error.

## DECISION
- **`expand()` takes `exp_context: bool`**: Simple flag rather than enum. Evaluator passes `true` only when expanding `exp=` TXT record content, `false` for domain-spec macros in mechanisms.
- **`%{p}` returns `"unknown"`**: Spec explicitly allows this stub. Full PTR validation for `%{p}` would require async DNS (not available in pure expansion context). Evaluator can supply a resolved value in `MacroContext` if desired.
- **`%{t}` uses real SystemTime**: Tests only verify the value is a valid timestamp > 1B (post-2001). No clock injection needed for this lane; evaluator tests can mock if needed.
- **Transformers rejoin with dots always**: RFC 7208 §7.3 says transformed output parts are rejoined with `.` regardless of original delimiter. Confirmed correct.

## SURPRISE
- `%{ir}` on IPv4 "192.0.2.1" → split by '.' → ["192","0","2","1"] → reverse → ["1","2","0","192"] → join → "1.2.0.192". This works naturally because the default delimiter is `.` and IPv4 `%{i}` output is already dot-delimited.
- URL encoding with `%{S}` correctly encodes `@` as `%40`: "user@example.com" → "user%40example.com". The unreserved set (alpha, digit, `-._~`) passes through.

## DEBT
- None. Macro expander is complete with all specified letters, transformers, escapes, and URL encoding.
