# Learnings — Cycle 1, Lane 2: spf-types-parsing

## FRICTION
- Modifier vs mechanism disambiguation: `redirect=a.com` looks like a modifier (alpha name + `=`), but `ip4:1.2.3.4` with no `=` is clearly a mechanism. The tricky case is that mechanism names can appear with `:` args. Solution: `try_parse_modifier()` checks if `name` before `=` is all-alphabetic AND not a known mechanism name (src/spf/parser.rs:73-95).
- A/MX dual CIDR parsing `a:domain/24//64`: the `//` is ambiguous with just string splitting. Used `find("//")` first to split off cidr6, then `rfind('/')` on remainder for cidr4 (src/spf/parser.rs:166-199).
- IPv6 address parsing with prefix: `ip6:2001:db8::1/32` — naive `find('/')` hits the wrong slash since IPv6 uses colons not slashes, but `rfind('/')` works correctly since IPv6 never contains `/` (src/spf/parser.rs:218-231).

## GAP
- Spec says "unknown mechanism → PermError" but doesn't define what makes something a mechanism vs modifier. Decided: if it has `name=value` form where name is all-alpha and not a known mechanism, it's a modifier. Everything else parsed as a directive, and unknown mechanism names → PermError.
- Spec says macros pass through in domain-spec strings at parse time — parser stores raw `%{...}` strings, expansion happens in lane 3 (macro module).
- Spec §8 mentions `SpfRecord::parse` returns owned struct for reuse (CHK-239) — implemented as `SpfRecord::parse(record: &str) -> Result<SpfRecord, String>`.

## DECISION
- **Parser returns `Result<SpfRecord, String>`**: Error string describes the parse failure. Could use a dedicated error enum but spec doesn't require one for parsing — String is sufficient and simpler.
- **CIDR defaults stored as `Option<u8>`**: `None` means "use default" (32 for v4, 128 for v6). Evaluator will apply defaults. This keeps parser pure — it doesn't need to know evaluation defaults.
- **Qualifier stored on Directive, not Mechanism**: Matches spec structure. Mechanism is just the match logic; qualifier determines what result to produce on match.
- **`pub(crate) mod parser`**: Parser internals not public. Users call `SpfRecord::parse()`.

## SURPRISE
- `split_whitespace()` handles multiple spaces and leading/trailing whitespace naturally — no special handling needed for CHK-191/192.
- The modifier disambiguation heuristic caught a subtle case: `a=b` could be interpreted as modifier `a` with value `b`, but since `a` is a known mechanism name, it's correctly rejected as an invalid directive syntax.

## DEBT
- None. Parser is clean and complete for lane 2 scope.
