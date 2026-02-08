# Cycle 1 – Lane 9: dmarc-types-parsing

## What worked
- Tag=value parsing pattern from DKIM translates directly to DMARC; same semicolon-separated, trim-whitespace approach.
- First-occurrence-wins for duplicate tags is cleanest — skip duplicates in the loop body with `if field.is_none()` guards.
- `parse_tag_list` as shared utility: identical structure to DKIM's tag parser. Future refactor candidate into `common/`.

## Gotchas
- `Policy::None` collides with `Option::None` — must write `Option::None` explicitly in parse methods returning `Option<Policy>`.
- DMARC `fo=` uses colon `:` as separator (not semicolon, not comma). Easy to confuse with tag-list separator.
- `pct=` must handle negative values (spec says 0-100 integer). Parse as `i64` first, then clamp, since `u8::parse` rejects negatives.
- URI `!` size suffix uses `rfind('!')` not `find('!')` — email addresses could theoretically contain `!` in local-part.
- Size suffix multipliers are 1024-based (k=1024, m=1024², g=1024³, t=1024⁴), not 1000-based.

## Design decisions
- `DmarcParseError` is a simple struct with `detail: String`, matching the pattern from DKIM. Keeps error handling uniform.
- `np=` (RFC 9091) included as `Option<Policy>` — absent means not specified (different from defaulting to `p=` like `sp=` does).
- `sp=` defaults to `p=` value when absent, per RFC 7489 §6.3.
- `ReportUri` stores the address without `mailto:` prefix — callers don't need the scheme.
- `DmarcResult` and `Disposition` types defined in types.rs for later use by evaluation lane — not tested with behavior yet, just structural tests.
