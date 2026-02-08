# Learnings — Cycle 1, Lane 5: dkim-types-parsing

## FRICTION
- `parse_tag_list` needs to be `pub` (not `pub(crate)`) because `key.rs` imports it from `parser.rs` via `super::parser::parse_tag_list`. Made it `pub` on the function but kept `mod parser` as `pub(crate)` in `mod.rs` — the function is accessible within the crate but not to external users.
- `DkimParseError` is shared between signature parsing and key parsing. Both return `PermFailKind::MalformedSignature` for structural errors. Key parse errors could use a dedicated kind, but the spec doesn't distinguish them — verifier maps key errors to `PermFail { KeyNotFound | KeyRevoked }` anyway.

## GAP
- Spec says `q=` tag should default to `dns/txt` and is the only defined value. No need to store it — parser accepts and ignores it (src/dkim/parser.rs:148).
- Spec doesn't specify whether `h=` header names should be lowercased during parsing. Kept them as-is — canonicalization handles case normalization during verification. This is consistent with RFC 6376 which says header selection is case-insensitive but doesn't mandate storage format.
- Spec doesn't specify whether duplicate flags in `t=` (e.g., `t=y:y`) should error. Silently deduplicates by just pushing to Vec — `is_testing()` checks `contains()` so duplicates are harmless.

## DECISION
- **`DkimParseError` as struct, not enum**: Contains `kind: PermFailKind` + `detail: String`. The verifier can convert this to `DkimResult::PermFail` directly. Simpler than a dedicated error hierarchy.
- **`parse_tag_list` shared between sig and key parsers**: Same tag=value format, same folding/whitespace rules. No duplication.
- **`hash_algorithms: Option<Vec<HashAlgorithm>>`**: `None` means unrestricted (any hash allowed). `Some(vec![])` can't happen — if all h= values are unknown, we return `None` (src/dkim/key.rs:90-93). This prevents a confusing state where h= is present but no algorithms are recognized.
- **`service_types: Option<Vec<String>>`**: `None` means default `*` (any service). Stored as raw strings rather than an enum because the spec allows arbitrary service type values.
- **Key stubs for RSA sizes**: Tests use fake byte arrays (162 bytes for 1024-bit, 294 bytes for 2048-bit) to verify the size threshold logic without needing real keys. Real crypto happens in lane 7 (verification).

## SURPRISE
- No friction from base64 crate — `STANDARD.decode()` works cleanly with pre-stripped whitespace. The spec learning §10.3 advice to strip whitespace before decoding was exactly right.
- Tag=value parsing was simpler than SPF mechanism parsing. No ambiguity between tags and values — the `=` separator is unambiguous since tag names are simple identifiers.
- `validate_auid_domain` using `rfind('@')` handles edge cases like `"user@host"@domain` correctly (takes last `@`), same pattern as SPF's `domain_from_email`.

## DEBT
- None. Types and parsing are clean. No shortcuts taken.
