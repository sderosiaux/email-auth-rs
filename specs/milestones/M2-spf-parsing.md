# M2: SPF Parsing
Scope: src/spf/record.rs, src/spf/mechanism.rs, src/spf/macro_exp.rs
Depends on: M1
RFC: 7208 Sections 2, 7, 12

## Contracts
- SpfRecord: version (must be "v=spf1"), directives (Vec<Directive>), redirect, explanation modifiers
- Directive: qualifier (Pass+/Fail-/SoftFail~/Neutral?) + mechanism
- All 8 mechanisms: All, Include, A, Mx, Ptr, Ip4, Ip6, Exists with full argument parsing
- A/Mx support dual CIDR: domain/cidr4//cidr6
- Parsing must reject: unknown mechanisms -> PermError, not silently skip
- Parsing must detect: duplicate redirect/exp modifiers -> PermError
- Unknown modifiers: ignore (forward compatibility per RFC). Modifiers have `=` in their syntax; mechanisms do not.
- Multiple SPF records in DNS -> PermError (not "pick first")

## SPF record filtering from DNS
DNS TXT query may return multiple TXT records. SPF filtering rules:
1. Each TXT record is the concatenation of its DNS strings (no separator)
2. Filter to records starting with `v=spf1` (case-insensitive) followed by whitespace or end-of-string
3. Exactly 1 match: parse it
4. 0 matches: SpfResult::None
5. 2+ matches: SpfResult::PermError (not "pick first", not "pick longest")

The `v=spf1` check must be strict: `v=spf10` does NOT match (require space/EOF after `v=spf1`).

## Mechanism parsing details

### CIDR defaults
- ip4: /32 default (exact match)
- ip6: /128 default (exact match)
- a mechanism: /32 for IPv4, /128 for IPv6 (dual CIDR: domain/cidr4//cidr6)
- mx mechanism: same as a

### Mechanism argument parsing
- `all`: no argument
- `include:<domain>`: domain required
- `a`, `mx`: optional domain (defaults to current domain), optional dual CIDR
- `ptr`: optional domain (defaults to current domain). Deprecated but MUST parse.
- `ip4:<network>/<cidr>`: network and optional CIDR
- `ip6:<network>/<cidr>`: network and optional CIDR
- `exists:<domain>`: domain required (commonly uses macros)

### Qualifier parsing
- `+` (Pass, default if omitted), `-` (Fail), `~` (SoftFail), `?` (Neutral)
- The qualifier is a single character prefix. If no qualifier, default is Pass.

## Macro expansion (RFC 7208 Section 7)
- Core letters: s, l, o, d, i, v, h — all contexts
- PTR letter p: must actually do PTR validation (expensive but required), or document as unsupported
- Explanation-only letters: c, r, t — valid ONLY in exp= TXT expansion context
- Reject c, r, t in non-exp context
- Uppercase letter -> URL-encode the expanded value
- Transformers: {letter}{digits}r{delimiters} — rightmost N, reverse, custom delimiters
- Escapes: %% (literal %), %_ (space), %- (URL-encoded space)
- IPv6 %{i}: dot-separated nibbles (32 chars), e.g., `2001:db8::1` -> `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2`
- MacroContext must carry: sender, local_part, domain, client_ip, helo, receiver (for %{r})

### Macro expansion gotchas from v1
- Default delimiter is `.` when none specified in transformer
- Digit transformer `0` means "use all parts" (no truncation), same as omitting digits
- Reverse flag `r` reverses AFTER splitting by delimiter, BEFORE truncation
- Empty local_part (MAIL FROM without @): use `postmaster`

## Review kill patterns
- Unknown mechanisms silently dropped instead of PermError
- Macro letter missing from match arms (especially p, c, r, t)
- Uppercase vs lowercase macro letter distinction absent (URL encoding)
- MacroContext missing receiver field
- Duplicate modifier not detected
- SPF record filtering: `v=spf10` incorrectly matches `v=spf1` prefix
- CIDR defaults not applied (missing /32 or /128)
- Multiple DNS TXT records with `v=spf1` accepted instead of PermError
- Unknown modifiers rejected instead of ignored (modifiers have `=`, mechanisms don't)
