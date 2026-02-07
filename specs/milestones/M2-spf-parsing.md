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
- Unknown modifiers: ignore (forward compatibility per RFC)
- Multiple SPF records in DNS -> PermError (not "pick first")

## Macro expansion (RFC 7208 Section 7)
- Core letters: s, l, o, d, i, v, h — all contexts
- PTR letter p: must actually do PTR validation (expensive but required), or document as unsupported
- Explanation-only letters: c, r, t — valid ONLY in exp= TXT expansion context
- Reject c, r, t in non-exp context
- Uppercase letter -> URL-encode the expanded value
- Transformers: {letter}{digits}r{delimiters} — rightmost N, reverse, custom delimiters
- Escapes: %% (literal %), %_ (space), %- (URL-encoded space)
- IPv6 %{i}: dot-separated nibbles (32 chars)
- MacroContext must carry: sender, local_part, domain, client_ip, helo, receiver (for %{r})

## Review kill patterns
- Unknown mechanisms silently dropped instead of PermError
- Macro letter missing from match arms (especially p, c, r, t)
- Uppercase vs lowercase macro letter distinction absent (URL encoding)
- MacroContext missing receiver field
- Duplicate modifier not detected
