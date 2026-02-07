# M3: SPF Evaluation
Scope: src/spf/eval.rs, src/spf/mod.rs (SpfVerifier)
Depends on: M2
RFC: 7208 Sections 4, 5

## Contracts
- check_host(ip, domain, sender, helo, receiver) -> SpfResult
- DNS lookup limit: max 10 across entire evaluation (include, redirect, a, mx, ptr, exists count; ip4, ip6, all do NOT)
- Void lookup limit: max 2 (NxDomain or empty responses) -> PermError
- Empty MAIL FROM: use postmaster@<helo_domain> as sender
- Left-to-right directive evaluation, first match wins
- No match + no redirect: Neutral
- redirect= modifier: only if no directive matched, target None -> PermError, counts as DNS lookup

## Mechanism evaluation
- all: always matches
- include: recursive check_host, map child Pass->match, Fail/SoftFail/Neutral/None->no match, TempError/PermError propagate
- a/mx: macro expand domain, query A (if client v4) or AAAA (if v6), CIDR match. MX limited to first 10 hosts.
- ptr: reverse lookup -> forward confirm -> domain suffix check. Limit to 10 PTR names. Deprecated but must support.
- ip4/ip6: CIDR match, no DNS lookup
- exists: macro expand domain, A query, any result=match, NxDomain=no match

## exp= modifier evaluation
- Only when result is Fail
- Query TXT at expanded exp domain
- Expand macros in TXT result (including c, r, t explanation-only macros)
- Attach explanation string to Fail result

## Review kill patterns
- exp= parsed but never evaluated during check_host
- DNS lookup counter not incremented for some mechanisms (especially exists, ptr)
- Void lookup counter absent or not enforced
- Multiple SPF records accepted instead of PermError
- include child PermError/TempError not propagated
- MX mechanism not limited to 10 hosts
