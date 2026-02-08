# Forge Work Items
<!-- Source: extracted from spec checkboxes OR derived by forge:plan -->

| ID | Source | Ref | Work Item | Lane | Test | Commit | Status |
|----|--------|-----|-----------|------|------|--------|--------|
| CHK-001 | 01-SPF-RFC7208.md:15 | checkbox | Define `SpfRecord` struct containing: | 2 | src/spf/types.rs:68 | 6b1ee0f | DONE |
| CHK-002 | 01-SPF-RFC7208.md:16 | checkbox | `directives: Vec<Directive>` (mechanisms with qualifiers, in order) | 2 | src/spf/types.rs:69 | 6b1ee0f | DONE |
| CHK-003 | 01-SPF-RFC7208.md:17 | checkbox | `redirect: Option<String>` (redirect modifier target domain) | 2 | src/spf/types.rs:70 | 6b1ee0f | DONE |
| CHK-004 | 01-SPF-RFC7208.md:18 | checkbox | `explanation: Option<String>` (exp= modifier domain) | 2 | src/spf/types.rs:71 | 6b1ee0f | DONE |
| CHK-005 | 01-SPF-RFC7208.md:19 | checkbox | Unknown modifiers: silently ignored (forward compatibility per RFC 7208 §6) | 2 | src/spf/parser.rs:51 | 6b1ee0f | DONE |
| CHK-006 | 01-SPF-RFC7208.md:23 | checkbox | Define `Directive` struct: | 2 | src/spf/types.rs:49 | 6b1ee0f | DONE |
| CHK-007 | 01-SPF-RFC7208.md:24 | checkbox | `qualifier: Qualifier` (enum: Pass `+`, Fail `-`, SoftFail `~`, Neutral `?`) | 2 | src/spf/types.rs:27 | 6b1ee0f | DONE |
| CHK-008 | 01-SPF-RFC7208.md:25 | checkbox | `mechanism: Mechanism` | 2 | src/spf/types.rs:50 | 6b1ee0f | DONE |
| CHK-009 | 01-SPF-RFC7208.md:29 | checkbox | Define `Mechanism` enum with variants: | 2 | src/spf/types.rs:54 | 6b1ee0f | DONE |
| CHK-010 | 01-SPF-RFC7208.md:30 | checkbox | `All` — matches everything | 2 | src/spf/types.rs:55 | 6b1ee0f | DONE |
| CHK-011 | 01-SPF-RFC7208.md:31 | checkbox | `Include { domain: String }` — recursive lookup | 2 | src/spf/types.rs:56 | 6b1ee0f | DONE |
| CHK-012 | 01-SPF-RFC7208.md:32 | checkbox | `A { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> }` — A/AAAA records | 2 | src/spf/types.rs:57 | 6b1ee0f | DONE |
| CHK-013 | 01-SPF-RFC7208.md:33 | checkbox | `Mx { domain: Option<String>, cidr4: Option<u8>, cidr6: Option<u8> }` — MX records | 2 | src/spf/types.rs:58 | 6b1ee0f | DONE |
| CHK-014 | 01-SPF-RFC7208.md:34 | checkbox | `Ptr { domain: Option<String> }` — PTR record (deprecated but MUST support per RFC) | 2 | src/spf/types.rs:59 | 6b1ee0f | DONE |
| CHK-015 | 01-SPF-RFC7208.md:35 | checkbox | `Ip4 { addr: Ipv4Addr, prefix: Option<u8> }` — IPv4 CIDR | 2 | src/spf/types.rs:60 | 6b1ee0f | DONE |
| CHK-016 | 01-SPF-RFC7208.md:36 | checkbox | `Ip6 { addr: Ipv6Addr, prefix: Option<u8> }` — IPv6 CIDR | 2 | src/spf/types.rs:61 | 6b1ee0f | DONE |
| CHK-017 | 01-SPF-RFC7208.md:37 | checkbox | `Exists { domain: String }` — DNS existence check | 2 | src/spf/types.rs:62 | 6b1ee0f | DONE |
| CHK-018 | 01-SPF-RFC7208.md:41 | checkbox | A and Mx mechanisms support dual CIDR: `a:domain/cidr4//cidr6` | 2 | src/spf/parser.rs:449 | 6b1ee0f | DONE |
| CHK-019 | 01-SPF-RFC7208.md:42 | checkbox | Parse both prefixes independently | 2 | src/spf/parser.rs:449 | 6b1ee0f | DONE |
| CHK-020 | 01-SPF-RFC7208.md:43 | checkbox | Default cidr4=32, cidr6=128 | 2 | src/spf/types.rs:57 | 6b1ee0f | DONE |
| CHK-021 | 01-SPF-RFC7208.md:44 | checkbox | Validate prefix ranges: v4 0-32, v6 0-128 | 2 | src/spf/parser.rs:525 | 6b1ee0f | DONE |
| CHK-022 | 01-SPF-RFC7208.md:48 | checkbox | Define `SpfResult` enum (RFC 7208 Section 2.6): | 2 | src/spf/types.rs:5 | 6b1ee0f | DONE |
| CHK-023 | 01-SPF-RFC7208.md:49 | checkbox | `Pass` — sender is authorized | 2 | src/spf/types.rs:7 | 6b1ee0f | DONE |
| CHK-024 | 01-SPF-RFC7208.md:50 | checkbox | `Fail { explanation: Option<String> }` — sender is NOT authorized, with optional explanation from exp= | 2 | src/spf/types.rs:9 | 6b1ee0f | DONE |
| CHK-025 | 01-SPF-RFC7208.md:51 | checkbox | `SoftFail` — weak authorization failure | 2 | src/spf/types.rs:11 | 6b1ee0f | DONE |
| CHK-026 | 01-SPF-RFC7208.md:52 | checkbox | `Neutral` — no assertion made | 2 | src/spf/types.rs:13 | 6b1ee0f | DONE |
| CHK-027 | 01-SPF-RFC7208.md:53 | checkbox | `None` — no SPF record found | 2 | src/spf/types.rs:15 | 6b1ee0f | DONE |
| CHK-028 | 01-SPF-RFC7208.md:54 | checkbox | `TempError` — transient DNS error | 2 | src/spf/types.rs:17 | 6b1ee0f | DONE |
| CHK-029 | 01-SPF-RFC7208.md:55 | checkbox | `PermError` — permanent error (syntax, too many lookups, etc.) | 2 | src/spf/types.rs:19 | 6b1ee0f | DONE |
| CHK-030 | 01-SPF-RFC7208.md:59 | checkbox | Define `MacroContext` struct for macro expansion: | 3 | src/spf/macros.rs:5 | b7bcd10 | DONE |
| CHK-031 | 01-SPF-RFC7208.md:60 | checkbox | `sender: String` — full sender address (local-part@domain) | 3 | src/spf/macros.rs:8 | b7bcd10 | DONE |
| CHK-032 | 01-SPF-RFC7208.md:61 | checkbox | `local_part: String` — local-part of sender | 3 | src/spf/macros.rs:10 | b7bcd10 | DONE |
| CHK-033 | 01-SPF-RFC7208.md:62 | checkbox | `sender_domain: String` — domain of sender | 3 | src/spf/macros.rs:12 | b7bcd10 | DONE |
| CHK-034 | 01-SPF-RFC7208.md:63 | checkbox | `client_ip: IpAddr` — connecting server IP | 3 | src/spf/macros.rs:14 | b7bcd10 | DONE |
| CHK-035 | 01-SPF-RFC7208.md:64 | checkbox | `helo: String` — HELO/EHLO identity | 3 | src/spf/macros.rs:16 | b7bcd10 | DONE |
| CHK-036 | 01-SPF-RFC7208.md:65 | checkbox | `domain: String` — current domain being evaluated | 3 | src/spf/macros.rs:18 | b7bcd10 | DONE |
| CHK-037 | 01-SPF-RFC7208.md:66 | checkbox | `receiver: String` — receiving domain name (for `%{r}` macro) | 3 | src/spf/macros.rs:20 | b7bcd10 | DONE |
| CHK-038 | 01-SPF-RFC7208.md:74 | checkbox | Query DNS TXT records for domain | 2 | src/spf/lookup.rs:49 | 8cbb285 | DONE |
| CHK-039 | 01-SPF-RFC7208.md:75 | checkbox | Filter records starting with "v=spf1" followed by space or end-of-string (case-insensitive) | 2 | src/spf/parser.rs:12 | 6b1ee0f | DONE |
| CHK-040 | 01-SPF-RFC7208.md:76 | checkbox | Handle multiple TXT records: MUST be exactly one SPF record, else `PermError` | 2 | src/spf/lookup.rs:71 | 8cbb285 | DONE |
| CHK-041 | 01-SPF-RFC7208.md:77 | checkbox | Handle no SPF record: return `None` | 2 | src/spf/lookup.rs:83 | 8cbb285 | DONE |
| CHK-042 | 01-SPF-RFC7208.md:78 | checkbox | DNS TempFail during TXT query: return `TempError` | 2 | src/spf/lookup.rs:99 | 8cbb285 | DONE |
| CHK-043 | 01-SPF-RFC7208.md:82 | checkbox | Parse version: `"v=spf1"` (case-insensitive) | 2 | src/spf/parser.rs:12 | 6b1ee0f | DONE |
| CHK-044 | 01-SPF-RFC7208.md:83 | checkbox | Parse directives: `[qualifier] mechanism` | 2 | src/spf/parser.rs:29 | 6b1ee0f | DONE |
| CHK-045 | 01-SPF-RFC7208.md:84 | checkbox | Default qualifier is `+` (Pass) if omitted | 2 | src/spf/parser.rs:152 | 6b1ee0f | DONE |
| CHK-046 | 01-SPF-RFC7208.md:85 | checkbox | Parse modifiers: `name=value` (only `redirect` and `exp` defined) | 2 | src/spf/parser.rs:38 | 6b1ee0f | DONE |
| CHK-047 | 01-SPF-RFC7208.md:86 | checkbox | Handle unknown mechanisms: `PermError` (NOT silently skip) | 2 | src/spf/parser.rs:139 | 6b1ee0f | DONE |
| CHK-048 | 01-SPF-RFC7208.md:87 | checkbox | Handle unknown modifiers: ignore (forward compatibility) | 2 | src/spf/parser.rs:51 | 6b1ee0f | DONE |
| CHK-049 | 01-SPF-RFC7208.md:88 | checkbox | Handle duplicate redirect or exp modifiers: `PermError` | 2 | src/spf/parser.rs:41 | 6b1ee0f | DONE |
| CHK-050 | 01-SPF-RFC7208.md:89 | checkbox | Whitespace between terms: one or more spaces, trimmed | 2 | src/spf/parser.rs:7 | 6b1ee0f | DONE |
| CHK-051 | 01-SPF-RFC7208.md:93 | checkbox | `all` — no arguments | 2 | src/spf/parser.rs:116 | 6b1ee0f | DONE |
| CHK-052 | 01-SPF-RFC7208.md:94 | checkbox | `include:<domain>` — domain spec required | 2 | src/spf/parser.rs:120 | 6b1ee0f | DONE |
| CHK-053 | 01-SPF-RFC7208.md:95 | checkbox | `a` / `a:<domain>` / `a:<domain>/<cidr4>` / `a:<domain>//<cidr6>` / `a:<domain>/<cidr4>//<cidr6>` | 2 | src/spf/parser.rs:187 | 6b1ee0f | DONE |
| CHK-054 | 01-SPF-RFC7208.md:96 | checkbox | `mx` — same argument patterns as `a` | 2 | src/spf/parser.rs:187 | 6b1ee0f | DONE |
| CHK-055 | 01-SPF-RFC7208.md:97 | checkbox | `ptr` / `ptr:<domain>` — optional domain | 2 | src/spf/parser.rs:131 | 6b1ee0f | DONE |
| CHK-056 | 01-SPF-RFC7208.md:98 | checkbox | `ip4:<ip4-network>` — address with optional `/prefix` (default /32) | 2 | src/spf/parser.rs:241 | 6b1ee0f | DONE |
| CHK-057 | 01-SPF-RFC7208.md:99 | checkbox | `ip6:<ip6-network>` — address with optional `/prefix` (default /128) | 2 | src/spf/parser.rs:258 | 6b1ee0f | DONE |
| CHK-058 | 01-SPF-RFC7208.md:100 | checkbox | `exists:<domain>` — domain spec with macros | 2 | src/spf/parser.rs:135 | 6b1ee0f | DONE |
| CHK-059 | 01-SPF-RFC7208.md:104 | checkbox | Implement macro expander for domain-spec strings | 3 | src/spf/macros.rs:26 | b7bcd10 | DONE |
| CHK-060 | 01-SPF-RFC7208.md:105 | checkbox | Macro letters (case determines URL encoding): | 3 | src/spf/macros.rs:107 | b7bcd10 | DONE |
| CHK-061 | 01-SPF-RFC7208.md:106 | checkbox | `s` — sender (local-part@domain or postmaster@domain) | 3 | src/spf/macros.rs:292 | b7bcd10 | DONE |
| CHK-062 | 01-SPF-RFC7208.md:107 | checkbox | `l` — local-part of sender | 3 | src/spf/macros.rs:299 | b7bcd10 | DONE |
| CHK-063 | 01-SPF-RFC7208.md:108 | checkbox | `o` — domain of sender | 3 | src/spf/macros.rs:299 | b7bcd10 | DONE |
| CHK-064 | 01-SPF-RFC7208.md:109 | checkbox | `d` — current domain being evaluated | 3 | src/spf/macros.rs:307 | b7bcd10 | DONE |
| CHK-065 | 01-SPF-RFC7208.md:110 | checkbox | `i` — client IP (dotted for v4, dot-separated nibbles for v6: 32 hex chars separated by dots) | 3 | src/spf/macros.rs:314 | b7bcd10 | DONE |
| CHK-066 | 01-SPF-RFC7208.md:111 | checkbox | `p` — validated domain name of client IP (PTR). Return "unknown" if PTR validation not performed. | 3 | src/spf/macros.rs:351 | b7bcd10 | DONE |
| CHK-067 | 01-SPF-RFC7208.md:112 | checkbox | `v` — IP version string ("in-addr" for v4, "ip6" for v6) | 3 | src/spf/macros.rs:331 | b7bcd10 | DONE |
| CHK-068 | 01-SPF-RFC7208.md:113 | checkbox | `h` — HELO/EHLO domain | 3 | src/spf/macros.rs:344 | b7bcd10 | DONE |
| CHK-069 | 01-SPF-RFC7208.md:114 | checkbox | Explanation-only macro letters (ONLY valid in `exp=` TXT expansion): | 3 | src/spf/macros.rs:125 | b7bcd10 | DONE |
| CHK-070 | 01-SPF-RFC7208.md:115 | checkbox | `c` — SMTP client IP in human-readable format (plain dotted-decimal/colon-hex) | 3 | src/spf/macros.rs:412 | b7bcd10 | DONE |
| CHK-071 | 01-SPF-RFC7208.md:116 | checkbox | `r` — receiving MTA domain name | 3 | src/spf/macros.rs:419 | b7bcd10 | DONE |
| CHK-072 | 01-SPF-RFC7208.md:117 | checkbox | `t` — current Unix timestamp as decimal string | 3 | src/spf/macros.rs:426 | b7bcd10 | DONE |
| CHK-073 | 01-SPF-RFC7208.md:118 | checkbox | MUST reject `c`, `r`, `t` when expanding in non-exp context | 3 | src/spf/macros.rs:436 | b7bcd10 | DONE |
| CHK-074 | 01-SPF-RFC7208.md:119 | checkbox | Uppercase macro letter → URL-encode the expanded value | 3 | src/spf/macros.rs:403 | b7bcd10 | DONE |
| CHK-075 | 01-SPF-RFC7208.md:120 | checkbox | Delimiter transformers: `{<letter><digits>r<delimiters>}` | 3 | src/spf/macros.rs:164 | b7bcd10 | DONE |
| CHK-076 | 01-SPF-RFC7208.md:121 | checkbox | Digits: take rightmost N parts (0 means all) | 3 | src/spf/macros.rs:211 | b7bcd10 | DONE |
| CHK-077 | 01-SPF-RFC7208.md:122 | checkbox | `r`: reverse order of parts | 3 | src/spf/macros.rs:211 | b7bcd10 | DONE |
| CHK-078 | 01-SPF-RFC7208.md:123 | checkbox | Delimiters: split characters (default ".") | 3 | src/spf/macros.rs:164 | b7bcd10 | DONE |
| CHK-079 | 01-SPF-RFC7208.md:124 | checkbox | Escapes: `%%` (literal %), `%_` (space), `%-` (URL-encoded space `%20`) | 3 | src/spf/macros.rs:445 | b7bcd10 | DONE |
| CHK-080 | 01-SPF-RFC7208.md:147 | checkbox | Empty MAIL FROM: use `postmaster@<helo_domain>` as sender | 4 | src/spf/eval.rs:73 | 99d7d91 | DONE |
| CHK-081 | 01-SPF-RFC7208.md:148 | checkbox | MAIL FROM without `@`: use `postmaster@<helo_domain>` as sender | 4 | src/spf/eval.rs:73 | 99d7d91 | DONE |
| CHK-082 | 01-SPF-RFC7208.md:152 | checkbox | Track DNS lookup count across entire evaluation (including recursive include/redirect) | 4 | src/spf/eval.rs:31 | 99d7d91 | DONE |
| CHK-083 | 01-SPF-RFC7208.md:153 | checkbox | Limit: max 10 DNS-querying mechanism lookups (A, MX, PTR, include, redirect, exists) | 4 | src/spf/eval.rs:31 | 99d7d91 | DONE |
| CHK-084 | 01-SPF-RFC7208.md:154 | checkbox | `ip4`, `ip6`, `all` do NOT count toward limit | 4 | src/spf/eval.rs:172 | 99d7d91 | DONE |
| CHK-085 | 01-SPF-RFC7208.md:155 | checkbox | Exceeding limit → `PermError` | 4 | src/spf/eval.rs:35 | 99d7d91 | DONE |
| CHK-086 | 01-SPF-RFC7208.md:156 | checkbox | Track void lookups (NxDomain or empty response on DNS-querying mechanisms): max 2 void lookups → `PermError` | 4 | src/spf/eval.rs:41 | 99d7d91 | DONE |
| CHK-087 | 01-SPF-RFC7208.md:157 | checkbox | Use shared mutable `EvalContext` struct across recursive calls: | 4 | src/spf/eval.rs:15 | 99d7d91 | DONE |
| CHK-088 | 01-SPF-RFC7208.md:168 | checkbox | Track visited domains in `EvalContext.visited_domains` (normalized: lowercase, no trailing dot) | 4 | src/spf/eval.rs:18 | 99d7d91 | DONE |
| CHK-089 | 01-SPF-RFC7208.md:169 | checkbox | Before each recursive `check_host` call (include or redirect): check if domain already visited | 4 | src/spf/eval.rs:51 | 99d7d91 | DONE |
| CHK-090 | 01-SPF-RFC7208.md:170 | checkbox | If visited: return `PermError` immediately | 4 | src/spf/eval.rs:54 | 99d7d91 | DONE |
| CHK-091 | 01-SPF-RFC7208.md:171 | checkbox | The DNS lookup limit (10) provides a secondary safety net but is NOT sufficient alone — a 2-domain cycle with 1-mechanism SPF records would execute up to 10 iterations before stopping | 4 | src/spf/eval.rs:31 | 99d7d91 | DONE |
| CHK-092 | 01-SPF-RFC7208.md:175 | checkbox | Evaluate directives left-to-right | 4 | src/spf/eval.rs:119 | 99d7d91 | DONE |
| CHK-093 | 01-SPF-RFC7208.md:176 | checkbox | First match determines result (qualifier → result mapping) | 4 | src/spf/eval.rs:120 | 99d7d91 | DONE |
| CHK-094 | 01-SPF-RFC7208.md:177 | checkbox | If no match and no `redirect`: return `Neutral` | 4 | src/spf/eval.rs:145 | 99d7d91 | DONE |
| CHK-095 | 01-SPF-RFC7208.md:178 | checkbox | If `redirect` modifier present: evaluate target domain instead | 4 | src/spf/eval.rs:142 | 99d7d91 | DONE |
| CHK-096 | 01-SPF-RFC7208.md:183 | checkbox | Always matches | 4 | src/spf/eval.rs:165 | 99d7d91 | DONE |
| CHK-097 | 01-SPF-RFC7208.md:184 | checkbox | Typically last directive (e.g., `-all`, `~all`) | 4 | src/spf/eval.rs:165 | 99d7d91 | DONE |
| CHK-098 | 01-SPF-RFC7208.md:187 | checkbox | Increment DNS lookup counter | 4 | src/spf/eval.rs:202 | 99d7d91 | DONE |
| CHK-099 | 01-SPF-RFC7208.md:188 | checkbox | Check visited domains → `PermError` if cycle detected | 4 | src/spf/eval.rs:207 | 99d7d91 | DONE |
| CHK-100 | 01-SPF-RFC7208.md:189 | checkbox | Expand macros in domain | 4 | src/spf/eval.rs:204 | 99d7d91 | DONE |
| CHK-101 | 01-SPF-RFC7208.md:190 | checkbox | Recursively call `check_host()` with new domain | 4 | src/spf/eval.rs:209 | 99d7d91 | DONE |
| CHK-102 | 01-SPF-RFC7208.md:191 | checkbox | Map child results: | 4 | src/spf/eval.rs:211 | 99d7d91 | DONE |
| CHK-103 | 01-SPF-RFC7208.md:192 | checkbox | `Pass` → match (use parent qualifier) | 4 | src/spf/eval.rs:212 | 99d7d91 | DONE |
| CHK-104 | 01-SPF-RFC7208.md:193 | checkbox | `Fail`, `SoftFail`, `Neutral`, `None` → no match (continue) | 4 | src/spf/eval.rs:213 | 99d7d91 | DONE |
| CHK-105 | 01-SPF-RFC7208.md:194 | checkbox | `TempError` → propagate `TempError` | 4 | src/spf/eval.rs:216 | 99d7d91 | DONE |
| CHK-106 | 01-SPF-RFC7208.md:195 | checkbox | `PermError` → propagate `PermError` | 4 | src/spf/eval.rs:217 | 99d7d91 | DONE |
| CHK-107 | 01-SPF-RFC7208.md:198 | checkbox | Increment DNS lookup counter | 4 | src/spf/eval.rs:229 | 99d7d91 | DONE |
| CHK-108 | 01-SPF-RFC7208.md:199 | checkbox | Expand macros in domain (default: current domain) | 4 | src/spf/eval.rs:231 | 99d7d91 | DONE |
| CHK-109 | 01-SPF-RFC7208.md:200 | checkbox | Query A records (if client is IPv4) or AAAA (if IPv6) — query only the address family that matches client IP | 4 | src/spf/eval.rs:236 | 99d7d91 | DONE |
| CHK-110 | 01-SPF-RFC7208.md:201 | checkbox | Apply CIDR mask (default /32 for v4, /128 for v6) | 4 | src/spf/eval.rs:237 | 99d7d91 | DONE |
| CHK-111 | 01-SPF-RFC7208.md:202 | checkbox | Match if client IP within any returned network | 4 | src/spf/eval.rs:238 | 99d7d91 | DONE |
| CHK-112 | 01-SPF-RFC7208.md:203 | checkbox | NxDomain → void lookup, no match | 4 | src/spf/eval.rs:242 | 99d7d91 | DONE |
| CHK-113 | 01-SPF-RFC7208.md:204 | checkbox | TempFail → `TempError` | 4 | src/spf/eval.rs:246 | 99d7d91 | DONE |
| CHK-114 | 01-SPF-RFC7208.md:207 | checkbox | Increment DNS lookup counter | 4 | src/spf/eval.rs:276 | 99d7d91 | DONE |
| CHK-115 | 01-SPF-RFC7208.md:208 | checkbox | Expand macros in domain | 4 | src/spf/eval.rs:278 | 99d7d91 | DONE |
| CHK-116 | 01-SPF-RFC7208.md:209 | checkbox | Query MX records, sort by preference | 4 | src/spf/eval.rs:291 | 99d7d91 | DONE |
| CHK-117 | 01-SPF-RFC7208.md:210 | checkbox | Limit to first 10 MX records | 4 | src/spf/eval.rs:292 | 99d7d91 | DONE |
| CHK-118 | 01-SPF-RFC7208.md:211 | checkbox | For each MX host: query A/AAAA, apply CIDR mask | 4 | src/spf/eval.rs:295 | 99d7d91 | DONE |
| CHK-119 | 01-SPF-RFC7208.md:212 | checkbox | Match if client IP within any resolved address | 4 | src/spf/eval.rs:298 | 99d7d91 | DONE |
| CHK-120 | 01-SPF-RFC7208.md:213 | checkbox | DNS errors on individual MX hosts: skip that host (not fatal) | 4 | src/spf/eval.rs:295 | 99d7d91 | DONE |
| CHK-121 | 01-SPF-RFC7208.md:216 | checkbox | Increment DNS lookup counter | 4 | src/spf/eval.rs:332 | 99d7d91 | DONE |
| CHK-122 | 01-SPF-RFC7208.md:217 | checkbox | Reverse lookup client IP → hostnames | 4 | src/spf/eval.rs:340 | 99d7d91 | DONE |
| CHK-123 | 01-SPF-RFC7208.md:218 | checkbox | Limit to 10 PTR names | 4 | src/spf/eval.rs:349 | 99d7d91 | DONE |
| CHK-124 | 01-SPF-RFC7208.md:219 | checkbox | For each hostname: forward lookup → IPs | 4 | src/spf/eval.rs:353 | 99d7d91 | DONE |
| CHK-125 | 01-SPF-RFC7208.md:220 | checkbox | Confirm client IP in forward results (validated hostname) | 4 | src/spf/eval.rs:353 | 99d7d91 | DONE |
| CHK-126 | 01-SPF-RFC7208.md:221 | checkbox | Match if any validated hostname equals or is subdomain of target domain | 4 | src/spf/eval.rs:367 | 99d7d91 | DONE |
| CHK-127 | 01-SPF-RFC7208.md:222 | checkbox | Expensive: avoid in production records, but MUST evaluate correctly | 4 | src/spf/eval.rs:324 | 99d7d91 | DONE |
| CHK-128 | 01-SPF-RFC7208.md:225 | checkbox | Parse IPv4 address and optional prefix length (default /32) | 4 | src/spf/eval.rs:173 | 99d7d91 | DONE |
| CHK-129 | 01-SPF-RFC7208.md:226 | checkbox | Match if client is IPv4 AND within CIDR range | 4 | src/spf/eval.rs:175 | 99d7d91 | DONE |
| CHK-130 | 01-SPF-RFC7208.md:227 | checkbox | IPv6 client: never matches ip4 | 4 | src/spf/eval.rs:176 | 99d7d91 | DONE |
| CHK-131 | 01-SPF-RFC7208.md:228 | checkbox | No DNS lookup, no counter increment | 4 | src/spf/eval.rs:172 | 99d7d91 | DONE |
| CHK-132 | 01-SPF-RFC7208.md:231 | checkbox | Parse IPv6 address and optional prefix length (default /128) | 4 | src/spf/eval.rs:180 | 99d7d91 | DONE |
| CHK-133 | 01-SPF-RFC7208.md:232 | checkbox | Match if client is IPv6 AND within CIDR range | 4 | src/spf/eval.rs:182 | 99d7d91 | DONE |
| CHK-134 | 01-SPF-RFC7208.md:233 | checkbox | IPv4 client: never matches ip6 | 4 | src/spf/eval.rs:183 | 99d7d91 | DONE |
| CHK-135 | 01-SPF-RFC7208.md:234 | checkbox | No DNS lookup, no counter increment | 4 | src/spf/eval.rs:179 | 99d7d91 | DONE |
| CHK-136 | 01-SPF-RFC7208.md:237 | checkbox | Increment DNS lookup counter | 4 | src/spf/eval.rs:388 | 99d7d91 | DONE |
| CHK-137 | 01-SPF-RFC7208.md:238 | checkbox | Expand macros in domain | 4 | src/spf/eval.rs:390 | 99d7d91 | DONE |
| CHK-138 | 01-SPF-RFC7208.md:239 | checkbox | Query A record: any result = match, NxDomain = no match | 4 | src/spf/eval.rs:393 | 99d7d91 | DONE |
| CHK-139 | 01-SPF-RFC7208.md:240 | checkbox | TempFail → `TempError` | 4 | src/spf/eval.rs:395 | 99d7d91 | DONE |
| CHK-140 | 01-SPF-RFC7208.md:245 | checkbox | Only processed if no directive matched | 4 | src/spf/eval.rs:142 | 99d7d91 | DONE |
| CHK-141 | 01-SPF-RFC7208.md:246 | checkbox | Increment DNS lookup counter | 4 | src/spf/eval.rs:407 | 99d7d91 | DONE |
| CHK-142 | 01-SPF-RFC7208.md:247 | checkbox | Check visited domains → `PermError` if cycle | 4 | src/spf/eval.rs:417 | 99d7d91 | DONE |
| CHK-143 | 01-SPF-RFC7208.md:248 | checkbox | Expand macros in domain | 4 | src/spf/eval.rs:409 | 99d7d91 | DONE |
| CHK-144 | 01-SPF-RFC7208.md:249 | checkbox | Empty expanded domain → `PermError` | 4 | src/spf/eval.rs:415 | 99d7d91 | DONE |
| CHK-145 | 01-SPF-RFC7208.md:250 | checkbox | Recursively `check_host()` on target | 4 | src/spf/eval.rs:419 | 99d7d91 | DONE |
| CHK-146 | 01-SPF-RFC7208.md:251 | checkbox | Target returns `None` → `PermError` (redirect to domain without SPF) | 4 | src/spf/eval.rs:424 | 99d7d91 | DONE |
| CHK-147 | 01-SPF-RFC7208.md:252 | checkbox | All other results passed through unchanged | 4 | src/spf/eval.rs:425 | 99d7d91 | DONE |
| CHK-148 | 01-SPF-RFC7208.md:255 | checkbox | Only evaluated when final result is `Fail` | 4 | src/spf/eval.rs:126 | 99d7d91 | DONE |
| CHK-149 | 01-SPF-RFC7208.md:256 | checkbox | Expand macros in exp domain | 4 | src/spf/eval.rs:435 | 99d7d91 | DONE |
| CHK-150 | 01-SPF-RFC7208.md:257 | checkbox | Query TXT record at expanded domain | 4 | src/spf/eval.rs:436 | 99d7d91 | DONE |
| CHK-151 | 01-SPF-RFC7208.md:258 | checkbox | Expand macros in TXT result (including explanation-only macros: `c`, `r`, `t`) | 4 | src/spf/eval.rs:437 | 99d7d91 | DONE |
| CHK-152 | 01-SPF-RFC7208.md:259 | checkbox | Attach expanded explanation to `Fail { explanation: Some(text) }` | 4 | src/spf/eval.rs:131 | 99d7d91 | DONE |
| CHK-153 | 01-SPF-RFC7208.md:260 | checkbox | Failure to retrieve/expand explanation: silently ignore, return Fail without explanation | 4 | src/spf/eval.rs:433 | 99d7d91 | DONE |
| CHK-154 | 01-SPF-RFC7208.md:282 | checkbox | `check_host_inner` must use `Box::pin` for async recursion (include/redirect chains) | 4 | src/spf/eval.rs:108 | 99d7d91 | DONE |
| CHK-155 | 01-SPF-RFC7208.md:283 | checkbox | Signature: returns `Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>>` | 4 | src/spf/eval.rs:107 | 99d7d91 | DONE |
| CHK-156 | 01-SPF-RFC7208.md:284 | checkbox | `EvalContext` is `&mut` — passed through the recursive chain | 4 | src/spf/eval.rs:106 | 99d7d91 | DONE |
| CHK-157 | 01-SPF-RFC7208.md:290 | checkbox | Abstract DNS resolver trait for testability (defined in M1 common module) | 1 | src/common/dns.rs:189 | 992b713 | DONE |
| CHK-158 | 01-SPF-RFC7208.md:291 | checkbox | Support async DNS queries | 1 | src/common/dns.rs:189 | 992b713 | DONE |
| CHK-159 | 01-SPF-RFC7208.md:292 | checkbox | Methods needed: | 1 | src/common/dns.rs:189 | 992b713 | DONE |
| CHK-160 | 01-SPF-RFC7208.md:293 | checkbox | `query_txt(domain) -> Result<Vec<String>, DnsError>` | 1 | src/common/dns.rs:196 | 992b713 | DONE |
| CHK-161 | 01-SPF-RFC7208.md:294 | checkbox | `query_a(domain) -> Result<Vec<Ipv4Addr>, DnsError>` | 1 | src/common/dns.rs:203 | 992b713 | DONE |
| CHK-162 | 01-SPF-RFC7208.md:295 | checkbox | `query_aaaa(domain) -> Result<Vec<Ipv6Addr>, DnsError>` | 1 | src/common/dns.rs:210 | 992b713 | DONE |
| CHK-163 | 01-SPF-RFC7208.md:296 | checkbox | `query_mx(domain) -> Result<Vec<MxRecord>, DnsError>` | 1 | src/common/dns.rs:217 | 992b713 | DONE |
| CHK-164 | 01-SPF-RFC7208.md:297 | checkbox | `query_ptr(ip) -> Result<Vec<String>, DnsError>` | 1 | src/common/dns.rs:226 | 992b713 | DONE |
| CHK-165 | 01-SPF-RFC7208.md:298 | checkbox | `query_exists(domain) -> Result<bool, DnsError>` (A-record existence check) | 1 | src/common/dns.rs:233 | 992b713 | DONE |
| CHK-166 | 01-SPF-RFC7208.md:299 | checkbox | DnsError MUST distinguish: NxDomain vs NoRecords vs TempFail | 1 | src/common/dns.rs:243 | 992b713 | DONE |
| CHK-167 | 01-SPF-RFC7208.md:300 | checkbox | DNS caching: CALLER responsibility (resolver layer), not library scope. Document this. | 1 | src/common/dns.rs:39 | 992b713 | DONE |
| CHK-168 | 01-SPF-RFC7208.md:306 | checkbox | `PermError` conditions: | 4 | src/spf/eval.rs:35 | 99d7d91 | DONE |
| CHK-169 | 01-SPF-RFC7208.md:307 | checkbox | Multiple SPF records for same domain | 4 | src/spf/lookup.rs:30 | 99d7d91 | DONE |
| CHK-170 | 01-SPF-RFC7208.md:308 | checkbox | Syntax errors in record | 4 | src/spf/lookup.rs:31 | 99d7d91 | DONE |
| CHK-171 | 01-SPF-RFC7208.md:309 | checkbox | Unknown mechanism (NOT unknown modifier) | 4 | src/spf/parser.rs:139 | 99d7d91 | DONE |
| CHK-172 | 01-SPF-RFC7208.md:310 | checkbox | DNS lookup limit exceeded (>10) | 4 | src/spf/eval.rs:35 | 99d7d91 | DONE |
| CHK-173 | 01-SPF-RFC7208.md:311 | checkbox | Void lookup limit exceeded (>2) | 4 | src/spf/eval.rs:45 | 99d7d91 | DONE |
| CHK-174 | 01-SPF-RFC7208.md:312 | checkbox | `redirect` to domain with no SPF | 4 | src/spf/eval.rs:424 | 99d7d91 | DONE |
| CHK-175 | 01-SPF-RFC7208.md:313 | checkbox | Circular `include`/`redirect` (detected via visited set) | 4 | src/spf/eval.rs:54 | 99d7d91 | DONE |
| CHK-176 | 01-SPF-RFC7208.md:314 | checkbox | Empty expanded domain in redirect | 4 | src/spf/eval.rs:415 | 99d7d91 | DONE |
| CHK-177 | 01-SPF-RFC7208.md:315 | checkbox | Duplicate redirect or exp modifier | 4 | src/spf/parser.rs:41 | 99d7d91 | DONE |
| CHK-178 | 01-SPF-RFC7208.md:316 | checkbox | `TempError` conditions: | 4 | src/spf/eval.rs:246 | 99d7d91 | DONE |
| CHK-179 | 01-SPF-RFC7208.md:317 | checkbox | DNS timeout or SERVFAIL | 4 | src/spf/eval.rs:246 | 99d7d91 | DONE |
| CHK-180 | 01-SPF-RFC7208.md:318 | checkbox | Transient network errors | 4 | src/spf/eval.rs:246 | 99d7d91 | DONE |
| CHK-181 | 01-SPF-RFC7208.md:326 | checkbox | Valid minimal: `v=spf1 -all` | 2 | src/spf/parser.rs:284 | 6b1ee0f | DONE |
| CHK-182 | 01-SPF-RFC7208.md:327 | checkbox | Multiple mechanisms: `v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all` | 2 | src/spf/parser.rs:295 | 6b1ee0f | DONE |
| CHK-183 | 01-SPF-RFC7208.md:328 | checkbox | Include: `v=spf1 include:_spf.google.com -all` | 2 | src/spf/parser.rs:312 | 6b1ee0f | DONE |
| CHK-184 | 01-SPF-RFC7208.md:329 | checkbox | All mechanism types with all argument forms | 2 | src/spf/parser.rs:323 | 6b1ee0f | DONE |
| CHK-185 | 01-SPF-RFC7208.md:330 | checkbox | Macros in domain specs: `exists:%{ir}.sbl.example.com` | 2 | src/spf/parser.rs:379 | 6b1ee0f | DONE |
| CHK-186 | 01-SPF-RFC7208.md:331 | checkbox | Case insensitivity: `V=SPF1 IP4:...` → same as lowercase | 2 | src/spf/parser.rs:389 | 6b1ee0f | DONE |
| CHK-187 | 01-SPF-RFC7208.md:332 | checkbox | Invalid version: `v=spf2` → error | 2 | src/spf/parser.rs:401 | 6b1ee0f | DONE |
| CHK-188 | 01-SPF-RFC7208.md:333 | checkbox | Duplicate modifiers: `redirect=a redirect=b` → PermError | 2 | src/spf/parser.rs:407 | 6b1ee0f | DONE |
| CHK-189 | 01-SPF-RFC7208.md:334 | checkbox | Unknown modifier: `foo=bar` → silently ignored | 2 | src/spf/parser.rs:420 | 6b1ee0f | DONE |
| CHK-190 | 01-SPF-RFC7208.md:335 | checkbox | Unknown mechanism: `custom:example.com` → PermError | 2 | src/spf/parser.rs:428 | 6b1ee0f | DONE |
| CHK-191 | 01-SPF-RFC7208.md:336 | checkbox | Multiple whitespace between terms | 2 | src/spf/parser.rs:435 | 6b1ee0f | DONE |
| CHK-192 | 01-SPF-RFC7208.md:337 | checkbox | Trailing whitespace | 2 | src/spf/parser.rs:442 | 6b1ee0f | DONE |
| CHK-193 | 01-SPF-RFC7208.md:338 | checkbox | A/MX dual CIDR: `a:example.com/24//64` | 2 | src/spf/parser.rs:449 | 6b1ee0f | DONE |
| CHK-194 | 01-SPF-RFC7208.md:339 | checkbox | Prefix edge cases: `a/0`, `a//0` | 2 | src/spf/parser.rs:489 | 6b1ee0f | DONE |
| CHK-195 | 01-SPF-RFC7208.md:343 | checkbox | Simple pass: IP in `ip4` range | 4 | src/spf/eval.rs:468 | 99d7d91 | DONE |
| CHK-196 | 01-SPF-RFC7208.md:344 | checkbox | Simple fail: IP not in range, ends `-all` | 4 | src/spf/eval.rs:479 | 99d7d91 | DONE |
| CHK-197 | 01-SPF-RFC7208.md:345 | checkbox | Include pass: nested lookup passes | 4 | src/spf/eval.rs:490 | 99d7d91 | DONE |
| CHK-198 | 01-SPF-RFC7208.md:346 | checkbox | Include fail: nested lookup fails | 4 | src/spf/eval.rs:503 | 99d7d91 | DONE |
| CHK-199 | 01-SPF-RFC7208.md:347 | checkbox | Include propagation: child TempError → parent TempError | 4 | src/spf/eval.rs:517 | 99d7d91 | DONE |
| CHK-200 | 01-SPF-RFC7208.md:348 | checkbox | Include propagation: child PermError → parent PermError | 4 | src/spf/eval.rs:530 | 99d7d91 | DONE |
| CHK-201 | 01-SPF-RFC7208.md:349 | checkbox | Include: child None → no match (continue) | 4 | src/spf/eval.rs:543 | 99d7d91 | DONE |
| CHK-202 | 01-SPF-RFC7208.md:350 | checkbox | MX mechanism: IP matches MX host | 4 | src/spf/eval.rs:558 | 99d7d91 | DONE |
| CHK-203 | 01-SPF-RFC7208.md:351 | checkbox | A mechanism with CIDR | 4 | src/spf/eval.rs:574 | 99d7d91 | DONE |
| CHK-204 | 01-SPF-RFC7208.md:352 | checkbox | PTR mechanism validation | 4 | src/spf/eval.rs:587 | 99d7d91 | DONE |
| CHK-205 | 01-SPF-RFC7208.md:353 | checkbox | Redirect modifier | 4 | src/spf/eval.rs:601 | 99d7d91 | DONE |
| CHK-206 | 01-SPF-RFC7208.md:354 | checkbox | Redirect to domain without SPF → PermError | 4 | src/spf/eval.rs:614 | 99d7d91 | DONE |
| CHK-207 | 01-SPF-RFC7208.md:355 | checkbox | DNS lookup limit (11th lookup → PermError) | 4 | src/spf/eval.rs:627 | 99d7d91 | DONE |
| CHK-208 | 01-SPF-RFC7208.md:356 | checkbox | Void lookup limit (3rd void → PermError) | 4 | src/spf/eval.rs:644 | 99d7d91 | DONE |
| CHK-209 | 01-SPF-RFC7208.md:357 | checkbox | Circular include between 2 domains → PermError (via visited set, not just DNS limit) | 4 | src/spf/eval.rs:659 | 99d7d91 | DONE |
| CHK-210 | 01-SPF-RFC7208.md:358 | checkbox | exp= explanation attached to Fail | 4 | src/spf/eval.rs:672 | 99d7d91 | DONE |
| CHK-211 | 01-SPF-RFC7208.md:359 | checkbox | exp= failure → Fail without explanation (not crash) | 4 | src/spf/eval.rs:687 | 99d7d91 | DONE |
| CHK-212 | 01-SPF-RFC7208.md:360 | checkbox | Empty MAIL FROM → postmaster@helo | 4 | src/spf/eval.rs:700 | 99d7d91 | DONE |
| CHK-213 | 01-SPF-RFC7208.md:361 | checkbox | IPv6 client with ip6 mechanism | 4 | src/spf/eval.rs:711 | 99d7d91 | DONE |
| CHK-214 | 01-SPF-RFC7208.md:362 | checkbox | IPv4 client skips ip6 mechanism | 4 | src/spf/eval.rs:722 | 99d7d91 | DONE |
| CHK-215 | 01-SPF-RFC7208.md:363 | checkbox | exists mechanism with macro expansion | 4 | src/spf/eval.rs:733 | 99d7d91 | DONE |
| CHK-216 | 01-SPF-RFC7208.md:367 | checkbox | `%{s}` sender expansion | 3 | src/spf/macros.rs:292 | b7bcd10 | DONE |
| CHK-217 | 01-SPF-RFC7208.md:368 | checkbox | `%{l}` local-part, `%{o}` domain | 3 | src/spf/macros.rs:299 | b7bcd10 | DONE |
| CHK-218 | 01-SPF-RFC7208.md:369 | checkbox | `%{d}` current domain expansion | 3 | src/spf/macros.rs:307 | b7bcd10 | DONE |
| CHK-219 | 01-SPF-RFC7208.md:370 | checkbox | `%{i}` IP expansion (v4 dotted, v6 dot-separated nibbles: 32 hex chars) | 3 | src/spf/macros.rs:314 | b7bcd10 | DONE |
| CHK-220 | 01-SPF-RFC7208.md:371 | checkbox | `%{v}` → "in-addr" for v4, "ip6" for v6 | 3 | src/spf/macros.rs:331 | b7bcd10 | DONE |
| CHK-221 | 01-SPF-RFC7208.md:372 | checkbox | `%{h}` HELO domain | 3 | src/spf/macros.rs:344 | b7bcd10 | DONE |
| CHK-222 | 01-SPF-RFC7208.md:373 | checkbox | `%{p}` → "unknown" (stub is acceptable) | 3 | src/spf/macros.rs:351 | b7bcd10 | DONE |
| CHK-223 | 01-SPF-RFC7208.md:374 | checkbox | `%{ir}.origin.example.com` reversed IP | 3 | src/spf/macros.rs:358 | b7bcd10 | DONE |
| CHK-224 | 01-SPF-RFC7208.md:375 | checkbox | `%{d2}` rightmost 2 labels, `%{d1r}` reversed first label | 3 | src/spf/macros.rs:372 | b7bcd10 | DONE |
| CHK-225 | 01-SPF-RFC7208.md:376 | checkbox | `%{l-}` local-part with hyphen delimiter | 3 | src/spf/macros.rs:392 | b7bcd10 | DONE |
| CHK-226 | 01-SPF-RFC7208.md:377 | checkbox | URL encoding with uppercase: `%{S}` URL-encodes sender | 3 | src/spf/macros.rs:403 | b7bcd10 | DONE |
| CHK-227 | 01-SPF-RFC7208.md:378 | checkbox | Explanation-only macros `%{c}`, `%{r}`, `%{t}` in exp= context → succeed | 3 | src/spf/macros.rs:412 | b7bcd10 | DONE |
| CHK-228 | 01-SPF-RFC7208.md:379 | checkbox | Reject `%{c}`, `%{r}`, `%{t}` outside exp= context → error | 3 | src/spf/macros.rs:436 | b7bcd10 | DONE |
| CHK-229 | 01-SPF-RFC7208.md:380 | checkbox | Escapes: `%%` → `%`, `%_` → space, `%-` → `%20` | 3 | src/spf/macros.rs:445 | b7bcd10 | DONE |
| CHK-230 | 01-SPF-RFC7208.md:381 | checkbox | `%{d0}` → entire domain (0 means all parts) | 3 | src/spf/macros.rs:458 | b7bcd10 | DONE |
| CHK-231 | 01-SPF-RFC7208.md:387 | checkbox | Prevent infinite loops in `include`/`redirect` via visited-domain HashSet | 4 | src/spf/eval.rs:51 | 99d7d91 | DONE |
| CHK-232 | 01-SPF-RFC7208.md:388 | checkbox | Enforce DNS lookup limits strictly (max 10) | 4 | src/spf/eval.rs:31 | 99d7d91 | DONE |
| CHK-233 | 01-SPF-RFC7208.md:389 | checkbox | Enforce void lookup limits (max 2) | 4 | src/spf/eval.rs:41 | 99d7d91 | DONE |
| CHK-234 | 01-SPF-RFC7208.md:390 | checkbox | Validate all DNS responses — handle NxDomain vs empty vs error distinctly | 4 | src/spf/eval.rs:236 | 99d7d91 | DONE |
| CHK-235 | 01-SPF-RFC7208.md:391 | checkbox | Don't trust PTR without forward confirmation | 4 | src/spf/eval.rs:353 | 99d7d91 | DONE |
| CHK-236 | 01-SPF-RFC7208.md:392 | checkbox | DNS caching is caller's responsibility — document this clearly | 4 | src/spf/eval.rs:64 | 99d7d91 | DONE |
| CHK-237 | 01-SPF-RFC7208.md:398 | checkbox | DNS caching: out of scope for library. Callers wrap the resolver. | 4 | src/spf/eval.rs:64 | 99d7d91 | DONE |
| CHK-238 | 01-SPF-RFC7208.md:399 | checkbox | Short-circuit on first match (left-to-right, stop at first matching directive) | 4 | src/spf/eval.rs:120 | 99d7d91 | DONE |
| CHK-239 | 01-SPF-RFC7208.md:400 | checkbox | Pre-compiled parsed records: `SpfRecord::parse` returns owned struct for reuse | 2 | src/spf/types.rs:75 | 6b1ee0f | DONE |
| CHK-240 | 01-SPF-RFC7208.md:401 | checkbox | A/MX mechanism: query only the address family matching client IP (v4→A, v6→AAAA) | 4 | src/spf/eval.rs:236 | 99d7d91 | DONE |
| CHK-241 | 01-SPF-RFC7208.md:461 | checkbox | DNS resolver (async): `hickory-resolver` 0.25 | 1 | Cargo.toml:11 | 992b713 | DONE |
| CHK-242 | 01-SPF-RFC7208.md:462 | checkbox | IP address handling: `std::net` | 1 | src/common/dns.rs:1 | 992b713 | DONE |
| CHK-243 | 01-SPF-RFC7208.md:463 | checkbox | CIDR matching: custom implementation (no external crate needed) | 1 | src/common/cidr.rs:38 | 992b713 | DONE |
| CHK-244 | 01-SPF-RFC7208.md:469 | checkbox | All data types defined with structured enums (not raw strings) | 2 | src/spf/types.rs:5 | 6b1ee0f | DONE |
| CHK-245 | 01-SPF-RFC7208.md:470 | checkbox | Parser complete with all 8 mechanisms and 2 modifiers | 2 | src/spf/parser.rs:6 | 6b1ee0f | DONE |
| CHK-246 | 01-SPF-RFC7208.md:471 | checkbox | Macro expander complete with all letters, transformers, escapes | 3 | src/spf/macros.rs:26 | b7bcd10 | DONE |
| CHK-247 | 01-SPF-RFC7208.md:472 | checkbox | `check_host()` algorithm implemented with recursive include/redirect | 4 | src/spf/eval.rs:64 | 99d7d91 | DONE |
| CHK-248 | 01-SPF-RFC7208.md:473 | checkbox | DNS lookup limits enforced (10 DNS, 2 void) | 4 | src/spf/eval.rs:31 | 99d7d91 | DONE |
| CHK-249 | 01-SPF-RFC7208.md:474 | checkbox | Circular include/redirect detection via visited-domain set | 4 | src/spf/eval.rs:51 | 99d7d91 | DONE |
| CHK-250 | 01-SPF-RFC7208.md:475 | checkbox | exp= evaluation produces explanation on Fail | 4 | src/spf/eval.rs:433 | 99d7d91 | DONE |
| CHK-251 | 01-SPF-RFC7208.md:476 | checkbox | All 7 result types returned correctly | 4 | src/spf/eval.rs:445 | 99d7d91 | DONE |
| CHK-252 | 01-SPF-RFC7208.md:477 | checkbox | Unit tests cover parsing, evaluation, macros, limits, cycles | 4 | src/spf/eval.rs:456 | 99d7d91 | DONE |
| CHK-253 | 01-SPF-RFC7208.md:478 | checkbox | No unwrap/expect in library code (tests only) | 4 | src/spf/eval.rs:1 | 99d7d91 | DONE |
| CHK-254 | 02-DKIM-RFC6376.md:15 | checkbox | Define `DkimSignature` struct (tag-value pairs from DKIM-Signature header): | 5 | src/dkim/types.rs:54 | 77373aa | DONE |
| CHK-255 | 02-DKIM-RFC6376.md:16 | checkbox | `version: u8` — version (must be 1) | 5 | src/dkim/types.rs:55 | 77373aa | DONE |
| CHK-256 | 02-DKIM-RFC6376.md:17 | checkbox | `algorithm: Algorithm` — signing algorithm | 5 | src/dkim/types.rs:56 | 77373aa | DONE |
| CHK-257 | 02-DKIM-RFC6376.md:18 | checkbox | `signature: Vec<u8>` — signature data (decoded from base64) | 5 | src/dkim/types.rs:57 | 77373aa | DONE |
| CHK-258 | 02-DKIM-RFC6376.md:19 | checkbox | `body_hash: Vec<u8>` — body hash (decoded from base64) | 5 | src/dkim/types.rs:58 | 77373aa | DONE |
| CHK-259 | 02-DKIM-RFC6376.md:20 | checkbox | `header_canonicalization: CanonicalizationMethod` — header canon | 5 | src/dkim/types.rs:59 | 77373aa | DONE |
| CHK-260 | 02-DKIM-RFC6376.md:21 | checkbox | `body_canonicalization: CanonicalizationMethod` — body canon | 5 | src/dkim/types.rs:60 | 77373aa | DONE |
| CHK-261 | 02-DKIM-RFC6376.md:22 | checkbox | `domain: String` — signing domain (SDID, d= tag) | 5 | src/dkim/types.rs:61 | 77373aa | DONE |
| CHK-262 | 02-DKIM-RFC6376.md:23 | checkbox | `signed_headers: Vec<String>` — signed header field names (h= tag) | 5 | src/dkim/types.rs:62 | 77373aa | DONE |
| CHK-263 | 02-DKIM-RFC6376.md:24 | checkbox | `auid: String` — agent/user identifier (i= tag, default `@<d=>`) | 5 | src/dkim/types.rs:63 | 77373aa | DONE |
| CHK-264 | 02-DKIM-RFC6376.md:25 | checkbox | `body_length: Option<u64>` — body length limit (l= tag) | 5 | src/dkim/types.rs:64 | 77373aa | DONE |
| CHK-265 | 02-DKIM-RFC6376.md:26 | checkbox | `selector: String` — selector (s= tag) | 5 | src/dkim/types.rs:65 | 77373aa | DONE |
| CHK-266 | 02-DKIM-RFC6376.md:27 | checkbox | `timestamp: Option<u64>` — signature timestamp (t= tag) | 5 | src/dkim/types.rs:66 | 77373aa | DONE |
| CHK-267 | 02-DKIM-RFC6376.md:28 | checkbox | `expiration: Option<u64>` — signature expiration (x= tag) | 5 | src/dkim/types.rs:67 | 77373aa | DONE |
| CHK-268 | 02-DKIM-RFC6376.md:29 | checkbox | `copied_headers: Option<Vec<String>>` — copied header fields (z= tag) | 5 | src/dkim/types.rs:68 | 77373aa | DONE |
| CHK-269 | 02-DKIM-RFC6376.md:30 | checkbox | `raw_header: String` — original header value for verification (needed for b= stripping) | 5 | src/dkim/types.rs:69 | 77373aa | DONE |
| CHK-270 | 02-DKIM-RFC6376.md:34 | checkbox | Define `Algorithm` enum: | 5 | src/dkim/types.rs:8 | 77373aa | DONE |
| CHK-271 | 02-DKIM-RFC6376.md:35 | checkbox | `RsaSha1` — RSA with SHA-1 (MUST support for verify, MUST NOT use for signing) | 5 | src/dkim/types.rs:10 | 77373aa | DONE |
| CHK-272 | 02-DKIM-RFC6376.md:36 | checkbox | `RsaSha256` — RSA with SHA-256 (MUST support, preferred) | 5 | src/dkim/types.rs:12 | 77373aa | DONE |
| CHK-273 | 02-DKIM-RFC6376.md:37 | checkbox | `Ed25519Sha256` — Ed25519 (RFC 8463, modern) | 5 | src/dkim/types.rs:14 | 77373aa | DONE |
| CHK-274 | 02-DKIM-RFC6376.md:38 | checkbox | Parsing: "rsa-sha1", "rsa-sha256", "ed25519-sha256" (case-insensitive) | 5 | src/dkim/parser.rs:341 | 77373aa | DONE |
| CHK-275 | 02-DKIM-RFC6376.md:39 | checkbox | Unknown algorithm → PermFail | 5 | src/dkim/parser.rs:347 | 77373aa | DONE |
| CHK-276 | 02-DKIM-RFC6376.md:43 | checkbox | Define `CanonicalizationMethod` enum: | 5 | src/dkim/types.rs:38 | 77373aa | DONE |
| CHK-277 | 02-DKIM-RFC6376.md:44 | checkbox | `Simple` — minimal transformation | 5 | src/dkim/types.rs:39 | 77373aa | DONE |
| CHK-278 | 02-DKIM-RFC6376.md:45 | checkbox | `Relaxed` — tolerates whitespace changes | 5 | src/dkim/types.rs:40 | 77373aa | DONE |
| CHK-279 | 02-DKIM-RFC6376.md:46 | checkbox | c= tag format: `header/body` or just `header` (body defaults to Simple) | 5 | src/dkim/parser.rs:284 | 77373aa | DONE |
| CHK-280 | 02-DKIM-RFC6376.md:47 | checkbox | Default when c= absent: `simple/simple` | 5 | src/dkim/parser.rs:290 | 77373aa | DONE |
| CHK-281 | 02-DKIM-RFC6376.md:51 | checkbox | Define `DkimPublicKey` struct (from DNS TXT record): | 5 | src/dkim/key.rs:10 | 77373aa | DONE |
| CHK-282 | 02-DKIM-RFC6376.md:52 | checkbox | `key_type: KeyType` — key type (default "rsa") | 5 | src/dkim/key.rs:11 | 77373aa | DONE |
| CHK-283 | 02-DKIM-RFC6376.md:53 | checkbox | `public_key: Vec<u8>` — public key data (base64 decoded) | 5 | src/dkim/key.rs:12 | 77373aa | DONE |
| CHK-284 | 02-DKIM-RFC6376.md:54 | checkbox | `revoked: bool` — true if p= is empty | 5 | src/dkim/key.rs:13 | 77373aa | DONE |
| CHK-285 | 02-DKIM-RFC6376.md:55 | checkbox | `hash_algorithms: Option<Vec<HashAlgorithm>>` — if present, restricts which hashes can be used | 5 | src/dkim/key.rs:14 | 77373aa | DONE |
| CHK-286 | 02-DKIM-RFC6376.md:56 | checkbox | `service_types: Option<Vec<String>>` — service types (default "*") | 5 | src/dkim/key.rs:15 | 77373aa | DONE |
| CHK-287 | 02-DKIM-RFC6376.md:57 | checkbox | `flags: Vec<KeyFlag>` — flags | 5 | src/dkim/key.rs:16 | 77373aa | DONE |
| CHK-288 | 02-DKIM-RFC6376.md:58 | checkbox | `notes: Option<String>` — human-readable notes | 5 | src/dkim/key.rs:17 | 77373aa | DONE |
| CHK-289 | 02-DKIM-RFC6376.md:60 | checkbox | Define `KeyType` enum: `Rsa`, `Ed25519` | 5 | src/dkim/types.rs:74 | 77373aa | DONE |
| CHK-290 | 02-DKIM-RFC6376.md:61 | checkbox | Define `HashAlgorithm` enum: `Sha1`, `Sha256` | 5 | src/dkim/types.rs:83 | 77373aa | DONE |
| CHK-291 | 02-DKIM-RFC6376.md:62 | checkbox | Define `KeyFlag` enum: `Testing` (t=y), `Strict` (t=s) | 5 | src/dkim/types.rs:94 | 77373aa | DONE |
| CHK-292 | 02-DKIM-RFC6376.md:66 | checkbox | Define `DkimResult` enum: | 5 | src/dkim/types.rs:101 | 77373aa | DONE |
| CHK-293 | 02-DKIM-RFC6376.md:67 | checkbox | `Pass { domain: String, selector: String, testing: bool }` — valid signature, carries signing domain, selector, and key testing flag | 5 | src/dkim/types.rs:103 | 77373aa | DONE |
| CHK-294 | 02-DKIM-RFC6376.md:68 | checkbox | `Fail { kind: FailureKind, detail: String }` — cryptographic verification failed | 5 | src/dkim/types.rs:108 | 77373aa | DONE |
| CHK-295 | 02-DKIM-RFC6376.md:69 | checkbox | `PermFail { kind: PermFailKind, detail: String }` — permanent structural/configuration error | 5 | src/dkim/types.rs:112 | 77373aa | DONE |
| CHK-296 | 02-DKIM-RFC6376.md:70 | checkbox | `TempFail { reason: String }` — transient error (DNS timeout) | 5 | src/dkim/types.rs:116 | 77373aa | DONE |
| CHK-297 | 02-DKIM-RFC6376.md:71 | checkbox | `None` — no DKIM-Signature header present | 5 | src/dkim/types.rs:119 | 77373aa | DONE |
| CHK-298 | 02-DKIM-RFC6376.md:73 | checkbox | Define `FailureKind` enum: | 5 | src/dkim/types.rs:123 | 77373aa | DONE |
| CHK-299 | 02-DKIM-RFC6376.md:74 | checkbox | `BodyHashMismatch` — computed body hash ≠ bh= value | 5 | src/dkim/types.rs:124 | 77373aa | DONE |
| CHK-300 | 02-DKIM-RFC6376.md:75 | checkbox | `SignatureVerificationFailed` — crypto signature check failed | 5 | src/dkim/types.rs:125 | 77373aa | DONE |
| CHK-301 | 02-DKIM-RFC6376.md:77 | checkbox | Define `PermFailKind` enum: | 5 | src/dkim/types.rs:129 | 77373aa | DONE |
| CHK-302 | 02-DKIM-RFC6376.md:78 | checkbox | `MalformedSignature` — parse error in DKIM-Signature header | 5 | src/dkim/types.rs:130 | 77373aa | DONE |
| CHK-303 | 02-DKIM-RFC6376.md:79 | checkbox | `KeyRevoked` — empty p= in DNS key record | 5 | src/dkim/types.rs:131 | 77373aa | DONE |
| CHK-304 | 02-DKIM-RFC6376.md:80 | checkbox | `KeyNotFound` — DNS NXDOMAIN for key record | 5 | src/dkim/types.rs:132 | 77373aa | DONE |
| CHK-305 | 02-DKIM-RFC6376.md:81 | checkbox | `ExpiredSignature` — past x= timestamp + clock skew | 5 | src/dkim/types.rs:133 | 77373aa | DONE |
| CHK-306 | 02-DKIM-RFC6376.md:82 | checkbox | `AlgorithmMismatch` — key type incompatible with signature algorithm | 5 | src/dkim/types.rs:134 | 77373aa | DONE |
| CHK-307 | 02-DKIM-RFC6376.md:83 | checkbox | `HashNotPermitted` — key h= tag rejects signature's hash | 5 | src/dkim/types.rs:135 | 77373aa | DONE |
| CHK-308 | 02-DKIM-RFC6376.md:84 | checkbox | `ServiceTypeMismatch` — key s= tag doesn't include "email" or "*" | 5 | src/dkim/types.rs:136 | 77373aa | DONE |
| CHK-309 | 02-DKIM-RFC6376.md:85 | checkbox | `StrictModeViolation` — key t=s but i= domain ≠ d= | 5 | src/dkim/types.rs:137 | 77373aa | DONE |
| CHK-310 | 02-DKIM-RFC6376.md:86 | checkbox | `DomainMismatch` — i= not subdomain of d= | 5 | src/dkim/types.rs:138 | 77373aa | DONE |
| CHK-311 | 02-DKIM-RFC6376.md:94 | checkbox | Parse as tag=value pairs, separated by semicolons | 5 | src/dkim/parser.rs:371 | 77373aa | DONE |
| CHK-312 | 02-DKIM-RFC6376.md:95 | checkbox | Handle folded headers (CRLF + whitespace) | 5 | src/dkim/parser.rs:378 | 77373aa | DONE |
| CHK-313 | 02-DKIM-RFC6376.md:96 | checkbox | Strip whitespace around tags and values | 5 | src/dkim/parser.rs:390 | 77373aa | DONE |
| CHK-314 | 02-DKIM-RFC6376.md:97 | checkbox | Handle base64 values with embedded whitespace (strip all whitespace before decoding) | 5 | src/dkim/parser.rs:397 | 77373aa | DONE |
| CHK-315 | 02-DKIM-RFC6376.md:101 | checkbox | `v=` — version (MUST be "1", as integer) | 5 | src/dkim/parser.rs:404 | 77373aa | DONE |
| CHK-316 | 02-DKIM-RFC6376.md:102 | checkbox | `a=` — algorithm (rsa-sha1, rsa-sha256, ed25519-sha256) | 5 | src/dkim/parser.rs:340 | 77373aa | DONE |
| CHK-317 | 02-DKIM-RFC6376.md:103 | checkbox | `b=` — signature (base64, strip whitespace before decode) | 5 | src/dkim/parser.rs:263 | 77373aa | DONE |
| CHK-318 | 02-DKIM-RFC6376.md:104 | checkbox | `bh=` — body hash (base64, strip whitespace before decode) | 5 | src/dkim/parser.rs:324 | 77373aa | DONE |
| CHK-319 | 02-DKIM-RFC6376.md:105 | checkbox | `d=` — signing domain | 5 | src/dkim/parser.rs:298 | 77373aa | DONE |
| CHK-320 | 02-DKIM-RFC6376.md:106 | checkbox | `h=` — signed headers (colon-separated list) | 5 | src/dkim/parser.rs:422 | 77373aa | DONE |
| CHK-321 | 02-DKIM-RFC6376.md:107 | checkbox | `s=` — selector | 5 | src/dkim/parser.rs:252 | 77373aa | DONE |
| CHK-322 | 02-DKIM-RFC6376.md:108 | checkbox | Missing any required tag → `PermFail { kind: MalformedSignature }` | 5 | src/dkim/parser.rs:241 | 77373aa | DONE |
| CHK-323 | 02-DKIM-RFC6376.md:112 | checkbox | `c=` — canonicalization (default: simple/simple) | 5 | src/dkim/parser.rs:284 | 77373aa | DONE |
| CHK-324 | 02-DKIM-RFC6376.md:113 | checkbox | Format: `header/body` or just `header` (body defaults to simple) | 5 | src/dkim/parser.rs:284 | 77373aa | DONE |
| CHK-325 | 02-DKIM-RFC6376.md:114 | checkbox | `i=` — AUID (default: `@<d=>`) | 5 | src/dkim/parser.rs:412 | 77373aa | DONE |
| CHK-326 | 02-DKIM-RFC6376.md:115 | checkbox | Must be subdomain of or equal to `d=` → PermFail if not | 5 | src/dkim/parser.rs:418 | 77373aa | DONE |
| CHK-327 | 02-DKIM-RFC6376.md:116 | checkbox | `l=` — body length (decimal, unsigned) | 5 | src/dkim/parser.rs:432 | 77373aa | DONE |
| CHK-328 | 02-DKIM-RFC6376.md:117 | checkbox | `q=` — query method (default: dns/txt, only defined value) | 5 | src/dkim/parser.rs:148 | 77373aa | DONE |
| CHK-329 | 02-DKIM-RFC6376.md:118 | checkbox | `t=` — timestamp (Unix epoch) | 5 | src/dkim/parser.rs:439 | 77373aa | DONE |
| CHK-330 | 02-DKIM-RFC6376.md:119 | checkbox | `x=` — expiration (Unix epoch, must be >= t if both present) | 5 | src/dkim/parser.rs:439 | 77373aa | DONE |
| CHK-331 | 02-DKIM-RFC6376.md:120 | checkbox | `z=` — copied headers (pipe-separated) | 5 | src/dkim/parser.rs:445 | 77373aa | DONE |
| CHK-332 | 02-DKIM-RFC6376.md:124 | checkbox | Unknown tags: ignore (forward compatibility) | 5 | src/dkim/parser.rs:454 | 77373aa | DONE |
| CHK-333 | 02-DKIM-RFC6376.md:125 | checkbox | Duplicate tags: PermFail | 5 | src/dkim/parser.rs:307 | 77373aa | DONE |
| CHK-334 | 02-DKIM-RFC6376.md:126 | checkbox | Missing required tags: PermFail | 5 | src/dkim/parser.rs:241 | 77373aa | DONE |
| CHK-335 | 02-DKIM-RFC6376.md:127 | checkbox | `h=` must include "from" (case-insensitive) → PermFail if missing | 5 | src/dkim/parser.rs:340 | 77373aa | DONE |
| CHK-336 | 02-DKIM-RFC6376.md:128 | checkbox | `i=` not subdomain of `d=` → PermFail | 5 | src/dkim/parser.rs:418 | 77373aa | DONE |
| CHK-337 | 02-DKIM-RFC6376.md:129 | checkbox | Store raw header value in `DkimSignature.raw_header` for b= stripping during verification | 5 | src/dkim/parser.rs:428 | 77373aa | DONE |
| CHK-338 | 02-DKIM-RFC6376.md:138 | checkbox | No changes to header content | 6 | - | - | PENDING |
| CHK-339 | 02-DKIM-RFC6376.md:139 | checkbox | Output: `name:value\r\n` exactly as it appears | 6 | - | - | PENDING |
| CHK-340 | 02-DKIM-RFC6376.md:140 | checkbox | Header names case-preserved in output, but selected case-insensitively from message | 6 | - | - | PENDING |
| CHK-341 | 02-DKIM-RFC6376.md:143 | checkbox | Convert header name to lowercase | 6 | - | - | PENDING |
| CHK-342 | 02-DKIM-RFC6376.md:144 | checkbox | Unfold headers (remove CRLF before whitespace) | 6 | - | - | PENDING |
| CHK-343 | 02-DKIM-RFC6376.md:145 | checkbox | Collapse sequential whitespace (SP/HTAB) to single SP | 6 | - | - | PENDING |
| CHK-344 | 02-DKIM-RFC6376.md:146 | checkbox | Remove trailing whitespace from header value | 6 | - | - | PENDING |
| CHK-345 | 02-DKIM-RFC6376.md:147 | checkbox | Remove whitespace before and after colon (NO space between name and value in output) | 6 | - | - | PENDING |
| CHK-346 | 02-DKIM-RFC6376.md:148 | checkbox | Output: `lowercasename:trimmed_collapsed_value\r\n` | 6 | - | - | PENDING |
| CHK-347 | 02-DKIM-RFC6376.md:153 | checkbox | Remove all trailing empty lines at end of body | 6 | - | - | PENDING |
| CHK-348 | 02-DKIM-RFC6376.md:154 | checkbox | If body is empty after stripping: treat as single CRLF (body is `\r\n`) | 6 | - | - | PENDING |
| CHK-349 | 02-DKIM-RFC6376.md:155 | checkbox | Ensure body ends with CRLF | 6 | - | - | PENDING |
| CHK-350 | 02-DKIM-RFC6376.md:158 | checkbox | Remove trailing whitespace (SP/HTAB) from each line | 6 | - | - | PENDING |
| CHK-351 | 02-DKIM-RFC6376.md:159 | checkbox | Collapse sequential whitespace within lines to single SP | 6 | - | - | PENDING |
| CHK-352 | 02-DKIM-RFC6376.md:160 | checkbox | Remove all trailing empty lines at end of body | 6 | - | - | PENDING |
| CHK-353 | 02-DKIM-RFC6376.md:161 | checkbox | If body is empty after stripping: body is empty (NOT CRLF — differs from simple!) | 6 | - | - | PENDING |
| CHK-354 | 02-DKIM-RFC6376.md:164 | checkbox | Convert bare LF (`\n`) to CRLF (`\r\n`) BEFORE canonicalization | 6 | - | - | PENDING |
| CHK-355 | 02-DKIM-RFC6376.md:165 | checkbox | This is critical: real-world messages may have mixed line endings | 6 | - | - | PENDING |
| CHK-356 | 02-DKIM-RFC6376.md:168 | checkbox | Truncate canonicalized body to `l=` bytes before hashing | 6 | - | - | PENDING |
| CHK-357 | 02-DKIM-RFC6376.md:169 | checkbox | `l=` is a security concern (body truncation attacks) — process it but note in result | 6 | - | - | PENDING |
| CHK-358 | 02-DKIM-RFC6376.md:173 | checkbox | Headers in `h=` selected case-insensitively from message | 6 | - | - | PENDING |
| CHK-359 | 02-DKIM-RFC6376.md:174 | checkbox | Multiple same-name headers: bottom-up selection (last occurrence consumed first) | 6 | - | - | PENDING |
| CHK-360 | 02-DKIM-RFC6376.md:175 | checkbox | Track consumed instances per header name using a counter | 6 | - | - | PENDING |
| CHK-361 | 02-DKIM-RFC6376.md:176 | checkbox | Over-signing: if `h=` lists a header name more times than it exists in message, extra entries contribute an EMPTY canonicalized header to the hash input: | 6 | - | - | PENDING |
| CHK-362 | 02-DKIM-RFC6376.md:179 | checkbox | Over-signed headers MUST NOT be silently skipped — they are security-critical (prevent header injection) | 6 | - | - | PENDING |
| CHK-363 | 02-DKIM-RFC6376.md:183 | checkbox | Remove the VALUE of the b= tag from DKIM-Signature header, keeping `b=` with empty value | 6 | - | - | PENDING |
| CHK-364 | 02-DKIM-RFC6376.md:184 | checkbox | MUST NOT affect the bh= tag (careful: naive "b=" search could match "bh=") | 6 | - | - | PENDING |
| CHK-365 | 02-DKIM-RFC6376.md:185 | checkbox | Implementation: find `b=` that is NOT preceded by `b` (i.e., not `bh=`), then strip value up to next `;` or end | 6 | - | - | PENDING |
| CHK-366 | 02-DKIM-RFC6376.md:186 | checkbox | The DKIM-Signature header is appended to hash input WITHOUT trailing CRLF | 6 | - | - | PENDING |
| CHK-367 | 02-DKIM-RFC6376.md:194 | checkbox | Find all DKIM-Signature headers in message (case-insensitive name match) | 7 | - | - | PENDING |
| CHK-368 | 02-DKIM-RFC6376.md:195 | checkbox | Parse each signature | 7 | - | - | PENDING |
| CHK-369 | 02-DKIM-RFC6376.md:196 | checkbox | Malformed signatures → PermFail with MalformedSignature kind | 7 | - | - | PENDING |
| CHK-370 | 02-DKIM-RFC6376.md:197 | checkbox | Return one result per DKIM-Signature, or single `None` if no signatures present | 7 | - | - | PENDING |
| CHK-371 | 02-DKIM-RFC6376.md:201 | checkbox | Construct query: `<selector>._domainkey.<domain>` TXT record | 7 | - | - | PENDING |
| CHK-372 | 02-DKIM-RFC6376.md:202 | checkbox | Handle multiple TXT strings: concatenate into single string before parsing | 7 | - | - | PENDING |
| CHK-373 | 02-DKIM-RFC6376.md:203 | checkbox | Handle NXDOMAIN → PermFail with KeyNotFound | 7 | - | - | PENDING |
| CHK-374 | 02-DKIM-RFC6376.md:204 | checkbox | Handle TempFail → TempFail | 7 | - | - | PENDING |
| CHK-375 | 02-DKIM-RFC6376.md:205 | checkbox | Empty `p=` → PermFail with KeyRevoked | 7 | - | - | PENDING |
| CHK-376 | 02-DKIM-RFC6376.md:206 | checkbox | DNS caching: caller responsibility (document this) | 7 | - | - | PENDING |
| CHK-377 | 02-DKIM-RFC6376.md:210 | checkbox | a. Empty p= → PermFail KeyRevoked | 7 | - | - | PENDING |
| CHK-378 | 02-DKIM-RFC6376.md:211 | checkbox | b. Key h= tag: if present, signature's hash algorithm must be in the list | 7 | - | - | PENDING |
| CHK-379 | 02-DKIM-RFC6376.md:214 | checkbox | c. Key s= tag: must include "email" or "*" → PermFail ServiceTypeMismatch | 7 | - | - | PENDING |
| CHK-380 | 02-DKIM-RFC6376.md:215 | checkbox | d. Key t=s flag: i= domain must exactly equal d= (not subdomain) → PermFail StrictModeViolation | 7 | - | - | PENDING |
| CHK-381 | 02-DKIM-RFC6376.md:216 | checkbox | e. Key type must match algorithm: | 7 | - | - | PENDING |
| CHK-382 | 02-DKIM-RFC6376.md:223 | checkbox | If x= present: `current_time > x + clock_skew` → PermFail ExpiredSignature | 7 | - | - | PENDING |
| CHK-383 | 02-DKIM-RFC6376.md:224 | checkbox | Clock skew: configurable, default 300 seconds | 7 | - | - | PENDING |
| CHK-384 | 02-DKIM-RFC6376.md:225 | checkbox | Check BEFORE DNS lookup to avoid unnecessary queries for expired signatures | 7 | - | - | PENDING |
| CHK-385 | 02-DKIM-RFC6376.md:229 | checkbox | Apply body canonicalization (simple or relaxed) | 7 | - | - | PENDING |
| CHK-386 | 02-DKIM-RFC6376.md:230 | checkbox | Apply length limit if `l=` present (truncate canonicalized body) | 7 | - | - | PENDING |
| CHK-387 | 02-DKIM-RFC6376.md:231 | checkbox | Compute hash (SHA-1 for rsa-sha1, SHA-256 for rsa-sha256/ed25519-sha256) | 7 | - | - | PENDING |
| CHK-388 | 02-DKIM-RFC6376.md:232 | checkbox | Compare with `bh=` value using CONSTANT-TIME comparison | 7 | - | - | PENDING |
| CHK-389 | 02-DKIM-RFC6376.md:233 | checkbox | Mismatch → Fail with BodyHashMismatch | 7 | - | - | PENDING |
| CHK-390 | 02-DKIM-RFC6376.md:236 | checkbox | Use `ring::constant_time::verify_slices_are_equal` or `subtle` crate's `ConstantTimeEq` | 7 | - | - | PENDING |
| CHK-391 | 02-DKIM-RFC6376.md:237 | checkbox | ring 0.17 has deprecated `verify_slices_are_equal` — check for replacement or use `subtle` crate | 7 | - | - | PENDING |
| CHK-392 | 02-DKIM-RFC6376.md:238 | checkbox | NEVER use `==` for body hash comparison (timing side-channel) | 7 | - | - | PENDING |
| CHK-393 | 02-DKIM-RFC6376.md:242 | checkbox | For each header name in `h=` (in order): | 7 | - | - | PENDING |
| CHK-394 | 02-DKIM-RFC6376.md:243 | checkbox | Find header in message (bottom-up: last unused occurrence) | 7 | - | - | PENDING |
| CHK-395 | 02-DKIM-RFC6376.md:244 | checkbox | Mark as consumed | 7 | - | - | PENDING |
| CHK-396 | 02-DKIM-RFC6376.md:245 | checkbox | If not found (over-signed): use empty header value | 7 | - | - | PENDING |
| CHK-397 | 02-DKIM-RFC6376.md:246 | checkbox | Canonicalize header | 7 | - | - | PENDING |
| CHK-398 | 02-DKIM-RFC6376.md:247 | checkbox | Append to hash input: `name:value\r\n` | 7 | - | - | PENDING |
| CHK-399 | 02-DKIM-RFC6376.md:248 | checkbox | Append DKIM-Signature header itself: | 7 | - | - | PENDING |
| CHK-400 | 02-DKIM-RFC6376.md:249 | checkbox | Use raw_header value stored during parsing | 7 | - | - | PENDING |
| CHK-401 | 02-DKIM-RFC6376.md:250 | checkbox | Strip b= tag value (keep `b=` with empty value) | 7 | - | - | PENDING |
| CHK-402 | 02-DKIM-RFC6376.md:251 | checkbox | Canonicalize the signature header | 7 | - | - | PENDING |
| CHK-403 | 02-DKIM-RFC6376.md:252 | checkbox | Append WITHOUT trailing CRLF (last header has no CRLF) | 7 | - | - | PENDING |
| CHK-404 | 02-DKIM-RFC6376.md:256 | checkbox | Pass RAW header data bytes to ring — ring hashes internally | 7 | - | - | PENDING |
| CHK-405 | 02-DKIM-RFC6376.md:257 | checkbox | **CRITICAL: Do NOT pre-hash the header data. ring::UnparsedPublicKey::verify(data, signature) takes the raw MESSAGE, not a digest. Pre-hashing = double-hash = always fails.** | 7 | - | - | PENDING |
| CHK-406 | 02-DKIM-RFC6376.md:260 | checkbox | ring requires different algorithm constants for different key sizes | 7 | - | - | PENDING |
| CHK-407 | 02-DKIM-RFC6376.md:261 | checkbox | 1024-bit RSA: DER-encoded SubjectPublicKeyInfo is ~140-170 bytes | 7 | - | - | PENDING |
| CHK-408 | 02-DKIM-RFC6376.md:262 | checkbox | 2048-bit RSA: DER-encoded SubjectPublicKeyInfo is ~290-300 bytes | 7 | - | - | PENDING |
| CHK-409 | 02-DKIM-RFC6376.md:263 | checkbox | 4096-bit RSA: DER-encoded SubjectPublicKeyInfo is ~550-560 bytes | 7 | - | - | PENDING |
| CHK-410 | 02-DKIM-RFC6376.md:264 | checkbox | Use threshold: `key.public_key.len() < 256` → use `_1024_8192_FOR_LEGACY_USE_ONLY` variant | 7 | - | - | PENDING |
| CHK-411 | 02-DKIM-RFC6376.md:265 | checkbox | ≥256 bytes → use `_2048_8192` variant | 7 | - | - | PENDING |
| CHK-412 | 02-DKIM-RFC6376.md:277 | checkbox | Ed25519 public key in DNS: raw 32-byte key, base64 encoded in p= tag | 7 | - | - | PENDING |
| CHK-413 | 02-DKIM-RFC6376.md:278 | checkbox | ring expects raw 32 bytes for Ed25519 verification | 7 | - | - | PENDING |
| CHK-414 | 02-DKIM-RFC6376.md:282 | checkbox | All checks pass → Pass { domain, selector, testing } | 7 | - | - | PENDING |
| CHK-415 | 02-DKIM-RFC6376.md:283 | checkbox | Body hash mismatch → Fail { BodyHashMismatch } | 7 | - | - | PENDING |
| CHK-416 | 02-DKIM-RFC6376.md:284 | checkbox | Crypto verification fails → Fail { SignatureVerificationFailed } | 7 | - | - | PENDING |
| CHK-417 | 02-DKIM-RFC6376.md:285 | checkbox | Key not found (NXDOMAIN) → PermFail { KeyNotFound } | 7 | - | - | PENDING |
| CHK-418 | 02-DKIM-RFC6376.md:286 | checkbox | Key revoked (empty p=) → PermFail { KeyRevoked } | 7 | - | - | PENDING |
| CHK-419 | 02-DKIM-RFC6376.md:287 | checkbox | DNS temp failure → TempFail | 7 | - | - | PENDING |
| CHK-420 | 02-DKIM-RFC6376.md:288 | checkbox | All other constraint violations → PermFail with specific kind | 7 | - | - | PENDING |
| CHK-421 | 02-DKIM-RFC6376.md:311 | checkbox | Load private key: PEM format (PKCS8) | 8 | - | - | PENDING |
| CHK-422 | 02-DKIM-RFC6376.md:312 | checkbox | Support RSA keys (minimum 1024-bit for verify, recommend 2048+ for signing) | 8 | - | - | PENDING |
| CHK-423 | 02-DKIM-RFC6376.md:313 | checkbox | Support Ed25519 keys (PKCS8 format) | 8 | - | - | PENDING |
| CHK-424 | 02-DKIM-RFC6376.md:314 | checkbox | ring: `RsaKeyPair::from_pkcs8()` for RSA, `Ed25519KeyPair::from_pkcs8()` for Ed25519 | 8 | - | - | PENDING |
| CHK-425 | 02-DKIM-RFC6376.md:315 | checkbox | Validate key loads successfully at signer creation time (fail fast) | 8 | - | - | PENDING |
| CHK-426 | 02-DKIM-RFC6376.md:319 | checkbox | MUST include From | 8 | - | - | PENDING |
| CHK-427 | 02-DKIM-RFC6376.md:320 | checkbox | Recommended: From, To, Subject, Date, MIME-Version, Content-Type, Message-ID | 8 | - | - | PENDING |
| CHK-428 | 02-DKIM-RFC6376.md:321 | checkbox | Avoid signing: Received, Return-Path (change in transit) | 8 | - | - | PENDING |
| CHK-429 | 02-DKIM-RFC6376.md:322 | checkbox | Over-signing recommended: include header names extra times to prevent injection | 8 | - | - | PENDING |
| CHK-430 | 02-DKIM-RFC6376.md:336 | checkbox | Set `t=` to current Unix timestamp | 8 | - | - | PENDING |
| CHK-431 | 02-DKIM-RFC6376.md:337 | checkbox | If `expiration_seconds` configured: set `x=` to `t + expiration_seconds` | 8 | - | - | PENDING |
| CHK-432 | 02-DKIM-RFC6376.md:341 | checkbox | Sign-then-verify round-trip: `sign(message) → verify(message + signature)` must Pass | 8 | - | - | PENDING |
| CHK-433 | 02-DKIM-RFC6376.md:342 | checkbox | ALSO test with ground-truth fixtures that bypass DkimSigner (use ring primitives directly) to catch self-consistent bugs | 8 | - | - | PENDING |
| CHK-434 | 02-DKIM-RFC6376.md:350 | checkbox | Query: `<selector>._domainkey.<domain>` TXT record | 5 | src/dkim/key.rs:212 | 77373aa | DONE |
| CHK-435 | 02-DKIM-RFC6376.md:351 | checkbox | Selector allows multiple keys per domain | 5 | src/dkim/key.rs:221 | 77373aa | DONE |
| CHK-436 | 02-DKIM-RFC6376.md:352 | checkbox | Multiple TXT strings in one record: concatenate before parsing | 5 | src/dkim/key.rs:230 | 77373aa | DONE |
| CHK-437 | 02-DKIM-RFC6376.md:356 | checkbox | `v=` — version (should be "DKIM1", optional — if present must be exactly "DKIM1") | 5 | src/dkim/key.rs:239 | 77373aa | DONE |
| CHK-438 | 02-DKIM-RFC6376.md:357 | checkbox | `h=` — acceptable hash algorithms (colon-separated). If present: signature's hash must be in list | 5 | src/dkim/key.rs:257 | 77373aa | DONE |
| CHK-439 | 02-DKIM-RFC6376.md:358 | checkbox | `k=` — key type (default: "rsa"). Support "rsa" and "ed25519" | 5 | src/dkim/key.rs:267 | 77373aa | DONE |
| CHK-440 | 02-DKIM-RFC6376.md:359 | checkbox | `n=` — notes (human-readable, ignored by verifier) | 5 | src/dkim/key.rs:278 | 77373aa | DONE |
| CHK-441 | 02-DKIM-RFC6376.md:360 | checkbox | `p=` — public key base64 (required, empty = key revoked) | 5 | src/dkim/key.rs:285 | 77373aa | DONE |
| CHK-442 | 02-DKIM-RFC6376.md:361 | checkbox | `s=` — service type (colon-separated, default: "*"). Must include "email" or "*" | 5 | src/dkim/key.rs:292 | 77373aa | DONE |
| CHK-443 | 02-DKIM-RFC6376.md:362 | checkbox | `t=` — flags (colon-separated): | 5 | src/dkim/key.rs:150 | 77373aa | DONE |
| CHK-444 | 02-DKIM-RFC6376.md:363 | checkbox | `y` — testing mode (key valid, but results are informational) | 5 | src/dkim/key.rs:156 | 77373aa | DONE |
| CHK-445 | 02-DKIM-RFC6376.md:364 | checkbox | `s` — strict mode (i= domain must exactly match d=, not subdomain) | 5 | src/dkim/key.rs:164 | 77373aa | DONE |
| CHK-446 | 02-DKIM-RFC6376.md:365 | checkbox | Unknown tags: ignore (forward compatibility) | 5 | src/dkim/key.rs:247 | 77373aa | DONE |
| CHK-447 | 02-DKIM-RFC6376.md:369 | checkbox | RSA: SubjectPublicKeyInfo DER format, base64 encoded | 5 | src/dkim/key.rs:303 | 77373aa | DONE |
| CHK-448 | 02-DKIM-RFC6376.md:370 | checkbox | Ed25519: raw 32-byte public key, base64 encoded | 5 | src/dkim/key.rs:310 | 77373aa | DONE |
| CHK-449 | 02-DKIM-RFC6376.md:371 | checkbox | Malformed/undecodable keys → PermFail | 5 | src/dkim/key.rs:317 | 77373aa | DONE |
| CHK-450 | 02-DKIM-RFC6376.md:421 | checkbox | Minimal valid signature (all required tags only) | 5 | src/dkim/parser.rs:222 | 77373aa | DONE |
| CHK-451 | 02-DKIM-RFC6376.md:422 | checkbox | All optional tags present | 5 | src/dkim/parser.rs:252 | 77373aa | DONE |
| CHK-452 | 02-DKIM-RFC6376.md:423 | checkbox | Folded header value (multiline with continuation) | 5 | src/dkim/parser.rs:270 | 77373aa | DONE |
| CHK-453 | 02-DKIM-RFC6376.md:424 | checkbox | Base64 with embedded whitespace | 5 | src/dkim/parser.rs:280 | 77373aa | DONE |
| CHK-454 | 02-DKIM-RFC6376.md:425 | checkbox | Missing required tag → PermFail | 5 | src/dkim/parser.rs:293 | 77373aa | DONE |
| CHK-455 | 02-DKIM-RFC6376.md:426 | checkbox | Duplicate tag → PermFail | 5 | src/dkim/parser.rs:307 | 77373aa | DONE |
| CHK-456 | 02-DKIM-RFC6376.md:427 | checkbox | Unknown tag → ignored | 5 | src/dkim/parser.rs:318 | 77373aa | DONE |
| CHK-457 | 02-DKIM-RFC6376.md:428 | checkbox | Invalid algorithm → PermFail | 5 | src/dkim/parser.rs:328 | 77373aa | DONE |
| CHK-458 | 02-DKIM-RFC6376.md:429 | checkbox | Case-insensitive algorithm: `a=RSA-SHA256` → parsed identical to `a=rsa-sha256` (applies `.to_ascii_lowercase()` before matching) | 5 | src/dkim/parser.rs:340 | 77373aa | DONE |
| CHK-459 | 02-DKIM-RFC6376.md:430 | checkbox | h= missing "from" → PermFail | 5 | src/dkim/parser.rs:351 | 77373aa | DONE |
| CHK-460 | 02-DKIM-RFC6376.md:431 | checkbox | i= not subdomain of d= → PermFail | 5 | src/dkim/parser.rs:362 | 77373aa | DONE |
| CHK-461 | 02-DKIM-RFC6376.md:432 | checkbox | c= parsing: "relaxed/relaxed", "simple", "relaxed" (body defaults to simple) | 5 | src/dkim/parser.rs:284 | 77373aa | DONE |
| CHK-462 | 02-DKIM-RFC6376.md:436 | checkbox | Minimal key: `p=<base64>` | 5 | src/dkim/key.rs:142 | 77373aa | DONE |
| CHK-463 | 02-DKIM-RFC6376.md:437 | checkbox | Full key with all tags | 5 | src/dkim/key.rs:155 | 77373aa | DONE |
| CHK-464 | 02-DKIM-RFC6376.md:438 | checkbox | Revoked key: `p=` (empty) | 5 | src/dkim/key.rs:175 | 77373aa | DONE |
| CHK-465 | 02-DKIM-RFC6376.md:439 | checkbox | h= tag with sha256 only | 5 | src/dkim/key.rs:183 | 77373aa | DONE |
| CHK-466 | 02-DKIM-RFC6376.md:440 | checkbox | s= tag with "email" vs "*" vs "other" | 5 | src/dkim/key.rs:193 | 77373aa | DONE |
| CHK-467 | 02-DKIM-RFC6376.md:441 | checkbox | t= flags: testing, strict, both | 5 | src/dkim/key.rs:222 | 77373aa | DONE |
| CHK-468 | 02-DKIM-RFC6376.md:442 | checkbox | Unknown key type | 5 | src/dkim/key.rs:250 | 77373aa | DONE |
| CHK-469 | 02-DKIM-RFC6376.md:443 | checkbox | Ed25519 key (32 bytes) | 5 | src/dkim/key.rs:259 | 77373aa | DONE |
| CHK-470 | 02-DKIM-RFC6376.md:444 | checkbox | RSA 1024-bit key | 5 | src/dkim/key.rs:268 | 77373aa | DONE |
| CHK-471 | 02-DKIM-RFC6376.md:445 | checkbox | RSA 2048-bit key | 5 | src/dkim/key.rs:278 | 77373aa | DONE |
| CHK-472 | 02-DKIM-RFC6376.md:449 | checkbox | Simple header: output unchanged (preserving case) | 6 | - | - | PENDING |
| CHK-473 | 02-DKIM-RFC6376.md:450 | checkbox | Relaxed header: lowercase name, collapse whitespace, remove trailing WSP, no space around colon | 6 | - | - | PENDING |
| CHK-474 | 02-DKIM-RFC6376.md:451 | checkbox | Simple body: trailing blank lines removed, empty body → `\r\n` | 6 | - | - | PENDING |
| CHK-475 | 02-DKIM-RFC6376.md:452 | checkbox | Relaxed body: whitespace normalized, empty body → empty (not `\r\n`) | 6 | - | - | PENDING |
| CHK-476 | 02-DKIM-RFC6376.md:453 | checkbox | Body length limit truncation | 6 | - | - | PENDING |
| CHK-477 | 02-DKIM-RFC6376.md:454 | checkbox | Bare LF → CRLF conversion | 6 | - | - | PENDING |
| CHK-478 | 02-DKIM-RFC6376.md:455 | checkbox | Header selection: bottom-up for multiple same-name headers | 6 | - | - | PENDING |
| CHK-479 | 02-DKIM-RFC6376.md:456 | checkbox | Over-signed headers: contribute empty value (not skipped) | 6 | - | - | PENDING |
| CHK-480 | 02-DKIM-RFC6376.md:457 | checkbox | b= tag stripping: does NOT affect bh= tag | 6 | - | - | PENDING |
| CHK-481 | 02-DKIM-RFC6376.md:461 | checkbox | Valid Ed25519 signature → Pass | 7 | - | - | PENDING |
| CHK-482 | 02-DKIM-RFC6376.md:462 | checkbox | Valid RSA-SHA256 signature → Pass (**pre-computed fixture**: sign with `rsa` crate or openssl, embed signed message + SPKI public key in test — cannot rely on sign→verify round-trip alone) | 7 | - | - | PENDING |
| CHK-483 | 02-DKIM-RFC6376.md:463 | checkbox | Valid RSA-SHA1 signature → Pass (**pre-computed fixture required**: ring 0.17 cannot sign SHA-1. Sign once externally, embed fixture with raw message bytes + signature + public key) | 7 | - | - | PENDING |
| CHK-484 | 02-DKIM-RFC6376.md:464 | checkbox | Tampered body → Fail (BodyHashMismatch) | 7 | - | - | PENDING |
| CHK-485 | 02-DKIM-RFC6376.md:465 | checkbox | Tampered header → Fail (SignatureVerificationFailed) | 7 | - | - | PENDING |
| CHK-486 | 02-DKIM-RFC6376.md:466 | checkbox | Expired signature → PermFail (ExpiredSignature) | 7 | - | - | PENDING |
| CHK-487 | 02-DKIM-RFC6376.md:467 | checkbox | Key not found (NXDOMAIN) → PermFail (KeyNotFound) | 7 | - | - | PENDING |
| CHK-488 | 02-DKIM-RFC6376.md:468 | checkbox | Key revoked (empty p=) → PermFail (KeyRevoked) | 7 | - | - | PENDING |
| CHK-489 | 02-DKIM-RFC6376.md:469 | checkbox | Key h= rejects algorithm → PermFail (HashNotPermitted) | 7 | - | - | PENDING |
| CHK-490 | 02-DKIM-RFC6376.md:470 | checkbox | Key s= rejects email → PermFail (ServiceTypeMismatch) | 7 | - | - | PENDING |
| CHK-491 | 02-DKIM-RFC6376.md:471 | checkbox | Key t=s strict mode violation → PermFail (StrictModeViolation) | 7 | - | - | PENDING |
| CHK-492 | 02-DKIM-RFC6376.md:472 | checkbox | Algorithm/key type mismatch → PermFail (AlgorithmMismatch) | 7 | - | - | PENDING |
| CHK-493 | 02-DKIM-RFC6376.md:473 | checkbox | DNS temp failure → TempFail | 7 | - | - | PENDING |
| CHK-494 | 02-DKIM-RFC6376.md:474 | checkbox | No DKIM-Signature → None | 7 | - | - | PENDING |
| CHK-495 | 02-DKIM-RFC6376.md:475 | checkbox | Simple/simple canonicalization end-to-end | 7 | - | - | PENDING |
| CHK-496 | 02-DKIM-RFC6376.md:476 | checkbox | Relaxed/relaxed canonicalization end-to-end | 7 | - | - | PENDING |
| CHK-497 | 02-DKIM-RFC6376.md:477 | checkbox | Over-signed header verification: signature with "from" listed twice in h=, message has one From → verify Pass (empty header contributes to hash, not skipped) | 7 | - | - | PENDING |
| CHK-498 | 02-DKIM-RFC6376.md:481 | checkbox | Construct DKIM signatures manually using ring primitives (Ed25519KeyPair.sign), bypassing DkimSigner entirely | 7 | - | - | PENDING |
| CHK-499 | 02-DKIM-RFC6376.md:482 | checkbox | Verify through the full DkimVerifier pipeline | 7 | - | - | PENDING |
| CHK-500 | 02-DKIM-RFC6376.md:483 | checkbox | This catches self-consistent bugs where signer and verifier agree but both are wrong | 7 | - | - | PENDING |
| CHK-501 | 02-DKIM-RFC6376.md:484 | checkbox | Include at minimum: Ed25519 relaxed/relaxed, Ed25519 simple/simple, tampered body, tampered headers | 7 | - | - | PENDING |
| CHK-502 | 02-DKIM-RFC6376.md:488 | checkbox | Sign and verify round-trip (Ed25519) | 8 | - | - | PENDING |
| CHK-503 | 02-DKIM-RFC6376.md:489 | checkbox | Sign and verify round-trip (RSA-SHA256) — generate RSA 2048 key, sign message, verify through DkimVerifier with MockResolver serving the public key | 8 | - | - | PENDING |
| CHK-504 | 02-DKIM-RFC6376.md:490 | checkbox | Different canonicalization modes | 8 | - | - | PENDING |
| CHK-505 | 02-DKIM-RFC6376.md:491 | checkbox | From header enforced in signed headers | 8 | - | - | PENDING |
| CHK-506 | 02-DKIM-RFC6376.md:492 | checkbox | Timestamp and expiration set correctly | 8 | - | - | PENDING |
| CHK-507 | 02-DKIM-RFC6376.md:493 | checkbox | PEM key loading: RSA 2048, Ed25519 | 8 | - | - | PENDING |
| CHK-508 | 02-DKIM-RFC6376.md:494 | checkbox | RSA-SHA1 signing prevention: `DkimSigner` API MUST NOT allow constructing a signer with `Algorithm::RsaSha1`. Either no constructor exists, or `sign_message()` returns error. Test that no code path produces an `a=rsa-sha1` signature. | 8 | - | - | PENDING |
| CHK-509 | 02-DKIM-RFC6376.md:495 | checkbox | Over-sign round-trip: sign with "from" in h= twice (over-sign), verify through DkimVerifier → Pass. This validates signer and verifier agree on empty-header hash contribution. A bug where signer skips the empty header but verifier includes it (or vice versa) causes Fail. | 8 | - | - | PENDING |
| CHK-510 | 02-DKIM-RFC6376.md:501 | checkbox | Minimum RSA key size: 1024 bits for verification (ring handles this via algorithm selection) | 7 | - | - | PENDING |
| CHK-511 | 02-DKIM-RFC6376.md:502 | checkbox | Recommended RSA key size for signing: 2048+ bits | 7 | - | - | PENDING |
| CHK-512 | 02-DKIM-RFC6376.md:503 | checkbox | RSA-SHA1: accept for verification only, NEVER use for signing | 7 | - | - | PENDING |
| CHK-513 | 02-DKIM-RFC6376.md:504 | checkbox | Constant-time comparison for body hash (timing attack prevention) | 7 | - | - | PENDING |
| CHK-514 | 02-DKIM-RFC6376.md:505 | checkbox | Validate signature timestamps with configurable clock skew (default ±300s) | 7 | - | - | PENDING |
| CHK-515 | 02-DKIM-RFC6376.md:506 | checkbox | l= body length: process but note it's a security concern (body truncation attacks) | 7 | - | - | PENDING |
| CHK-516 | 02-DKIM-RFC6376.md:507 | checkbox | Verify i= domain is subdomain of d= during parsing | 7 | - | - | PENDING |
| CHK-517 | 02-DKIM-RFC6376.md:508 | checkbox | Key t=s strict mode: i= domain must EXACTLY equal d= | 7 | - | - | PENDING |
| CHK-518 | 02-DKIM-RFC6376.md:584 | checkbox | Cryptography: `ring` 0.17 (RSA + Ed25519 + SHA) | 1 | Cargo.toml:14 | 992b713 | DONE |
| CHK-519 | 02-DKIM-RFC6376.md:585 | checkbox | Base64: `base64` 0.22 crate | 1 | Cargo.toml:17 | 992b713 | DONE |
| CHK-520 | 02-DKIM-RFC6376.md:586 | checkbox | DNS resolver: `hickory-resolver` 0.25 (shared via DnsResolver trait) | 1 | Cargo.toml:11 | 992b713 | DONE |
| CHK-521 | 02-DKIM-RFC6376.md:592 | checkbox | All data types defined with typed enums (FailureKind, PermFailKind, not raw strings) | 5 | src/dkim/parser.rs:355 | 77373aa | DONE |
| CHK-522 | 02-DKIM-RFC6376.md:593 | checkbox | Signature parsing complete with all required and optional tags | 5 | src/dkim/parser.rs:460 | 77373aa | DONE |
| CHK-523 | 02-DKIM-RFC6376.md:594 | checkbox | Key record parsing complete with constraint fields (h=, s=, t=) | 5 | src/dkim/key.rs:323 | 77373aa | DONE |
| CHK-524 | 02-DKIM-RFC6376.md:595 | checkbox | Both canonicalization methods implemented (simple and relaxed, header and body) | 6 | - | - | PENDING |
| CHK-525 | 02-DKIM-RFC6376.md:596 | checkbox | Header selection with bottom-up and over-signing | 6 | - | - | PENDING |
| CHK-526 | 02-DKIM-RFC6376.md:597 | checkbox | Bare LF → CRLF normalization | 6 | - | - | PENDING |
| CHK-527 | 02-DKIM-RFC6376.md:598 | checkbox | b= tag stripping (safe against bh=) | 6 | - | - | PENDING |
| CHK-528 | 02-DKIM-RFC6376.md:599 | checkbox | Verification algorithm complete with all constraint checks | 7 | - | - | PENDING |
| CHK-529 | 02-DKIM-RFC6376.md:600 | checkbox | RSA-SHA256 + RSA-SHA1 + Ed25519 verification working | 7 | - | - | PENDING |
| CHK-530 | 02-DKIM-RFC6376.md:601 | checkbox | Signing algorithm complete (RSA-SHA256 + Ed25519) | 8 | - | - | PENDING |
| CHK-531 | 02-DKIM-RFC6376.md:602 | checkbox | Ground-truth tests (bypass signer, construct signatures manually) | 7 | - | - | PENDING |
| CHK-532 | 02-DKIM-RFC6376.md:603 | checkbox | RSA-SHA1 verification tested | 7 | - | - | PENDING |
| CHK-533 | 02-DKIM-RFC6376.md:604 | checkbox | DNS key lookup working with TXT string concatenation | 7 | - | - | PENDING |
| CHK-534 | 02-DKIM-RFC6376.md:605 | checkbox | No unwrap/expect in library code (tests only) | 7 | - | - | PENDING |
| CHK-535 | 03-DMARC-RFC7489.md:19 | checkbox | Define `DmarcRecord` struct: | 9 | - | - | PENDING |
| CHK-536 | 03-DMARC-RFC7489.md:20 | checkbox | `policy: Policy` — policy for organizational domain (p= tag) | 9 | - | - | PENDING |
| CHK-537 | 03-DMARC-RFC7489.md:21 | checkbox | `subdomain_policy: Policy` — subdomain policy (sp= tag, defaults to p) | 9 | - | - | PENDING |
| CHK-538 | 03-DMARC-RFC7489.md:22 | checkbox | `non_existent_subdomain_policy: Option<Policy>` — np= tag (RFC 9091) | 9 | - | - | PENDING |
| CHK-539 | 03-DMARC-RFC7489.md:23 | checkbox | `dkim_alignment: AlignmentMode` — DKIM alignment mode (adkim= tag, default: relaxed) | 9 | - | - | PENDING |
| CHK-540 | 03-DMARC-RFC7489.md:24 | checkbox | `spf_alignment: AlignmentMode` — SPF alignment mode (aspf= tag, default: relaxed) | 9 | - | - | PENDING |
| CHK-541 | 03-DMARC-RFC7489.md:25 | checkbox | `percent: u8` — percentage of messages to apply policy (pct= tag, default: 100) | 9 | - | - | PENDING |
| CHK-542 | 03-DMARC-RFC7489.md:26 | checkbox | `failure_options: Vec<FailureOption>` — failure reporting options (fo= tag) | 9 | - | - | PENDING |
| CHK-543 | 03-DMARC-RFC7489.md:27 | checkbox | `report_format: ReportFormat` — report format (rf= tag, default: AFRF) | 9 | - | - | PENDING |
| CHK-544 | 03-DMARC-RFC7489.md:28 | checkbox | `report_interval: u32` — aggregate report interval seconds (ri= tag, default: 86400) | 9 | - | - | PENDING |
| CHK-545 | 03-DMARC-RFC7489.md:29 | checkbox | `rua: Vec<ReportUri>` — aggregate report URIs (rua= tag) | 9 | - | - | PENDING |
| CHK-546 | 03-DMARC-RFC7489.md:30 | checkbox | `ruf: Vec<ReportUri>` — failure report URIs (ruf= tag) | 9 | - | - | PENDING |
| CHK-547 | 03-DMARC-RFC7489.md:34 | checkbox | Define `Policy` enum: | 9 | - | - | PENDING |
| CHK-548 | 03-DMARC-RFC7489.md:35 | checkbox | `None` — no action, monitoring only | 9 | - | - | PENDING |
| CHK-549 | 03-DMARC-RFC7489.md:36 | checkbox | `Quarantine` — treat as suspicious (spam folder) | 9 | - | - | PENDING |
| CHK-550 | 03-DMARC-RFC7489.md:37 | checkbox | `Reject` — reject the message | 9 | - | - | PENDING |
| CHK-551 | 03-DMARC-RFC7489.md:38 | checkbox | Parsing: case-insensitive ("none", "quarantine", "reject") | 9 | - | - | PENDING |
| CHK-552 | 03-DMARC-RFC7489.md:42 | checkbox | Define `AlignmentMode` enum: | 9 | - | - | PENDING |
| CHK-553 | 03-DMARC-RFC7489.md:43 | checkbox | `Relaxed` — organizational domain match (default) | 9 | - | - | PENDING |
| CHK-554 | 03-DMARC-RFC7489.md:44 | checkbox | `Strict` — exact domain match | 9 | - | - | PENDING |
| CHK-555 | 03-DMARC-RFC7489.md:45 | checkbox | Parsing: "r" → Relaxed, "s" → Strict | 9 | - | - | PENDING |
| CHK-556 | 03-DMARC-RFC7489.md:49 | checkbox | Define `FailureOption` enum: | 9 | - | - | PENDING |
| CHK-557 | 03-DMARC-RFC7489.md:50 | checkbox | `Zero` — `0`: generate report if all mechanisms fail (default) | 9 | - | - | PENDING |
| CHK-558 | 03-DMARC-RFC7489.md:51 | checkbox | `One` — `1`: generate report if any mechanism fails | 9 | - | - | PENDING |
| CHK-559 | 03-DMARC-RFC7489.md:52 | checkbox | `D` — `d`: generate report if DKIM fails | 9 | - | - | PENDING |
| CHK-560 | 03-DMARC-RFC7489.md:53 | checkbox | `S` — `s`: generate report if SPF fails | 9 | - | - | PENDING |
| CHK-561 | 03-DMARC-RFC7489.md:54 | checkbox | Parsing: colon-separated, case-insensitive. Unknown options ignored. | 9 | - | - | PENDING |
| CHK-562 | 03-DMARC-RFC7489.md:58 | checkbox | Define `ReportUri` struct: | 9 | - | - | PENDING |
| CHK-563 | 03-DMARC-RFC7489.md:59 | checkbox | `address: String` — email address (after stripping `mailto:` prefix) | 9 | - | - | PENDING |
| CHK-564 | 03-DMARC-RFC7489.md:60 | checkbox | `max_size: Option<u64>` — size limit in bytes | 9 | - | - | PENDING |
| CHK-565 | 03-DMARC-RFC7489.md:62 | checkbox | Size suffix parsing: `!` followed by number + optional unit (k/m/g/t, case-insensitive) | 9 | - | - | PENDING |
| CHK-566 | 03-DMARC-RFC7489.md:68 | checkbox | Define `DmarcResult` struct (NOT a flat enum — structured with evaluation details): | 9 | - | - | PENDING |
| CHK-567 | 03-DMARC-RFC7489.md:69 | checkbox | `disposition: Disposition` — what to do with message | 9 | - | - | PENDING |
| CHK-568 | 03-DMARC-RFC7489.md:70 | checkbox | `dkim_aligned: bool` — whether any DKIM signature aligned | 9 | - | - | PENDING |
| CHK-569 | 03-DMARC-RFC7489.md:71 | checkbox | `spf_aligned: bool` — whether SPF passed and aligned | 9 | - | - | PENDING |
| CHK-570 | 03-DMARC-RFC7489.md:72 | checkbox | `applied_policy: Option<Policy>` — the policy that was applied | 9 | - | - | PENDING |
| CHK-571 | 03-DMARC-RFC7489.md:73 | checkbox | `record: Option<DmarcRecord>` — the DMARC record found (if any) | 9 | - | - | PENDING |
| CHK-572 | 03-DMARC-RFC7489.md:75 | checkbox | Define `Disposition` enum: | 9 | - | - | PENDING |
| CHK-573 | 03-DMARC-RFC7489.md:76 | checkbox | `Pass` — message passed DMARC | 9 | - | - | PENDING |
| CHK-574 | 03-DMARC-RFC7489.md:77 | checkbox | `Quarantine` — quarantine per policy | 9 | - | - | PENDING |
| CHK-575 | 03-DMARC-RFC7489.md:78 | checkbox | `Reject` — reject per policy | 9 | - | - | PENDING |
| CHK-576 | 03-DMARC-RFC7489.md:79 | checkbox | `None` — no policy (monitoring mode, pct sampling excluded, or no record) | 9 | - | - | PENDING |
| CHK-577 | 03-DMARC-RFC7489.md:80 | checkbox | `TempFail` — DNS temporary failure during record discovery | 9 | - | - | PENDING |
| CHK-578 | 03-DMARC-RFC7489.md:88 | checkbox | Extract domain from RFC5322.From header | 10 | - | - | PENDING |
| CHK-579 | 03-DMARC-RFC7489.md:89 | checkbox | Query: `_dmarc.<from-domain>` TXT record | 10 | - | - | PENDING |
| CHK-580 | 03-DMARC-RFC7489.md:90 | checkbox | If no record found and domain is not organizational domain: | 10 | - | - | PENDING |
| CHK-581 | 03-DMARC-RFC7489.md:91 | checkbox | Determine organizational domain (public suffix + 1 label) | 10 | - | - | PENDING |
| CHK-582 | 03-DMARC-RFC7489.md:92 | checkbox | Query: `_dmarc.<organizational-domain>` | 10 | - | - | PENDING |
| CHK-583 | 03-DMARC-RFC7489.md:93 | checkbox | Multiple TXT records at same name: use first valid DMARC record (parse each, take first success) | 10 | - | - | PENDING |
| CHK-584 | 03-DMARC-RFC7489.md:94 | checkbox | No record found (NXDOMAIN or no valid DMARC records): DmarcResult with disposition=None, no policy | 10 | - | - | PENDING |
| CHK-585 | 03-DMARC-RFC7489.md:98 | checkbox | **CRITICAL**: DNS TempFail during record discovery MUST NOT be treated as "no record" | 10 | - | - | PENDING |
| CHK-586 | 03-DMARC-RFC7489.md:99 | checkbox | If TXT query returns TempFail: return DmarcResult with `disposition: Disposition::TempFail` | 10 | - | - | PENDING |
| CHK-587 | 03-DMARC-RFC7489.md:100 | checkbox | Rationale: treating DNS outage as "no policy" means messages bypass DMARC during DNS failures — this is a security violation | 10 | - | - | PENDING |
| CHK-588 | 03-DMARC-RFC7489.md:104 | checkbox | Use Public Suffix List (PSL) to determine organizational domain | 1 | src/common/domain.rs:167 | 992b713 | DONE |
| CHK-589 | 03-DMARC-RFC7489.md:105 | checkbox | Organizational domain = public suffix + one label | 1 | src/common/domain.rs:167 | 992b713 | DONE |
| CHK-590 | 03-DMARC-RFC7489.md:106 | checkbox | Example: `mail.example.com` → `example.com` | 1 | src/common/domain.rs:173 | 992b713 | DONE |
| CHK-591 | 03-DMARC-RFC7489.md:107 | checkbox | Example: `foo.bar.co.uk` → `bar.co.uk` | 1 | src/common/domain.rs:197 | 992b713 | DONE |
| CHK-592 | 03-DMARC-RFC7489.md:108 | checkbox | Use `psl` crate v2: `psl::domain_str(&normalized)` returns the registrable domain | 1 | src/common/domain.rs:44 | 992b713 | DONE |
| CHK-593 | 03-DMARC-RFC7489.md:109 | checkbox | The psl crate embeds a snapshot of the PSL — no runtime fetch needed | 1 | src/common/domain.rs:44 | 992b713 | DONE |
| CHK-594 | 03-DMARC-RFC7489.md:113 | checkbox | DNS caching: CALLER responsibility (resolver layer), not library scope | 10 | - | - | PENDING |
| CHK-595 | 03-DMARC-RFC7489.md:114 | checkbox | Document this clearly — callers implement caching in their DnsResolver wrapper | 10 | - | - | PENDING |
| CHK-596 | 03-DMARC-RFC7489.md:122 | checkbox | Parse as tag=value pairs, separated by semicolons | 9 | - | - | PENDING |
| CHK-597 | 03-DMARC-RFC7489.md:123 | checkbox | Tags are case-insensitive | 9 | - | - | PENDING |
| CHK-598 | 03-DMARC-RFC7489.md:124 | checkbox | Values may be case-sensitive (URIs) or case-insensitive (policies) | 9 | - | - | PENDING |
| CHK-599 | 03-DMARC-RFC7489.md:125 | checkbox | Whitespace around tags/values is ignored | 9 | - | - | PENDING |
| CHK-600 | 03-DMARC-RFC7489.md:126 | checkbox | Trailing semicolons allowed | 9 | - | - | PENDING |
| CHK-601 | 03-DMARC-RFC7489.md:130 | checkbox | `v=` — version, MUST be "DMARC1", MUST be first tag | 9 | - | - | PENDING |
| CHK-602 | 03-DMARC-RFC7489.md:131 | checkbox | `p=` — policy: "none", "quarantine", "reject" (case-insensitive) | 9 | - | - | PENDING |
| CHK-603 | 03-DMARC-RFC7489.md:132 | checkbox | Missing v= or p= → parse error | 9 | - | - | PENDING |
| CHK-604 | 03-DMARC-RFC7489.md:133 | checkbox | v= not first → parse error | 9 | - | - | PENDING |
| CHK-605 | 03-DMARC-RFC7489.md:134 | checkbox | Invalid p= value → parse error | 9 | - | - | PENDING |
| CHK-606 | 03-DMARC-RFC7489.md:138 | checkbox | `sp=` — subdomain policy (defaults to `p` value if absent) | 9 | - | - | PENDING |
| CHK-607 | 03-DMARC-RFC7489.md:139 | checkbox | `np=` — non-existent subdomain policy (RFC 9091). Optional field, no default. | 9 | - | - | PENDING |
| CHK-608 | 03-DMARC-RFC7489.md:140 | checkbox | `adkim=` — DKIM alignment: "r" (relaxed, default) or "s" (strict) | 9 | - | - | PENDING |
| CHK-609 | 03-DMARC-RFC7489.md:141 | checkbox | `aspf=` — SPF alignment: "r" (relaxed, default) or "s" (strict) | 9 | - | - | PENDING |
| CHK-610 | 03-DMARC-RFC7489.md:142 | checkbox | `pct=` — percentage 0-100, default 100. Values >100 clamped to 100, <0 clamped to 0. Non-numeric → use default. | 9 | - | - | PENDING |
| CHK-611 | 03-DMARC-RFC7489.md:143 | checkbox | `fo=` — failure options, colon-separated. Default: "0". Parse into `Vec<FailureOption>`, unknown options ignored. | 9 | - | - | PENDING |
| CHK-612 | 03-DMARC-RFC7489.md:144 | checkbox | `rf=` — report format. Default: "afrf". Parse into enum. | 9 | - | - | PENDING |
| CHK-613 | 03-DMARC-RFC7489.md:145 | checkbox | `ri=` — report interval in seconds. Default: 86400. Non-numeric → use default. | 9 | - | - | PENDING |
| CHK-614 | 03-DMARC-RFC7489.md:146 | checkbox | `rua=` — aggregate report URIs, comma-separated. Parse into `Vec<ReportUri>`. | 9 | - | - | PENDING |
| CHK-615 | 03-DMARC-RFC7489.md:147 | checkbox | `ruf=` — failure report URIs, comma-separated. Parse into `Vec<ReportUri>`. | 9 | - | - | PENDING |
| CHK-616 | 03-DMARC-RFC7489.md:148 | checkbox | Unknown tags: ignore (forward compatibility) | 9 | - | - | PENDING |
| CHK-617 | 03-DMARC-RFC7489.md:152 | checkbox | Format: `mailto:address` or `mailto:address!size` or `mailto:address!size_unit` | 9 | - | - | PENDING |
| CHK-618 | 03-DMARC-RFC7489.md:153 | checkbox | Only "mailto:" scheme accepted. Non-mailto URIs → parse error. | 9 | - | - | PENDING |
| CHK-619 | 03-DMARC-RFC7489.md:154 | checkbox | Size suffix: `!` followed by decimal number + optional unit (k/m/g/t, case-insensitive) | 9 | - | - | PENDING |
| CHK-620 | 03-DMARC-RFC7489.md:155 | checkbox | No unit → raw bytes | 9 | - | - | PENDING |
| CHK-621 | 03-DMARC-RFC7489.md:156 | checkbox | Multiple URIs: comma-separated | 9 | - | - | PENDING |
| CHK-622 | 03-DMARC-RFC7489.md:160 | checkbox | Duplicate p= → use first value (per RFC 7489 §6.3) | 9 | - | - | PENDING |
| CHK-623 | 03-DMARC-RFC7489.md:161 | checkbox | Other duplicate tags: implementation may use first or last. Be consistent. | 9 | - | - | PENDING |
| CHK-624 | 03-DMARC-RFC7489.md:169 | checkbox | For each DKIM result that is `Pass`: | 10 | - | - | PENDING |
| CHK-625 | 03-DMARC-RFC7489.md:170 | checkbox | Get the `d=` domain from the DKIM signature | 10 | - | - | PENDING |
| CHK-626 | 03-DMARC-RFC7489.md:171 | checkbox | Compare with RFC5322.From domain | 10 | - | - | PENDING |
| CHK-627 | 03-DMARC-RFC7489.md:172 | checkbox | Strict mode: exact match required (case-insensitive, normalize trailing dots) | 10 | - | - | PENDING |
| CHK-628 | 03-DMARC-RFC7489.md:173 | checkbox | Relaxed mode: `organizational_domain(dkim_d)` == `organizational_domain(from_domain)` | 10 | - | - | PENDING |
| CHK-629 | 03-DMARC-RFC7489.md:174 | checkbox | If ANY DKIM signature both passes AND aligns: DKIM alignment passes | 10 | - | - | PENDING |
| CHK-630 | 03-DMARC-RFC7489.md:178 | checkbox | SPF must have resulted in `Pass` (not SoftFail, not Neutral) | 10 | - | - | PENDING |
| CHK-631 | 03-DMARC-RFC7489.md:179 | checkbox | SPF authenticated domain = MAIL FROM domain (or HELO if MAIL FROM empty) | 10 | - | - | PENDING |
| CHK-632 | 03-DMARC-RFC7489.md:180 | checkbox | Compare authenticated domain with RFC5322.From domain | 10 | - | - | PENDING |
| CHK-633 | 03-DMARC-RFC7489.md:181 | checkbox | Strict mode: exact match required | 10 | - | - | PENDING |
| CHK-634 | 03-DMARC-RFC7489.md:182 | checkbox | Relaxed mode: organizational domain match | 10 | - | - | PENDING |
| CHK-635 | 03-DMARC-RFC7489.md:183 | checkbox | SPF must pass AND align for SPF alignment to pass | 10 | - | - | PENDING |
| CHK-636 | 03-DMARC-RFC7489.md:216 | checkbox | DKIM alignment passes, OR | 10 | - | - | PENDING |
| CHK-637 | 03-DMARC-RFC7489.md:217 | checkbox | SPF alignment passes | 10 | - | - | PENDING |
| CHK-638 | 03-DMARC-RFC7489.md:218 | checkbox | Only ONE needs to pass (OR logic) | 10 | - | - | PENDING |
| CHK-639 | 03-DMARC-RFC7489.md:222 | checkbox | If From domain equals organizational domain: use `p=` (organizational domain policy) | 10 | - | - | PENDING |
| CHK-640 | 03-DMARC-RFC7489.md:223 | checkbox | If From domain is a subdomain: | 10 | - | - | PENDING |
| CHK-641 | 03-DMARC-RFC7489.md:224 | checkbox | Check if subdomain is non-existent (see §5.4) | 10 | - | - | PENDING |
| CHK-642 | 03-DMARC-RFC7489.md:225 | checkbox | If non-existent: use `np=` if present, else fall back to `sp=`, else fall back to `p=` | 10 | - | - | PENDING |
| CHK-643 | 03-DMARC-RFC7489.md:226 | checkbox | If existing subdomain: use `sp=` (which defaults to `p=` if absent in record) | 10 | - | - | PENDING |
| CHK-644 | 03-DMARC-RFC7489.md:227 | checkbox | Fallback chain: `np=` → `sp=` → `p=` | 10 | - | - | PENDING |
| CHK-645 | 03-DMARC-RFC7489.md:231 | checkbox | Query DNS for the From domain: A, AAAA, and MX records | 10 | - | - | PENDING |
| CHK-646 | 03-DMARC-RFC7489.md:232 | checkbox | If ALL THREE return NxDomain → domain is non-existent | 10 | - | - | PENDING |
| CHK-647 | 03-DMARC-RFC7489.md:233 | checkbox | Any other result (even empty records) → domain exists | 10 | - | - | PENDING |
| CHK-648 | 03-DMARC-RFC7489.md:234 | checkbox | **Performance**: parallelize these 3 DNS queries with `tokio::join!` — they are independent | 10 | - | - | PENDING |
| CHK-649 | 03-DMARC-RFC7489.md:238 | checkbox | If `pct` < 100: | 10 | - | - | PENDING |
| CHK-650 | 03-DMARC-RFC7489.md:239 | checkbox | Generate random value 0-99 | 10 | - | - | PENDING |
| CHK-651 | 03-DMARC-RFC7489.md:240 | checkbox | If value < pct: apply the policy (quarantine/reject) | 10 | - | - | PENDING |
| CHK-652 | 03-DMARC-RFC7489.md:241 | checkbox | If value >= pct: disposition = None (monitoring mode, policy not enforced) | 10 | - | - | PENDING |
| CHK-653 | 03-DMARC-RFC7489.md:242 | checkbox | pct=100: always apply policy (no sampling) | 10 | - | - | PENDING |
| CHK-654 | 03-DMARC-RFC7489.md:243 | checkbox | pct=0: never apply policy (all monitoring) | 10 | - | - | PENDING |
| CHK-655 | 03-DMARC-RFC7489.md:244 | checkbox | Use `rand` crate for randomness | 10 | - | - | PENDING |
| CHK-656 | 03-DMARC-RFC7489.md:245 | checkbox | For testing: provide internal method that accepts deterministic roll value | 10 | - | - | PENDING |
| CHK-657 | 03-DMARC-RFC7489.md:311 | checkbox | Define `AggregateReport` struct per RFC 7489 Appendix C XML schema: | 11 | - | - | PENDING |
| CHK-658 | 03-DMARC-RFC7489.md:312 | checkbox | Report metadata: org_name, email, report_id, date_range (begin/end timestamps) | 11 | - | - | PENDING |
| CHK-659 | 03-DMARC-RFC7489.md:313 | checkbox | Policy published: domain, adkim, aspf, p, sp, pct | 11 | - | - | PENDING |
| CHK-660 | 03-DMARC-RFC7489.md:314 | checkbox | Records: source_ip, count, disposition, dkim results, spf results | 11 | - | - | PENDING |
| CHK-661 | 03-DMARC-RFC7489.md:315 | checkbox | XML serialization matching the DMARC aggregate report schema | 11 | - | - | PENDING |
| CHK-662 | 03-DMARC-RFC7489.md:316 | checkbox | `AggregateReportBuilder` — accumulates authentication results, produces XML | 11 | - | - | PENDING |
| CHK-663 | 03-DMARC-RFC7489.md:317 | checkbox | External report URI verification: query `<target-domain>._report._dmarc.<sender-domain>` TXT for `v=DMARC1` authorization | 11 | - | - | PENDING |
| CHK-664 | 03-DMARC-RFC7489.md:318 | checkbox | If target domain differs from sender domain, verify authorization before including URI | 11 | - | - | PENDING |
| CHK-665 | 03-DMARC-RFC7489.md:319 | checkbox | If `_report._dmarc` query fails or returns no `v=DMARC1` record → drop that report URI | 11 | - | - | PENDING |
| CHK-666 | 03-DMARC-RFC7489.md:323 | checkbox | Define `FailureReport` struct per RFC 6591 (AFRF): | 11 | - | - | PENDING |
| CHK-667 | 03-DMARC-RFC7489.md:324 | checkbox | Original headers (or relevant subset) | 11 | - | - | PENDING |
| CHK-668 | 03-DMARC-RFC7489.md:325 | checkbox | Authentication failure details | 11 | - | - | PENDING |
| CHK-669 | 03-DMARC-RFC7489.md:326 | checkbox | Feedback type: "auth-failure" | 11 | - | - | PENDING |
| CHK-670 | 03-DMARC-RFC7489.md:327 | checkbox | AFRF message generation (MIME multipart/report with message/feedback-report) | 11 | - | - | PENDING |
| CHK-671 | 03-DMARC-RFC7489.md:328 | checkbox | Failure option filtering: check `fo=` tag to determine which failures trigger reports | 11 | - | - | PENDING |
| CHK-672 | 03-DMARC-RFC7489.md:329 | checkbox | `fo=0` (default): report only when ALL mechanisms fail to produce aligned pass | 11 | - | - | PENDING |
| CHK-673 | 03-DMARC-RFC7489.md:330 | checkbox | `fo=1`: report when ANY mechanism fails to produce aligned pass | 11 | - | - | PENDING |
| CHK-674 | 03-DMARC-RFC7489.md:331 | checkbox | `fo=d`: report when DKIM evaluation fails (regardless of SPF) | 11 | - | - | PENDING |
| CHK-675 | 03-DMARC-RFC7489.md:332 | checkbox | `fo=s`: report when SPF evaluation fails (regardless of DKIM) | 11 | - | - | PENDING |
| CHK-676 | 03-DMARC-RFC7489.md:346 | checkbox | Use `psl` crate v2 (v2.1+) | 1 | src/common/domain.rs:44 | 992b713 | DONE |
| CHK-677 | 03-DMARC-RFC7489.md:347 | checkbox | `psl::domain_str(&normalized_domain)` → returns registrable domain (org domain) | 1 | src/common/domain.rs:44 | 992b713 | DONE |
| CHK-678 | 03-DMARC-RFC7489.md:348 | checkbox | The crate embeds a PSL snapshot — no runtime download needed | 1 | src/common/domain.rs:44 | 992b713 | DONE |
| CHK-679 | 03-DMARC-RFC7489.md:349 | checkbox | PSL data freshness: tied to crate publish date. For production, consider periodic crate updates. | 1 | src/common/domain.rs:44 | 992b713 | DONE |
| CHK-680 | 03-DMARC-RFC7489.md:350 | checkbox | Normalize domain before PSL lookup: lowercase, strip trailing dot | 1 | src/common/domain.rs:209 | 992b713 | DONE |
| CHK-681 | 03-DMARC-RFC7489.md:379 | checkbox | Minimal valid: `v=DMARC1; p=none` | 9 | - | - | PENDING |
| CHK-682 | 03-DMARC-RFC7489.md:380 | checkbox | Full record with all tags | 9 | - | - | PENDING |
| CHK-683 | 03-DMARC-RFC7489.md:381 | checkbox | Missing `v=` → error | 9 | - | - | PENDING |
| CHK-684 | 03-DMARC-RFC7489.md:382 | checkbox | `v=` not first tag → error | 9 | - | - | PENDING |
| CHK-685 | 03-DMARC-RFC7489.md:383 | checkbox | Invalid `p=` value → error | 9 | - | - | PENDING |
| CHK-686 | 03-DMARC-RFC7489.md:384 | checkbox | Unknown tags → ignored | 9 | - | - | PENDING |
| CHK-687 | 03-DMARC-RFC7489.md:385 | checkbox | Case insensitivity: `v=dmarc1; p=Quarantine` → valid | 9 | - | - | PENDING |
| CHK-688 | 03-DMARC-RFC7489.md:386 | checkbox | URI parsing with size limits (k, m, g, t units, bare bytes) | 9 | - | - | PENDING |
| CHK-689 | 03-DMARC-RFC7489.md:387 | checkbox | Multiple URIs in rua | 9 | - | - | PENDING |
| CHK-690 | 03-DMARC-RFC7489.md:388 | checkbox | Non-mailto URI → error | 9 | - | - | PENDING |
| CHK-691 | 03-DMARC-RFC7489.md:389 | checkbox | Trailing semicolons → valid | 9 | - | - | PENDING |
| CHK-692 | 03-DMARC-RFC7489.md:390 | checkbox | Whitespace variations → valid | 9 | - | - | PENDING |
| CHK-693 | 03-DMARC-RFC7489.md:391 | checkbox | No semicolons: `v=DMARC1;p=none;pct=75` → valid | 9 | - | - | PENDING |
| CHK-694 | 03-DMARC-RFC7489.md:392 | checkbox | Duplicate p= → first wins | 9 | - | - | PENDING |
| CHK-695 | 03-DMARC-RFC7489.md:393 | checkbox | pct > 100 → clamped to 100 | 9 | - | - | PENDING |
| CHK-696 | 03-DMARC-RFC7489.md:394 | checkbox | pct < 0 → clamped to 0 | 9 | - | - | PENDING |
| CHK-697 | 03-DMARC-RFC7489.md:395 | checkbox | pct non-numeric → default 100 | 9 | - | - | PENDING |
| CHK-698 | 03-DMARC-RFC7489.md:396 | checkbox | fo= with multiple options: `fo=0:1:d:s` | 9 | - | - | PENDING |
| CHK-699 | 03-DMARC-RFC7489.md:397 | checkbox | fo= with unknown options → unknown ignored | 9 | - | - | PENDING |
| CHK-700 | 03-DMARC-RFC7489.md:398 | checkbox | np= parsing (RFC 9091) | 9 | - | - | PENDING |
| CHK-701 | 03-DMARC-RFC7489.md:399 | checkbox | sp= defaults to p= when absent | 9 | - | - | PENDING |
| CHK-702 | 03-DMARC-RFC7489.md:400 | checkbox | ri= parsing, non-numeric → default | 9 | - | - | PENDING |
| CHK-703 | 03-DMARC-RFC7489.md:404 | checkbox | Strict DKIM alignment: exact match passes | 10 | - | - | PENDING |
| CHK-704 | 03-DMARC-RFC7489.md:405 | checkbox | Strict DKIM alignment: subdomain fails | 10 | - | - | PENDING |
| CHK-705 | 03-DMARC-RFC7489.md:406 | checkbox | Relaxed DKIM alignment: subdomain passes (org domain matches) | 10 | - | - | PENDING |
| CHK-706 | 03-DMARC-RFC7489.md:407 | checkbox | Relaxed DKIM alignment: different org domain fails | 10 | - | - | PENDING |
| CHK-707 | 03-DMARC-RFC7489.md:408 | checkbox | Strict SPF alignment: exact match passes | 10 | - | - | PENDING |
| CHK-708 | 03-DMARC-RFC7489.md:409 | checkbox | Relaxed SPF alignment: subdomain passes | 10 | - | - | PENDING |
| CHK-709 | 03-DMARC-RFC7489.md:410 | checkbox | SPF SoftFail does NOT produce alignment (must be Pass) | 10 | - | - | PENDING |
| CHK-710 | 03-DMARC-RFC7489.md:411 | checkbox | Misaligned both → DMARC fails | 10 | - | - | PENDING |
| CHK-711 | 03-DMARC-RFC7489.md:415 | checkbox | No DMARC record: disposition=None | 10 | - | - | PENDING |
| CHK-712 | 03-DMARC-RFC7489.md:416 | checkbox | DNS TempFail during discovery: disposition=TempFail (NOT None) | 10 | - | - | PENDING |
| CHK-713 | 03-DMARC-RFC7489.md:417 | checkbox | DKIM passes and aligns: Pass | 10 | - | - | PENDING |
| CHK-714 | 03-DMARC-RFC7489.md:418 | checkbox | SPF passes and aligns: Pass | 10 | - | - | PENDING |
| CHK-715 | 03-DMARC-RFC7489.md:419 | checkbox | Both pass and align: Pass | 10 | - | - | PENDING |
| CHK-716 | 03-DMARC-RFC7489.md:420 | checkbox | DKIM passes, not aligned + SPF fails: apply policy | 10 | - | - | PENDING |
| CHK-717 | 03-DMARC-RFC7489.md:421 | checkbox | Policy=none: disposition=None (monitoring) | 10 | - | - | PENDING |
| CHK-718 | 03-DMARC-RFC7489.md:422 | checkbox | Policy=quarantine: disposition=Quarantine | 10 | - | - | PENDING |
| CHK-719 | 03-DMARC-RFC7489.md:423 | checkbox | Policy=reject: disposition=Reject | 10 | - | - | PENDING |
| CHK-720 | 03-DMARC-RFC7489.md:424 | checkbox | Subdomain policy different from parent (sp= test) | 10 | - | - | PENDING |
| CHK-721 | 03-DMARC-RFC7489.md:425 | checkbox | np= tag: non-existent subdomain uses np policy | 10 | - | - | PENDING |
| CHK-722 | 03-DMARC-RFC7489.md:426 | checkbox | np= absent, non-existent subdomain: fall back to sp=, then p= | 10 | - | - | PENDING |
| CHK-723 | 03-DMARC-RFC7489.md:427 | checkbox | pct=50: test with deterministic roll — verify both branches | 10 | - | - | PENDING |
| CHK-724 | 03-DMARC-RFC7489.md:428 | checkbox | pct=0: always monitoring | 10 | - | - | PENDING |
| CHK-725 | 03-DMARC-RFC7489.md:429 | checkbox | pct=100: always apply | 10 | - | - | PENDING |
| CHK-726 | 03-DMARC-RFC7489.md:433 | checkbox | `example.com` → `example.com` | 1 | src/common/domain.rs:167 | 992b713 | DONE |
| CHK-727 | 03-DMARC-RFC7489.md:434 | checkbox | `mail.example.com` → `example.com` | 1 | src/common/domain.rs:173 | 992b713 | DONE |
| CHK-728 | 03-DMARC-RFC7489.md:435 | checkbox | `foo.bar.example.com` → `example.com` | 1 | src/common/domain.rs:179 | 992b713 | DONE |
| CHK-729 | 03-DMARC-RFC7489.md:436 | checkbox | `example.co.uk` → `example.co.uk` | 1 | src/common/domain.rs:185 | 992b713 | DONE |
| CHK-730 | 03-DMARC-RFC7489.md:437 | checkbox | `mail.example.co.uk` → `example.co.uk` | 1 | src/common/domain.rs:191 | 992b713 | DONE |
| CHK-731 | 03-DMARC-RFC7489.md:438 | checkbox | `foo.bar.co.uk` → `bar.co.uk` | 1 | src/common/domain.rs:197 | 992b713 | DONE |
| CHK-732 | 03-DMARC-RFC7489.md:439 | checkbox | Deep subdomain: `a.b.c.example.com` → `example.com` | 1 | src/common/domain.rs:203 | 992b713 | DONE |
| CHK-733 | 03-DMARC-RFC7489.md:444 | checkbox | Build aggregate report with AggregateReportBuilder → serialize to XML → verify XML structure matches RFC 7489 Appendix C schema | 11 | - | - | PENDING |
| CHK-734 | 03-DMARC-RFC7489.md:445 | checkbox | Report metadata: org_name, email, report_id, date_range present in XML | 11 | - | - | PENDING |
| CHK-735 | 03-DMARC-RFC7489.md:446 | checkbox | Policy published: domain, adkim, aspf, p, sp, pct fields in XML | 11 | - | - | PENDING |
| CHK-736 | 03-DMARC-RFC7489.md:447 | checkbox | Multiple records: add 3 auth results, verify 3 `<record>` elements in output | 11 | - | - | PENDING |
| CHK-737 | 03-DMARC-RFC7489.md:448 | checkbox | Empty report (no records): valid XML with zero records | 11 | - | - | PENDING |
| CHK-738 | 03-DMARC-RFC7489.md:451 | checkbox | Same domain (sender=example.com, rua=mailto:dmarc@example.com): no `_report._dmarc` query needed | 11 | - | - | PENDING |
| CHK-739 | 03-DMARC-RFC7489.md:452 | checkbox | Cross-domain (sender=example.com, rua=mailto:reports@thirdparty.com): query `example.com._report._dmarc.thirdparty.com` TXT → `v=DMARC1` → authorized | 11 | - | - | PENDING |
| CHK-740 | 03-DMARC-RFC7489.md:453 | checkbox | Cross-domain without authorization record → URI dropped | 11 | - | - | PENDING |
| CHK-741 | 03-DMARC-RFC7489.md:454 | checkbox | Cross-domain with TempFail on `_report._dmarc` query → URI dropped (safe default) | 11 | - | - | PENDING |
| CHK-742 | 03-DMARC-RFC7489.md:457 | checkbox | Failure report AFRF format: verify output contains `Feedback-Type: auth-failure` | 11 | - | - | PENDING |
| CHK-743 | 03-DMARC-RFC7489.md:458 | checkbox | fo=0 (default): both SPF and DKIM fail → generate report | 11 | - | - | PENDING |
| CHK-744 | 03-DMARC-RFC7489.md:459 | checkbox | fo=0: SPF fails but DKIM aligns → NO report (not all mechanisms failed) | 11 | - | - | PENDING |
| CHK-745 | 03-DMARC-RFC7489.md:460 | checkbox | fo=1: SPF fails but DKIM aligns → generate report (any mechanism failed) | 11 | - | - | PENDING |
| CHK-746 | 03-DMARC-RFC7489.md:461 | checkbox | fo=d: DKIM fails → generate report (regardless of SPF result) | 11 | - | - | PENDING |
| CHK-747 | 03-DMARC-RFC7489.md:462 | checkbox | fo=d: DKIM passes, SPF fails → NO report (fo=d only triggers on DKIM failure) | 11 | - | - | PENDING |
| CHK-748 | 03-DMARC-RFC7489.md:463 | checkbox | fo=s: SPF fails → generate report (regardless of DKIM result) | 11 | - | - | PENDING |
| CHK-749 | 03-DMARC-RFC7489.md:464 | checkbox | fo=s: SPF passes, DKIM fails → NO report | 11 | - | - | PENDING |
| CHK-750 | 03-DMARC-RFC7489.md:470 | checkbox | DMARC DNS TempFail → TempFail disposition (NEVER treat as "no policy") | 10 | - | - | PENDING |
| CHK-751 | 03-DMARC-RFC7489.md:471 | checkbox | Validate all DNS responses — handle NxDomain vs empty vs TempFail distinctly | 10 | - | - | PENDING |
| CHK-752 | 03-DMARC-RFC7489.md:472 | checkbox | Handle oversized records gracefully (truncate parsing, don't crash) | 10 | - | - | PENDING |
| CHK-753 | 03-DMARC-RFC7489.md:473 | checkbox | l= body length in DKIM: accept but note security concern (body truncation attacks) | 10 | - | - | PENDING |
| CHK-754 | 03-DMARC-RFC7489.md:474 | checkbox | Rate limiting DNS queries: caller responsibility (document this) | 10 | - | - | PENDING |
| CHK-755 | 03-DMARC-RFC7489.md:480 | checkbox | SPF module (from this crate) | 10 | - | - | PENDING |
| CHK-756 | 03-DMARC-RFC7489.md:481 | checkbox | DKIM module (from this crate) | 10 | - | - | PENDING |
| CHK-757 | 03-DMARC-RFC7489.md:482 | checkbox | Public Suffix List: `psl` crate v2 | 1 | Cargo.toml:20 | 992b713 | DONE |
| CHK-758 | 03-DMARC-RFC7489.md:483 | checkbox | DNS resolver: shared with SPF/DKIM via DnsResolver trait | 1 | src/common/dns.rs:39 | 992b713 | DONE |
| CHK-759 | 03-DMARC-RFC7489.md:484 | checkbox | Random: `rand` crate for pct sampling | 1 | Cargo.toml:26 | 992b713 | DONE |
| CHK-760 | 03-DMARC-RFC7489.md:590 | checkbox | DMARC record parsing complete with all tags (including np= from RFC 9091) | 9 | - | - | PENDING |
| CHK-761 | 03-DMARC-RFC7489.md:591 | checkbox | All parsed fields are structured types (enums, not raw strings) | 9 | - | - | PENDING |
| CHK-762 | 03-DMARC-RFC7489.md:592 | checkbox | DNS discovery with fallback to organizational domain | 10 | - | - | PENDING |
| CHK-763 | 03-DMARC-RFC7489.md:593 | checkbox | DNS TempFail during discovery → TempFail disposition (NOT None) | 10 | - | - | PENDING |
| CHK-764 | 03-DMARC-RFC7489.md:594 | checkbox | Public Suffix List integration via psl crate | 10 | - | - | PENDING |
| CHK-765 | 03-DMARC-RFC7489.md:595 | checkbox | DKIM alignment implemented (strict and relaxed) | 10 | - | - | PENDING |
| CHK-766 | 03-DMARC-RFC7489.md:596 | checkbox | SPF alignment implemented (strict and relaxed, requires SPF Pass) | 10 | - | - | PENDING |
| CHK-767 | 03-DMARC-RFC7489.md:597 | checkbox | Policy selection logic: p= / sp= / np= with fallback chain | 10 | - | - | PENDING |
| CHK-768 | 03-DMARC-RFC7489.md:598 | checkbox | Non-existent subdomain detection (A + AAAA + MX queries, parallelized) | 10 | - | - | PENDING |
| CHK-769 | 03-DMARC-RFC7489.md:599 | checkbox | Percentage sampling with deterministic testing support | 10 | - | - | PENDING |
| CHK-770 | 03-DMARC-RFC7489.md:600 | checkbox | DmarcResult is structured (disposition, alignment bools, policy, record) | 10 | - | - | PENDING |
| CHK-771 | 03-DMARC-RFC7489.md:601 | checkbox | Combined EmailAuthenticator with From extraction | 17 | - | - | PENDING |
| CHK-772 | 03-DMARC-RFC7489.md:602 | checkbox | Unit tests cover: parsing, alignment, policy, org domain, discovery, TempFail | 10 | - | - | PENDING |
| CHK-773 | 03-DMARC-RFC7489.md:603 | checkbox | No unwrap/expect in library code (tests only) | 10 | - | - | PENDING |
| CHK-774 | 04-ARC-RFC8617.md:19 | checkbox | `ArcAuthenticationResults` (AAR) — authentication snapshot on arrival | 12 | - | - | PENDING |
| CHK-775 | 04-ARC-RFC8617.md:20 | checkbox | `ArcMessageSignature` (AMS) — DKIM-like signature over message headers+body | 12 | - | - | PENDING |
| CHK-776 | 04-ARC-RFC8617.md:21 | checkbox | `ArcSeal` (AS) — signature over ARC headers only, seals the chain | 12 | - | - | PENDING |
| CHK-777 | 04-ARC-RFC8617.md:34 | checkbox | `instance: u32` — i= tag (required, 1-50) | 12 | - | - | PENDING |
| CHK-778 | 04-ARC-RFC8617.md:35 | checkbox | `payload: String` — RFC 8601 Authentication-Results content | 12 | - | - | PENDING |
| CHK-779 | 04-ARC-RFC8617.md:36 | checkbox | Format: `ARC-Authentication-Results: i=<N>; <authres-payload>` | 12 | - | - | PENDING |
| CHK-780 | 04-ARC-RFC8617.md:40 | checkbox | `instance: u32` — i= tag (required, NOT the DKIM AUID) | 12 | - | - | PENDING |
| CHK-781 | 04-ARC-RFC8617.md:41 | checkbox | `algorithm: Algorithm` — a= tag (rsa-sha256 primary) | 12 | - | - | PENDING |
| CHK-782 | 04-ARC-RFC8617.md:42 | checkbox | `signature: Vec<u8>` — b= tag (base64) | 12 | - | - | PENDING |
| CHK-783 | 04-ARC-RFC8617.md:43 | checkbox | `body_hash: Vec<u8>` — bh= tag (base64) | 12 | - | - | PENDING |
| CHK-784 | 04-ARC-RFC8617.md:44 | checkbox | `domain: String` — d= tag | 12 | - | - | PENDING |
| CHK-785 | 04-ARC-RFC8617.md:45 | checkbox | `selector: String` — s= tag | 12 | - | - | PENDING |
| CHK-786 | 04-ARC-RFC8617.md:46 | checkbox | `signed_headers: Vec<String>` — h= tag (colon-separated) | 12 | - | - | PENDING |
| CHK-787 | 04-ARC-RFC8617.md:47 | checkbox | `canonicalization: (CanonicalizationMethod, CanonicalizationMethod)` — c= tag | 12 | - | - | PENDING |
| CHK-788 | 04-ARC-RFC8617.md:48 | checkbox | `timestamp: Option<u64>` — t= tag | 12 | - | - | PENDING |
| CHK-789 | 04-ARC-RFC8617.md:49 | checkbox | `body_length: Option<u64>` — l= tag | 12 | - | - | PENDING |
| CHK-790 | 04-ARC-RFC8617.md:50 | checkbox | **NO v= tag** (unlike DKIM-Signature) | 12 | - | - | PENDING |
| CHK-791 | 04-ARC-RFC8617.md:51 | checkbox | h= MUST NOT include Authentication-Results or ARC-* headers | 12 | - | - | PENDING |
| CHK-792 | 04-ARC-RFC8617.md:52 | checkbox | h= SHOULD include existing DKIM-Signature headers | 12 | - | - | PENDING |
| CHK-793 | 04-ARC-RFC8617.md:56 | checkbox | `instance: u32` — i= tag (required) | 12 | - | - | PENDING |
| CHK-794 | 04-ARC-RFC8617.md:57 | checkbox | `cv: ChainValidationStatus` — cv= tag (required: "none", "pass", "fail") | 12 | - | - | PENDING |
| CHK-795 | 04-ARC-RFC8617.md:58 | checkbox | `algorithm: Algorithm` — a= tag | 12 | - | - | PENDING |
| CHK-796 | 04-ARC-RFC8617.md:59 | checkbox | `signature: Vec<u8>` — b= tag (base64) | 12 | - | - | PENDING |
| CHK-797 | 04-ARC-RFC8617.md:60 | checkbox | `domain: String` — d= tag | 12 | - | - | PENDING |
| CHK-798 | 04-ARC-RFC8617.md:61 | checkbox | `selector: String` — s= tag | 12 | - | - | PENDING |
| CHK-799 | 04-ARC-RFC8617.md:62 | checkbox | `timestamp: Option<u64>` — t= tag | 12 | - | - | PENDING |
| CHK-800 | 04-ARC-RFC8617.md:63 | checkbox | **Allowed tags ONLY: i, cv, a, b, d, s, t** | 12 | - | - | PENDING |
| CHK-801 | 04-ARC-RFC8617.md:64 | checkbox | h= tag present → MUST fail validation | 12 | - | - | PENDING |
| CHK-802 | 04-ARC-RFC8617.md:65 | checkbox | **NO body hash** — AS does not cover message body | 12 | - | - | PENDING |
| CHK-803 | 04-ARC-RFC8617.md:66 | checkbox | **ONLY relaxed header canonicalization** — no body canonicalization | 12 | - | - | PENDING |
| CHK-804 | 04-ARC-RFC8617.md:99 | checkbox | Collect all ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal headers | 12 | - | - | PENDING |
| CHK-805 | 04-ARC-RFC8617.md:100 | checkbox | Group by instance number (i= tag) | 12 | - | - | PENDING |
| CHK-806 | 04-ARC-RFC8617.md:101 | checkbox | Each instance MUST have exactly one of each header type | 12 | - | - | PENDING |
| CHK-807 | 04-ARC-RFC8617.md:102 | checkbox | Maximum 50 ARC Sets (exceeding → Fail) | 12 | - | - | PENDING |
| CHK-808 | 04-ARC-RFC8617.md:103 | checkbox | Instance values MUST form continuous sequence 1..N (no gaps, no duplicates) | 12 | - | - | PENDING |
| CHK-809 | 04-ARC-RFC8617.md:107 | checkbox | AMS: same tag=value format as DKIM-Signature (reuse `parse_tags`) | 12 | - | - | PENDING |
| CHK-810 | 04-ARC-RFC8617.md:108 | checkbox | AS: same tag=value format but restricted tag set | 12 | - | - | PENDING |
| CHK-811 | 04-ARC-RFC8617.md:109 | checkbox | AAR: `i=<N>; <authres-payload>` — parse instance, rest is opaque | 12 | - | - | PENDING |
| CHK-812 | 04-ARC-RFC8617.md:113 | checkbox | AMS required: i, a, b, bh, d, s, h | 12 | - | - | PENDING |
| CHK-813 | 04-ARC-RFC8617.md:114 | checkbox | AMS optional: c, t, l | 12 | - | - | PENDING |
| CHK-814 | 04-ARC-RFC8617.md:115 | checkbox | AS required: i, cv, a, b, d, s | 12 | - | - | PENDING |
| CHK-815 | 04-ARC-RFC8617.md:116 | checkbox | AS optional: t | 12 | - | - | PENDING |
| CHK-816 | 04-ARC-RFC8617.md:117 | checkbox | AAR required: i | 12 | - | - | PENDING |
| CHK-817 | 04-ARC-RFC8617.md:121 | checkbox | Missing required tag | 12 | - | - | PENDING |
| CHK-818 | 04-ARC-RFC8617.md:122 | checkbox | Duplicate tag | 12 | - | - | PENDING |
| CHK-819 | 04-ARC-RFC8617.md:123 | checkbox | Instance number outside 1-50 | 12 | - | - | PENDING |
| CHK-820 | 04-ARC-RFC8617.md:124 | checkbox | Malformed base64 (b=, bh=) | 12 | - | - | PENDING |
| CHK-821 | 04-ARC-RFC8617.md:125 | checkbox | Unknown algorithm | 12 | - | - | PENDING |
| CHK-822 | 04-ARC-RFC8617.md:126 | checkbox | AS header with h= tag present | 12 | - | - | PENDING |
| CHK-823 | 04-ARC-RFC8617.md:127 | checkbox | Multiple headers with same instance and type | 12 | - | - | PENDING |
| CHK-824 | 04-ARC-RFC8617.md:128 | checkbox | Instance gaps (e.g., 1, 2, 4 — missing 3) | 12 | - | - | PENDING |
| CHK-825 | 04-ARC-RFC8617.md:138 | checkbox | If none exist → status="none", STOP | 12 | - | - | PENDING |
| CHK-826 | 04-ARC-RFC8617.md:139 | checkbox | If >50 sets → status="fail", STOP | 12 | - | - | PENDING |
| CHK-827 | 04-ARC-RFC8617.md:140 | checkbox | Let N = highest instance value | 12 | - | - | PENDING |
| CHK-828 | 04-ARC-RFC8617.md:144 | checkbox | If AS(N) has cv=fail → status="fail", STOP | 12 | - | - | PENDING |
| CHK-829 | 04-ARC-RFC8617.md:148 | checkbox | Each ARC Set has exactly one AAR, AMS, AS | 12 | - | - | PENDING |
| CHK-830 | 04-ARC-RFC8617.md:149 | checkbox | Instances form continuous 1..N | 12 | - | - | PENDING |
| CHK-831 | 04-ARC-RFC8617.md:150 | checkbox | Instance 1: cv=none | 12 | - | - | PENDING |
| CHK-832 | 04-ARC-RFC8617.md:151 | checkbox | Instance >1: cv=pass (not "fail" or "none") | 12 | - | - | PENDING |
| CHK-833 | 04-ARC-RFC8617.md:152 | checkbox | Any violation → status="fail", STOP | 12 | - | - | PENDING |
| CHK-834 | 04-ARC-RFC8617.md:156 | checkbox | Validate AMS(N) using DKIM verification algorithm (RFC 6376 Section 5) | 12 | - | - | PENDING |
| CHK-835 | 04-ARC-RFC8617.md:157 | checkbox | DNS key lookup at `<selector>._domainkey.<domain>` | 12 | - | - | PENDING |
| CHK-836 | 04-ARC-RFC8617.md:158 | checkbox | If fails → status="fail", STOP | 12 | - | - | PENDING |
| CHK-837 | 04-ARC-RFC8617.md:162 | checkbox | From instance N-1 down to 1: validate each AMS | 12 | - | - | PENDING |
| CHK-838 | 04-ARC-RFC8617.md:163 | checkbox | If instance M fails → oldest-pass = M+1, go to Step 6 | 12 | - | - | PENDING |
| CHK-839 | 04-ARC-RFC8617.md:164 | checkbox | If all pass → oldest-pass = 0 | 12 | - | - | PENDING |
| CHK-840 | 04-ARC-RFC8617.md:168 | checkbox | From instance N down to 1: validate each AS | 12 | - | - | PENDING |
| CHK-841 | 04-ARC-RFC8617.md:169 | checkbox | Build signature input: all ARC headers from instance 1 to i, in order (AAR, AMS, AS per set) | 12 | - | - | PENDING |
| CHK-842 | 04-ARC-RFC8617.md:170 | checkbox | Strip b= from AS being validated | 12 | - | - | PENDING |
| CHK-843 | 04-ARC-RFC8617.md:171 | checkbox | Use **relaxed header canonicalization only** | 12 | - | - | PENDING |
| CHK-844 | 04-ARC-RFC8617.md:172 | checkbox | If any fails → status="fail", STOP | 12 | - | - | PENDING |
| CHK-845 | 04-ARC-RFC8617.md:176 | checkbox | status="pass" | 12 | - | - | PENDING |
| CHK-846 | 04-ARC-RFC8617.md:184 | checkbox | Include ARC Sets 1 through i in increasing order | 12 | - | - | PENDING |
| CHK-847 | 04-ARC-RFC8617.md:185 | checkbox | Within each set, header order: AAR → AMS → AS | 12 | - | - | PENDING |
| CHK-848 | 04-ARC-RFC8617.md:186 | checkbox | Apply relaxed header canonicalization to each | 12 | - | - | PENDING |
| CHK-849 | 04-ARC-RFC8617.md:187 | checkbox | Strip b= value from the AS being validated/signed (same b= stripping as DKIM) | 12 | - | - | PENDING |
| CHK-850 | 04-ARC-RFC8617.md:188 | checkbox | **NO body content** in AS signature input | 12 | - | - | PENDING |
| CHK-851 | 04-ARC-RFC8617.md:189 | checkbox | Last header (the AS being validated) WITHOUT trailing CRLF | 12 | - | - | PENDING |
| CHK-852 | 04-ARC-RFC8617.md:197 | checkbox | Perform ALL message modifications (including DKIM signing) BEFORE sealing | 13 | - | - | PENDING |
| CHK-853 | 04-ARC-RFC8617.md:198 | checkbox | ARC sealing is the LAST operation | 13 | - | - | PENDING |
| CHK-854 | 04-ARC-RFC8617.md:202 | checkbox | If existing chain has highest AS with cv=fail → STOP, do NOT seal | 13 | - | - | PENDING |
| CHK-855 | 04-ARC-RFC8617.md:206 | checkbox | If chain exists: instance = max_existing + 1 | 13 | - | - | PENDING |
| CHK-856 | 04-ARC-RFC8617.md:207 | checkbox | If no chain: instance = 1 | 13 | - | - | PENDING |
| CHK-857 | 04-ARC-RFC8617.md:208 | checkbox | If instance > 50 → STOP, do NOT seal | 13 | - | - | PENDING |
| CHK-858 | 04-ARC-RFC8617.md:212 | checkbox | Validate incoming chain | 13 | - | - | PENDING |
| CHK-859 | 04-ARC-RFC8617.md:213 | checkbox | No chain → cv=none | 13 | - | - | PENDING |
| CHK-860 | 04-ARC-RFC8617.md:214 | checkbox | Validation passed → cv=pass | 13 | - | - | PENDING |
| CHK-861 | 04-ARC-RFC8617.md:215 | checkbox | Validation failed → cv=fail (but Step 2 should have stopped) | 13 | - | - | PENDING |
| CHK-862 | 04-ARC-RFC8617.md:219 | checkbox | `ARC-Authentication-Results: i=<N>; <authservid>; <results>` | 13 | - | - | PENDING |
| CHK-863 | 04-ARC-RFC8617.md:220 | checkbox | Include ALL authentication results from this ADMD (SPF, DKIM, DMARC, ARC) | 13 | - | - | PENDING |
| CHK-864 | 04-ARC-RFC8617.md:224 | checkbox | Compute body hash (same as DKIM) | 13 | - | - | PENDING |
| CHK-865 | 04-ARC-RFC8617.md:225 | checkbox | Select headers for h= tag: | 13 | - | - | PENDING |
| CHK-866 | 04-ARC-RFC8617.md:229 | checkbox | Sign using DKIM algorithm | 13 | - | - | PENDING |
| CHK-867 | 04-ARC-RFC8617.md:230 | checkbox | Format: `ARC-Message-Signature: i=<N>; a=rsa-sha256; c=relaxed/relaxed; d=<d>; s=<s>; h=<h>; bh=<bh>; b=<b>` | 13 | - | - | PENDING |
| CHK-868 | 04-ARC-RFC8617.md:234 | checkbox | Build signature input: ALL ARC Sets (1..N) in order (AAR, AMS, AS per set) | 13 | - | - | PENDING |
| CHK-869 | 04-ARC-RFC8617.md:235 | checkbox | Strip b= from this AS | 13 | - | - | PENDING |
| CHK-870 | 04-ARC-RFC8617.md:236 | checkbox | **Relaxed header canonicalization only** | 13 | - | - | PENDING |
| CHK-871 | 04-ARC-RFC8617.md:237 | checkbox | Sign | 13 | - | - | PENDING |
| CHK-872 | 04-ARC-RFC8617.md:238 | checkbox | Format: `ARC-Seal: i=<N>; cv=<cv>; a=rsa-sha256; d=<d>; s=<s>; b=<b>` | 13 | - | - | PENDING |
| CHK-873 | 04-ARC-RFC8617.md:242 | checkbox | Add AAR, AMS, AS to message | 13 | - | - | PENDING |
| CHK-874 | 04-ARC-RFC8617.md:243 | checkbox | Added at message exit (after all processing) | 13 | - | - | PENDING |
| CHK-875 | 04-ARC-RFC8617.md:312 | checkbox | Valid AAR with instance 1 | 12 | - | - | PENDING |
| CHK-876 | 04-ARC-RFC8617.md:313 | checkbox | Valid AMS with all required tags | 12 | - | - | PENDING |
| CHK-877 | 04-ARC-RFC8617.md:314 | checkbox | Valid AS with cv=none, cv=pass, cv=fail | 12 | - | - | PENDING |
| CHK-878 | 04-ARC-RFC8617.md:315 | checkbox | AS with h= tag → Fail | 12 | - | - | PENDING |
| CHK-879 | 04-ARC-RFC8617.md:316 | checkbox | Missing required tag → Fail | 12 | - | - | PENDING |
| CHK-880 | 04-ARC-RFC8617.md:317 | checkbox | Instance 0 or 51 → Fail | 12 | - | - | PENDING |
| CHK-881 | 04-ARC-RFC8617.md:318 | checkbox | Duplicate tags → Fail | 12 | - | - | PENDING |
| CHK-882 | 04-ARC-RFC8617.md:322 | checkbox | Single ARC Set (i=1, cv=none) → Pass | 12 | - | - | PENDING |
| CHK-883 | 04-ARC-RFC8617.md:323 | checkbox | Three sets (i=1,2,3; cv=none,pass,pass) → Pass | 12 | - | - | PENDING |
| CHK-884 | 04-ARC-RFC8617.md:324 | checkbox | Gap in instances (1,2,4) → Fail | 12 | - | - | PENDING |
| CHK-885 | 04-ARC-RFC8617.md:325 | checkbox | Duplicate instances → Fail | 12 | - | - | PENDING |
| CHK-886 | 04-ARC-RFC8617.md:326 | checkbox | Instance 1 with cv=pass → Fail | 12 | - | - | PENDING |
| CHK-887 | 04-ARC-RFC8617.md:327 | checkbox | Instance 2 with cv=none → Fail | 12 | - | - | PENDING |
| CHK-888 | 04-ARC-RFC8617.md:328 | checkbox | Highest instance cv=fail → Fail immediately | 12 | - | - | PENDING |
| CHK-889 | 04-ARC-RFC8617.md:329 | checkbox | >50 sets → Fail | 12 | - | - | PENDING |
| CHK-890 | 04-ARC-RFC8617.md:330 | checkbox | Most recent AMS fails → Fail | 12 | - | - | PENDING |
| CHK-891 | 04-ARC-RFC8617.md:331 | checkbox | Any AS fails → Fail | 12 | - | - | PENDING |
| CHK-892 | 04-ARC-RFC8617.md:335 | checkbox | Seal with no existing chain → i=1, cv=none | 13 | - | - | PENDING |
| CHK-893 | 04-ARC-RFC8617.md:336 | checkbox | Seal with valid chain (i=2) → i=3, cv=pass | 13 | - | - | PENDING |
| CHK-894 | 04-ARC-RFC8617.md:337 | checkbox | Incoming cv=fail → do not seal | 13 | - | - | PENDING |
| CHK-895 | 04-ARC-RFC8617.md:338 | checkbox | Instance would exceed 50 → do not seal | 13 | - | - | PENDING |
| CHK-896 | 04-ARC-RFC8617.md:339 | checkbox | Verify AS covers all prior ARC Sets | 13 | - | - | PENDING |
| CHK-897 | 04-ARC-RFC8617.md:343 | checkbox | Seal → validate → Pass: `ArcSealer::seal_message()` produces AAR/AMS/AS → prepend to message headers → `ArcVerifier::validate_chain()` returns Pass. **MUST NOT substitute manual ring verification** — the purpose is to test that sealer and verifier agree. | 13 | - | - | PENDING |
| CHK-898 | 04-ARC-RFC8617.md:344 | checkbox | Seal → modify body → validate AMS fails | 13 | - | - | PENDING |
| CHK-899 | 04-ARC-RFC8617.md:345 | checkbox | Seal → tamper ARC header → validate AS fails | 13 | - | - | PENDING |
| CHK-900 | 04-ARC-RFC8617.md:346 | checkbox | Multi-hop: 3 sealers each adding ARC set, final `ArcVerifier::validate_chain()` returns Pass with all 3 sets | 13 | - | - | PENDING |
| CHK-901 | 04-ARC-RFC8617.md:347 | checkbox | Multi-hop body modification: sealer 1 signs, intermediary modifies body, sealer 2 re-signs → validate_chain returns Pass for set 2 AMS but oldest_pass > 1 | 13 | - | - | PENDING |
| CHK-902 | 04-ARC-RFC8617.md:353 | checkbox | Up to 2*N DNS queries for N sets — implement timeouts | 12 | - | - | PENDING |
| CHK-903 | 04-ARC-RFC8617.md:354 | checkbox | ARC conveys authentication assessment, NOT authorization — receivers must maintain trusted sealer lists | 12 | - | - | PENDING |
| CHK-904 | 04-ARC-RFC8617.md:355 | checkbox | cv=fail propagates — once failed, subsequent handlers should not seal with cv=pass | 12 | - | - | PENDING |
| CHK-905 | 04-ARC-RFC8617.md:356 | checkbox | Replay: intact ARC chains can be replayed; ARC does not prevent this | 12 | - | - | PENDING |
| CHK-906 | 04-ARC-RFC8617.md:362 | checkbox | DKIM module (canonicalization, signing, verification, key parsing) | 12 | - | - | PENDING |
| CHK-907 | 04-ARC-RFC8617.md:363 | checkbox | DNS resolver (shared DnsResolver trait) | 12 | - | - | PENDING |
| CHK-908 | 04-ARC-RFC8617.md:364 | checkbox | Crypto: ring 0.17 (RSA-SHA256, same as DKIM) | 12 | - | - | PENDING |
| CHK-909 | 04-ARC-RFC8617.md:365 | checkbox | Base64: base64 0.22 | 12 | - | - | PENDING |
| CHK-910 | 04-ARC-RFC8617.md:409 | checkbox | All three ARC header types parsed (AAR, AMS, AS) | 12 | - | - | PENDING |
| CHK-911 | 04-ARC-RFC8617.md:410 | checkbox | ARC Set grouping by instance with structure validation | 12 | - | - | PENDING |
| CHK-912 | 04-ARC-RFC8617.md:411 | checkbox | Chain validation algorithm (steps 1-7) complete | 12 | - | - | PENDING |
| CHK-913 | 04-ARC-RFC8617.md:412 | checkbox | AMS validation reuses DKIM verification | 12 | - | - | PENDING |
| CHK-914 | 04-ARC-RFC8617.md:413 | checkbox | AS validation with correct signature input ordering | 12 | - | - | PENDING |
| CHK-915 | 04-ARC-RFC8617.md:414 | checkbox | Chain sealing (AAR + AMS + AS generation) | 13 | - | - | PENDING |
| CHK-916 | 04-ARC-RFC8617.md:415 | checkbox | Seal uses DKIM signing primitives | 13 | - | - | PENDING |
| CHK-917 | 04-ARC-RFC8617.md:416 | checkbox | cv= propagation rules enforced | 13 | - | - | PENDING |
| CHK-918 | 04-ARC-RFC8617.md:417 | checkbox | Instance limit (50) enforced | 13 | - | - | PENDING |
| CHK-919 | 04-ARC-RFC8617.md:418 | checkbox | Unit tests cover parsing, validation, sealing, roundtrip | 13 | - | - | PENDING |
| CHK-920 | 05-BIMI.md:27 | checkbox | `v=` — version, MUST be "BIMI1", MUST be first tag | 14 | - | - | PENDING |
| CHK-921 | 05-BIMI.md:28 | checkbox | `l=` — logo URI(s), comma-separated, 1-2 URIs, MUST be HTTPS | 14 | - | - | PENDING |
| CHK-922 | 05-BIMI.md:29 | checkbox | `a=` — authority evidence URI (VMC), MUST be HTTPS if present | 14 | - | - | PENDING |
| CHK-923 | 05-BIMI.md:30 | checkbox | Empty `l=` with no `a=` → declination record (domain opts out) | 14 | - | - | PENDING |
| CHK-924 | 05-BIMI.md:31 | checkbox | Unknown tags → ignored | 14 | - | - | PENDING |
| CHK-925 | 05-BIMI.md:42 | checkbox | Optional header in email, SHOULD be DKIM-signed | 14 | - | - | PENDING |
| CHK-926 | 05-BIMI.md:43 | checkbox | Format: `BIMI-Selector: v=BIMI1; s=<selector>;` | 14 | - | - | PENDING |
| CHK-927 | 05-BIMI.md:73 | checkbox | Query: `<selector>._bimi.<author-domain>` TXT record | 14 | - | - | PENDING |
| CHK-928 | 05-BIMI.md:74 | checkbox | Default selector: "default" | 14 | - | - | PENDING |
| CHK-929 | 05-BIMI.md:75 | checkbox | Custom selector: from BIMI-Selector header s= tag | 14 | - | - | PENDING |
| CHK-930 | 05-BIMI.md:76 | checkbox | If no record at author domain → fallback to `<selector>._bimi.<organizational-domain>` | 14 | - | - | PENDING |
| CHK-931 | 05-BIMI.md:77 | checkbox | Filter: records starting with `v=` | 14 | - | - | PENDING |
| CHK-932 | 05-BIMI.md:78 | checkbox | Exactly one valid record required: parse ALL TXT records, count valid BIMI records, multiple valid → Fail (do NOT silently pick first) | 14 | - | - | PENDING |
| CHK-933 | 05-BIMI.md:82 | checkbox | DMARC result MUST be Pass (disposition == Pass) | 14 | - | - | PENDING |
| CHK-934 | 05-BIMI.md:83 | checkbox | DMARC policy MUST be `quarantine` or `reject` (NOT `none`) | 14 | - | - | PENDING |
| CHK-935 | 05-BIMI.md:84 | checkbox | DMARC pct MUST be 100: access `dmarc_result.record` and verify `record.percent == 100`. pct < 100 → NOT eligible. | 14 | - | - | PENDING |
| CHK-936 | 05-BIMI.md:85 | checkbox | SPF or DKIM alignment: `dmarc_result.dkim_aligned || dmarc_result.spf_aligned` (redundant with Pass disposition but spec-mandated — check explicitly) | 14 | - | - | PENDING |
| CHK-937 | 05-BIMI.md:89 | checkbox | Before BIMI processing, strip any pre-existing `BIMI-Location` and `BIMI-Indicator` headers from the message | 14 | - | - | PENDING |
| CHK-938 | 05-BIMI.md:90 | checkbox | These headers are receiver-only; senders MUST NOT insert them | 14 | - | - | PENDING |
| CHK-939 | 05-BIMI.md:91 | checkbox | If present, treat as potentially malicious and remove before evaluation | 14 | - | - | PENDING |
| CHK-940 | 05-BIMI.md:99 | checkbox | Semicolon-separated tag=value pairs | 14 | - | - | PENDING |
| CHK-941 | 05-BIMI.md:100 | checkbox | First tag MUST be `v=BIMI1` | 14 | - | - | PENDING |
| CHK-942 | 05-BIMI.md:101 | checkbox | `l=` tag: comma-separated URIs, each MUST be HTTPS | 14 | - | - | PENDING |
| CHK-943 | 05-BIMI.md:102 | checkbox | `a=` tag: single HTTPS URI | 14 | - | - | PENDING |
| CHK-944 | 05-BIMI.md:103 | checkbox | Max 2 logo URIs in `l=` | 14 | - | - | PENDING |
| CHK-945 | 05-BIMI.md:104 | checkbox | Unknown tags → ignored | 14 | - | - | PENDING |
| CHK-946 | 05-BIMI.md:108 | checkbox | v= not first → error | 14 | - | - | PENDING |
| CHK-947 | 05-BIMI.md:109 | checkbox | v= not "BIMI1" → error | 14 | - | - | PENDING |
| CHK-948 | 05-BIMI.md:110 | checkbox | Missing l= → error (unless declination) | 14 | - | - | PENDING |
| CHK-949 | 05-BIMI.md:111 | checkbox | Non-HTTPS URI → error | 14 | - | - | PENDING |
| CHK-950 | 05-BIMI.md:112 | checkbox | More than 2 logo URIs → error | 14 | - | - | PENDING |
| CHK-951 | 05-BIMI.md:116 | checkbox | `v=BIMI1;` (empty l=, no a=) → domain explicitly opts out | 14 | - | - | PENDING |
| CHK-952 | 05-BIMI.md:117 | checkbox | Return BimiResult::Declined | 14 | - | - | PENDING |
| CHK-953 | 05-BIMI.md:125 | checkbox | Root element MUST be `<svg>` | 15 | - | - | PENDING |
| CHK-954 | 05-BIMI.md:126 | checkbox | `baseProfile="tiny-ps"` attribute required | 15 | - | - | PENDING |
| CHK-955 | 05-BIMI.md:127 | checkbox | `<title>` element required (max 65 characters) | 15 | - | - | PENDING |
| CHK-956 | 05-BIMI.md:128 | checkbox | Square aspect ratio (1:1) | 15 | - | - | PENDING |
| CHK-957 | 05-BIMI.md:129 | checkbox | viewBox space-delimited (NOT comma-delimited) | 15 | - | - | PENDING |
| CHK-958 | 05-BIMI.md:130 | checkbox | Maximum size: 32KB (32,768 bytes) | 15 | - | - | PENDING |
| CHK-959 | 05-BIMI.md:134 | checkbox | `<script>` — no scripts | 15 | - | - | PENDING |
| CHK-960 | 05-BIMI.md:135 | checkbox | External references (except XML namespace declarations) | 15 | - | - | PENDING |
| CHK-961 | 05-BIMI.md:136 | checkbox | Animations (`<animate>`, `<animateTransform>`, etc.) | 15 | - | - | PENDING |
| CHK-962 | 05-BIMI.md:137 | checkbox | Embedded raster images (`<image>` with base64 PNG/JPG) | 15 | - | - | PENDING |
| CHK-963 | 05-BIMI.md:138 | checkbox | `<!ENTITY>` declarations (XXE prevention) | 15 | - | - | PENDING |
| CHK-964 | 05-BIMI.md:139 | checkbox | `javascript:` URIs | 15 | - | - | PENDING |
| CHK-965 | 05-BIMI.md:143 | checkbox | XML bomb detection (entity expansion depth limit) | 15 | - | - | PENDING |
| CHK-966 | 05-BIMI.md:144 | checkbox | Size limit enforcement before parsing | 15 | - | - | PENDING |
| CHK-967 | 05-BIMI.md:145 | checkbox | No external resource loading | 15 | - | - | PENDING |
| CHK-968 | 05-BIMI.md:153 | checkbox | X.509 certificate with BIMI-specific extensions | 16 | - | - | PENDING |
| CHK-969 | 05-BIMI.md:154 | checkbox | Extended Key Usage OID: `1.3.6.1.5.5.7.3.31` (id-kp-BrandIndicatorforMessageIdentification) | 16 | - | - | PENDING |
| CHK-970 | 05-BIMI.md:155 | checkbox | LogoType extension (RFC 3709): contains SVG as `data:image/svg+xml;base64,<data>` URI | 16 | - | - | PENDING |
| CHK-971 | 05-BIMI.md:156 | checkbox | Subject Alternative Names: `<selector>._bimi.<domain>` DNS names | 16 | - | - | PENDING |
| CHK-972 | 05-BIMI.md:160 | checkbox | Parse PEM certificate chain (VMC first, then issuer chain) | 16 | - | - | PENDING |
| CHK-973 | 05-BIMI.md:161 | checkbox | Validate certificate chain to trusted BIMI root CA | 16 | - | - | PENDING |
| CHK-974 | 05-BIMI.md:162 | checkbox | Check validity period (not expired, not before) | 16 | - | - | PENDING |
| CHK-975 | 05-BIMI.md:163 | checkbox | Check revocation status (CRL) | 16 | - | - | PENDING |
| CHK-976 | 05-BIMI.md:164 | checkbox | Validate EKU contains BIMI OID | 16 | - | - | PENDING |
| CHK-977 | 05-BIMI.md:165 | checkbox | Match SAN to `<selector>._bimi.<author-domain>` | 16 | - | - | PENDING |
| CHK-978 | 05-BIMI.md:166 | checkbox | Extract SVG from LogoType extension | 16 | - | - | PENDING |
| CHK-979 | 05-BIMI.md:167 | checkbox | Validate extracted SVG against SVG Tiny PS profile | 16 | - | - | PENDING |
| CHK-980 | 05-BIMI.md:168 | checkbox | Compare logo hash: DNS-fetched logo MUST match VMC-embedded logo | 16 | - | - | PENDING |
| CHK-981 | 05-BIMI.md:172 | checkbox | PEM encoding required | 16 | - | - | PENDING |
| CHK-982 | 05-BIMI.md:173 | checkbox | Order: VMC → Intermediate CA(s) → optional Root | 16 | - | - | PENDING |
| CHK-983 | 05-BIMI.md:174 | checkbox | Out-of-order → reject | 16 | - | - | PENDING |
| CHK-984 | 05-BIMI.md:175 | checkbox | Duplicate certificates → reject | 16 | - | - | PENDING |
| CHK-985 | 05-BIMI.md:176 | checkbox | Multiple VMCs → reject | 16 | - | - | PENDING |
| CHK-986 | 05-BIMI.md:233 | checkbox | Valid: `v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem;` | 14 | - | - | PENDING |
| CHK-987 | 05-BIMI.md:234 | checkbox | Multiple logo URIs: `l=https://a.com/1.svg,https://a.com/2.svg` | 14 | - | - | PENDING |
| CHK-988 | 05-BIMI.md:235 | checkbox | v= not first → error | 14 | - | - | PENDING |
| CHK-989 | 05-BIMI.md:236 | checkbox | Non-HTTPS URI → error | 14 | - | - | PENDING |
| CHK-990 | 05-BIMI.md:237 | checkbox | Unknown tags → ignored | 14 | - | - | PENDING |
| CHK-991 | 05-BIMI.md:238 | checkbox | Declination: `v=BIMI1;` → Declined | 14 | - | - | PENDING |
| CHK-992 | 05-BIMI.md:239 | checkbox | More than 2 URIs → error | 14 | - | - | PENDING |
| CHK-993 | 05-BIMI.md:243 | checkbox | DMARC pass + quarantine → eligible | 14 | - | - | PENDING |
| CHK-994 | 05-BIMI.md:244 | checkbox | DMARC pass + reject → eligible | 14 | - | - | PENDING |
| CHK-995 | 05-BIMI.md:245 | checkbox | DMARC pass + none → NOT eligible | 14 | - | - | PENDING |
| CHK-996 | 05-BIMI.md:246 | checkbox | DMARC fail → NOT eligible | 14 | - | - | PENDING |
| CHK-997 | 05-BIMI.md:247 | checkbox | pct < 100 → NOT eligible (construct DmarcResult with record.percent=50, verify rejection) | 14 | - | - | PENDING |
| CHK-998 | 05-BIMI.md:248 | checkbox | pct=100 explicit → eligible | 14 | - | - | PENDING |
| CHK-999 | 05-BIMI.md:249 | checkbox | Alignment check: dkim_aligned=true → eligible | 14 | - | - | PENDING |
| CHK-1000 | 05-BIMI.md:250 | checkbox | Alignment check: both dkim_aligned=false and spf_aligned=false → NOT eligible (even if disposition=Pass, which shouldn't normally happen, but defensive) | 14 | - | - | PENDING |
| CHK-1001 | 05-BIMI.md:254 | checkbox | Record at author domain → use it | 14 | - | - | PENDING |
| CHK-1002 | 05-BIMI.md:255 | checkbox | No record at author domain, record at org domain → use fallback | 14 | - | - | PENDING |
| CHK-1003 | 05-BIMI.md:256 | checkbox | No record anywhere → None | 14 | - | - | PENDING |
| CHK-1004 | 05-BIMI.md:257 | checkbox | DNS TempFail → TempError | 14 | - | - | PENDING |
| CHK-1005 | 05-BIMI.md:258 | checkbox | Custom selector via BIMI-Selector header | 14 | - | - | PENDING |
| CHK-1006 | 05-BIMI.md:259 | checkbox | Multiple valid BIMI records at same DNS name → Fail (not first-wins) | 14 | - | - | PENDING |
| CHK-1007 | 05-BIMI.md:260 | checkbox | One valid + one invalid record → use the valid one (invalid silently skipped) | 14 | - | - | PENDING |
| CHK-1008 | 05-BIMI.md:264 | checkbox | Valid SVG Tiny PS → pass | 15 | - | - | PENDING |
| CHK-1009 | 05-BIMI.md:265 | checkbox | Missing baseProfile → fail | 15 | - | - | PENDING |
| CHK-1010 | 05-BIMI.md:266 | checkbox | Contains `<script>` → fail | 15 | - | - | PENDING |
| CHK-1011 | 05-BIMI.md:267 | checkbox | Exceeds 32KB → fail | 15 | - | - | PENDING |
| CHK-1012 | 05-BIMI.md:268 | checkbox | Missing `<title>` → fail | 15 | - | - | PENDING |
| CHK-1013 | 05-BIMI.md:269 | checkbox | Comma-delimited viewBox → fail | 15 | - | - | PENDING |
| CHK-1014 | 05-BIMI.md:270 | checkbox | Event handler on self-closing element: `<rect onclick="x"/>` → fail (Event::Empty, not just Event::Start) | 15 | - | - | PENDING |
| CHK-1015 | 05-BIMI.md:271 | checkbox | `javascript:` URI in href → fail | 15 | - | - | PENDING |
| CHK-1016 | 05-BIMI.md:272 | checkbox | `<animate>` element → fail | 15 | - | - | PENDING |
| CHK-1017 | 05-BIMI.md:273 | checkbox | `<image>` element → fail | 15 | - | - | PENDING |
| CHK-1018 | 05-BIMI.md:274 | checkbox | `<foreignObject>` element → fail | 15 | - | - | PENDING |
| CHK-1019 | 05-BIMI.md:275 | checkbox | Title exceeding 65 characters → fail | 15 | - | - | PENDING |
| CHK-1020 | 05-BIMI.md:276 | checkbox | Entity declaration (`<!ENTITY`) → fail (XXE prevention) | 15 | - | - | PENDING |
| CHK-1021 | 05-BIMI.md:280 | checkbox | Valid VMC: PEM cert with BIMI EKU OID `1.3.6.1.5.5.7.3.31` → pass | 16 | - | - | PENDING |
| CHK-1022 | 05-BIMI.md:281 | checkbox | Missing BIMI EKU OID → fail | 16 | - | - | PENDING |
| CHK-1023 | 05-BIMI.md:282 | checkbox | SAN matches `<selector>._bimi.<domain>` → pass | 16 | - | - | PENDING |
| CHK-1024 | 05-BIMI.md:283 | checkbox | SAN mismatch → fail | 16 | - | - | PENDING |
| CHK-1025 | 05-BIMI.md:284 | checkbox | Expired certificate → fail | 16 | - | - | PENDING |
| CHK-1026 | 05-BIMI.md:285 | checkbox | Not-yet-valid certificate → fail | 16 | - | - | PENDING |
| CHK-1027 | 05-BIMI.md:286 | checkbox | Extract SVG from LogoType extension (RFC 3709) → validate as SVG Tiny PS | 16 | - | - | PENDING |
| CHK-1028 | 05-BIMI.md:287 | checkbox | Logo hash comparison: DNS-fetched logo matches VMC-embedded logo → pass | 16 | - | - | PENDING |
| CHK-1029 | 05-BIMI.md:288 | checkbox | Logo hash comparison: mismatch → fail | 16 | - | - | PENDING |
| CHK-1030 | 05-BIMI.md:289 | checkbox | PEM chain: VMC → Intermediate → Root, validate chain | 16 | - | - | PENDING |
| CHK-1031 | 05-BIMI.md:290 | checkbox | Out-of-order PEM chain → reject | 16 | - | - | PENDING |
| CHK-1032 | 05-BIMI.md:291 | checkbox | Multiple VMC certificates in chain → reject | 16 | - | - | PENDING |
| CHK-1033 | 05-BIMI.md:295 | checkbox | BIMI pass → `format_bimi_headers()` produces `BIMI-Location` header with logo URI | 15 | - | - | PENDING |
| CHK-1034 | 05-BIMI.md:296 | checkbox | BIMI pass with VMC → `BIMI-Indicator` header with base64-encoded SVG | 15 | - | - | PENDING |
| CHK-1035 | 05-BIMI.md:297 | checkbox | BIMI fail/none/declined → `format_bimi_headers()` returns None | 15 | - | - | PENDING |
| CHK-1036 | 05-BIMI.md:301 | checkbox | Message with pre-existing `BIMI-Location` header → header stripped before evaluation | 14 | - | - | PENDING |
| CHK-1037 | 05-BIMI.md:302 | checkbox | Message with pre-existing `BIMI-Indicator` header → header stripped before evaluation | 14 | - | - | PENDING |
| CHK-1038 | 05-BIMI.md:303 | checkbox | Message with no BIMI headers → no-op | 14 | - | - | PENDING |
| CHK-1039 | 05-BIMI.md:309 | checkbox | Logo size limit (32KB) prevents resource exhaustion | 15 | - | - | PENDING |
| CHK-1040 | 05-BIMI.md:310 | checkbox | XXE prevention: reject `<!ENTITY>` declarations | 15 | - | - | PENDING |
| CHK-1041 | 05-BIMI.md:311 | checkbox | Script injection: reject `<script>`, `javascript:` URIs | 15 | - | - | PENDING |
| CHK-1042 | 05-BIMI.md:312 | checkbox | TLS 1.2 minimum for logo and VMC fetch | 15 | - | - | PENDING |
| CHK-1043 | 05-BIMI.md:313 | checkbox | BIMI does NOT prevent lookalike domains — separate reputation system needed | 15 | - | - | PENDING |
| CHK-1044 | 05-BIMI.md:314 | checkbox | Remove sender-inserted BIMI-Location headers before processing | 15 | - | - | PENDING |
| CHK-1045 | 05-BIMI.md:320 | checkbox | DMARC module (for eligibility check) | 14 | - | - | PENDING |
| CHK-1046 | 05-BIMI.md:321 | checkbox | DNS resolver (shared DnsResolver trait) | 14 | - | - | PENDING |
| CHK-1047 | 05-BIMI.md:322 | checkbox | XML parser (for SVG validation): `quick-xml` or similar | 15 | - | - | PENDING |
| CHK-1048 | 05-BIMI.md:323 | checkbox | X.509 library (for VMC): `x509-parser` or `webpki` | 16 | - | - | PENDING |
| CHK-1049 | 05-BIMI.md:324 | checkbox | Optional: `reqwest` for HTTPS fetching (caller can provide) | 16 | - | - | PENDING |
| CHK-1050 | 05-BIMI.md:375 | checkbox | BIMI DNS record parsing (v=, l=, a= tags) | 14 | - | - | PENDING |
| CHK-1051 | 05-BIMI.md:376 | checkbox | BIMI-Selector header parsing | 14 | - | - | PENDING |
| CHK-1052 | 05-BIMI.md:377 | checkbox | Record discovery with org-domain fallback | 14 | - | - | PENDING |
| CHK-1053 | 05-BIMI.md:378 | checkbox | Multiple valid records → Fail (not first-wins) | 14 | - | - | PENDING |
| CHK-1054 | 05-BIMI.md:379 | checkbox | DMARC eligibility check (disposition + policy + pct=100 + alignment) | 14 | - | - | PENDING |
| CHK-1055 | 05-BIMI.md:380 | checkbox | SVG Tiny PS validation (size, baseProfile, prohibited elements, Event::Start AND Event::Empty) | 15 | - | - | PENDING |
| CHK-1056 | 05-BIMI.md:381 | checkbox | VMC validation (EKU OID, SAN matching, chain validation, LogoType SVG extraction, logo hash comparison) | 16 | - | - | PENDING |
| CHK-1057 | 05-BIMI.md:382 | checkbox | Declination record handling | 14 | - | - | PENDING |
| CHK-1058 | 05-BIMI.md:383 | checkbox | BIMI-Location and BIMI-Indicator header generation (`format_bimi_headers()`) | 15 | - | - | PENDING |
| CHK-1059 | 05-BIMI.md:384 | checkbox | Sender-inserted BIMI header removal | 14 | - | - | PENDING |
| CHK-1060 | 05-BIMI.md:385 | checkbox | Unit tests for: parsing, discovery (incl. multiple records), SVG validation, DMARC eligibility, VMC, header generation, header removal | 16 | - | - | PENDING |
