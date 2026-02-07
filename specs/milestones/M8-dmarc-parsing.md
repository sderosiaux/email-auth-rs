# M8: DMARC Parsing
Scope: src/dmarc/record.rs
Depends on: M1
RFC: 7489 Section 6.3, RFC 9091

## Record parsing contracts
- Tag=value pairs separated by semicolons, whitespace tolerant
- v= must be first tag, must be "DMARC1" -> reject if not
- p= required: "none", "quarantine", "reject" -> structured Policy enum, not raw string
- sp=: subdomain policy, same enum, defaults to p value
- np=: non-existent subdomain policy (RFC 9091), same enum
- adkim=: "r" (relaxed, default) or "s" (strict) -> AlignmentMode enum
- aspf=: same as adkim
- pct=: 0-100 integer, default 100. >100 -> 100, <0 -> 0.
- fo=: colon-separated failure options -> Vec<FailureOption> enum (Zero/One/D/S), not raw string
- rf=: report format, default "afrf" -> structured, not raw string
- ri=: report interval seconds, default 86400 -> u32
- rua=: comma-separated URIs -> Vec<ReportUri> where ReportUri has scheme (mailto), address, optional size limit (!size suffix with k/m/g/t units)
- ruf=: same as rua
- Unknown tags: ignore

## URI parsing contracts
- Format: mailto:address or mailto:address!10m
- Parse scheme, address, optional size+unit
- Validate mailto: scheme (only defined scheme per RFC)

## Review kill patterns
- fo/rf stored as raw strings instead of structured types
- rua/ruf stored as Vec<String> without URI parsing
- np= parsed but never exposed in struct
- pct= bounds not enforced (negative or >100 accepted)
- v= ordering not enforced (accepts v= as non-first tag)
- Policy/AlignmentMode as strings instead of enums
