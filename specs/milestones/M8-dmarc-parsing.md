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

## Scope boundary: reporting OUT OF SCOPE
rua=, ruf=, fo=, rf=, ri= are parsed and stored in the record struct for completeness, but this library does NOT implement report generation or delivery. Parsing these fields is needed for record fidelity, but evaluation ignores them. Explicitly document this scope boundary.

## v= position enforcement
The v=DMARC1 tag MUST be the very first tag in the record. Implementation:
1. Split by `;`
2. First non-empty segment must be `v=DMARC1` (after whitespace trimming)
3. If v= appears as a non-first tag, or is missing, or has wrong value -> reject record
4. Do NOT just check "contains v=DMARC1 somewhere"

## URI parsing contracts
- Format: `mailto:address` or `mailto:address!10m`
- Parse scheme, address, optional size+unit
- Validate mailto: scheme (only defined scheme per RFC)
- Size suffixes: k (kilobytes), m (megabytes), g (gigabytes), t (terabytes)
- Multiple URIs separated by commas (with optional whitespace)

### URI parsing gotchas from v1
- Comma-separated values may have whitespace around commas
- The `!` size delimiter is part of the URI, not a separate tag
- mailto: URIs should NOT be URL-decoded during parsing (store as-is)

## Tag=value parsing shared patterns
DMARC tag parsing is similar to DKIM but NOT identical:
- DMARC uses `;` separator (same as DKIM)
- DMARC has position-sensitive v= (first tag)
- DMARC p= is required (DKIM has different required tags)
- Do NOT share parsing code — the validation rules differ enough that shared code creates subtle bugs. Use the same pattern but separate implementations.

## Review kill patterns
- fo/rf stored as raw strings instead of structured types
- rua/ruf stored as Vec<String> without URI parsing
- np= parsed but never exposed in struct
- pct= bounds not enforced (negative or >100 accepted)
- v= ordering not enforced (accepts v= as non-first tag)
- Policy/AlignmentMode as strings instead of enums
- Duplicate tags silently overwritten instead of rejected
- Missing p= tag not detected (defaults instead of error)
- URI size suffix (!10m) not parsed, stored as part of address
