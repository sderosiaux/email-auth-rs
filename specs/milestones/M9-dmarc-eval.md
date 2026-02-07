# M9: DMARC Evaluation
Scope: src/dmarc/mod.rs, src/dmarc/alignment.rs, src/dmarc/policy.rs
Depends on: M3 (SpfResult), M6 (DkimResult), M8 (DmarcRecord)
RFC: 7489 Sections 3, 4, 6; RFC 9091

## DNS discovery contracts
- Extract domain from RFC5322.From header
- Query _dmarc.<from_domain> TXT
- If no record and from_domain != org_domain: fallback to _dmarc.<org_domain>
- Multiple TXT records: use first valid DMARC record
- No record: DmarcResult with disposition=None, no policy

## Alignment contracts
- DKIM alignment: for each DkimResult::Pass, compare signature d= with From domain
  - Strict: exact match (case-insensitive)
  - Relaxed: organizational_domain(d=) == organizational_domain(from)
  - ANY passing+aligned signature -> DKIM alignment passes
- SPF alignment: SPF must have passed AND spf_domain aligns with From domain
  - Strict: exact match
  - Relaxed: org domain match
- DMARC passes if DKIM alignment OR SPF alignment passes

## Policy evaluation contracts
- Pass -> disposition Pass
- Fail -> select applicable policy:
  - From domain == record domain (org domain): use p=
  - From domain is existing subdomain: use sp= (fallback to p=)
  - From domain is non-existent subdomain (RFC 9091): use np= (fallback to sp=, then p=)
- Non-existent subdomain detection: DNS query for From domain A, AAAA, MX. If NxDomain for all three -> non-existent.
- pct= sampling: if pct < 100, randomly sample. Non-sampled failures -> disposition None (monitoring mode).

## Result contracts
- DmarcResult must carry: disposition (Pass/Quarantine/Reject/None), dkim_alignment (Pass/Fail), spf_alignment (Pass/Fail), applied_policy, record (if found)
- Not a flat enum — structured with all evaluation details

## Review kill patterns
- np= parsed in M8 but never referenced during policy selection
- Non-existent subdomain detection absent (no DNS A/AAAA/MX probe)
- pct sampling always applies policy (ignores pct field)
- Alignment uses == instead of org_domain comparison for relaxed mode
- DmarcResult is flat enum without alignment/disposition details
- Fallback chain sp->p or np->sp->p not implemented
