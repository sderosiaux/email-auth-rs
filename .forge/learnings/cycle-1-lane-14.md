# Learnings — Cycle 1, Lane 14: bimi-types-parsing-discovery

## FRICTION
- **MockResolver::add_tempfail() doesn't exist**: MockResolver has `add_txt_err(domain, DnsError)` not a domain-specific `add_tempfail()`. Must use `resolver.add_txt_err("...", DnsError::TempFail)` with explicit import of `crate::common::dns::DnsError`.
- **BIMI declination detection**: A declination record is `v=BIMI1;` with empty/missing `l=` and no `a=`. But `missing l= with a=` present is NOT a declination — it's a valid record with authority evidence only. The `is_declination()` check must verify BOTH conditions: `logo_uris.is_empty() && authority_uri.is_none()`.
- **No unwrap() in library code (review fix)**: `valid_records.into_iter().next().unwrap()` in `lookup_bimi_record()` violated project rule even though logically safe inside `1 =>` match arm. Replaced with `match iter.next()` pattern (src/bimi/discovery.rs:161-165).

## GAP
- **Multiple valid records → Fail, not first-wins**: BIMI spec explicitly mandates that multiple valid BIMI TXT records at the same DNS name produce Fail. This differs from DMARC's "first valid wins" approach. The discovery loop must parse ALL records, count valid ones, and fail if count > 1.
- **One valid + one invalid → use valid**: Invalid records (parse errors) are silently skipped in the counting loop. Only successfully parsed records contribute to the valid count. This means 1 valid + N invalid = use the valid one.

## DECISION
- **BimiVerifier<R: DnsResolver> pattern**: Follows same generic resolver pattern as SpfVerifier, DkimVerifier, ArcVerifier. `discover()` is async, takes DMARC result + author domain + optional selector, returns BimiValidationResult.
- **check_dmarc_ineligible returns Option<String>**: Returns `Some(reason)` if BIMI is ineligible, None if eligible. Caller uses `.is_some()` to branch — the reason string is for diagnostics but currently unused in the result type.
- **strip_bimi_headers as free function**: Takes `&[(&str, &str)]` headers and returns filtered `Vec<(&str, &str)>`. Not a method on BimiVerifier since header stripping is a pre-processing step independent of DNS.
- **format_bimi_location as free function**: Formats a `BimiValidationResult` into a `BIMI-Location` header value on Pass. Returns `None` for non-Pass results.

## SURPRISE
- The BIMI tag parser reuses the same semicolon-separated `tag=value` pattern as DKIM/DMARC/ARC. Could share parsing, but the tag semantics differ enough that a dedicated parser is cleaner.
- Org-domain fallback for BIMI uses the same `organizational_domain()` from `common::domain` that DMARC uses. No new code needed.

## DEBT
- **No VMC/SVG validation in this lane**: BimiRecord stores the `authority_uri` but VMC certificate fetching/validation and SVG Tiny PS validation are lanes 15-16. The types are ready for it.
