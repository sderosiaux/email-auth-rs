# DMARC Implementation Spec (RFC 7489)

> LLM-actionable specification for implementing Domain-based Message Authentication, Reporting, and Conformance

## Overview

DMARC builds on SPF and DKIM to provide domain-level policy for email authentication. It enables domain owners to:
1. Declare how unauthenticated messages should be handled
2. Ensure the RFC5322.From domain aligns with authenticated identifiers

**Scope**: This library implements DMARC policy evaluation (record parsing, alignment checks, policy selection) and DMARC reporting (aggregate XML generation, failure AFRF reports). Report delivery (email sending, compression) is caller responsibility.

---

## 1. Data Types

### 1.1 DMARC Record Structure

- [ ] Define `DmarcRecord` struct:
  - [ ] `policy: Policy` — policy for organizational domain (p= tag)
  - [ ] `subdomain_policy: Policy` — subdomain policy (sp= tag, defaults to p)
  - [ ] `non_existent_subdomain_policy: Option<Policy>` — np= tag (RFC 9091)
  - [ ] `dkim_alignment: AlignmentMode` — DKIM alignment mode (adkim= tag, default: relaxed)
  - [ ] `spf_alignment: AlignmentMode` — SPF alignment mode (aspf= tag, default: relaxed)
  - [ ] `percent: u8` — percentage of messages to apply policy (pct= tag, default: 100)
  - [ ] `failure_options: Vec<FailureOption>` — failure reporting options (fo= tag)
  - [ ] `report_format: ReportFormat` — report format (rf= tag, default: AFRF)
  - [ ] `report_interval: u32` — aggregate report interval seconds (ri= tag, default: 86400)
  - [ ] `rua: Vec<ReportUri>` — aggregate report URIs (rua= tag)
  - [ ] `ruf: Vec<ReportUri>` — failure report URIs (ruf= tag)

### 1.2 Policy

- [ ] Define `Policy` enum:
  - [ ] `None` — no action, monitoring only
  - [ ] `Quarantine` — treat as suspicious (spam folder)
  - [ ] `Reject` — reject the message
- [ ] Parsing: case-insensitive ("none", "quarantine", "reject")

### 1.3 Alignment Mode

- [ ] Define `AlignmentMode` enum:
  - [ ] `Relaxed` — organizational domain match (default)
  - [ ] `Strict` — exact domain match
- [ ] Parsing: "r" → Relaxed, "s" → Strict

### 1.4 Failure Reporting Options

- [ ] Define `FailureOption` enum:
  - [ ] `Zero` — `0`: generate report if all mechanisms fail (default)
  - [ ] `One` — `1`: generate report if any mechanism fails
  - [ ] `D` — `d`: generate report if DKIM fails
  - [ ] `S` — `s`: generate report if SPF fails
- [ ] Parsing: colon-separated, case-insensitive. Unknown options ignored.

### 1.5 Report URI

- [ ] Define `ReportUri` struct:
  - [ ] `address: String` — email address (after stripping `mailto:` prefix)
  - [ ] `max_size: Option<u64>` — size limit in bytes
  - Note: `scheme` field omitted — only `mailto:` is accepted (validated during parsing, not stored). Non-mailto URIs are rejected at parse time.
- [ ] Size suffix parsing: `!` followed by number + optional unit (k/m/g/t, case-insensitive)
  - k = 1024, m = 1024², g = 1024³, t = 1024⁴
  - No unit suffix → raw bytes

### 1.6 DMARC Result

- [ ] Define `DmarcResult` struct (NOT a flat enum — structured with evaluation details):
  - [ ] `disposition: Disposition` — what to do with message
  - [ ] `dkim_aligned: bool` — whether any DKIM signature aligned
  - [ ] `spf_aligned: bool` — whether SPF passed and aligned
  - [ ] `applied_policy: Option<Policy>` — the policy that was applied
  - [ ] `record: Option<DmarcRecord>` — the DMARC record found (if any)

- [ ] Define `Disposition` enum:
  - [ ] `Pass` — message passed DMARC
  - [ ] `Quarantine` — quarantine per policy
  - [ ] `Reject` — reject per policy
  - [ ] `None` — no policy (monitoring mode, pct sampling excluded, or no record)
  - [ ] `TempFail` — DNS temporary failure during record discovery

---

## 2. Record Discovery (RFC 7489 Section 6.6.3)

### 2.1 DNS Query

- [ ] Extract domain from RFC5322.From header
- [ ] Query: `_dmarc.<from-domain>` TXT record
- [ ] If no record found and domain is not organizational domain:
  - [ ] Determine organizational domain (public suffix + 1 label)
  - [ ] Query: `_dmarc.<organizational-domain>`
- [ ] Multiple TXT records at same name: use first valid DMARC record (parse each, take first success)
- [ ] No record found (NXDOMAIN or no valid DMARC records): DmarcResult with disposition=None, no policy

### 2.2 DNS TempFail During Discovery

- [ ] **CRITICAL**: DNS TempFail during record discovery MUST NOT be treated as "no record"
- [ ] If TXT query returns TempFail: return DmarcResult with `disposition: Disposition::TempFail`
- [ ] Rationale: treating DNS outage as "no policy" means messages bypass DMARC during DNS failures — this is a security violation

### 2.3 Organizational Domain Determination

- [ ] Use Public Suffix List (PSL) to determine organizational domain
- [ ] Organizational domain = public suffix + one label
- [ ] Example: `mail.example.com` → `example.com`
- [ ] Example: `foo.bar.co.uk` → `bar.co.uk`
- [ ] Use `psl` crate v2: `psl::domain_str(&normalized)` returns the registrable domain
- [ ] The psl crate embeds a snapshot of the PSL — no runtime fetch needed

### 2.4 DNS Caching

- [ ] DNS caching: CALLER responsibility (resolver layer), not library scope
- [ ] Document this clearly — callers implement caching in their DnsResolver wrapper

---

## 3. Record Parsing (RFC 7489 Section 6.3)

### 3.1 Record Format

- [ ] Parse as tag=value pairs, separated by semicolons
- [ ] Tags are case-insensitive
- [ ] Values may be case-sensitive (URIs) or case-insensitive (policies)
- [ ] Whitespace around tags/values is ignored
- [ ] Trailing semicolons allowed

### 3.2 Required Tags

- [ ] `v=` — version, MUST be "DMARC1", MUST be first tag
- [ ] `p=` — policy: "none", "quarantine", "reject" (case-insensitive)
- [ ] Missing v= or p= → parse error
- [ ] v= not first → parse error
- [ ] Invalid p= value → parse error

### 3.3 Optional Tags

- [ ] `sp=` — subdomain policy (defaults to `p` value if absent)
- [ ] `np=` — non-existent subdomain policy (RFC 9091). Optional field, no default.
- [ ] `adkim=` — DKIM alignment: "r" (relaxed, default) or "s" (strict)
- [ ] `aspf=` — SPF alignment: "r" (relaxed, default) or "s" (strict)
- [ ] `pct=` — percentage 0-100, default 100. Values >100 clamped to 100, <0 clamped to 0. Non-numeric → use default.
- [ ] `fo=` — failure options, colon-separated. Default: "0". Parse into `Vec<FailureOption>`, unknown options ignored.
- [ ] `rf=` — report format. Default: "afrf". Parse into enum.
- [ ] `ri=` — report interval in seconds. Default: 86400. Non-numeric → use default.
- [ ] `rua=` — aggregate report URIs, comma-separated. Parse into `Vec<ReportUri>`.
- [ ] `ruf=` — failure report URIs, comma-separated. Parse into `Vec<ReportUri>`.
- [ ] Unknown tags: ignore (forward compatibility)

### 3.4 URI Parsing

- [ ] Format: `mailto:address` or `mailto:address!size` or `mailto:address!size_unit`
- [ ] Only "mailto:" scheme accepted. Non-mailto URIs → parse error.
- [ ] Size suffix: `!` followed by decimal number + optional unit (k/m/g/t, case-insensitive)
- [ ] No unit → raw bytes
- [ ] Multiple URIs: comma-separated

### 3.5 Duplicate Tag Handling

- [ ] Duplicate p= → use first value (per RFC 7489 §6.3)
- [ ] Other duplicate tags: implementation may use first or last. Be consistent.

---

## 4. Identifier Alignment (RFC 7489 Section 3.1)

### 4.1 DKIM Alignment Check

- [ ] For each DKIM result that is `Pass`:
  - [ ] Get the `d=` domain from the DKIM signature
  - [ ] Compare with RFC5322.From domain
  - [ ] Strict mode: exact match required (case-insensitive, normalize trailing dots)
  - [ ] Relaxed mode: `organizational_domain(dkim_d)` == `organizational_domain(from_domain)`
- [ ] If ANY DKIM signature both passes AND aligns: DKIM alignment passes

### 4.2 SPF Alignment Check

- [ ] SPF must have resulted in `Pass` (not SoftFail, not Neutral)
- [ ] SPF authenticated domain = MAIL FROM domain (or HELO if MAIL FROM empty)
- [ ] Compare authenticated domain with RFC5322.From domain
- [ ] Strict mode: exact match required
- [ ] Relaxed mode: organizational domain match
- [ ] SPF must pass AND align for SPF alignment to pass

### 4.3 Alignment Comparison Functions

```rust
fn domains_aligned(d1: &str, d2: &str, mode: AlignmentMode) -> bool {
    match mode {
        Strict  => domains_equal(d1, d2),  // case-insensitive, ignore trailing dots
        Relaxed => organizational_domain(d1) == organizational_domain(d2),
    }
}
```

---

## 5. Policy Evaluation (RFC 7489 Section 6)

### 5.1 Evaluation Flow

```
1. Extract RFC5322.From domain
2. Determine organizational domain via PSL
3. Query DMARC record (with org-domain fallback)
4. If DNS TempFail: return disposition TempFail (NOT "no record")
5. If no record: return disposition None, done
6. Check DKIM alignment
7. Check SPF alignment
8. If DKIM OR SPF aligns: disposition = Pass
9. Else: select applicable policy, apply pct sampling
```

### 5.2 DMARC Pass Condition

- [ ] DKIM alignment passes, OR
- [ ] SPF alignment passes
- [ ] Only ONE needs to pass (OR logic)

### 5.3 Policy Selection on Failure (RFC 7489 + RFC 9091)

- [ ] If From domain equals organizational domain: use `p=` (organizational domain policy)
- [ ] If From domain is a subdomain:
  - [ ] Check if subdomain is non-existent (see §5.4)
  - [ ] If non-existent: use `np=` if present, else fall back to `sp=`, else fall back to `p=`
  - [ ] If existing subdomain: use `sp=` (which defaults to `p=` if absent in record)
- [ ] Fallback chain: `np=` → `sp=` → `p=`

### 5.4 Non-Existent Subdomain Detection (RFC 9091)

- [ ] Query DNS for the From domain: A, AAAA, and MX records
- [ ] If ALL THREE return NxDomain → domain is non-existent
- [ ] Any other result (even empty records) → domain exists
- [ ] **Performance**: parallelize these 3 DNS queries with `tokio::join!` — they are independent

### 5.5 Percentage Sampling (pct)

- [ ] If `pct` < 100:
  - [ ] Generate random value 0-99
  - [ ] If value < pct: apply the policy (quarantine/reject)
  - [ ] If value >= pct: disposition = None (monitoring mode, policy not enforced)
- [ ] pct=100: always apply policy (no sampling)
- [ ] pct=0: never apply policy (all monitoring)
- [ ] Use `rand` crate for randomness
- [ ] For testing: provide internal method that accepts deterministic roll value

---

## 6. API Design

### 6.1 Evaluator

```rust
pub struct DmarcEvaluator<R: DnsResolver> {
    resolver: R,
}

impl<R: DnsResolver> DmarcEvaluator<R> {
    pub fn new(resolver: R) -> Self;

    pub async fn evaluate(
        &self,
        from_domain: &str,
        spf_result: &SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult;
}
```

### 6.2 Combined Authentication Function

```rust
pub struct EmailAuthenticator<R: DnsResolver> {
    resolver: R,
    clock_skew: u64,
    receiver: String,
}

impl<R: DnsResolver> EmailAuthenticator<R> {
    pub async fn authenticate(
        &self,
        message: &[u8],    // raw RFC 5322 bytes
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult;
}

pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub from_domain: String,
    pub spf_domain: String,
}
```

### 6.3 Record Parsing API

```rust
DmarcRecord::parse(txt: &str) -> Result<DmarcRecord, DmarcParseError>
```

---

## 7. Reporting (RFC 7489 Section 7)

### 7.1 Aggregate Reports (rua)

- [ ] Define `AggregateReport` struct per RFC 7489 Appendix C XML schema:
  - [ ] Report metadata: org_name, email, report_id, date_range (begin/end timestamps)
  - [ ] Policy published: domain, adkim, aspf, p, sp, pct
  - [ ] Records: source_ip, count, disposition, dkim results, spf results
- [ ] XML serialization matching the DMARC aggregate report schema
- [ ] `AggregateReportBuilder` — accumulates authentication results, produces XML
- [ ] External report URI verification: query `<target-domain>._report._dmarc.<sender-domain>` TXT for `v=DMARC1` authorization
  - [ ] If target domain differs from sender domain, verify authorization before including URI
  - [ ] If `_report._dmarc` query fails or returns no `v=DMARC1` record → drop that report URI

### 7.2 Failure Reports (ruf)

- [ ] Define `FailureReport` struct per RFC 6591 (AFRF):
  - [ ] Original headers (or relevant subset)
  - [ ] Authentication failure details
  - [ ] Feedback type: "auth-failure"
- [ ] AFRF message generation (MIME multipart/report with message/feedback-report)
- [ ] Failure option filtering: check `fo=` tag to determine which failures trigger reports
  - [ ] `fo=0` (default): report only when ALL mechanisms fail to produce aligned pass
  - [ ] `fo=1`: report when ANY mechanism fails to produce aligned pass
  - [ ] `fo=d`: report when DKIM evaluation fails (regardless of SPF)
  - [ ] `fo=s`: report when SPF evaluation fails (regardless of DKIM)

### 7.3 Report Delivery (caller responsibility)

- Report delivery (gzip compression, email sending, size limit enforcement per rua/ruf max_size) is NOT implemented — callers handle transport
- Library provides: report struct generation and XML/AFRF serialization
- Library exposes: `DmarcRecord.rua` / `DmarcRecord.ruf` with parsed URIs and size limits

---

## 8. Public Suffix List Integration

### 8.1 PSL Implementation

- [ ] Use `psl` crate v2 (v2.1+)
- [ ] `psl::domain_str(&normalized_domain)` → returns registrable domain (org domain)
- [ ] The crate embeds a PSL snapshot — no runtime download needed
- [ ] PSL data freshness: tied to crate publish date. For production, consider periodic crate updates.
- [ ] Normalize domain before PSL lookup: lowercase, strip trailing dot

### 8.2 Organizational Domain Function

```rust
pub fn organizational_domain(domain: &str) -> String {
    let normalized = domain::normalize(domain);  // lowercase + strip trailing dot
    psl::domain_str(&normalized)
        .unwrap_or(&normalized)
        .to_string()
}
```

### 8.3 Domain Utilities

```rust
fn normalize(domain: &str) -> String;           // lowercase + strip trailing dot
fn domains_equal(a: &str, b: &str) -> bool;     // normalized comparison
fn is_subdomain_of(child: &str, parent: &str) -> bool;
fn domain_from_email(email: &str) -> Option<&str>;  // extract domain after @
fn local_part_from_email(email: &str) -> &str;       // extract local part before @
```

---

## 9. Test Cases

### 9.1 Record Parsing Tests

- [ ] Minimal valid: `v=DMARC1; p=none`
- [ ] Full record with all tags
- [ ] Missing `v=` → error
- [ ] `v=` not first tag → error
- [ ] Invalid `p=` value → error
- [ ] Unknown tags → ignored
- [ ] Case insensitivity: `v=dmarc1; p=Quarantine` → valid
- [ ] URI parsing with size limits (k, m, g, t units, bare bytes)
- [ ] Multiple URIs in rua
- [ ] Non-mailto URI → error
- [ ] Trailing semicolons → valid
- [ ] Whitespace variations → valid
- [ ] No semicolons: `v=DMARC1;p=none;pct=75` → valid
- [ ] Duplicate p= → first wins
- [ ] pct > 100 → clamped to 100
- [ ] pct < 0 → clamped to 0
- [ ] pct non-numeric → default 100
- [ ] fo= with multiple options: `fo=0:1:d:s`
- [ ] fo= with unknown options → unknown ignored
- [ ] np= parsing (RFC 9091)
- [ ] sp= defaults to p= when absent
- [ ] ri= parsing, non-numeric → default

### 9.2 Alignment Tests

- [ ] Strict DKIM alignment: exact match passes
- [ ] Strict DKIM alignment: subdomain fails
- [ ] Relaxed DKIM alignment: subdomain passes (org domain matches)
- [ ] Relaxed DKIM alignment: different org domain fails
- [ ] Strict SPF alignment: exact match passes
- [ ] Relaxed SPF alignment: subdomain passes
- [ ] SPF SoftFail does NOT produce alignment (must be Pass)
- [ ] Misaligned both → DMARC fails

### 9.3 Policy Evaluation Tests

- [ ] No DMARC record: disposition=None
- [ ] DNS TempFail during discovery: disposition=TempFail (NOT None)
- [ ] DKIM passes and aligns: Pass
- [ ] SPF passes and aligns: Pass
- [ ] Both pass and align: Pass
- [ ] DKIM passes, not aligned + SPF fails: apply policy
- [ ] Policy=none: disposition=None (monitoring)
- [ ] Policy=quarantine: disposition=Quarantine
- [ ] Policy=reject: disposition=Reject
- [ ] Subdomain policy different from parent (sp= test)
- [ ] np= tag: non-existent subdomain uses np policy
- [ ] np= absent, non-existent subdomain: fall back to sp=, then p=
- [ ] pct=50: test with deterministic roll — verify both branches
- [ ] pct=0: always monitoring
- [ ] pct=100: always apply

### 9.4 Organizational Domain Tests

- [ ] `example.com` → `example.com`
- [ ] `mail.example.com` → `example.com`
- [ ] `foo.bar.example.com` → `example.com`
- [ ] `example.co.uk` → `example.co.uk`
- [ ] `mail.example.co.uk` → `example.co.uk`
- [ ] `foo.bar.co.uk` → `bar.co.uk`
- [ ] Deep subdomain: `a.b.c.example.com` → `example.com`

### 9.5 Reporting Tests

#### Aggregate Reports
- [ ] Build aggregate report with AggregateReportBuilder → serialize to XML → verify XML structure matches RFC 7489 Appendix C schema
- [ ] Report metadata: org_name, email, report_id, date_range present in XML
- [ ] Policy published: domain, adkim, aspf, p, sp, pct fields in XML
- [ ] Multiple records: add 3 auth results, verify 3 `<record>` elements in output
- [ ] Empty report (no records): valid XML with zero records

#### External Report URI Verification
- [ ] Same domain (sender=example.com, rua=mailto:dmarc@example.com): no `_report._dmarc` query needed
- [ ] Cross-domain (sender=example.com, rua=mailto:reports@thirdparty.com): query `example.com._report._dmarc.thirdparty.com` TXT → `v=DMARC1` → authorized
- [ ] Cross-domain without authorization record → URI dropped
- [ ] Cross-domain with TempFail on `_report._dmarc` query → URI dropped (safe default)

#### Failure Reports
- [ ] Failure report AFRF format: verify output contains `Feedback-Type: auth-failure`
- [ ] fo=0 (default): both SPF and DKIM fail → generate report
- [ ] fo=0: SPF fails but DKIM aligns → NO report (not all mechanisms failed)
- [ ] fo=1: SPF fails but DKIM aligns → generate report (any mechanism failed)
- [ ] fo=d: DKIM fails → generate report (regardless of SPF result)
- [ ] fo=d: DKIM passes, SPF fails → NO report (fo=d only triggers on DKIM failure)
- [ ] fo=s: SPF fails → generate report (regardless of DKIM result)
- [ ] fo=s: SPF passes, DKIM fails → NO report

---

## 10. Security Considerations

- [ ] DMARC DNS TempFail → TempFail disposition (NEVER treat as "no policy")
- [ ] Validate all DNS responses — handle NxDomain vs empty vs TempFail distinctly
- [ ] Handle oversized records gracefully (truncate parsing, don't crash)
- [ ] l= body length in DKIM: accept but note security concern (body truncation attacks)
- [ ] Rate limiting DNS queries: caller responsibility (document this)

---

## 11. Dependencies

- [ ] SPF module (from this crate)
- [ ] DKIM module (from this crate)
- [ ] Public Suffix List: `psl` crate v2
- [ ] DNS resolver: shared with SPF/DKIM via DnsResolver trait
- [ ] Random: `rand` crate for pct sampling

---

## 12. Combined Crate Structure

```
email-auth/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Re-exports, combined API
│   ├── auth.rs             # EmailAuthenticator, message parsing, From extraction
│   ├── common/
│   │   ├── mod.rs
│   │   ├── dns.rs          # DnsResolver trait, HickoryResolver, MockResolver
│   │   ├── domain.rs       # Domain utilities (normalize, equals, subdomain, email parse)
│   │   └── psl.rs          # organizational_domain() via psl crate
│   ├── spf/
│   │   ├── mod.rs          # SpfResult, SpfVerifier (thin wrapper)
│   │   ├── record.rs       # SpfRecord::parse()
│   │   ├── mechanism.rs    # Mechanism enum, parsing
│   │   ├── macro_exp.rs    # Macro expansion engine
│   │   └── eval.rs         # check_host() algorithm
│   ├── dkim/
│   │   ├── mod.rs          # DkimResult, re-exports
│   │   ├── signature.rs    # DkimSignature parsing
│   │   ├── key.rs          # DkimPublicKey parsing
│   │   ├── canon.rs        # Canonicalization + header selection
│   │   ├── verify.rs       # DkimVerifier
│   │   └── sign.rs         # DkimSigner
│   └── dmarc/
│       ├── mod.rs          # Re-exports
│       ├── record.rs       # DmarcRecord parsing
│       └── eval.rs         # DmarcEvaluator (alignment, policy, discovery)
```

---

## 13. Implementation Learnings (from v1)

### 13.1 DnsResolver Sharing
- `EmailAuthenticator` holds `R: DnsResolver` and needs to pass it to sub-verifiers
- Add `impl<R: DnsResolver> DnsResolver for &R` blanket impl to allow passing `&self.resolver`
- Use UFCS to avoid infinite recursion: `<R as DnsResolver>::query_txt(self, name).await`

### 13.2 psl Crate Usage
- `psl::domain_str(&str)` returns `Option<&str>` — the registrable domain
- Input must be normalized (lowercase, no trailing dot)
- `psl` crate uses `Psl` trait — import it for the `domain_str` function

### 13.3 DMARC Record Discovery Pattern
```rust
async fn discover_record(&self, from_domain: &str, org_domain: &str) -> Option<DmarcRecord> {
    if let Some(rec) = self.query_dmarc(from_domain).await { return Some(rec); }
    if !domains_equal(from_domain, org_domain) {
        if let Some(rec) = self.query_dmarc(org_domain).await { return Some(rec); }
    }
    None
}
```
**NOTE**: Must handle TempFail explicitly — DO NOT use `Err(_) => return None`.

### 13.4 Message Parsing (auth.rs)
- Split raw bytes at `\r\n\r\n` (with `\n\n` fallback) into headers + body
- Parse headers: `name:value` pairs, folded lines (start with SP/HTAB) appended to previous
- Use `.lines()` with CRLF rejoining for folded headers
- From header extraction: check angle brackets BEFORE comma-splitting (handles `"Smith, John" <j@example.com>`)
- Strip RFC 5322 comments (parenthesized text with nesting) before extracting domain
- Unfold `\r\n ` and `\r\n\t` to single space

### 13.5 Deterministic pct Testing
- Provide internal `evaluate_with_roll(... roll: Option<u8>)` method
- Public `evaluate()` calls it with `None` (random)
- Tests call it with `Some(value)` for deterministic results

### 13.6 Non-Existent Subdomain Detection
- 3 DNS queries (A, AAAA, MX) — parallelize with `tokio::join!` for performance
- All three must return NxDomain → non-existent
- Any other result (even NoRecords/empty) → exists

### 13.7 rand Crate
- rand 0.9: `random_range` (not `gen_range` from 0.8)
- `rand::random_range(0u8..100)` for pct sampling

### 13.8 v3 Learnings

#### 13.8.1 Bugs Found in v3 (MUST fix in v4)
- **pct sampling only applied to Quarantine, not Reject**: `eval.rs` only applied pct sampling when `policy == Quarantine`. RFC 7489 §6.6.4 says pct applies to BOTH quarantine and reject. `p=reject; pct=50` always rejected instead of 50% reject / 50% monitoring. **FIX**: Apply pct sampling to any non-None policy disposition (both Quarantine and Reject).
- **np= missing AAAA query**: Non-existent subdomain detection only checked A + MX records. RFC 9091 requires A + AAAA + MX all returning NxDomain. Missing AAAA means a subdomain with only AAAA records would be falsely treated as non-existent. **FIX**: Add `query_aaaa()` call to the `tokio::join!` triple.
- **Multiple DMARC records → NotFound**: When multiple valid DMARC records existed at the same DNS name, v3 returned "not found". RFC 7489 §6.6.3 says to use the first valid record. **FIX**: Parse each TXT record, take first successful parse result.
- **Non-mailto URIs accepted**: `record.rs` URI parser accepted any scheme (http, ftp, etc.) in rua/ruf. RFC 7489 §6.3 only defines mailto: scheme. **FIX**: Reject URIs with scheme != "mailto" during parsing.

#### 13.8.2 Test Coverage Gaps
- **Deterministic pct testing**: The `evaluate_with_roll()` internal method existed but pct=50 tests should cover BOTH branches (roll < pct → enforce, roll >= pct → monitoring). Add explicit tests for both.
- **External report URI verification**: Spec §7.1 mentions querying `<target-domain>._report._dmarc.<sender-domain>` for cross-domain report authorization. Not implemented. Add to spec and implement.
- **Multiple DMARC records test**: Add test where two valid `v=DMARC1` records exist — verify first is used, not error.

#### 13.8.3 Patterns That Worked
- `evaluate_with_roll(roll: Option<u8>)` pattern for deterministic pct testing — clean separation of randomness
- DmarcResult as a struct (not flat enum) with disposition + alignment bools + policy + record — gives callers full context
- TempFail propagation from DNS discovery — correctly distinguishes "no policy" from "can't determine policy"

---

## Completion Checklist

- [ ] DMARC record parsing complete with all tags (including np= from RFC 9091)
- [ ] All parsed fields are structured types (enums, not raw strings)
- [ ] DNS discovery with fallback to organizational domain
- [ ] DNS TempFail during discovery → TempFail disposition (NOT None)
- [ ] Public Suffix List integration via psl crate
- [ ] DKIM alignment implemented (strict and relaxed)
- [ ] SPF alignment implemented (strict and relaxed, requires SPF Pass)
- [ ] Policy selection logic: p= / sp= / np= with fallback chain
- [ ] Non-existent subdomain detection (A + AAAA + MX queries, parallelized)
- [ ] Percentage sampling with deterministic testing support
- [ ] DmarcResult is structured (disposition, alignment bools, policy, record)
- [ ] Combined EmailAuthenticator with From extraction
- [ ] Unit tests cover: parsing, alignment, policy, org domain, discovery, TempFail
- [ ] No unwrap/expect in library code (tests only)
