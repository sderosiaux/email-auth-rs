# DMARC Implementation Spec (RFC 7489)

> LLM-actionable specification for implementing Domain-based Message Authentication, Reporting, and Conformance

## Overview

DMARC builds on SPF and DKIM to provide domain-level policy for email authentication. It enables domain owners to:
1. Declare how unauthenticated messages should be handled
2. Receive reports about authentication results
3. Ensure the RFC5322.From domain aligns with authenticated identifiers

---

## 1. Data Types

### 1.1 DMARC Record Structure

- [ ] Define `DmarcRecord` struct:
  - [ ] `v: String` — version (must be "DMARC1")
  - [ ] `p: Policy` — policy for domain
  - [ ] `sp: Option<Policy>` — subdomain policy (defaults to p)
  - [ ] `adkim: AlignmentMode` — DKIM alignment mode (default: relaxed)
  - [ ] `aspf: AlignmentMode` — SPF alignment mode (default: relaxed)
  - [ ] `np: Option<Policy>` — non-existent subdomain policy (RFC 9091)
  - [ ] `pct: u8` — percentage of messages to apply policy (default: 100)
  - [ ] `fo: Vec<FailureOption>` — failure reporting options
  - [ ] `rf: ReportFormat` — report format (default: AFRF)
  - [ ] `ri: u32` — aggregate report interval in seconds (default: 86400)
  - [ ] `rua: Vec<Uri>` — aggregate report URIs
  - [ ] `ruf: Vec<Uri>` — failure report URIs

### 1.2 Policy

- [ ] Define `Policy` enum:
  - [ ] `None` — no action, monitoring only
  - [ ] `Quarantine` — treat as suspicious (spam folder)
  - [ ] `Reject` — reject the message

### 1.3 Alignment Mode

- [ ] Define `AlignmentMode` enum:
  - [ ] `Relaxed` — organizational domain match (default)
  - [ ] `Strict` — exact domain match

### 1.4 Failure Reporting Options

- [ ] Define `FailureOption` enum:
  - [ ] `Zero` — `0`: Generate report if all mechanisms fail (default)
  - [ ] `One` — `1`: Generate report if any mechanism fails
  - [ ] `D` — `d`: Generate report if DKIM fails
  - [ ] `S` — `s`: Generate report if SPF fails

### 1.5 DMARC Result

- [ ] Define `DmarcResult` struct:
  - [ ] `disposition: Disposition` — what to do with message
  - [ ] `dkim_result: DkimAlignment` — DKIM alignment result
  - [ ] `spf_result: SpfAlignment` — SPF alignment result
  - [ ] `policy: Policy` — policy that was applied
  - [ ] `record: Option<DmarcRecord>` — the DMARC record found

- [ ] Define `Disposition` enum:
  - [ ] `Pass` — message passed DMARC
  - [ ] `Quarantine` — quarantine per policy
  - [ ] `Reject` — reject per policy
  - [ ] `None` — no policy (monitoring mode or no record)

- [ ] Define `DkimAlignment` enum:
  - [ ] `Pass` — aligned DKIM signature found
  - [ ] `Fail` — no aligned DKIM signature
  - [ ] `None` — no DKIM signatures present

- [ ] Define `SpfAlignment` enum:
  - [ ] `Pass` — SPF passed and aligned
  - [ ] `Fail` — SPF failed or not aligned
  - [ ] `None` — SPF not evaluated

---

## 2. Record Discovery (RFC 7489 Section 6.6.3)

### 2.1 DNS Query

- [ ] Extract domain from RFC5322.From header
- [ ] Query: `_dmarc.<from-domain>` TXT record
- [ ] If no record found and domain is not organizational domain:
  - [ ] Determine organizational domain (public suffix + 1 label)
  - [ ] Query: `_dmarc.<organizational-domain>`
- [ ] Handle multiple TXT records: use first valid DMARC record
- [ ] No record found: return `None` (no DMARC policy)

### 2.2 Organizational Domain Determination

- [ ] Implement Public Suffix List lookup
- [ ] Organizational domain = public suffix + one label
- [ ] Example: `mail.example.com` → `example.com`
- [ ] Example: `foo.bar.co.uk` → `bar.co.uk`
- [ ] Handle edge cases (TLDs, private suffixes)

### 2.3 Record Caching

- [ ] Cache DMARC records (respect DNS TTL)
- [ ] Cache organizational domain mappings
- [ ] Negative caching for missing records

---

## 3. Record Parsing (RFC 7489 Section 6.3)

### 3.1 Record Format

- [ ] Parse as tag=value pairs, separated by semicolons
- [ ] Tags are case-insensitive
- [ ] Values may be case-sensitive (URIs, domain names)
- [ ] Whitespace around tags/values is ignored

### 3.2 Required Tags

- [ ] `v=` — version, MUST be "DMARC1", MUST be first tag
- [ ] `p=` — policy: "none", "quarantine", "reject"

### 3.3 Optional Tags

- [ ] `sp=` — subdomain policy (defaults to `p` value)
- [ ] `adkim=` — DKIM alignment: "r" (relaxed, default) or "s" (strict)
- [ ] `aspf=` — SPF alignment: "r" (relaxed, default) or "s" (strict)
- [ ] `np=` — non-existent subdomain policy (RFC 9091): applies when From domain is subdomain that doesn't exist in DNS
- [ ] `pct=` — percentage 0-100 (default: 100)
- [ ] `fo=` — failure options, colon-separated (default: "0")
- [ ] `rf=` — report format (default: "afrf")
- [ ] `ri=` — report interval in seconds (default: 86400)
- [ ] `rua=` — aggregate report URIs, comma-separated
- [ ] `ruf=` — failure report URIs, comma-separated

### 3.4 URI Parsing

- [ ] Format: `mailto:address` or `mailto:address!size`
- [ ] Size suffix: `k` (kilobytes), `m` (megabytes), `g` (gigabytes), `t` (terabytes)
- [ ] External reporting requires verification (see Section 7.1)
- [ ] Validate URI syntax

### 3.5 Validation Rules

- [ ] `v=` must be first tag
- [ ] `v=` must be "DMARC1"
- [ ] Unknown tags: ignore (forward compatibility)
- [ ] Invalid `p=` value: record is invalid
- [ ] `pct=` > 100: treat as 100
- [ ] `pct=` < 0: treat as 0

---

## 4. Identifier Alignment (RFC 7489 Section 3.1)

### 4.1 DKIM Alignment Check

- [ ] For each DKIM signature that passed verification:
  - [ ] Get the `d=` domain from signature
  - [ ] Compare with RFC5322.From domain
  - [ ] Strict mode: exact match required
  - [ ] Relaxed mode: organizational domain match
- [ ] If ANY signature aligns: DKIM alignment passes

### 4.2 SPF Alignment Check

- [ ] Get SPF result and authenticated domain
- [ ] SPF authenticated domain = RFC5321.MailFrom domain (or HELO if MAIL FROM empty)
- [ ] Compare with RFC5322.From domain
- [ ] Strict mode: exact match required
- [ ] Relaxed mode: organizational domain match
- [ ] SPF must pass AND align for SPF alignment to pass

### 4.3 Alignment Comparison

```
Relaxed: org_domain(authenticated) == org_domain(from_header)
Strict:  authenticated == from_header
```

- [ ] Implement `domains_aligned(d1: &str, d2: &str, mode: AlignmentMode) -> bool`
- [ ] Handle case-insensitive comparison
- [ ] Handle trailing dots in domain names

---

## 5. Policy Evaluation (RFC 7489 Section 6)

### 5.1 Evaluation Flow

```
1. Extract RFC5322.From domain
2. Query DMARC record
3. If no record: disposition = None, done
4. Check DKIM alignment
5. Check SPF alignment
6. If DKIM OR SPF aligns: disposition = Pass
7. Else: apply policy (none/quarantine/reject)
8. Apply pct sampling
```

### 5.2 DMARC Pass Condition

- [ ] DKIM alignment passes, OR
- [ ] SPF alignment passes
- [ ] Only ONE needs to pass (OR logic)

### 5.3 Policy Application (RFC 7489 Section 6.3 + RFC 9091)

- [ ] If DMARC passes: disposition = Pass
- [ ] If DMARC fails:
  - [ ] Use `p=` for organizational domain itself
  - [ ] Use `sp=` (or `p=` if no `sp=`) for existing subdomains
  - [ ] Use `np=` (or `sp=` or `p=`) for non-existent subdomains (RFC 9091)
- [ ] Non-existent subdomain detection (RFC 9091): query DNS for From domain A, AAAA, and MX records; non-existent if NXDOMAIN or NODATA for all three

### 5.4 Percentage Sampling (pct)

- [ ] If `pct` < 100:
  - [ ] Randomly sample messages
  - [ ] Non-sampled failures: treat as policy=none
- [ ] Example: pct=50 means 50% get policy, 50% get none

### 5.5 Subdomain vs Organizational Domain

- [ ] If From domain == queried domain: use `p=`
- [ ] If From domain is subdomain of queried domain: use `sp=`
- [ ] Determine using organizational domain hierarchy

---

## 6. API Design

### 6.1 Core Verification Function

```rust
pub struct DmarcVerifier {
    dns_resolver: Box<dyn DnsResolver>,
    psl: PublicSuffixList,
}

impl DmarcVerifier {
    pub async fn verify(
        &self,
        from_header: &str,
        spf_result: SpfResult,
        spf_domain: &str,
        dkim_results: &[DkimResult],
    ) -> DmarcResult;
}
```

### 6.2 Combined Authentication Function

```rust
pub struct EmailAuthenticator {
    spf: SpfVerifier,
    dkim: DkimVerifier,
    dmarc: DmarcVerifier,
}

impl EmailAuthenticator {
    pub async fn authenticate(
        &self,
        message: &Message,
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> AuthenticationResult;
}

pub struct AuthenticationResult {
    pub spf: SpfResult,
    pub dkim: Vec<DkimResult>,
    pub dmarc: DmarcResult,
    pub disposition: Disposition,
}
```

### 6.3 Record Parsing API

- [ ] `DmarcRecord::parse(txt: &str) -> Result<DmarcRecord, ParseError>`
- [ ] `DmarcRecord::lookup(domain: &str, resolver: &dyn DnsResolver) -> Result<Option<DmarcRecord>, DnsError>`

---

## 7. Reporting (RFC 7489 Section 7)

### 7.1 Aggregate Reports (rua)

- [ ] Define `AggregateReport` struct:
  - [ ] Report metadata (org name, report ID, date range)
  - [ ] Policy published
  - [ ] Records: source IP, count, disposition, SPF/DKIM results
- [ ] Generate XML format (RFC 7489 Appendix C)
- [ ] Send via email to `rua` addresses
- [ ] Gzip compress reports

### 7.2 Failure Reports (ruf)

- [ ] Define `FailureReport` struct (AFRF format)
- [ ] Include original headers
- [ ] Include authentication results
- [ ] Send when `fo` conditions met
- [ ] Respect size limits in URI

### 7.3 External Reporting Verification

- [ ] If report URI domain != organizational domain of DMARC record:
  - [ ] Query TXT record at `<dmarc-domain>._report._dmarc.<uri-domain>`
  - [ ] Example: DMARC at example.com, rua=mailto:reports@external.com → query `example.com._report._dmarc.external.com`
  - [ ] TXT record must contain "v=DMARC1" to authorize
  - [ ] If not present or invalid: don't send reports to that URI
- [ ] This prevents using DMARC for spam/DoS against third parties

### 7.4 Report Generation API

- [ ] `AggregateReportBuilder` — collect data over reporting interval
- [ ] `generate_aggregate_report() -> AggregateReport`
- [ ] `serialize_report(report: &AggregateReport) -> Vec<u8>` (XML + gzip)
- [ ] `FailureReportBuilder` — for individual failures

---

## 8. Public Suffix List Integration

### 8.1 PSL Requirements

- [ ] Load Public Suffix List (publicsuffix.org)
- [ ] Support ICANN suffixes (required)
- [ ] Support private suffixes (optional, recommended)
- [ ] Update mechanism (PSL changes over time)

### 8.2 Organizational Domain Algorithm

```
org_domain(domain):
  suffix = find_public_suffix(domain)
  if domain == suffix:
    return domain  # TLD itself
  labels = domain.split('.')
  suffix_labels = suffix.split('.')
  # org domain = suffix + one label
  org_label_count = suffix_labels.len() + 1
  return labels[-org_label_count:].join('.')
```

### 8.3 API

- [ ] `PublicSuffixList::load(data: &str) -> Result<Self, Error>`
- [ ] `psl.organizational_domain(domain: &str) -> String`
- [ ] `psl.is_public_suffix(domain: &str) -> bool`

---

## 9. Test Cases

### 9.1 Record Parsing Tests

- [ ] Minimal valid: `v=DMARC1; p=none`
- [ ] Full record with all tags
- [ ] Missing `v=` first: invalid
- [ ] Invalid `p=` value: invalid
- [ ] Unknown tags: ignored
- [ ] URI parsing with size limits
- [ ] Multiple URIs

### 9.2 Alignment Tests

- [ ] Strict DKIM alignment: exact match passes
- [ ] Strict DKIM alignment: subdomain fails
- [ ] Relaxed DKIM alignment: subdomain passes
- [ ] Strict SPF alignment: exact match passes
- [ ] Relaxed SPF alignment: subdomain passes
- [ ] Misaligned both: fails

### 9.3 Policy Evaluation Tests

- [ ] No DMARC record: disposition=None
- [ ] DKIM passes and aligns: Pass
- [ ] SPF passes and aligns: Pass
- [ ] Both pass and align: Pass
- [ ] DKIM passes, not aligned + SPF fails: apply policy
- [ ] Policy=none: disposition=None (monitoring)
- [ ] Policy=quarantine: disposition=Quarantine
- [ ] Policy=reject: disposition=Reject
- [ ] Subdomain policy different from parent
- [ ] np= tag: non-existent subdomain uses np policy
- [ ] np= fallback: absent np falls back to sp, then p
- [ ] pct=50: 50% get policy, 50% get none

### 9.4 Organizational Domain Tests

- [ ] `example.com` → `example.com`
- [ ] `mail.example.com` → `example.com`
- [ ] `foo.bar.example.com` → `example.com`
- [ ] `example.co.uk` → `example.co.uk`
- [ ] `mail.example.co.uk` → `example.co.uk`
- [ ] `foo.bar.co.uk` → `bar.co.uk`

### 9.5 Integration Tests

- [ ] Gmail message: full SPF+DKIM+DMARC chain
- [ ] Microsoft message: full chain
- [ ] Spoofed From header: DMARC fails
- [ ] Forwarded message: DKIM may pass, SPF may fail

---

## 10. Security Considerations

- [ ] Validate all DNS responses
- [ ] Don't trust external report URIs without verification
- [ ] Rate limit report generation
- [ ] Handle oversized records gracefully
- [ ] Protect against DNS amplification
- [ ] Log authentication decisions for audit

---

## 11. Dependencies

- [ ] SPF module (from this crate)
- [ ] DKIM module (from this crate)
- [ ] Public Suffix List: `psl` crate or custom
- [ ] DNS resolver: shared with SPF/DKIM
- [ ] XML generation: `quick-xml` for reports
- [ ] Compression: `flate2` for gzip

---

## 12. Combined Crate Structure

```
email-auth/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Re-exports, combined API
│   ├── common/
│   │   ├── mod.rs
│   │   ├── dns.rs          # Shared DNS resolver trait
│   │   ├── domain.rs       # Domain utilities
│   │   └── psl.rs          # Public suffix list
│   ├── spf/
│   │   ├── mod.rs          # SPF public API
│   │   ├── record.rs       # Record parsing
│   │   ├── macros.rs       # Macro expansion
│   │   └── eval.rs         # check_host()
│   ├── dkim/
│   │   ├── mod.rs          # DKIM public API
│   │   ├── signature.rs    # Signature parsing
│   │   ├── key.rs          # DNS key parsing
│   │   ├── canon.rs        # Canonicalization
│   │   ├── verify.rs       # Verification
│   │   └── sign.rs         # Signing
│   ├── dmarc/
│   │   ├── mod.rs          # DMARC public API
│   │   ├── record.rs       # Record parsing
│   │   ├── alignment.rs    # Alignment checks
│   │   ├── policy.rs       # Policy evaluation
│   │   └── report.rs       # Reporting
│   └── auth.rs             # Combined authenticator
```

---

## 13. Completion Checklist

- [ ] DMARC record parsing complete
- [ ] DNS discovery with fallback to org domain
- [ ] Public Suffix List integration
- [ ] DKIM alignment implemented
- [ ] SPF alignment implemented
- [ ] Policy evaluation logic complete
- [ ] Subdomain policy handling
- [ ] Percentage sampling
- [ ] Aggregate report generation (optional)
- [ ] Failure report generation (optional)
- [ ] External report verification
- [ ] Unit tests passing
- [ ] Integration tests with SPF+DKIM
- [ ] Real-world message tests
- [ ] Documentation complete
