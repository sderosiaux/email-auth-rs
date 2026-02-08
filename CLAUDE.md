# email-auth

Rust email authentication library: SPF, DKIM, DMARC, ARC, BIMI.

## Philosophy

Spec-driven, code-ephemeral. The specs are the sole source of truth. Source code is generated from specs, validated, then deleted. Specs stay, code is disposable. Each implementation pass lets the LLM infer the best architecture from scratch — no legacy, no debt, no local optima.

## Specs

```
specs/01-SPF-RFC7208.md    — RFC 7208 Sender Policy Framework
specs/02-DKIM-RFC6376.md   — RFC 6376 DomainKeys Identified Mail
specs/03-DMARC-RFC7489.md  — RFC 7489 Domain-based Message Authentication
specs/04-ARC-RFC8617.md    — RFC 8617 Authenticated Received Chain
specs/05-BIMI.md           — Brand Indicators for Message Identification
```

Each spec contains: data types, parsing rules, algorithms, API surface, test cases, security considerations, and implementation learnings from prior iterations. Learnings accumulate across wipes — the specs get smarter, the code doesn't carry scars.

Source RFCs in `specs/RFC*.txt` and `specs/draft-*.txt`.

## Spec Structure

Every spec follows this layout:
1. **Data Types** — structs, enums, fields with `- [ ]` checkboxes
2. **Parsing/Algorithm** — step-by-step behavior with checkboxes
3. **API Design** — public interfaces with Rust signatures
4. **Test Cases** — every requirement has a corresponding test item
5. **Security Considerations** — attack surfaces and mitigations
6. **Implementation Learnings** — bugs, gotchas, patterns from prior iterations
7. **Completion Checklist** — gate for done

The `- [ ]` checkboxes are the contract. Every checkbox = one requirement = one test.

## Implementation Rules

- Read ALL specs before writing any code. Understand cross-module dependencies (DKIM reused by ARC, DMARC depends on SPF+DKIM, BIMI depends on DMARC).
- Implementation order: common/ → SPF + DKIM (parallel) → DMARC + ARC (parallel) → BIMI + auth.rs (parallel).
- Every `- [ ]` in the test section must have a corresponding test. No exceptions.
- Pre-computed fixtures required where ring 0.17 can't sign (RSA-SHA1). Spec says how.
- Ground-truth tests (bypass signer, construct manually) required for DKIM. Sign-then-verify alone is insufficient.
- `cargo test` must pass before any commit. Zero warnings.
- No `unwrap`/`expect` in library code. Tests only.

## Key Dependencies

- `ring` 0.17 — crypto (RSA, Ed25519, SHA). Ring hashes internally — never pre-hash.
- `psl` 2 — Public Suffix List for organizational domain detection
- `quick-xml` 0.37 — SVG Tiny PS validation
- `base64` 0.22, `subtle` 2.6, `rand` 0.9, `tokio` 1, `x509-parser` 0.16

## Known Gotchas (from prior iterations)

- ring `UnparsedPublicKey::verify(data, sig)` takes raw data, NOT a digest. Pre-hashing = double-hash = always fails.
- DKIM `p=` tag stores SPKI format. ring expects PKCS#1 for RSA. Must strip SPKI wrapper.
- DKIM `b=` stripping must not match `bh=`. Use structural parsing, not naive string search.
- DKIM over-signed headers contribute empty canonicalized headers to hash. Never skip them.
- DMARC pct sampling applies to BOTH quarantine AND reject dispositions.
- ARC-Seal has NO h= tag and NO body hash. Relaxed header canonicalization only.
- SVG validation must check both `Event::Start` AND `Event::Empty` for prohibited attributes.
- `async fn` recursion (SPF include/redirect) requires `Pin<Box<dyn Future>>`.

# Forge Project

This project is built with **Forge** — an autonomous spec-driven development loop.

## Methodology

- **Spec is truth.** All implementation derives from `specs/`. Read them first.
- **Code is ephemeral.** Code is wiped between cycles. Only the spec and learnings persist.
- **TDD.** Write tests before or alongside implementation. Tests prove spec compliance.
- **Lanes.** Work is decomposed into independent lanes (see `.forge/lanes.yaml`). Implement one lane at a time.
- **Adversarial review.** Every lane is reviewed against the spec. Violations trigger re-implementation.

## Key Paths

| Path | Purpose |
|------|---------|
| `specs/` | Source of truth — all requirements and constraints |
| `.forge/state.yaml` | Current cycle, phase, lane, and config |
| `.forge/lanes.yaml` | Lane decomposition for current cycle |
| `.forge/checkboxes.md` | Work items extracted from spec checkboxes |
| `.forge/learnings/` | Accumulated insights from previous cycles |
| `.forge/escalation.md` | Unresolved review failures |

## Rules

1. Never contradict the spec. If spec and code disagree, the spec wins.
2. Read `.forge/learnings/` before implementing — previous cycles discovered constraints.
3. Commit after each meaningful unit of work with `[FORGE]` prefix.
4. Update `.forge/checkboxes.md` status as work items are completed.
5. Keep implementations minimal — solve what the spec asks, nothing more.
