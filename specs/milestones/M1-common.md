# M1: Common Infrastructure
Scope: src/common/, src/lib.rs
Depends on: nothing
RFCs: shared across 7208, 6376, 7489

## Contracts
- DnsResolver trait: async, Send+Sync, with query_txt, query_a, query_aaaa, query_mx, query_ptr, query_exists
- All DNS methods return Result<Vec<T>, DnsError> where DnsError distinguishes NxDomain vs TempFail (timeout/servfail)
- HickoryResolver wraps hickory-resolver 0.25 (builder pattern, TokioConnectionProvider from name_server module)
- MockResolver for testing: HashMap-backed, supports configuring NxDomain/TempFail responses per query
- Domain utilities: lowercase normalization, trailing dot stripping, domain equality
- PSL: organizational_domain() using publicsuffix 2 crate (use List::new(), Psl trait import, Domain<'_> type annotation)
- Shared result type shells defined here: SpfResult (7 variants), DkimResult (Pass/Fail/PermFail/TempFail/None with metadata), DmarcResult (structured with disposition, alignment details, policy)
- Error types: DnsError, ParseError as shared foundations
- This module is the interface contract. Once frozen, parallel milestones depend on exact signatures.

## Key API gotchas (from previous implementation)
- hickory 0.25: Resolver::builder_with_config(), not Resolver::new()
- hickory 0.25: TokioConnectionProvider from hickory_resolver::name_server
- hickory 0.25: NXDOMAIN via proto_err.is_nx_domain()
- hickory A/AAAA: access IP via .0 on wrapper types
- publicsuffix 2: List::new(), use publicsuffix::Psl trait, Domain<'_> annotation

## Review kill patterns
- Any DNS method missing from the trait that downstream milestones will need
- DnsError that doesn't distinguish NxDomain vs transient failure
- Result types that are flat enums instead of carrying metadata (domain, selector, reason)
- MockResolver that can't simulate NxDomain distinctly from empty results
