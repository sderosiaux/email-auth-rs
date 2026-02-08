---
verdict: APPROVED
lane: 13
cycle: 1
---

## Summary

All 41 work items (CHK-852 through CHK-919) verified. 498 tests pass, 0 failures. Spec compliance confirmed.

This review covers the review-fixes commit (`1342bf9`), which resolves both violations from the prior review:

1. **CHK-865 (AMS h= MUST include DKIM-Signature headers)**: `seal_message` now scans input headers for DKIM-Signature occurrences and appends `"dkim-signature"` to h= once per occurrence (`src/arc/seal.rs:164-173`). The `select_headers` call uses the augmented list (`src/arc/seal.rs:201-204`). Four new tests: single DKIM-Sig, multiple DKIM-Sigs, no DKIM-Sigs, and seal-then-validate roundtrip with DKIM-Sig.

2. **CHK-901 (Multi-hop body modification: oldest_pass > 1)**: New test `oldest_pass_after_body_modification` in `src/arc/validate.rs:860-1012` manually constructs a 2-hop chain where AMS(1) signed original body, AMS(2) signed modified body, both AS valid. Validates with modified body: Pass with `oldest_pass = 2`. This tests the validator's oldest_pass logic directly, matching spec intent.

## Coverage

| CHK-ID | Test | Passes | Matches Spec |
|--------|------|--------|--------------|
| CHK-852 | Design constraint (API takes completed headers) | Y | Y |
| CHK-853 | Design constraint (returns headers, caller adds) | Y | Y |
| CHK-854 | `seal_cv_fail_stops` | Y | Y |
| CHK-855 | `seal_with_existing_chain_increments` | Y | Y |
| CHK-856 | `seal_no_chain_instance_1_cv_none` | Y | Y |
| CHK-857 | `seal_instance_exceeds_50` | Y | Y |
| CHK-858 | `seal_then_validate_pass` | Y | Y |
| CHK-859 | `seal_no_chain_instance_1_cv_none` | Y | Y |
| CHK-860 | `seal_with_existing_chain_increments` (cv=pass) | Y | Y |
| CHK-861 | `multi_hop_body_mod_cv_fail` (cv=fail) | Y | Y |
| CHK-862 | `seal_uses_dkim_primitives` (AAR format) | Y | Y |
| CHK-863 | `seal_uses_dkim_primitives` (authres payload) | Y | Y |
| CHK-864 | `seal_uses_dkim_primitives` + code:seal.rs:159 | Y | Y |
| CHK-865 | `ams_h_includes_dkim_signature`, `ams_h_includes_multiple_dkim_signatures`, `ams_h_no_dkim_sig_when_none_present`, `seal_validate_roundtrip_with_dkim_sig` | Y | Y |
| CHK-866 | `seal_uses_dkim_primitives` | Y | Y |
| CHK-867 | `seal_uses_dkim_primitives` (AMS tags) | Y | Y |
| CHK-868 | `seal_as_covers_all_prior_sets` | Y | Y |
| CHK-869 | Code: seal.rs:277-278 | Y | Y |
| CHK-870 | Code: all `canonicalize_header` calls use Relaxed | Y | Y |
| CHK-871 | `seal_then_validate_pass` | Y | Y |
| CHK-872 | `seal_uses_dkim_primitives` (AS tags) | Y | Y |
| CHK-873 | `seal_then_validate_pass` | Y | Y |
| CHK-874 | Design constraint (caller prepends) | Y | Y |
| CHK-892 | `seal_no_chain_instance_1_cv_none` | Y | Y |
| CHK-893 | `seal_with_existing_chain_increments` | Y | Y |
| CHK-894 | `seal_cv_fail_stops` | Y | Y |
| CHK-895 | `seal_instance_exceeds_50` | Y | Y |
| CHK-896 | `seal_as_covers_all_prior_sets` | Y | Y |
| CHK-897 | `seal_then_validate_pass` | Y | Y |
| CHK-898 | `seal_modify_body_ams_fails` | Y | Y |
| CHK-899 | `seal_tamper_arc_header_as_fails` | Y | Y |
| CHK-900 | `multi_hop_three_sealers_pass` | Y | Y |
| CHK-901 | `multi_hop_body_mod_cv_fail` + `oldest_pass_after_body_modification` | Y | Y |
| CHK-915 | `seal_uses_dkim_primitives` | Y | Y |
| CHK-916 | Code imports: compute_hash, canonicalize_* | Y | Y |
| CHK-917 | `cv_none_for_first_instance`, `seal_cv_fail_stops` | Y | Y |
| CHK-918 | `seal_instance_exceeds_50` | Y | Y |
| CHK-919 | 498 tests pass | Y | Y |

## Notes

- `oldest_pass_after_body_modification` correctly bypasses the sealer to test validator behavior directly. The spec describes a validator outcome (Pass with oldest_pass > 1), not a sealer outcome. The sealer would set cv=fail in this scenario per RFC 8617 §5.1 Step 4, so testing via manual chain construction is the correct approach.
- CHK-865 fix adds DKIM-Signature entries proportional to count in message. Roundtrip test confirms verifier agrees with sealer.
- Checkboxes.md Test/Commit columns show `-` for lane 13 items. Tests are mapped via CHK-ID comments in source. Not blocking.
