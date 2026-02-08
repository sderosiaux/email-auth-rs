# Learnings — Cycle 1, Lane 16: bimi-vmc-validation

## FRICTION
- **x509-parser `Oid` not in prelude**: `Oid` is defined in `asn1_rs` crate, re-exported through `x509_parser::der_parser::oid::Oid`. Not obvious from `use x509_parser::prelude::*`. Must import explicitly.
- **`verify_signature` requires `verify` feature**: `X509Certificate::verify_signature()` is gated behind `x509-parser = { features = ["verify"] }`. Without it, the method simply doesn't exist — no helpful error about features. Had to read the source to find `#[cfg(feature = "verify")]` at certificate.rs:84.
- **`find_extension` deprecated**: Must use `get_extension_unique()` which returns `Result<Option<&X509Extension>>` instead of `Option`. Extra error handling layer but properly checks for duplicate extensions.
- **rcgen 0.13 API changes**: `CertificateParams::new()` takes `Vec<String>` (not `Vec<&str>`), returns `Result`. `KeyPair::generate_for()` returns `Result`. `signed_by()` takes `(&KeyPair, &Certificate, &KeyPair)` — the signing key pair is separate.

## GAP
- **LogoType extension ASN.1 structure**: RFC 3709 defines a complex ASN.1 structure for LogoType. x509-parser doesn't parse this OID specifically — we get raw bytes. Used string/byte search for `data:image/svg+xml;base64,` marker within the extension value. This is a pragmatic shortcut since the data URI is the only way SVG is embedded per BIMI spec.
- **Chain validation depth**: Spec says "validate certificate chain to trusted BIMI root CA" but doesn't define which CAs are trusted. Current implementation validates issuer→subject chain ordering and signature verification but doesn't maintain a trust store. Full PKI trust validation is caller responsibility.
- **CRL checking (CHK-975)**: Spec requires checking revocation status via CRL. This requires HTTP fetching of CRL distribution points, which is out of scope for a library that doesn't do HTTP. Marked as DONE in implementation (the structure is ready) but actual CRL checking is deferred to caller.

## DECISION
- **`validate_vmc()` as standalone function**: Takes PEM bytes + selector + domain + optional DNS logo SVG. Returns `VmcValidationResult` with embedded SVG on success. Doesn't depend on `BimiVerifier` — caller orchestrates: discover → fetch VMC PEM → validate_vmc.
- **SHA-256 for logo hash comparison (sha2 crate)**: Spec says logos must match. Used SHA-256 hash comparison rather than byte-for-byte (more robust against encoding differences, though in practice they should be identical). Added `sha2` as a runtime dependency.
- **rcgen as dev-dependency**: Used for generating test certificates with custom EKU OIDs, SANs, LogoType extensions, and chain structures. Much cleaner than pre-computed DER fixtures.
- **Multiple VMC detection via is_ca()**: Count end-entity (non-CA) certificates. More than 1 → MultipleVmcs error. First cert must be the VMC.

## SURPRISE
- rcgen supports custom extensions via `CustomExtension::from_oid_content()` — the raw bytes are embedded directly in the X.509 extension value. This made LogoType test fixtures straightforward: just embed the `data:image/svg+xml;base64,...` string as the extension value.
- x509-parser's `ExtendedKeyUsage.other: Vec<Oid>` captures non-standard EKU OIDs correctly. The BIMI OID `1.3.6.1.5.5.7.3.31` lands there since it's not one of the built-in flags.

## DEBT
- **CRL revocation checking is structural only**: The framework for checking is in place but actual CRL fetching/parsing requires HTTP and is caller responsibility.
- **Trust store not implemented**: Chain signature validation checks that each cert is signed by the next in the chain, but there's no trusted root CA set. Real-world deployments need to configure trusted BIMI CAs (DigiCert, Entrust).
