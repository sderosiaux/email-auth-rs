//! DMARC (Domain-based Message Authentication, Reporting & Conformance) - RFC 7489

mod record;
mod alignment;
mod policy;

pub use record::DmarcRecord;
pub use policy::{Policy, Disposition, AlignmentMode, DmarcResult, DmarcVerifier};
