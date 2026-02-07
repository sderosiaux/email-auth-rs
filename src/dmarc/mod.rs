pub mod eval;
pub mod record;

pub use eval::{Disposition, DmarcEvaluator, DmarcResult};
pub use record::{
    AlignmentMode, DmarcError, DmarcRecord, FailureOption, Policy, ReportFormat, ReportUri,
};
