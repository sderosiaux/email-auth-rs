pub mod types;
pub(crate) mod parser;
pub mod eval;
pub mod report;

pub use types::{
    AlignmentMode, DmarcRecord, DmarcResult, Disposition, FailureOption, Policy, ReportFormat,
    ReportUri,
};
pub use parser::DmarcParseError;
pub use eval::DmarcEvaluator;
pub use report::{
    AggregateReport, AggregateReportBuilder, FailureReport, PublishedPolicy, ReportAuthResult,
    ReportDisposition, ReportRecord,
};
