use super::record::{DmarcRecord, Policy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Pass,
    None,
    Quarantine,
    Reject,
}

impl std::fmt::Display for Disposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Disposition::Pass => write!(f, "pass"),
            Disposition::None => write!(f, "none"),
            Disposition::Quarantine => write!(f, "quarantine"),
            Disposition::Reject => write!(f, "reject"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DmarcResult {
    pub disposition: Disposition,
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub policy: Option<Policy>,
    pub record: Option<DmarcRecord>,
}

impl DmarcResult {
    pub fn passed(&self) -> bool {
        self.disposition == Disposition::Pass
    }
}
