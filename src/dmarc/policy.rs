#[derive(Debug, Clone, PartialEq)]
pub enum PolicyAction {
    None,
    Quarantine,
    Reject,
}

impl PolicyAction {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "quarantine" => PolicyAction::Quarantine,
            "reject" => PolicyAction::Reject,
            _ => PolicyAction::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert!(matches!(PolicyAction::parse("none"), PolicyAction::None));
        assert!(matches!(PolicyAction::parse("quarantine"), PolicyAction::Quarantine));
        assert!(matches!(PolicyAction::parse("reject"), PolicyAction::Reject));
        assert!(matches!(PolicyAction::parse("REJECT"), PolicyAction::Reject));
    }
}
