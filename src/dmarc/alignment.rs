#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlignmentMode {
    Strict,
    Relaxed,
}

impl AlignmentMode {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "s" => AlignmentMode::Strict,
            _ => AlignmentMode::Relaxed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert!(matches!(AlignmentMode::parse("s"), AlignmentMode::Strict));
        assert!(matches!(AlignmentMode::parse("r"), AlignmentMode::Relaxed));
        assert!(matches!(AlignmentMode::parse("anything"), AlignmentMode::Relaxed));
    }
}
