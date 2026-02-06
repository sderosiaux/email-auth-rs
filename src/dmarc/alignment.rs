use crate::spf::SpfResult;
use crate::dkim::DkimResult;
use crate::common::organizational_domain;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    Strict,
    Relaxed,
}

impl AlignmentMode {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "s" | "strict" => AlignmentMode::Strict,
            _ => AlignmentMode::Relaxed,
        }
    }
}

pub fn check_dkim_alignment(
    from_domain: &str,
    dkim_results: &[DkimResult],
    alignment_mode: AlignmentMode,
) -> bool {
    let from_lower = from_domain.to_lowercase();
    let from_org = organizational_domain(&from_lower);

    for result in dkim_results {
        if let DkimResult::Pass { domain, .. } = result {
            let dkim_lower = domain.to_lowercase();

            match alignment_mode {
                AlignmentMode::Strict => {
                    if dkim_lower == from_lower {
                        return true;
                    }
                }
                AlignmentMode::Relaxed => {
                    let dkim_org = organizational_domain(&dkim_lower);
                    if dkim_org == from_org {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub fn check_spf_alignment(
    from_domain: &str,
    spf_result: &SpfResult,
    spf_domain: &str,
    alignment_mode: AlignmentMode,
) -> bool {
    if *spf_result != SpfResult::Pass {
        return false;
    }

    let from_lower = from_domain.to_lowercase();
    let spf_lower = spf_domain.to_lowercase();

    match alignment_mode {
        AlignmentMode::Strict => from_lower == spf_lower,
        AlignmentMode::Relaxed => {
            let from_org = organizational_domain(&from_lower);
            let spf_org = organizational_domain(&spf_lower);
            from_org == spf_org
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkim_strict_alignment() {
        let results = vec![DkimResult::Pass {
            domain: "example.com".into(),
            selector: "s1".into(),
        }];

        assert!(check_dkim_alignment("example.com", &results, AlignmentMode::Strict));
        assert!(!check_dkim_alignment("mail.example.com", &results, AlignmentMode::Strict));
    }

    #[test]
    fn test_dkim_relaxed_alignment() {
        let results = vec![DkimResult::Pass {
            domain: "mail.example.com".into(),
            selector: "s1".into(),
        }];

        assert!(check_dkim_alignment("example.com", &results, AlignmentMode::Relaxed));
        assert!(check_dkim_alignment("other.example.com", &results, AlignmentMode::Relaxed));
    }

    #[test]
    fn test_spf_strict_alignment() {
        assert!(check_spf_alignment(
            "example.com",
            &SpfResult::Pass,
            "example.com",
            AlignmentMode::Strict
        ));
        assert!(!check_spf_alignment(
            "mail.example.com",
            &SpfResult::Pass,
            "example.com",
            AlignmentMode::Strict
        ));
    }

    #[test]
    fn test_spf_relaxed_alignment() {
        assert!(check_spf_alignment(
            "mail.example.com",
            &SpfResult::Pass,
            "example.com",
            AlignmentMode::Relaxed
        ));
    }

    #[test]
    fn test_spf_fail_no_alignment() {
        assert!(!check_spf_alignment(
            "example.com",
            &SpfResult::Fail,
            "example.com",
            AlignmentMode::Strict
        ));
    }
}
