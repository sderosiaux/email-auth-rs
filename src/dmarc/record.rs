use super::alignment::AlignmentMode;
use super::policy::Policy;

#[derive(Debug, Clone)]
pub struct DmarcRecord {
    pub version: String,
    pub policy: Policy,
    pub subdomain_policy: Option<Policy>,
    pub pua_policy: Option<Policy>,  // np= for PUA (non-existent subdomain)
    pub pct: u8,
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub fo: String,
    pub rf: String,
    pub ri: u32,
}

pub fn parse_dmarc_record(txt: &str) -> Option<DmarcRecord> {
    let txt = txt.trim();

    if !txt.to_lowercase().starts_with("v=dmarc1") {
        return None;
    }

    let mut policy = None;
    let mut subdomain_policy = None;
    let mut pua_policy = None;
    let mut pct = 100u8;
    let mut adkim = AlignmentMode::Relaxed;
    let mut aspf = AlignmentMode::Relaxed;
    let mut rua = Vec::new();
    let mut ruf = Vec::new();
    let mut fo = "0".to_string();
    let mut rf = "afrf".to_string();
    let mut ri = 86400u32;

    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (key, value) = match part.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };

        let key = key.trim().to_lowercase();
        let value = value.trim();

        match key.as_str() {
            "p" => policy = Policy::parse(value),
            "sp" => subdomain_policy = Policy::parse(value),
            "np" => pua_policy = Policy::parse(value),
            "pct" => pct = value.parse().unwrap_or(100).min(100),
            "adkim" => adkim = AlignmentMode::parse(value),
            "aspf" => aspf = AlignmentMode::parse(value),
            "rua" => rua = value.split(',').map(|s| s.trim().to_string()).collect(),
            "ruf" => ruf = value.split(',').map(|s| s.trim().to_string()).collect(),
            "fo" => fo = value.to_string(),
            "rf" => rf = value.to_string(),
            "ri" => ri = value.parse().unwrap_or(86400),
            _ => {}
        }
    }

    Some(DmarcRecord {
        version: "DMARC1".to_string(),
        policy: policy?,
        subdomain_policy,
        pua_policy,
        pct,
        adkim,
        aspf,
        rua,
        ruf,
        fo,
        rf,
        ri,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let record = parse_dmarc_record("v=DMARC1; p=none").unwrap();
        assert_eq!(record.policy, Policy::None);
        assert_eq!(record.pct, 100);
        assert_eq!(record.adkim, AlignmentMode::Relaxed);
    }

    #[test]
    fn test_parse_full() {
        let record = parse_dmarc_record(
            "v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; aspf=s; rua=mailto:dmarc@example.com"
        ).unwrap();

        assert_eq!(record.policy, Policy::Reject);
        assert_eq!(record.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!(record.pct, 50);
        assert_eq!(record.adkim, AlignmentMode::Strict);
        assert_eq!(record.aspf, AlignmentMode::Strict);
        assert!(record.rua.contains(&"mailto:dmarc@example.com".to_string()));
    }

    #[test]
    fn test_parse_np_tag() {
        let record = parse_dmarc_record("v=DMARC1; p=none; np=reject").unwrap();
        assert_eq!(record.pua_policy, Some(Policy::Reject));
    }

    #[test]
    fn test_invalid_version() {
        assert!(parse_dmarc_record("v=DMARC2; p=none").is_none());
    }

    #[test]
    fn test_missing_policy() {
        assert!(parse_dmarc_record("v=DMARC1").is_none());
    }
}
