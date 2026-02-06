use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

impl Algorithm {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rsa-sha1" => Some(Algorithm::RsaSha1),
            "rsa-sha256" => Some(Algorithm::RsaSha256),
            "ed25519-sha256" => Some(Algorithm::Ed25519Sha256),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::RsaSha1 => "rsa-sha1",
            Algorithm::RsaSha256 => "rsa-sha256",
            Algorithm::Ed25519Sha256 => "ed25519-sha256",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizationType {
    Simple,
    Relaxed,
}

impl CanonicalizationType {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "relaxed" => CanonicalizationType::Relaxed,
            _ => CanonicalizationType::Simple,
        }
    }
}

impl std::fmt::Display for CanonicalizationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalizationType::Simple => write!(f, "simple"),
            CanonicalizationType::Relaxed => write!(f, "relaxed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canonicalization {
    pub header: CanonicalizationType,
    pub body: CanonicalizationType,
}

impl Default for Canonicalization {
    fn default() -> Self {
        Self {
            header: CanonicalizationType::Simple,
            body: CanonicalizationType::Simple,
        }
    }
}

impl Canonicalization {
    pub fn parse(s: &str) -> Self {
        let parts: Vec<&str> = s.split('/').collect();
        let header = CanonicalizationType::parse(parts.first().unwrap_or(&"simple"));
        let body = parts.get(1).map(|s| CanonicalizationType::parse(s)).unwrap_or(header);
        Self { header, body }
    }
}

impl std::fmt::Display for Canonicalization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.header, self.body)
    }
}

#[derive(Debug, Clone)]
pub struct DkimSignature {
    pub version: u8,
    pub algorithm: Algorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub canonicalization: Canonicalization,
    pub domain: String,
    pub selector: String,
    pub signed_headers: Vec<String>,
    pub body_length: Option<usize>,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
    pub copied_headers: Option<String>,
    pub auid: Option<String>,
    pub query_methods: Option<String>,
    pub raw_header: String,
}

impl DkimSignature {
    pub fn parse(header_value: &str, raw_header: &str) -> Option<Self> {
        let mut version = None;
        let mut algorithm = None;
        let mut signature = None;
        let mut body_hash = None;
        let mut canonicalization = Canonicalization::default();
        let mut domain = None;
        let mut selector = None;
        let mut signed_headers = None;
        let mut body_length = None;
        let mut timestamp = None;
        let mut expiration = None;
        let mut copied_headers = None;
        let mut auid = None;
        let mut query_methods = None;

        for part in header_value.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (key, value) = part.split_once('=')?;
            let key = key.trim().to_lowercase();
            let value = value.trim().replace([' ', '\t', '\r', '\n'], "");

            match key.as_str() {
                "v" => version = value.parse().ok(),
                "a" => algorithm = Algorithm::parse(&value),
                "b" => signature = base64::engine::general_purpose::STANDARD.decode(&value).ok(),
                "bh" => body_hash = base64::engine::general_purpose::STANDARD.decode(&value).ok(),
                "c" => canonicalization = Canonicalization::parse(&value),
                "d" => domain = Some(value.to_lowercase()),
                "s" => selector = Some(value),
                "h" => {
                    signed_headers = Some(
                        value.split(':').map(|s| s.trim().to_lowercase()).collect()
                    );
                }
                "l" => body_length = value.parse().ok(),
                "t" => timestamp = value.parse().ok(),
                "x" => expiration = value.parse().ok(),
                "z" => copied_headers = Some(value),
                "i" => auid = Some(value),
                "q" => query_methods = Some(value),
                _ => {}
            }
        }

        Some(DkimSignature {
            version: version?,
            algorithm: algorithm?,
            signature: signature?,
            body_hash: body_hash?,
            canonicalization,
            domain: domain?,
            selector: selector?,
            signed_headers: signed_headers?,
            body_length,
            timestamp,
            expiration,
            copied_headers,
            auid,
            query_methods,
            raw_header: raw_header.to_string(),
        })
    }
}

pub fn parse_signatures(headers: &str) -> Vec<DkimSignature> {
    let mut signatures = Vec::new();
    let mut current_name = String::new();
    let mut current_value = String::new();
    let mut current_raw = String::new();

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line
            current_value.push(' ');
            current_value.push_str(line.trim());
            current_raw.push_str("\r\n");
            current_raw.push_str(line);
        } else {
            // New header - process previous if it was DKIM-Signature
            if current_name.to_lowercase() == "dkim-signature" {
                if let Some(sig) = DkimSignature::parse(&current_value, &current_raw) {
                    signatures.push(sig);
                }
            }

            // Start new header
            if let Some(pos) = line.find(':') {
                current_name = line[..pos].to_string();
                current_value = line[pos + 1..].trim().to_string();
                current_raw = line.to_string();
            } else {
                current_name.clear();
                current_value.clear();
                current_raw.clear();
            }
        }
    }

    // Don't forget last header
    if current_name.to_lowercase() == "dkim-signature" {
        if let Some(sig) = DkimSignature::parse(&current_value, &current_raw) {
            signatures.push(sig);
        }
    }

    signatures
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let header = "v=1; a=rsa-sha256; d=example.com; s=selector; \
                      h=from:to:subject; bh=dGVzdA==; b=c2lnbmF0dXJl";
        let sig = DkimSignature::parse(header, header).unwrap();

        assert_eq!(sig.version, 1);
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain, "example.com");
        assert_eq!(sig.selector, "selector");
        assert_eq!(sig.signed_headers, vec!["from", "to", "subject"]);
    }

    #[test]
    fn test_parse_canonicalization() {
        assert_eq!(
            Canonicalization::parse("relaxed/simple"),
            Canonicalization {
                header: CanonicalizationType::Relaxed,
                body: CanonicalizationType::Simple,
            }
        );
    }
}
