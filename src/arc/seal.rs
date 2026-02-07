use super::parse::collect_arc_sets;
use super::validate::build_seal_hash_input;
use super::{
    ArcAuthenticationResults, ArcMessageSignature, ArcSeal, ArcSet, ChainValidationStatus,
    SealError,
};
use crate::dkim::canon::{canonicalize_body, canonicalize_header, select_headers, strip_b_tag};
use crate::dkim::{Algorithm, CanonicalizationMethod};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature as ring_sig;

pub struct ArcSealer {
    pub domain: String,
    pub selector: String,
    pub private_key_pem: Vec<u8>,
    pub algorithm: Algorithm,
    pub signed_headers: Vec<String>,
}

impl ArcSealer {
    pub fn new(
        domain: impl Into<String>,
        selector: impl Into<String>,
        private_key_pem: &[u8],
        algorithm: Algorithm,
    ) -> Self {
        Self {
            domain: domain.into(),
            selector: selector.into(),
            private_key_pem: private_key_pem.to_vec(),
            algorithm,
            signed_headers: vec![
                "from".into(),
                "to".into(),
                "subject".into(),
                "date".into(),
                "message-id".into(),
                "dkim-signature".into(),
            ],
        }
    }

    pub fn signed_headers(mut self, headers: Vec<String>) -> Self {
        self.signed_headers = headers;
        self
    }

    /// Seal a message with ARC headers.
    ///
    /// Returns (AAR header value, AMS header value, AS header value).
    /// These should be prepended to the message as:
    ///   `ARC-Seal: <as_value>`
    ///   `ARC-Message-Signature: <ams_value>`
    ///   `ARC-Authentication-Results: <aar_value>`
    pub fn seal(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        authres_payload: &str,
        chain_status: ChainValidationStatus,
    ) -> Result<(String, String, String), SealError> {
        // Collect existing ARC sets
        let existing_sets = collect_arc_sets(headers).map_err(|e| {
            SealError::SigningError(format!("failed to collect ARC sets: {e}"))
        })?;

        let instance = if existing_sets.is_empty() {
            1u32
        } else {
            let max = existing_sets.last().unwrap().instance;
            // Step 2: Check incoming chain
            if existing_sets.last().unwrap().seal.cv == ChainValidationStatus::Fail {
                return Err(SealError::ChainFailed);
            }
            max + 1
        };

        if instance > 50 {
            return Err(SealError::InstanceLimitExceeded);
        }

        // Determine cv
        let cv = if instance == 1 {
            ChainValidationStatus::None
        } else {
            chain_status
        };

        let cv_str = match cv {
            ChainValidationStatus::None => "none",
            ChainValidationStatus::Pass => "pass",
            ChainValidationStatus::Fail => return Err(SealError::ChainFailed),
        };

        // Step 5: Generate AAR
        let aar_value = format!(" i={instance}; {authres_payload}");

        // Step 6: Generate AMS
        let ams_value = self.generate_ams(headers, body, instance)?;

        // Step 7: Generate AS — need to build sets including the new one
        let as_value = self.generate_seal(
            &existing_sets,
            instance,
            cv_str,
            &aar_value,
            &ams_value,
        )?;

        Ok((aar_value, ams_value, as_value))
    }

    fn generate_ams(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        instance: u32,
    ) -> Result<String, SealError> {
        // Body hash
        let canon_body = canonicalize_body(body, CanonicalizationMethod::Relaxed);
        let body_hash = compute_hash(self.algorithm, &canon_body);
        let b64_bh = base64::engine::general_purpose::STANDARD.encode(&body_hash);

        let h_str = self.signed_headers.join(":");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build AMS template with empty b=
        let ams_template = format!(
            " i={instance}; a={}; c=relaxed/relaxed; d={}; s={};\r\n\th={h_str};\r\n\tbh={b64_bh};\r\n\tt={timestamp}; b=",
            alg_name(self.algorithm),
            self.domain,
            self.selector,
        );

        // Compute header hash
        let canon_headers = select_headers(
            headers,
            &self.signed_headers,
            CanonicalizationMethod::Relaxed,
        );
        let mut hash_input = String::new();
        for h in &canon_headers {
            hash_input.push_str(h);
        }

        // Append AMS header with empty b= (no trailing CRLF)
        let stripped = strip_b_tag(&ams_template);
        let canon_sig =
            canonicalize_header("ARC-Message-Signature", &stripped, CanonicalizationMethod::Relaxed);
        let canon_sig = canon_sig.strip_suffix("\r\n").unwrap_or(&canon_sig);
        hash_input.push_str(canon_sig);

        // Sign
        let sig_bytes = self.sign_data(hash_input.as_bytes())?;
        let b64_sig = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        Ok(format!("{ams_template}{b64_sig}"))
    }

    fn generate_seal(
        &self,
        existing_sets: &[ArcSet],
        instance: u32,
        cv_str: &str,
        aar_value: &str,
        ams_value: &str,
    ) -> Result<String, SealError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // AS template with empty b=
        let as_template = format!(
            " i={instance}; cv={cv_str}; a={}; d={}; s={}; t={timestamp}; b=",
            alg_name(self.algorithm),
            self.domain,
            self.selector,
        );

        // Build the new ARC set for seal hash computation
        let new_aar = ArcAuthenticationResults {
            instance,
            payload: String::new(),
            raw_value: aar_value.to_string(),
        };
        let new_ams = ArcMessageSignature {
            instance,
            algorithm: self.algorithm,
            signature: Vec::new(),
            body_hash: Vec::new(),
            domain: self.domain.clone(),
            selector: self.selector.clone(),
            signed_headers: self.signed_headers.clone(),
            header_canonicalization: CanonicalizationMethod::Relaxed,
            body_canonicalization: CanonicalizationMethod::Relaxed,
            timestamp: None,
            body_length: None,
            raw_value: ams_value.to_string(),
        };
        let new_seal = ArcSeal {
            instance,
            cv: match cv_str {
                "none" => ChainValidationStatus::None,
                "pass" => ChainValidationStatus::Pass,
                _ => ChainValidationStatus::Fail,
            },
            algorithm: self.algorithm,
            signature: Vec::new(),
            domain: self.domain.clone(),
            selector: self.selector.clone(),
            timestamp: None,
            raw_value: as_template.clone(),
        };

        let mut all_sets: Vec<ArcSet> = existing_sets.to_vec();
        all_sets.push(ArcSet {
            instance,
            aar: new_aar,
            ams: new_ams,
            seal: new_seal,
        });

        // Build seal hash input
        let hash_input = build_seal_hash_input(&all_sets, all_sets.len() - 1);

        // Sign
        let sig_bytes = self.sign_data(hash_input.as_bytes())?;
        let b64_sig = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        Ok(format!("{as_template}{b64_sig}"))
    }

    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SealError> {
        let key_der = pem_to_der(&self.private_key_pem)
            .map_err(|e| SealError::SigningError(e))?;

        match self.algorithm {
            Algorithm::RsaSha256 => {
                let key_pair = ring_sig::RsaKeyPair::from_pkcs8(&key_der)
                    .map_err(|e| SealError::SigningError(format!("invalid RSA key: {e}")))?;
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; key_pair.public().modulus_len()];
                key_pair
                    .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, data, &mut sig)
                    .map_err(|e| SealError::SigningError(format!("RSA signing failed: {e}")))?;
                Ok(sig)
            }
            Algorithm::Ed25519Sha256 => {
                let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8(&key_der)
                    .map_err(|e| SealError::SigningError(format!("invalid Ed25519 key: {e}")))?;
                let sig = key_pair.sign(data);
                Ok(sig.as_ref().to_vec())
            }
            Algorithm::RsaSha1 => Err(SealError::SigningError(
                "RSA-SHA1 signing not supported".into(),
            )),
        }
    }
}

fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, String> {
    let pem_str = std::str::from_utf8(pem).map_err(|e| format!("invalid PEM: {e}"))?;
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem_str.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if trimmed.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(trimmed);
        }
    }
    if b64.is_empty() {
        return Err("no PEM data found".into());
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("PEM base64 decode error: {e}"))
}

fn compute_hash(algorithm: Algorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
            ring::digest::digest(&ring::digest::SHA256, data)
                .as_ref()
                .to_vec()
        }
        Algorithm::RsaSha1 => {
            ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
                .as_ref()
                .to_vec()
        }
    }
}

fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::RsaSha256 => "rsa-sha256",
        Algorithm::RsaSha1 => "rsa-sha1",
        Algorithm::Ed25519Sha256 => "ed25519-sha256",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arc::validate::ArcVerifier;
    use crate::arc::ArcResult;
    use crate::common::dns::MockResolver;

    const RSA_2048_PEM: &str = include_str!("../../specs/ground-truth/rsa2048.pem");
    const RSA_2048_PUB_B64: &str = include_str!("../../specs/ground-truth/rsa2048.pub.b64");

    fn make_resolver() -> MockResolver {
        let record = format!("v=DKIM1; k=rsa; p={}", RSA_2048_PUB_B64.trim());
        MockResolver::new().with_txt(
            "sel1._domainkey.example.com",
            vec![Box::leak(record.into_boxed_str()) as &str],
        )
    }

    fn test_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("From", " user@example.com"),
            ("To", " recipient@example.com"),
            ("Subject", " Test Message"),
            ("Date", " Mon, 01 Jan 2024 00:00:00 +0000"),
        ]
    }

    #[tokio::test]
    async fn test_seal_and_validate_single() {
        let sealer = ArcSealer::new(
            "example.com",
            "sel1",
            RSA_2048_PEM.as_bytes(),
            Algorithm::RsaSha256,
        );

        let headers = test_headers();
        let body = b"Hello, ARC!\r\n";

        let (aar_val, ams_val, as_val) = sealer
            .seal(&headers, body, "mx.example.com; spf=pass", ChainValidationStatus::None)
            .unwrap();

        // Build message with ARC headers prepended
        let mut full_headers: Vec<(&str, &str)> = Vec::new();
        full_headers.push(("ARC-Seal", Box::leak(as_val.into_boxed_str())));
        full_headers.push(("ARC-Message-Signature", Box::leak(ams_val.into_boxed_str())));
        full_headers.push(("ARC-Authentication-Results", Box::leak(aar_val.into_boxed_str())));
        full_headers.extend_from_slice(&headers);

        // Validate
        let resolver = make_resolver();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&full_headers, body).await;

        assert_eq!(result.status, ArcResult::Pass, "validation failed: {:?}", result);
        assert_eq!(result.oldest_pass, Some(0));
    }

    #[tokio::test]
    async fn test_seal_multi_hop() {
        let sealer = ArcSealer::new(
            "example.com",
            "sel1",
            RSA_2048_PEM.as_bytes(),
            Algorithm::RsaSha256,
        );

        let headers = test_headers();
        let body = b"Hello, ARC multi-hop!\r\n";

        // Hop 1
        let (aar1, ams1, as1) = sealer
            .seal(&headers, body, "hop1.example.com; spf=pass", ChainValidationStatus::None)
            .unwrap();

        let mut hop1_headers: Vec<(&str, &str)> = Vec::new();
        hop1_headers.push(("ARC-Seal", Box::leak(as1.into_boxed_str())));
        hop1_headers.push(("ARC-Message-Signature", Box::leak(ams1.into_boxed_str())));
        hop1_headers.push(("ARC-Authentication-Results", Box::leak(aar1.into_boxed_str())));
        hop1_headers.extend_from_slice(&headers);

        // Hop 2
        let (aar2, ams2, as2) = sealer
            .seal(&hop1_headers, body, "hop2.example.com; dkim=pass", ChainValidationStatus::Pass)
            .unwrap();

        let mut hop2_headers: Vec<(&str, &str)> = Vec::new();
        hop2_headers.push(("ARC-Seal", Box::leak(as2.into_boxed_str())));
        hop2_headers.push(("ARC-Message-Signature", Box::leak(ams2.into_boxed_str())));
        hop2_headers.push(("ARC-Authentication-Results", Box::leak(aar2.into_boxed_str())));
        hop2_headers.extend_from_slice(&hop1_headers);

        // Validate
        let resolver = make_resolver();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&hop2_headers, body).await;

        assert_eq!(result.status, ArcResult::Pass, "multi-hop validation failed: {:?}", result);
    }

    #[test]
    fn test_seal_instance_limit() {
        let sealer = ArcSealer::new(
            "example.com",
            "sel1",
            RSA_2048_PEM.as_bytes(),
            Algorithm::RsaSha256,
        );

        // Build 50 fake ARC sets in headers
        let mut headers: Vec<(&str, &str)> = Vec::new();
        for i in 1..=50 {
            let cv = if i == 1 { "none" } else { "pass" };
            let aar_val: &str = Box::leak(format!(" i={i}; spf=pass").into_boxed_str());
            let ams_val: &str = Box::leak(format!(
                " i={i}; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA==; bh=dGVzdA==; h=from"
            ).into_boxed_str());
            let as_val: &str = Box::leak(format!(
                " i={i}; cv={cv}; a=rsa-sha256; d=example.com; s=sel1; b=dGVzdA=="
            ).into_boxed_str());
            headers.push(("ARC-Authentication-Results", aar_val));
            headers.push(("ARC-Message-Signature", ams_val));
            headers.push(("ARC-Seal", as_val));
        }

        let result = sealer.seal(&headers, b"body", "spf=pass", ChainValidationStatus::Pass);
        assert_eq!(result, Err(SealError::InstanceLimitExceeded));
    }

    #[tokio::test]
    async fn test_tampered_body_fails_ams() {
        let sealer = ArcSealer::new(
            "example.com",
            "sel1",
            RSA_2048_PEM.as_bytes(),
            Algorithm::RsaSha256,
        );

        let headers = test_headers();
        let body = b"Original body\r\n";

        let (aar_val, ams_val, as_val) = sealer
            .seal(&headers, body, "mx.example.com; spf=pass", ChainValidationStatus::None)
            .unwrap();

        let mut full_headers: Vec<(&str, &str)> = Vec::new();
        full_headers.push(("ARC-Seal", Box::leak(as_val.into_boxed_str())));
        full_headers.push(("ARC-Message-Signature", Box::leak(ams_val.into_boxed_str())));
        full_headers.push(("ARC-Authentication-Results", Box::leak(aar_val.into_boxed_str())));
        full_headers.extend_from_slice(&headers);

        let resolver = make_resolver();
        let verifier = ArcVerifier::new(resolver);
        let result = verifier.validate_chain(&full_headers, b"Tampered body\r\n").await;

        assert!(matches!(result.status, ArcResult::Fail { .. }), "expected fail, got: {:?}", result);
    }
}
