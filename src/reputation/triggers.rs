pub fn post_child_candidates(
    components: &[ComponentEvidence],
    authenticity: Option<&AuthenticityEvidence>,
) -> Vec<String> {
    let mut hashes = Vec::new();
    for component in components {
        let executable = component.formats.iter().any(|format| {
            matches!(
                format.kind.as_str(),
                "pe" | "msi" | "powershell" | "batch" | "vbscript" | "javascript" | "hta"
            )
        });
        let severe_script = component.formats.iter().any(|format| format.kind != "pe")
            && component.severity >= Severity::High;
        let missing_signature = executable && component.signed == Some(false);
        if let Some(hash) = &component.sha256
            && (missing_signature || severe_script)
        {
            hashes.push(hash.clone());
        }
    }
    if let Some(auth) = authenticity
        && matches!(
            auth.publisher_reputation,
            PublisherReputation::RemoteAccess | PublisherReputation::BundlerOrPup
        )
    {
        // The root hash is added by the caller, which knows the source hash.
    }
    hashes.sort();
    hashes.dedup();
    hashes
}

trait WithBatch {
    fn with_batch(self, batch: VtBatch) -> Self;
}

impl WithBatch for ReputationEvidence {
    fn with_batch(mut self, batch: VtBatch) -> Self {
        self.vt_batch = Some(batch);
        self.used_by_batch = vec![batch];
        self
    }
}

fn parse_cached(
    sha256: &str,
    body: &serde_json::Value,
    checked_at: DateTime<Utc>,
) -> ReputationEvidence {
    if body
        .get("isitsafe_not_found")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return ReputationEvidence {
            sha256: sha256.into(),
            state: ReputationState::NotFound,
            vt_batch: None,
            used_by_batch: Vec::new(),
            detections: None,
            engines_total: None,
            checked_at: Some(checked_at),
            signature_info: Vec::new(),
            detail: Some("VirusTotal has no record for this hash".into()),
        };
    }
    let attributes = body
        .pointer("/data/attributes")
        .unwrap_or(&serde_json::Value::Null);
    let stats = attributes
        .get("last_analysis_stats")
        .and_then(serde_json::Value::as_object);
    let malicious = stats
        .and_then(|stats| stats.get("malicious"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let suspicious = stats
        .and_then(|stats| stats.get("suspicious"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let undetected = stats
        .and_then(|stats| stats.get("undetected"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let harmless = stats
        .and_then(|stats| stats.get("harmless"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let state = if malicious > 0 {
        ReputationState::Malicious
    } else if suspicious > 0 {
        ReputationState::Suspicious
    } else {
        ReputationState::Undetected
    };
    let mut signature_info = Vec::new();
    if let Some(info) = attributes
        .get("signature_info")
        .and_then(serde_json::Value::as_object)
    {
        for key in ["product", "description", "original name", "company"] {
            if let Some(value) = info.get(key).and_then(serde_json::Value::as_str) {
                signature_info.push(format!("{key}: {value}"));
            }
        }
    }
    ReputationEvidence {
        sha256: sha256.into(),
        state,
        vt_batch: None,
        used_by_batch: Vec::new(),
        detections: Some(malicious + suspicious),
        engines_total: Some(malicious + suspicious + undetected + harmless),
        checked_at: Some(checked_at),
        signature_info,
        detail: None,
    }
}

fn batch_name(batch: VtBatch) -> &'static str {
    match batch {
        VtBatch::PreChild => "pre_child",
        VtBatch::PostChild => "post_child",
    }
}

fn parse_batch(value: &str) -> Option<VtBatch> {
    match value {
        "pre_child" => Some(VtBatch::PreChild),
        "post_child" => Some(VtBatch::PostChild),
        _ => None,
    }
}

fn unavailable(sha256: &str, batch: VtBatch, detail: String) -> ReputationEvidence {
    ReputationEvidence {
        sha256: sha256.into(),
        state: ReputationState::Unavailable,
        vt_batch: Some(batch),
        used_by_batch: vec![batch],
        detections: None,
        engines_total: None,
        checked_at: Some(Utc::now()),
        signature_info: Vec::new(),
        detail: Some(detail),
    }
}

fn not_queried(sha256: &str, batch: VtBatch, detail: &str) -> ReputationEvidence {
    ReputationEvidence {
        sha256: sha256.into(),
        state: ReputationState::NotQueried,
        vt_batch: Some(batch),
        used_by_batch: Vec::new(),
        detections: None,
        engines_total: None,
        checked_at: None,
        signature_info: Vec::new(),
        detail: Some(detail.into()),
    }
}

fn read_limited_json(mut response: Response, max_bytes: usize) -> Result<serde_json::Value> {
    if response
        .content_length()
        .is_some_and(|size| size > max_bytes as u64)
    {
        anyhow::bail!("network response exceeds configured size limit");
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = std::io::Read::read(&mut response, &mut buffer)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > max_bytes {
            anyhow::bail!("network response exceeds configured size limit");
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    serde_json::from_slice(&bytes).context("invalid VirusTotal JSON response")
}

