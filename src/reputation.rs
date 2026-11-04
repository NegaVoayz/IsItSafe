use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};

use crate::config::Config;
use crate::db::Database;
use crate::report::{
    AuthenticityEvidence, Classification, ComponentEvidence, MotwState, OriginEvidence,
    PublisherReputation, ReputationEvidence, ReputationState, Severity, VtBatch,
};
use crate::secrets::virus_total_api_key;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreChildTrigger {
    ExtensionMismatch,
    MotwPresent,
    AboveThreshold,
    BlockedOrReviewOrigin,
    OriginDanger,
    AlwaysQuery,
}

pub struct ReputationManager<'a> {
    config: &'a Config,
    database: &'a Database,
    client: Client,
}

impl<'a> ReputationManager<'a> {
    pub fn new(config: &'a Config, database: &'a Database) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.virus_total.request_timeout_ms))
            .user_agent(concat!("isitsafe/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            config,
            database,
            client,
        })
    }

    pub fn query(&self, sha256: &str, batch: VtBatch) -> Result<ReputationEvidence> {
        if !self.config.virus_total.enabled {
            return Ok(not_queried(sha256, batch, "VirusTotal is disabled"));
        }
        let ttl = Duration::from_secs(self.config.virus_total.cache_ttl_seconds);
        if let Some(cached) = self.database.cached_reputation(sha256, ttl)? {
            let mut evidence = parse_cached(sha256, &cached.body, cached.checked_at);
            evidence.vt_batch = cached
                .query_batch
                .as_deref()
                .and_then(parse_batch)
                .or(Some(batch));
            evidence.used_by_batch = vec![batch];
            return Ok(evidence);
        }
        let api_key = match virus_total_api_key(self.config) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return Ok(not_queried(
                    sha256,
                    batch,
                    "VirusTotal API key is not configured",
                ));
            }
            Err(error) => {
                return Ok(unavailable(sha256, batch, error.to_string()));
            }
        };
        if self
            .database
            .claim_rate_slot("virustotal", self.config.virus_total.requests_per_minute)?
        {
            // Slot claimed.
        }
        let url = format!(
            "{}/files/{}",
            self.config.virus_total.base_url.trim_end_matches('/'),
            sha256
        );
        let response = match self.client.get(&url).header("x-apikey", api_key).send() {
            Ok(response) => response,
            Err(error) => return Ok(unavailable(sha256, batch, error.to_string())),
        };
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Ok(ReputationEvidence {
                sha256: sha256.into(),
                state: ReputationState::RateLimited,
                vt_batch: Some(batch),
                used_by_batch: vec![batch],
                detections: None,
                engines_total: None,
                checked_at: Some(Utc::now()),
                signature_info: Vec::new(),
                detail: Some("VirusTotal rate limit reached".into()),
            });
        }
        if response.status() == StatusCode::NOT_FOUND {
            let body = serde_json::json!({"isitsafe_not_found": true});
            let checked_at = Utc::now();
            self.database
                .cache_reputation(sha256, &body, checked_at, Some(batch_name(batch)))?;
            return Ok(ReputationEvidence {
                sha256: sha256.into(),
                state: ReputationState::NotFound,
                vt_batch: Some(batch),
                used_by_batch: vec![batch],
                detections: None,
                engines_total: None,
                checked_at: Some(checked_at),
                signature_info: Vec::new(),
                detail: Some("VirusTotal has no record for this hash".into()),
            });
        }
        if !response.status().is_success() {
            return Ok(unavailable(
                sha256,
                batch,
                format!("VirusTotal returned HTTP {}", response.status()),
            ));
        }
        let body = match read_limited_json(
            response,
            self.config.limits.max_network_response_bytes as usize,
        ) {
            Ok(body) => body,
            Err(error) => return Ok(unavailable(sha256, batch, error.to_string())),
        };
        let checked_at = Utc::now();
        self.database
            .cache_reputation(sha256, &body, checked_at, Some(batch_name(batch)))?;
        Ok(parse_cached(sha256, &body, checked_at).with_batch(batch))
    }

    pub fn merge_result(&self, existing: &mut Vec<ReputationEvidence>, next: ReputationEvidence) {
        if let Some(item) = existing.iter_mut().find(|item| item.sha256 == next.sha256) {
            if let Some(batch) = next.vt_batch
                && !item.used_by_batch.contains(&batch)
            {
                item.used_by_batch.push(batch);
            }
            if item.state == ReputationState::NotQueried
                && next.state != ReputationState::NotQueried
            {
                *item = next;
            }
        } else {
            existing.push(next);
        }
    }
}

pub fn pre_child_triggers(
    classification: &Classification,
    motw_state: MotwState,
    size: u64,
    origin: &OriginEvidence,
    config: &Config,
) -> Vec<PreChildTrigger> {
    let mut triggers = Vec::new();
    if classification.extension_mismatch {
        triggers.push(PreChildTrigger::ExtensionMismatch);
    }
    if matches!(motw_state, MotwState::Present | MotwState::PresentEmpty) {
        triggers.push(PreChildTrigger::MotwPresent);
    }
    if size > config.limits.snapshot_max_bytes {
        triggers.push(PreChildTrigger::AboveThreshold);
    }
    if origin.source_url.as_deref().is_some_and(|url| {
        config.policy.blocked_origins.iter().any(|blocked| {
            url::Url::parse(url)
                .ok()
                .zip(url::Url::parse(blocked).ok())
                .is_some_and(|(left, right)| {
                    left.host_str() == right.host_str() && left.scheme() == right.scheme()
                })
        }) || config.policy.review_origins.iter().any(|blocked| {
            url::Url::parse(url)
                .ok()
                .zip(url::Url::parse(blocked).ok())
                .is_some_and(|(left, right)| {
                    left.host_str() == right.host_str() && left.scheme() == right.scheme()
                })
        })
    }) {
        triggers.push(PreChildTrigger::BlockedOrReviewOrigin);
    }
    if config.virus_total.always_query {
        triggers.push(PreChildTrigger::AlwaysQuery);
    }
    if origin.browser_danger.as_deref().is_some_and(|danger| {
        matches!(
            danger.to_ascii_lowercase().as_str(),
            "dangerous" | "untrusted" | "unwanted" | "uncommon"
        )
    }) {
        triggers.push(PreChildTrigger::OriginDanger);
    }
    triggers.sort_by_key(|trigger| format!("{trigger:?}"));
    triggers.dedup();
    triggers
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vt_stats() {
        let body = serde_json::json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "undetected": 10,
                        "harmless": 0
                    },
                    "signature_info": {"product": "Example"}
                }
            }
        });
        let evidence = parse_cached(&"a".repeat(64), &body, Utc::now());
        assert_eq!(evidence.state, ReputationState::Malicious);
        assert_eq!(evidence.detections, Some(3));
    }

    #[test]
    fn large_files_trigger_prechild_lookup() {
        let mut config = Config::default();
        config.limits.snapshot_max_bytes = 10;
        config.limits.basic_check_threshold_bytes = 20;
        let triggers = pre_child_triggers(
            &Classification::default(),
            MotwState::Absent,
            21,
            &OriginEvidence::default(),
            &config,
        );
        assert!(triggers.contains(&PreChildTrigger::AboveThreshold));
    }
}
