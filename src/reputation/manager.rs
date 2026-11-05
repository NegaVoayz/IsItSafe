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

