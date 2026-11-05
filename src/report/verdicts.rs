impl ProductIdentityEvidence {
    pub fn is_meaningful(&self) -> bool {
        self.product_name.is_some()
            || self.manufacturer.is_some()
            || self.product_version.is_some()
            || self.product_code.is_some()
            || self.upgrade_code.is_some()
            || self.original_filename.is_some()
            || self.file_description.is_some()
            || self.legal_copyright.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEvidence {
    pub sha256: String,
    pub state: ReputationState,
    pub vt_batch: Option<VtBatch>,
    pub used_by_batch: Vec<VtBatch>,
    pub detections: Option<u64>,
    pub engines_total: Option<u64>,
    pub checked_at: Option<DateTime<Utc>>,
    pub signature_info: Vec<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReputationState {
    Malicious,
    Suspicious,
    Undetected,
    NotFound,
    NotQueried,
    Pending,
    RateLimited,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VtBatch {
    PreChild,
    PostChild,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub reasons: Vec<String>,
    pub allowlist_downgraded: bool,
    pub quarantine_requested: bool,
    pub quarantine_path: Option<String>,
    #[serde(default)]
    pub user_decision: Option<UserDecision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    #[default]
    NoAction,
    Notify,
    RequireReview,
    Quarantine,
    BlockRecommended,
    UserRemoved,
    AwaitUserDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserDecision {
    Keep,
    Quarantine,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Malicious,
    Suspicious,
    ReviewRequired,
    Unverified,
    Limited,
    Incomplete,
    BasicCheckOnly,
    NoHighRiskFound,
}
