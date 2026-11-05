#![allow(clippy::derivable_impls)]

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SCHEMA_VERSION: &str = "1.2";
pub const REPORT_SUMMARY_SCHEMA_VERSION: &str = "1.0";
pub const LIMITATION_NOTICE: &str =
    "Static analysis found no high-risk content; this does not prove runtime safety.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReportV1 {
    pub schema_version: String,
    pub report_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub file: FileEvidence,
    pub origin: OriginEvidence,
    pub classification: Classification,
    pub facts: Vec<Evidence>,
    pub inference: Vec<Evidence>,
    pub boundaries: Vec<Boundary>,
    pub threshold_decisions: ThresholdDecisions,
    pub lock_acquisition: LockAcquisitionEvidence,
    pub motw: MotwEvidence,
    pub alternate_streams: Vec<AlternateStream>,
    pub child_execution: Option<ChildExecution>,
    pub certificates: Vec<CertificateChainEvidence>,
    pub components: Vec<ComponentEvidence>,
    #[serde(default)]
    pub products: Vec<ProductIdentityEvidence>,
    pub authenticity: Option<AuthenticityEvidence>,
    pub reputation: Vec<ReputationEvidence>,
    pub policy: PolicyDecision,
    pub verdict: Verdict,
    pub limitations_notice: String,
    #[serde(skip, default)]
    pub source_path: Option<std::path::PathBuf>,
}

impl AnalysisReportV1 {
    pub fn new(file: FileEvidence) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            report_id: Uuid::new_v4(),
            observed_at: Utc::now(),
            file,
            origin: OriginEvidence::default(),
            classification: Classification::default(),
            facts: Vec::new(),
            inference: Vec::new(),
            boundaries: Vec::new(),
            threshold_decisions: ThresholdDecisions::default(),
            lock_acquisition: LockAcquisitionEvidence::default(),
            motw: MotwEvidence::default(),
            alternate_streams: Vec::new(),
            child_execution: None,
            certificates: Vec::new(),
            components: Vec::new(),
            products: Vec::new(),
            authenticity: None,
            reputation: Vec::new(),
            policy: PolicyDecision::default(),
            verdict: Verdict::Incomplete,
            limitations_notice: LIMITATION_NOTICE.into(),
            source_path: None,
        }
    }

    pub fn add_boundary(&mut self, kind: BoundaryKind, detail: impl Into<String>) {
        self.boundaries.push(Boundary {
            kind,
            detail: detail.into(),
        });
    }

    pub fn has_boundary(&self, kind: BoundaryKind) -> bool {
        self.boundaries.iter().any(|b| b.kind == kind)
    }

    pub fn request_quarantine(&mut self) {
        self.policy.quarantine_requested = true;
    }

    pub fn summary(&self) -> ReportSummary {
        ReportSummary {
            schema_version: REPORT_SUMMARY_SCHEMA_VERSION.into(),
            report_id: self.report_id,
            path: self.file.display_path.clone(),
            file_name: std::path::Path::new(&self.file.display_path)
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| self.file.display_path.clone()),
            sha256: self.file.sha256.clone(),
            size: self.file.size,
            verdict: self.verdict,
            observed_at: self.observed_at,
            reasons: concise_reasons(self),
            user_decision: self.policy.user_decision,
        }
    }
}

/// Compact report data used by the desktop lists. The complete report remains
/// available separately and is loaded only when its details are requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub schema_version: String,
    pub report_id: Uuid,
    pub path: String,
    pub file_name: String,
    pub sha256: Option<String>,
    pub size: u64,
    pub verdict: Verdict,
    pub observed_at: DateTime<Utc>,
    pub reasons: Vec<String>,
    pub user_decision: Option<UserDecision>,
}

fn concise_reasons(report: &AnalysisReportV1) -> Vec<String> {
    let mut reasons = Vec::new();
    for reason in &report.policy.reasons {
        if reason.starts_with("Waiting for a Keep, Quarantine, or Remove") {
            continue;
        }
        push_unique(&mut reasons, reason.clone());
    }

    let mut facts: Vec<&Evidence> = report
        .facts
        .iter()
        .filter(|evidence| evidence.severity >= Severity::Medium)
        .collect();
    facts.sort_by_key(|evidence| std::cmp::Reverse(evidence.severity));
    for evidence in facts {
        push_unique(&mut reasons, evidence.summary.clone());
        if reasons.len() >= 4 {
            break;
        }
    }

    for reputation in &report.reputation {
        if matches!(
            reputation.state,
            ReputationState::Malicious
                | ReputationState::Suspicious
                | ReputationState::RateLimited
                | ReputationState::Unavailable
        ) {
            let detail = match (reputation.detections, reputation.engines_total) {
                (Some(detections), Some(engines)) => {
                    format!("VirusTotal: {detections}/{engines} engines flagged this file")
                }
                _ => reputation
                    .detail
                    .clone()
                    .unwrap_or_else(|| format!("VirusTotal state: {:?}", reputation.state)),
            };
            push_unique(&mut reasons, detail);
        }
    }

    if reasons.len() < 2 {
        for boundary in &report.boundaries {
            push_unique(&mut reasons, boundary.detail.clone());
            if reasons.len() >= 4 {
                break;
            }
        }
    }

    if reasons.is_empty() {
        reasons.push(format!(
            "{:?} verdict; no concise reason was recorded",
            report.verdict
        ));
    }
    reasons.truncate(4);
    reasons
        .into_iter()
        .map(|reason| sanitize_visible_text(&reason))
        .collect()
}

fn push_unique(reasons: &mut Vec<String>, value: String) {
    let value = value.trim();
    if value.is_empty()
        || reasons
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(value))
    {
        return;
    }
    reasons.push(value.to_string());
}

fn sanitize_visible_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            value if value.is_control() => format!("\\u{{{:x}}}", value as u32).chars().collect(),
            value => vec![value],
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileEvidence {
    pub display_path: String,
    pub full_path_redacted: Option<String>,
    pub extension: Option<String>,
    pub size: u64,
    pub modified_at: Option<DateTime<Utc>>,
    pub sha256: Option<String>,
    pub volume_identity: Option<String>,
    pub file_id: Option<String>,
    pub is_reparse_point: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Classification {
    pub formats: Vec<DetectedFormat>,
    pub extension_mismatch: bool,
    pub risky_trailing_data: bool,
    pub installer_family: Option<String>,
    pub is_markdown: bool,
    pub is_text: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedFormat {
    pub kind: String,
    pub offset: u64,
    pub confidence: Confidence,
    pub parser: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Structural,
    Inferred,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub summary: String,
    pub detail: Option<String>,
    pub provenance: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Boundary {
    pub kind: BoundaryKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryKind {
    BasicCheckOnly,
    Limited,
    LockAcquisitionTimeout,
    LockNotAvailable,
    ReadOnlyContent,
    FileChangedDuringRead,
    MotwEmptyAfterRetry,
    TempOnly,
    OutputTruncated,
    BudgetExceeded,
    UnsupportedFormat,
    EncryptedMember,
    ChildCrashed,
    ChildTimedOut,
    ChildKilledByJob,
    SandboxViolation,
    QuarantineFailed,
    RemovalFailed,
    FileSystemChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OriginEvidence {
    pub state: OriginState,
    pub download_id: Option<String>,
    pub source_url: Option<String>,
    pub final_url: Option<String>,
    pub referrer: Option<String>,
    pub referrer_state: FieldState,
    pub browser_danger: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub correlation: Option<String>,
}

impl Default for OriginState {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginState {
    Matched,
    Pending,
    Unknown,
    TrackingDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldState {
    Present,
    Unavailable,
    Unknown,
}

impl Default for FieldState {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThresholdDecisions {
    pub snapshot_max_bytes: u64,
    pub basic_check_threshold_bytes: u64,
    pub deep_analysis_eligible: bool,
    pub basic_check_only: bool,
    pub limited: bool,
    pub triggered: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LockAcquisitionEvidence {
    pub attempts: u32,
    pub wait_ms: u64,
    pub outcome: LockAcquisitionOutcome,
    pub pre_lock_size: Option<u64>,
    pub locked_size: Option<u64>,
    pub final_size: Option<u64>,
    pub changed_inside_lock: bool,
}

impl Default for LockAcquisitionOutcome {
    fn default() -> Self {
        Self::NotAttempted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockAcquisitionOutcome {
    NotAttempted,
    Acquired,
    Timeout,
    ReadOnlyContent,
    LockNotAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MotwEvidence {
    pub state: MotwState,
    pub zone_id: Option<u32>,
    pub referrer_url: Option<String>,
    pub host_url: Option<String>,
    pub raw: Option<String>,
}

impl Default for MotwState {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MotwState {
    Present,
    PresentEmpty,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternateStream {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildExecution {
    pub launched: bool,
    pub exit_code: Option<i32>,
    pub job_terminated: bool,
    pub peak_memory_bytes: Option<u64>,
    pub cpu_time_ms: Option<u64>,
    pub wall_time_ms: u64,
    pub output_bytes: u64,
    pub output_truncated: bool,
    pub process_creation_limit: Option<u32>,
    pub network_capability: SandboxCapability,
    pub filesystem_capability: SandboxCapability,
    pub sandbox_self_tests: BTreeMap<String, SandboxSelfTest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxCapability {
    None,
    Restricted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxSelfTest {
    Denied,
    Allowed,
    NotRun,
    Unknown,
}

impl Default for SandboxSelfTest {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChainEvidence {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub sha256_fingerprint: String,
    pub ocsp_urls: Vec<String>,
    pub crl_urls: Vec<String>,
    pub role: CertificateRole,
    pub root_trusted: Option<bool>,
    pub timestamp_present: bool,
    pub timestamp_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    pub revocation: RevocationEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateRole {
    Leaf,
    Intermediate,
    Root,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevocationEvidence {
    pub state: RevocationState,
    pub source: Option<String>,
    pub this_update: Option<DateTime<Utc>>,
    pub next_update: Option<DateTime<Utc>>,
    pub detail: Option<String>,
}

impl Default for RevocationState {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationState {
    Valid,
    Revoked,
    Unknown,
    NotChecked,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthenticityEvidence {
    pub signature_digest_valid: Option<bool>,
    pub chain_valid: Option<bool>,
    pub timestamp_state: TimestampState,
    pub publisher_identity: Option<String>,
    pub publisher_reputation: PublisherReputation,
    pub unsigned_components: u32,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampState {
    Valid,
    Missing,
    Invalid,
    Unknown,
}

impl Default for TimestampState {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherReputation {
    Trusted,
    Known,
    RemoteAccess,
    BundlerOrPup,
    Untrusted,
    Unknown,
}

impl Default for PublisherReputation {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentEvidence {
    pub nesting_path: String,
    pub name: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub formats: Vec<DetectedFormat>,
    pub severity: Severity,
    pub signed: Option<bool>,
    pub evidence: Vec<Evidence>,
}

/// Product metadata declared by an executable or installer package. This is
/// what the file claims it will install; it is not proof of runtime behavior.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProductIdentityEvidence {
    pub product_name: Option<String>,
    pub manufacturer: Option<String>,
    pub product_version: Option<String>,
    pub product_code: Option<String>,
    pub upgrade_code: Option<String>,
    pub original_filename: Option<String>,
    pub file_description: Option<String>,
    pub legal_copyright: Option<String>,
    #[serde(default)]
    pub signer_identity: Option<String>,
    #[serde(default)]
    pub signer_sha256: Option<String>,
    #[serde(default)]
    pub signature_digest_valid: Option<bool>,
    #[serde(default)]
    pub signature_not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub signature_not_after: Option<DateTime<Utc>>,
    pub source: String,
    pub nesting_path: Option<String>,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    NoAction,
    Notify,
    RequireReview,
    Quarantine,
    BlockRecommended,
    UserRemoved,
    AwaitUserDecision,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::NoAction
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_schema_is_versioned_and_stable_json() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: "download.exe".into(),
            size: 7,
            ..FileEvidence::default()
        });
        report.source_path = Some(std::path::PathBuf::from(r"C:\secret\download.exe"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["limitations_notice"], LIMITATION_NOTICE);
        assert_eq!(json["products"], serde_json::json!([]));
        assert!(json.get("source_path").is_none());
    }

    #[test]
    fn report_summary_carries_concise_reasons_without_full_inventory() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Downloads\setup.exe".into(),
            size: 42,
            sha256: Some("a".repeat(64)),
            ..FileEvidence::default()
        });
        report.verdict = Verdict::Suspicious;
        report
            .policy
            .reasons
            .push("Unsigned executable\nwith remote-access behavior".into());
        report
            .policy
            .reasons
            .push("Waiting for a Keep, Quarantine, or Remove notification action".into());
        let summary = report.summary();
        assert_eq!(summary.file_name, "setup.exe");
        assert_eq!(summary.verdict, Verdict::Suspicious);
        assert_eq!(
            summary.reasons,
            vec!["Unsigned executable\\nwith remote-access behavior"]
        );
        let json = serde_json::to_value(summary).unwrap();
        assert!(json.get("components").is_none());
    }

    #[test]
    fn legacy_product_identity_without_signer_fields_deserializes() {
        let product: ProductIdentityEvidence = serde_json::from_value(serde_json::json!({
            "product_name": "Legacy Product",
            "manufacturer": "Example Corp",
            "product_version": "1.0",
            "product_code": null,
            "upgrade_code": null,
            "original_filename": "legacy.exe",
            "file_description": "Legacy executable",
            "legal_copyright": null,
            "source": "PE version information",
            "nesting_path": "legacy.exe"
        }))
        .unwrap();

        assert_eq!(product.product_name.as_deref(), Some("Legacy Product"));
        assert!(product.signer_identity.is_none());
        assert!(product.signer_sha256.is_none());
        assert!(product.signature_digest_valid.is_none());
    }
}
