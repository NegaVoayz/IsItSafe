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

