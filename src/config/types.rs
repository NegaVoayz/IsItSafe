pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub download_dir: PathBuf,
    pub security: SecurityConfig,
    pub interaction: InteractionConfig,
    pub limits: LimitsConfig,
    pub events: EventsConfig,
    pub origin: OriginConfig,
    pub child: ChildConfig,
    pub virus_total: VirusTotalConfig,
    pub reports: ReportsConfig,
    pub policy: PolicyConfig,
    pub yara: YaraConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Apply and verify an inherited NTFS deny-execute ACE on the download directory.
    pub block_execution_in_download_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InteractionConfig {
    /// Post a Windows review notification for actionable analysis results.
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub snapshot_max_bytes: u64,
    pub basic_check_threshold_bytes: u64,
    pub lock_acquisition_timeout_ms: u64,
    pub lock_acquisition_retry_backoff_ms: u64,
    pub motw_read_timeout_ms: u64,
    pub motw_retry_backoff_ms: u64,
    pub child_committed_memory_bytes: u64,
    pub child_cpu_time_ms: u64,
    pub child_wall_time_ms: u64,
    pub child_output_max_bytes: u64,
    pub entry_max_bytes: u64,
    pub total_output_max_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
    pub compression_ratio_warning: u64,
    pub max_network_response_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsConfig {
    pub debounce_ms: u64,
    pub temp_rename_grace_ms: u64,
    pub temp_extensions: Vec<String>,
    pub reconciliation_interval_ms: u64,
    pub origin_correlation_window_ms: u64,
    pub follow_reparse_points: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OriginConfig {
    pub enabled: bool,
    pub max_message_bytes: u64,
    pub chrome_extension_ids: Vec<String>,
    pub firefox_extension_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChildConfig {
    pub use_app_container: bool,
    pub executable: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VirusTotalConfig {
    pub enabled: bool,
    pub base_url: String,
    pub requests_per_minute: u32,
    pub cache_ttl_seconds: u64,
    pub request_timeout_ms: u64,
    pub upload_unknown: bool,
    pub always_query: bool,
    #[serde(default, skip_serializing)]
    pub api_key: Option<ApiKey>,
}

/// A VirusTotal API key loaded from a local configuration file.
///
/// The value is deliberately omitted from serialization and redacted from
/// debug output so normal configuration logging cannot disclose it.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct ApiKey(String);

impl ApiKey {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportsConfig {
    pub retention_days: u64,
    pub max_total_bytes: u64,
    pub log_max_bytes: u64,
    pub log_retained_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub allowlist: Vec<AllowlistEntry>,
    pub blocked_origins: Vec<String>,
    pub review_origins: Vec<String>,
    pub quarantine_enabled: bool,
    pub quarantine_review_required: bool,
    pub quarantine_retention_days: u64,
    pub signer_categories: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct YaraConfig {
    pub enabled: bool,
    pub remote_manifest_url: Option<String>,
    pub public_key_base64: Option<String>,
    pub max_rules_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub origin: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub signer_sha256: Option<String>,
}

