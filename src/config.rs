use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

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

impl Default for Config {
    fn default() -> Self {
        Self {
            download_dir: default_download_dir(),
            security: SecurityConfig::default(),
            interaction: InteractionConfig::default(),
            limits: LimitsConfig::default(),
            events: EventsConfig::default(),
            origin: OriginConfig::default(),
            child: ChildConfig::default(),
            virus_total: VirusTotalConfig::default(),
            reports: ReportsConfig::default(),
            policy: PolicyConfig::default(),
            yara: YaraConfig::default(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            block_execution_in_download_dir: true,
        }
    }
}

impl Default for InteractionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            blocked_origins: Vec::new(),
            review_origins: Vec::new(),
            quarantine_enabled: true,
            quarantine_review_required: false,
            quarantine_retention_days: 30,
            signer_categories: BTreeMap::new(),
        }
    }
}

impl Default for OriginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_message_bytes: 1024 * 1024,
            chrome_extension_ids: Vec::new(),
            firefox_extension_ids: Vec::new(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            snapshot_max_bytes: 512 * MIB,
            basic_check_threshold_bytes: 2 * GIB,
            lock_acquisition_timeout_ms: 30_000,
            lock_acquisition_retry_backoff_ms: 250,
            motw_read_timeout_ms: 5_000,
            motw_retry_backoff_ms: 100,
            child_committed_memory_bytes: 1280 * MIB,
            child_cpu_time_ms: 120_000,
            child_wall_time_ms: 300_000,
            child_output_max_bytes: 64 * MIB,
            entry_max_bytes: 256 * MIB,
            total_output_max_bytes: 2 * GIB,
            max_entries: 10_000,
            max_depth: 8,
            compression_ratio_warning: 200,
            max_network_response_bytes: 8 * MIB,
        }
    }
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            debounce_ms: 5_000,
            temp_rename_grace_ms: 60 * 60 * 1000,
            temp_extensions: vec![
                ".crdownload".into(),
                ".part".into(),
                ".tmp".into(),
                ".download".into(),
                ".opdownload".into(),
                ".partial".into(),
            ],
            reconciliation_interval_ms: 5 * 60 * 1000,
            origin_correlation_window_ms: 30 * 60 * 1000,
            follow_reparse_points: false,
        }
    }
}

impl Default for ChildConfig {
    fn default() -> Self {
        Self {
            use_app_container: true,
            executable: None,
        }
    }
}

impl Default for VirusTotalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_url: "https://www.virustotal.com/api/v3".into(),
            requests_per_minute: 4,
            cache_ttl_seconds: 24 * 60 * 60,
            request_timeout_ms: 15_000,
            upload_unknown: false,
            always_query: false,
            api_key: None,
        }
    }
}

impl Default for ReportsConfig {
    fn default() -> Self {
        Self {
            retention_days: 30,
            max_total_bytes: 2 * GIB,
            log_max_bytes: 10 * MIB,
            log_retained_files: 5,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            return Self::load(path);
        }
        let config = Self::default();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = toml::to_string_pretty(&config)?;
        fs::write(path, body)
            .with_context(|| format!("failed to create config {}", path.display()))?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.limits.snapshot_max_bytes == 0 {
            bail!("limits.snapshot_max_bytes must be greater than zero");
        }
        if self.limits.basic_check_threshold_bytes < self.limits.snapshot_max_bytes {
            bail!("limits.basic_check_threshold_bytes must not be below snapshot_max_bytes");
        }
        if self.limits.lock_acquisition_timeout_ms == 0 {
            bail!("limits.lock_acquisition_timeout_ms must be greater than zero");
        }
        if self.limits.lock_acquisition_retry_backoff_ms == 0 {
            bail!("limits.lock_acquisition_retry_backoff_ms must be greater than zero");
        }
        if self.limits.child_output_max_bytes == 0 {
            bail!("limits.child_output_max_bytes must be greater than zero");
        }
        if self.limits.child_wall_time_ms == 0
            || self.limits.child_cpu_time_ms == 0
            || self.limits.child_committed_memory_bytes == 0
        {
            bail!("child time and memory limits must be greater than zero");
        }
        if self.events.debounce_ms == 0 {
            bail!("events.debounce_ms must be greater than zero");
        }
        if self.virus_total.requests_per_minute == 0 {
            bail!("virus_total.requests_per_minute must be greater than zero");
        }
        if self.policy.quarantine_enabled && self.policy.quarantine_retention_days == 0 {
            bail!("policy.quarantine_retention_days must be greater than zero");
        }
        if !self.virus_total.base_url.starts_with("https://") {
            bail!("virus_total.base_url must use HTTPS");
        }
        if self.yara.enabled
            && self
                .yara
                .remote_manifest_url
                .as_deref()
                .is_some_and(|url| !url.is_empty())
            && !self
                .yara
                .remote_manifest_url
                .as_deref()
                .is_some_and(|url| url.starts_with("https://"))
        {
            bail!("yara.remote_manifest_url must use HTTPS");
        }
        for entry in &self.policy.allowlist {
            let url = url::Url::parse(&entry.origin)
                .with_context(|| format!("invalid allowlist origin {}", entry.origin))?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!("allowlist origin must use http or https: {}", entry.origin);
            }
        }
        Ok(())
    }

    pub fn lock_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.lock_acquisition_timeout_ms)
    }
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub database: PathBuf,
    pub reports_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    pub rules_dir: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let appdata = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .context("APPDATA is not defined")?;
        let localappdata = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .context("LOCALAPPDATA is not defined")?;
        let config_dir = appdata.join("IsItSafe");
        let data_dir = localappdata.join("IsItSafe");
        let config_file = std::env::current_exe()
            .ok()
            .and_then(|executable| development_config_file_from(&executable))
            .unwrap_or_else(|| config_dir.join("config.toml"));
        Ok(Self {
            config_file,
            database: data_dir.join("state.db"),
            reports_dir: data_dir.join("reports"),
            logs_dir: data_dir.join("logs"),
            quarantine_dir: data_dir.join("quarantine"),
            rules_dir: data_dir.join("rules"),
            data_dir,
        })
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)?;
        fs::create_dir_all(&self.reports_dir)?;
        fs::create_dir_all(&self.logs_dir)?;
        fs::create_dir_all(&self.quarantine_dir)?;
        fs::create_dir_all(&self.rules_dir)?;
        if let Some(parent) = self.config_file.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }
}

pub fn default_download_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Downloads")
}

fn development_config_file_from(executable: &Path) -> Option<PathBuf> {
    for directory in executable.ancestors().skip(1).take(6) {
        let manifest = directory.join("Cargo.toml");
        let config = directory.join("config.toml");
        if !manifest.is_file() || !config.is_file() {
            continue;
        }
        let is_this_project = fs::read_to_string(&manifest).is_ok_and(|contents| {
            contents
                .lines()
                .any(|line| line.trim() == "name = \"isitsafe\"")
        });
        if is_this_project {
            return Some(config);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_project_config_accepts_an_api_key_without_disclosing_it() {
        let config: Config = toml::from_str(
            r#"
[virus_total]
api_key = "test-only-personal-key"
"#,
        )
        .unwrap();

        assert_eq!(
            config.virus_total.api_key.as_ref().map(ApiKey::as_str),
            Some("test-only-personal-key")
        );
        assert_eq!(config.download_dir, default_download_dir());

        let debug = format!("{config:?}");
        assert!(!debug.contains("test-only-personal-key"));
        assert!(debug.contains("ApiKey([REDACTED])"));

        let serialized = toml::to_string_pretty(&config).unwrap();
        assert!(!serialized.contains("test-only-personal-key"));
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn repository_build_discovers_an_ignored_project_config() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("target/debug/isitsafe.exe");
        let config = directory.path().join("config.toml");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(config.clone(), "[virus_total]\napi_key = \"test\"\n").unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname = \"isitsafe\"\n",
        )
        .unwrap();

        assert_eq!(development_config_file_from(&executable), Some(config));
    }
}
