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

