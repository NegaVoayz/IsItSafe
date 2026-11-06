impl Default for Config {
    fn default() -> Self {
        Self {
            download_dir: default_download_dir(),
            storage: StorageConfig::default(),
            runtime: RuntimeConfig::default(),
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

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            quarantine_dir: default_quarantine_dir(),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            monitor_enabled: true,
            start_at_login: false,
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

