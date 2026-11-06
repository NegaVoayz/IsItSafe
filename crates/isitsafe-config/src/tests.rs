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

    #[test]
    fn runtime_settings_preserve_secrets_and_unrelated_options() {
        let directory = tempfile::tempdir().unwrap();
        let downloads = directory.path().join("Downloads");
        let quarantine = directory.path().join("Quarantine");
        fs::create_dir_all(&downloads).unwrap();
        let config_file = directory.path().join("config.toml");
        fs::write(
            &config_file,
            format!(
                "download_dir = '{}'\n\n[virus_total]\napi_key = 'keep-me'\nrequests_per_minute = 3\n",
                downloads.display()
            ),
        )
        .unwrap();

        let settings = RuntimeSettings {
            download_dir: downloads,
            quarantine_dir: quarantine,
            monitor_enabled: false,
            start_at_login: true,
            context_menu_enabled: true,
        };
        save_runtime_settings(&config_file, &settings).unwrap();

        let saved = fs::read_to_string(config_file).unwrap();
        assert!(saved.contains("api_key = 'keep-me'"));
        assert!(saved.contains("requests_per_minute = 3"));
        assert!(saved.contains("monitor_enabled = false"));
        assert!(saved.contains("start_at_login = true"));
        assert!(saved.contains("context_menu_enabled = true"));
    }

    #[test]
    fn quarantine_cannot_share_the_download_tree() {
        let directory = tempfile::tempdir().unwrap();
        let downloads = directory.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let settings = RuntimeSettings {
            download_dir: downloads.clone(),
            quarantine_dir: downloads.join("quarantine"),
            monitor_enabled: true,
            start_at_login: false,
            context_menu_enabled: false,
        };

        assert!(settings.validate().is_err());
    }
