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
