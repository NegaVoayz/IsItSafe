    use std::fs;

    use notify::event::CreateKind;

    use super::*;
    use crate::config::{ChildConfig, LimitsConfig, MIB};

    fn test_watcher() -> (tempfile::TempDir, Watcher) {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let paths = AppPaths {
            config_file: directory.path().join("config.toml"),
            data_dir: data_dir.clone(),
            database: data_dir.join("state.db"),
            reports_dir: data_dir.join("reports"),
            logs_dir: data_dir.join("logs"),
            rules_dir: data_dir.join("rules"),
        };
        paths.ensure().unwrap();
        let mut config = Config {
            download_dir: directory.path().join("downloads"),
            ..Config::default()
        };
        config.storage.quarantine_dir = data_dir.join("quarantine");
        fs::create_dir_all(&config.download_dir).unwrap();
        let database = Database::open(&paths.database).unwrap();
        (directory, Watcher::new(config, database, paths))
    }

    #[test]
    fn final_rename_absorbs_temporary_download_entry() {
        let (directory, watcher) = test_watcher();
        let temp = directory
            .path()
            .join("downloads")
            .join("setup.exe.crdownload");
        let final_path = directory.path().join("downloads").join("setup.exe");
        fs::write(&temp, b"partial").unwrap();
        fs::write(&final_path, b"complete").unwrap();
        let (sender, _receiver) = mpsc::channel();
        let mut debounce = HashMap::new();
        watcher
            .schedule_path(
                &temp,
                EventKind::Create(CreateKind::File),
                &mut debounce,
                &sender,
                Duration::from_secs(1),
            )
            .unwrap();
        assert!(debounce.contains_key(&temp));
        watcher
            .schedule_path(
                &final_path,
                EventKind::Create(CreateKind::File),
                &mut debounce,
                &sender,
                Duration::from_secs(1),
            )
            .unwrap();
        assert!(!debounce.contains_key(&temp));
        assert!(debounce.contains_key(&final_path));
        assert_eq!(debounce.len(), 1);
    }

    #[test]
    fn disappeared_path_does_not_publish_an_incomplete_report() {
        let (directory, watcher) = test_watcher();
        let missing = directory.path().join("downloads").join("restored.zip");

        let report = watcher.process_path_optional(&missing, false).unwrap();

        assert!(report.is_none());
        assert!(
            watcher
                .database
                .latest_report_summaries()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn basic_check_never_launches_the_child() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let paths = AppPaths {
            config_file: directory.path().join("config.toml"),
            data_dir: data_dir.clone(),
            database: data_dir.join("state.db"),
            reports_dir: data_dir.join("reports"),
            logs_dir: data_dir.join("logs"),
            rules_dir: data_dir.join("rules"),
        };
        paths.ensure().unwrap();
        let config = Config {
            download_dir: directory.path().join("downloads"),
            limits: LimitsConfig {
                snapshot_max_bytes: MIB,
                basic_check_threshold_bytes: 2 * MIB,
                motw_read_timeout_ms: 0,
                ..LimitsConfig::default()
            },
            child: ChildConfig {
                executable: Some(directory.path().join("missing-child.exe")),
                use_app_container: true,
            },
            ..Config::default()
        };
        fs::create_dir_all(&config.download_dir).unwrap();
        let path = config.download_dir.join("large.bin");
        let file = fs::File::create(&path).unwrap();
        file.set_len(3 * MIB).unwrap();
        drop(file);
        let database = Database::open(&paths.database).unwrap();
        let watcher = Watcher::new(config, database, paths);
        let report = watcher.process_path(&path).unwrap();
        assert!(report.threshold_decisions.basic_check_only);
        assert!(report.child_execution.is_none());
        assert!(report.has_boundary(BoundaryKind::BasicCheckOnly));
    }
