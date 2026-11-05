    use super::*;
    use crate::config::{AppPaths, Config};
    use crate::db::Database;
    use crate::report::{AnalysisReportV1, FileEvidence};
    use sha2::{Digest, Sha256};

    #[test]
    fn notification_action_uri_round_trips() {
        let report_id = Uuid::new_v4();
        let uri = action_uri(UserDecision::Quarantine, report_id);
        assert_eq!(
            parse_action_uri(&uri).unwrap(),
            (UserDecision::Quarantine, report_id)
        );
    }

    #[test]
    fn notification_detail_uri_round_trips() {
        let report_id = Uuid::new_v4();
        let uri = detail_action_uri(report_id);
        assert_eq!(uri, format!("isitsafe://detail/{report_id}"));
        assert_eq!(
            parse_notification_action(&uri).unwrap(),
            NotificationAction::Detail(report_id)
        );
    }

    #[test]
    fn legacy_notification_actions_remain_compatible() {
        let report_id = Uuid::new_v4();
        let uri = format!("isitsafe-action://keep/{report_id}");
        assert_eq!(
            parse_notification_action(&uri).unwrap(),
            NotificationAction::Decision(UserDecision::Keep)
        );
    }

    #[test]
    fn only_actionable_verdicts_raise_notifications() {
        assert!(should_notify(Verdict::Malicious));
        assert!(should_notify(Verdict::ReviewRequired));
        assert!(!should_notify(Verdict::NoHighRiskFound));
        assert!(!should_notify(Verdict::BasicCheckOnly));
    }

    #[test]
    fn restore_filename_is_a_single_safe_windows_name() {
        assert!(validate_download_file_name("setup (restored).exe").is_ok());
        for invalid in [
            "",
            "..\\outside.exe",
            "folder/file.exe",
            "CON.txt",
            "LPT1.log",
            "bad:name.exe",
            "trailing.exe.",
            " padded.exe",
        ] {
            assert!(
                validate_download_file_name(invalid).is_err(),
                "{invalid:?} should be rejected"
            );
        }
    }

    #[test]
    fn desktop_quarantine_and_restore_round_trip_through_verified_paths() {
        let root = tempfile::tempdir().unwrap();
        let downloads = root.path().join("Downloads");
        let quarantine = root.path().join("quarantine");
        std::fs::create_dir_all(&downloads).unwrap();
        let source = downloads.join("sample.exe");
        let bytes = b"verified test content";
        std::fs::write(&source, bytes).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        let mut config = Config {
            download_dir: downloads.clone(),
            ..Config::default()
        };
        config.security.block_execution_in_download_dir = false;
        let paths = AppPaths {
            config_file: root.path().join("config.toml"),
            data_dir: root.path().to_path_buf(),
            database: root.path().join("state.db"),
            reports_dir: root.path().join("reports"),
            logs_dir: root.path().join("logs"),
            quarantine_dir: quarantine.clone(),
            rules_dir: root.path().join("rules"),
        };
        paths.ensure().unwrap();
        let database = Database::open(&paths.database).unwrap();
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: source.to_string_lossy().into_owned(),
            extension: Some("exe".into()),
            size: bytes.len() as u64,
            sha256: Some(hash.clone()),
            ..FileEvidence::default()
        });
        report.verdict = Verdict::Malicious;
        report.policy.action = PolicyAction::AwaitUserDecision;
        report.policy.reasons.push("test quarantine reason".into());
        database.store_report(&report).unwrap();

        execute_user_decision(
            report.report_id,
            UserDecision::Quarantine,
            DecisionSource::Desktop,
            &config,
            &database,
            &paths,
        )
        .unwrap();
        assert!(!source.exists());
        assert_eq!(database.list_quarantine().unwrap().len(), 1);

        restore_quarantine_from_desktop(&database, &config, &paths, &hash, "sample.exe").unwrap();
        assert!(source.exists());
        assert!(database.list_quarantine().unwrap().is_empty());
        let restored = database.report_by_sha256(&hash).unwrap().unwrap();
        assert_eq!(restored.policy.user_decision, None);
        assert!(
            restored
                .policy
                .reasons
                .iter()
                .all(|reason| !reason.starts_with("The user restored"))
        );
    }
