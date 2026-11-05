    #[test]
    fn snapshot_hides_safe_kept_and_outside_downloads() {
        let root = tempfile::tempdir().unwrap();
        let downloads = root.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let questionable = downloads.join("questionable.exe");
        let safe = downloads.join("safe.txt");
        let kept = downloads.join("kept.exe");
        fs::write(&questionable, b"x").unwrap();
        fs::write(&safe, b"x").unwrap();
        fs::write(&kept, b"x").unwrap();

        let db = Database::open(&root.path().join("state.db")).unwrap();
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: questionable.to_string_lossy().into_owned(),
            sha256: Some("a".repeat(64)),
            size: 1,
            ..FileEvidence::default()
        });
        report.verdict = Verdict::Suspicious;
        report.policy.action = PolicyAction::RequireReview;
        report
            .policy
            .reasons
            .push("Suspicious test evidence".into());
        db.store_report(&report).unwrap();

        let mut safe_report = AnalysisReportV1::new(FileEvidence {
            display_path: safe.to_string_lossy().into_owned(),
            sha256: Some("b".repeat(64)),
            size: 1,
            ..FileEvidence::default()
        });
        safe_report.verdict = Verdict::NoHighRiskFound;
        db.store_report(&safe_report).unwrap();

        let mut kept_report = AnalysisReportV1::new(FileEvidence {
            display_path: kept.to_string_lossy().into_owned(),
            sha256: Some("c".repeat(64)),
            size: 1,
            ..FileEvidence::default()
        });
        kept_report.verdict = Verdict::Malicious;
        kept_report.policy.user_decision = Some(UserDecision::Keep);
        db.store_report(&kept_report).unwrap();

        let config = Config {
            download_dir: downloads,
            ..Config::default()
        };
        let paths = AppPaths {
            config_file: root.path().join("config.toml"),
            data_dir: root.path().to_path_buf(),
            database: root.path().join("state.db"),
            reports_dir: root.path().join("reports"),
            logs_dir: root.path().join("logs"),
            quarantine_dir: root.path().join("quarantine"),
            rules_dir: root.path().join("rules"),
        };
        let snapshot = load_snapshot(&config, &db, &paths).unwrap();
        assert_eq!(snapshot.questionable.len(), 1);
        assert_eq!(
            snapshot.questionable[0].summary.file_name,
            "questionable.exe"
        );
    }

    #[test]
    fn restored_quarantine_returns_to_review() {
        let root = tempfile::tempdir().unwrap();
        let downloads = root.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let source = downloads.join("restored.exe");
        let bytes = b"restored test content";
        fs::write(&source, bytes).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        let mut config = Config {
            download_dir: downloads,
            ..Config::default()
        };
        config.security.block_execution_in_download_dir = false;
        let paths = AppPaths {
            config_file: root.path().join("config.toml"),
            data_dir: root.path().to_path_buf(),
            database: root.path().join("state.db"),
            reports_dir: root.path().join("reports"),
            logs_dir: root.path().join("logs"),
            quarantine_dir: root.path().join("quarantine"),
            rules_dir: root.path().join("rules"),
        };
        paths.ensure().unwrap();
        let database = Database::open(&paths.database).unwrap();
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: source.to_string_lossy().into_owned(),
            sha256: Some(hash.clone()),
            size: bytes.len() as u64,
            ..FileEvidence::default()
        });
        report.verdict = Verdict::Suspicious;
        report.policy.action = PolicyAction::RequireReview;
        report
            .policy
            .reasons
            .push("Suspicious test evidence".into());
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
        restore_quarantine_from_desktop(&database, &config, &paths, &hash, "restored.exe").unwrap();

        let snapshot = load_snapshot(&config, &database, &paths).unwrap();
        assert_eq!(snapshot.questionable.len(), 1);
        assert_eq!(snapshot.questionable[0].summary.file_name, "restored.exe");
        assert_eq!(snapshot.questionable[0].summary.user_decision, None);
    }
