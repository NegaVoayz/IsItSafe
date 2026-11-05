    use super::*;

    #[test]
    fn database_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("state.db")).unwrap();
        let observation = Observation {
            path: "C:\\Downloads\\a.exe".into(),
            volume_identity: Some("1".into()),
            file_id: Some("2".into()),
            size: 42,
            modified_ns: None,
            sha256: Some("abc".into()),
            state: "complete".into(),
            updated_at: Utc::now(),
        };
        db.upsert_observation(&observation).unwrap();
        assert_eq!(db.observation(&observation.path).unwrap().unwrap().size, 42);
    }

    #[test]
    fn origin_correlation_handles_file_event_first() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("state.db")).unwrap();
        assert!(
            db.find_origin("C:\\Downloads\\first.exe", Duration::from_secs(60))
                .unwrap()
                .is_none()
        );
        db.insert_origin(&DownloadOrigin {
            schema_version: 1,
            download_id: "download-1".into(),
            source_url: "https://example.invalid/file".into(),
            final_url: Some("https://cdn.example.invalid/file.exe".into()),
            referrer: Some("https://example.invalid/".into()),
            final_path: "C:\\Downloads\\first.exe".into(),
            timestamp: Utc::now(),
            expected_size: Some(10),
            browser_danger: Some("safe".into()),
        })
        .unwrap();
        let found = db
            .find_origin("c:/downloads/FIRST.EXE", Duration::from_secs(60))
            .unwrap()
            .unwrap();
        assert_eq!(found.download_id, "download-1");
    }

    #[test]
    fn latest_summary_and_quarantine_reason_are_linked_to_the_report() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("state.db")).unwrap();
        let path = directory.path().join("bad.exe");
        fs::write(&path, b"sample").unwrap();
        let mut older = AnalysisReportV1::new(crate::report::FileEvidence {
            display_path: path.to_string_lossy().into_owned(),
            sha256: Some("a".repeat(64)),
            size: 6,
            ..crate::report::FileEvidence::default()
        });
        older.verdict = Verdict::Suspicious;
        older.policy.reasons.push("older reason".into());
        db.store_report(&older).unwrap();

        let mut current = AnalysisReportV1::new(crate::report::FileEvidence {
            display_path: path.to_string_lossy().into_owned(),
            sha256: Some("b".repeat(64)),
            size: 7,
            ..crate::report::FileEvidence::default()
        });
        current.verdict = Verdict::Malicious;
        current
            .policy
            .reasons
            .push("current malicious reason".into());
        db.store_report(&current).unwrap();

        let summaries = db.latest_report_summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].report_id, current.report_id);
        assert_eq!(summaries[0].reasons, vec!["current malicious reason"]);

        let quarantine_path = directory.path().join("bad.exe.aaaaaaaaaaaa.quarantined");
        db.quarantine_record("a".repeat(64).as_str(), &quarantine_path, older.report_id)
            .unwrap();
        let entries = db.list_quarantine_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].report_id, Some(older.report_id));
        assert_eq!(
            entries[0].summary.as_ref().unwrap().reasons,
            vec!["older reason"]
        );
    }

    #[test]
    fn latest_summaries_refresh_after_the_summary_schema_changes() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("state.db")).unwrap();
        let mut report = AnalysisReportV1::new(crate::report::FileEvidence {
            display_path: directory
                .path()
                .join("metadata.winmd")
                .to_string_lossy()
                .into_owned(),
            ..crate::report::FileEvidence::default()
        });
        report.authenticity = Some(crate::report::AuthenticityEvidence {
            signature_digest_valid: Some(true),
            chain_valid: Some(true),
            timestamp_state: crate::report::TimestampState::Unknown,
            ..crate::report::AuthenticityEvidence::default()
        });
        report
            .certificates
            .push(crate::report::CertificateChainEvidence {
                subject: "CN=Example Publisher".into(),
                issuer: "CN=Example Root".into(),
                serial_number: "01".into(),
                sha256_fingerprint: "a".repeat(64),
                ocsp_urls: Vec::new(),
                crl_urls: Vec::new(),
                role: crate::report::CertificateRole::Leaf,
                root_trusted: Some(true),
                timestamp_present: true,
                timestamp_time: None,
                not_before: Some(Utc::now() - chrono::Duration::days(365)),
                not_after: Some(Utc::now() - chrono::Duration::days(1)),
                revocation: crate::report::RevocationEvidence {
                    state: crate::report::RevocationState::Valid,
                    ..crate::report::RevocationEvidence::default()
                },
            });
        db.store_report(&report).unwrap();

        let mut old_summary = report.summary();
        old_summary.schema_version = "1.0".into();
        old_summary.reasons = vec!["Online reputation incomplete".into()];
        db.connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE reports SET summary_json=?1 WHERE report_id=?2",
                params![
                    serde_json::to_string(&old_summary).unwrap(),
                    report.report_id.to_string()
                ],
            )
            .unwrap();

        let summaries = db.latest_report_summaries().unwrap();

        assert_eq!(summaries[0].schema_version, REPORT_SUMMARY_SCHEMA_VERSION);
        assert_eq!(summaries[0].reasons, vec!["Certificate has expired"]);
    }
