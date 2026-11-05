    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::report::{
        AnalysisReportV1, AuthenticityEvidence, Confidence, DetectedFormat, Evidence, FileEvidence,
        ReputationEvidence, TimestampState, VtBatch,
    };

    #[test]
    fn vt_malicious_is_terminal() {
        let mut report = AnalysisReportV1::new(FileEvidence::default());
        report.reputation.push(ReputationEvidence {
            sha256: "a".repeat(64),
            state: ReputationState::Malicious,
            vt_batch: Some(VtBatch::PreChild),
            used_by_batch: vec![VtBatch::PreChild],
            detections: Some(12),
            engines_total: Some(70),
            checked_at: Some(Utc::now()),
            signature_info: Vec::new(),
            detail: None,
        });
        let config = Config::default();
        evaluate(&mut report, &config);
        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.policy.action, PolicyAction::Quarantine);
        assert_ne!(report.report_id, Uuid::nil());
    }

    #[test]
    fn invalid_certificate_chain_requires_review() {
        let mut report = AnalysisReportV1::new(FileEvidence::default());
        report.authenticity = Some(AuthenticityEvidence {
            signature_digest_valid: Some(true),
            chain_valid: Some(false),
            timestamp_state: TimestampState::Unknown,
            ..AuthenticityEvidence::default()
        });

        evaluate(&mut report, &Config::default());

        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_eq!(report.policy.action, PolicyAction::RequireReview);
        assert_eq!(report.policy.reasons, vec!["Certificate chain is invalid"]);
    }

    #[test]
    fn expired_certificate_is_reported_without_escalating_the_verdict() {
        let mut report = AnalysisReportV1::new(FileEvidence::default());
        report.authenticity = Some(AuthenticityEvidence {
            signature_digest_valid: Some(true),
            chain_valid: Some(false),
            timestamp_state: TimestampState::Invalid,
            ..AuthenticityEvidence::default()
        });

        evaluate(&mut report, &Config::default());

        assert_eq!(report.verdict, Verdict::NoHighRiskFound);
        assert!(
            !report
                .policy
                .reasons
                .iter()
                .any(|reason| reason.contains("expired"))
        );
        assert_eq!(
            report.certificate_state_reason(),
            Some("Certificate has expired")
        );
    }

    #[test]
    fn ordinary_ooxml_does_not_require_a_network_verdict() {
        let mut report = AnalysisReportV1::new(FileEvidence::default());
        report.classification.formats.push(DetectedFormat {
            kind: "zip".into(),
            offset: 0,
            confidence: Confidence::Structural,
            parser: "zip".into(),
        });
        report.classification.formats.push(DetectedFormat {
            kind: "ooxml:pptx".into(),
            offset: 0,
            confidence: Confidence::Structural,
            parser: "ooxml".into(),
        });
        report.reputation.push(ReputationEvidence {
            sha256: "a".repeat(64),
            state: ReputationState::NotQueried,
            vt_batch: None,
            used_by_batch: Vec::new(),
            detections: None,
            engines_total: None,
            checked_at: None,
            signature_info: Vec::new(),
            detail: Some("no pre-child VirusTotal trigger applied".into()),
        });

        evaluate(&mut report, &Config::default());

        assert_eq!(report.verdict, Verdict::NoHighRiskFound);
        assert_eq!(report.policy.action, PolicyAction::NoAction);
    }

    #[test]
    fn active_ooxml_content_remains_high_risk_without_a_network_verdict() {
        let mut report = AnalysisReportV1::new(FileEvidence::default());
        report.classification.formats.push(DetectedFormat {
            kind: "zip".into(),
            offset: 0,
            confidence: Confidence::Structural,
            parser: "zip".into(),
        });
        report.classification.formats.push(DetectedFormat {
            kind: "ooxml:docm".into(),
            offset: 0,
            confidence: Confidence::Structural,
            parser: "ooxml".into(),
        });
        report.facts.push(Evidence {
            id: "ooxml:macro".into(),
            category: "ooxml_macro".into(),
            severity: Severity::High,
            summary: "Office package contains a VBA macro project".into(),
            detail: None,
            provenance: "child OOXML package inventory".into(),
            confidence: Confidence::Structural,
        });
        report.reputation.push(ReputationEvidence {
            sha256: "a".repeat(64),
            state: ReputationState::NotQueried,
            vt_batch: None,
            used_by_batch: Vec::new(),
            detections: None,
            engines_total: None,
            checked_at: None,
            signature_info: Vec::new(),
            detail: Some("no pre-child VirusTotal trigger applied".into()),
        });

        evaluate(&mut report, &Config::default());

        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_eq!(report.policy.action, PolicyAction::RequireReview);
    }

    #[test]
    fn quarantine_name_is_searchable_and_not_a_path() {
        let name = quarantine_file_name(
            Path::new(r"C:\Users\example\Downloads\setup.exe"),
            &"a".repeat(64),
            0,
        );
        assert_eq!(name, "setup.exe.aaaaaaaaaaaa.quarantined");
        assert!(!name.contains(['/', '\\']));
    }

    #[test]
    fn verified_removal_requires_the_reviewed_hash() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("sample.bin");
        fs::write(&source, b"reviewed bytes").unwrap();
        let config = Config {
            download_dir: directory.path().to_path_buf(),
            ..Config::default()
        };
        let captured = capture(&source, &config).unwrap();
        let mut report = AnalysisReportV1::new(captured.file);
        report.source_path = Some(source.clone());
        report.file.sha256 = Some("0".repeat(64));

        let error = remove_verified(&report, &config).unwrap_err();
        assert!(error.to_string().contains("source changed"));
        assert!(source.exists());
    }

    #[test]
    fn verified_removal_deletes_matching_content() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("sample.bin");
        fs::write(&source, b"reviewed bytes").unwrap();
        let config = Config {
            download_dir: directory.path().to_path_buf(),
            ..Config::default()
        };
        let captured = capture(&source, &config).unwrap();
        let mut report = AnalysisReportV1::new(captured.file);
        report.source_path = Some(source.clone());

        remove_verified(&report, &config).unwrap();
        assert!(!source.exists());
    }

    #[test]
    fn protected_destination_detection_is_case_insensitive_and_direct_child_safe() {
        assert!(path_is_under(
            Path::new(r"c:\users\me\downloads\SETUP.EXE"),
            Path::new(r"C:\Users\Me\Downloads")
        ));
        assert!(!path_is_under(
            Path::new(r"C:\Users\Me\Downloads-old\setup.exe"),
            Path::new(r"C:\Users\Me\Downloads")
        ));
    }
