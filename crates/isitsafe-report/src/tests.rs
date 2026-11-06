    use super::*;

    #[test]
    fn report_schema_is_versioned_and_stable_json() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: "download.exe".into(),
            size: 7,
            ..FileEvidence::default()
        });
        report.source_path = Some(std::path::PathBuf::from(r"C:\secret\download.exe"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["limitations_notice"], LIMITATION_NOTICE);
        assert_eq!(json["products"], serde_json::json!([]));
        assert!(json.get("source_path").is_none());
    }

    #[test]
    fn report_summary_carries_concise_reasons_without_full_inventory() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Downloads\setup.exe".into(),
            size: 42,
            sha256: Some("a".repeat(64)),
            ..FileEvidence::default()
        });
        report.verdict = Verdict::Suspicious;
        report
            .policy
            .reasons
            .push("Unsigned executable\nwith remote-access behavior".into());
        report
            .policy
            .reasons
            .push("Waiting for a Keep, Quarantine, or Remove notification action".into());
        report
            .policy
            .reasons
            .push("The user restored the file to Downloads as setup.exe".into());
        let summary = report.summary();
        assert_eq!(summary.file_name, "setup.exe");
        assert_eq!(summary.verdict, Verdict::Suspicious);
        assert_eq!(
            summary.reasons,
            vec!["Unsigned executable\\nwith remote-access behavior"]
        );
        let json = serde_json::to_value(summary).unwrap();
        assert!(json.get("components").is_none());
    }

    #[test]
    fn report_summary_includes_expired_certificate_state() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Downloads\metadata.winmd".into(),
            ..FileEvidence::default()
        });
        report.authenticity = Some(AuthenticityEvidence {
            signature_digest_valid: Some(true),
            chain_valid: Some(true),
            timestamp_state: TimestampState::Unknown,
            ..AuthenticityEvidence::default()
        });
        report.certificates.push(CertificateChainEvidence {
            subject: "CN=Example Publisher".into(),
            issuer: "CN=Example Root".into(),
            serial_number: "01".into(),
            sha256_fingerprint: "a".repeat(64),
            ocsp_urls: Vec::new(),
            crl_urls: Vec::new(),
            role: CertificateRole::Leaf,
            root_trusted: Some(true),
            timestamp_present: true,
            timestamp_time: None,
            not_before: Some(Utc::now() - chrono::Duration::days(365)),
            not_after: Some(Utc::now() - chrono::Duration::days(1)),
            revocation: RevocationEvidence {
                state: RevocationState::Valid,
                ..RevocationEvidence::default()
            },
        });
        report
            .policy
            .reasons
            .push("Some required network reputation checks are not complete".into());

        assert_eq!(
            report.summary().reasons,
            vec![
                "Some required network reputation checks are not complete",
                "Certificate has expired"
            ]
        );
    }

    #[test]
    fn legacy_product_identity_without_signer_fields_deserializes() {
        let product: ProductIdentityEvidence = serde_json::from_value(serde_json::json!({
            "product_name": "Legacy Product",
            "manufacturer": "Example Corp",
            "product_version": "1.0",
            "product_code": null,
            "upgrade_code": null,
            "original_filename": "legacy.exe",
            "file_description": "Legacy executable",
            "legal_copyright": null,
            "source": "PE version information",
            "nesting_path": "legacy.exe"
        }))
        .unwrap();

        assert_eq!(product.product_name.as_deref(), Some("Legacy Product"));
        assert!(product.signer_identity.is_none());
        assert!(product.signer_sha256.is_none());
        assert!(product.signature_digest_valid.is_none());
    }

    #[test]
    fn legacy_certificate_evidence_without_validity_dates_deserializes() {
        let certificate: CertificateChainEvidence = serde_json::from_value(serde_json::json!({
            "subject": "CN=Legacy Publisher",
            "issuer": "CN=Legacy Root",
            "serial_number": "01",
            "sha256_fingerprint": "a".repeat(64),
            "ocsp_urls": [],
            "crl_urls": [],
            "role": "leaf",
            "root_trusted": true,
            "timestamp_present": false,
            "timestamp_time": null,
            "revocation": {
                "state": "not_checked",
                "source": null,
                "this_update": null,
                "next_update": null,
                "detail": null
            }
        }))
        .unwrap();

        assert!(certificate.not_before.is_none());
        assert!(certificate.not_after.is_none());
    }
