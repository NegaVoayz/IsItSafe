    #[test]
    fn one_software_identity_can_contain_multiple_certificate_groups() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\runtime.zip".into(),
            ..FileEvidence::default()
        });
        for (filename, fingerprint) in [("alpha.dll", "1"), ("beta.dll", "2")] {
            report.products.push(ProductIdentityEvidence {
                product_name: Some("Example Runtime".into()),
                manufacturer: Some("Example Corporation".into()),
                product_version: Some("14.0".into()),
                signer_identity: Some(format!("CN=Example Publisher {fingerprint}")),
                signer_sha256: Some(fingerprint.repeat(64)),
                signature_digest_valid: Some(true),
                nesting_path: Some(filename.into()),
                ..ProductIdentityEvidence::default()
            });
        }

        let groups = group_products_by_software(&report);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].product_name, "Example Runtime");
        assert_eq!(
            groups[0].manufacturer.as_deref(),
            Some("Example Corporation")
        );
        assert_eq!(groups[0].certificates.len(), 2);
    }

    #[test]
    fn software_identities_sort_by_risk_then_name() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\bundle.zip".into(),
            ..FileEvidence::default()
        });
        for (name, fingerprint, digest_valid) in [
            ("Valid Product", Some("1".repeat(64)), Some(true)),
            ("Another Valid Product", Some("4".repeat(64)), Some(true)),
            ("Unsigned Product", None, None),
            ("Unverified Product", Some("2".repeat(64)), None),
            ("Invalid Product", Some("3".repeat(64)), Some(false)),
        ] {
            report.products.push(ProductIdentityEvidence {
                product_name: Some(name.into()),
                signer_identity: fingerprint.as_ref().map(|_| format!("CN={name} Publisher")),
                signer_sha256: fingerprint,
                signature_digest_valid: digest_valid,
                nesting_path: Some(format!("{name}.exe")),
                ..ProductIdentityEvidence::default()
            });
        }
        report.components.push(crate::report::ComponentEvidence {
            nesting_path: "Unsigned Product.exe".into(),
            name: "Unsigned Product.exe".into(),
            size: 1,
            sha256: None,
            formats: Vec::new(),
            severity: Severity::High,
            signed: Some(false),
            evidence: Vec::new(),
        });

        let groups = group_products_by_software(&report);
        assert_eq!(
            groups
                .iter()
                .map(SoftwareIdentityGroup::risk_state)
                .collect::<Vec<_>>(),
            vec![
                SignatureState::Invalid,
                SignatureState::Unsigned,
                SignatureState::Unverified,
                SignatureState::Valid,
                SignatureState::Valid,
            ]
        );
        assert_eq!(
            groups[3..]
                .iter()
                .map(|group| group.product_name.as_str())
                .collect::<Vec<_>>(),
            vec!["Another Valid Product", "Valid Product"]
        );
        assert!(groups[3..].iter().all(|group| !group.starts_expanded()));
        assert!(
            groups[..3]
                .iter()
                .all(SoftwareIdentityGroup::starts_expanded)
        );
    }

    #[test]
    fn expired_signer_metadata_takes_precedence_over_a_valid_digest() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\expired.exe".into(),
            ..FileEvidence::default()
        });
        report.products.push(ProductIdentityEvidence {
            product_name: Some("Expired Product".into()),
            signer_identity: Some("CN=Expired Publisher".into()),
            signer_sha256: Some("e".repeat(64)),
            signature_digest_valid: Some(true),
            signature_not_before: Some(Utc::now() - chrono::Duration::days(30)),
            signature_not_after: Some(Utc::now() - chrono::Duration::days(1)),
            nesting_path: Some("expired.exe".into()),
            ..ProductIdentityEvidence::default()
        });

        let groups = group_products_by_software(&report);
        assert_eq!(groups[0].certificates[0].state, SignatureState::Expired);
    }

