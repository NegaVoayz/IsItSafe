    #[test]
    fn software_identities_group_carriers_before_certificates() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\bundle.zip".into(),
            sha256: Some("a".repeat(64)),
            ..FileEvidence::default()
        });
        let signed_product = |name: &str, path: &str| ProductIdentityEvidence {
            product_name: Some(name.into()),
            signer_identity: Some("C=US, O=Example Corp, CN=Example Corp Code Signing".into()),
            signer_sha256: Some("b".repeat(64)),
            signature_digest_valid: Some(true),
            nesting_path: Some(path.into()),
            ..ProductIdentityEvidence::default()
        };
        report
            .products
            .push(signed_product("Example App", "Example.exe"));
        report
            .products
            .push(signed_product("Example App", "Example.dll"));
        report.products.push(ProductIdentityEvidence {
            product_name: Some("Hidden Payload".into()),
            nesting_path: Some("payload.dll".into()),
            ..ProductIdentityEvidence::default()
        });
        report.components.push(crate::report::ComponentEvidence {
            nesting_path: "Example.exe".into(),
            name: "Example.exe".into(),
            size: 1,
            sha256: Some("c".repeat(64)),
            formats: Vec::new(),
            severity: Severity::Info,
            signed: Some(true),
            evidence: Vec::new(),
        });
        report.components.push(crate::report::ComponentEvidence {
            nesting_path: "payload.dll".into(),
            name: "payload.dll".into(),
            size: 1,
            sha256: Some("d".repeat(64)),
            formats: Vec::new(),
            severity: Severity::High,
            signed: Some(false),
            evidence: Vec::new(),
        });

        let groups = group_products_by_software(&report);
        let signed = groups
            .iter()
            .find(|group| group.product_name == "Example App")
            .expect("signed software");
        assert_eq!(signed.manufacturer.as_deref(), None);
        assert_eq!(signed.certificates.len(), 1);
        assert_eq!(signed.certificates[0].signer, "Example Corp Code Signing");
        assert_eq!(signed.certificates[0].products.len(), 2);
        assert_eq!(signed.certificates[0].state, SignatureState::Valid);
        let unsigned = groups
            .iter()
            .find(|group| group.product_name == "Hidden Payload")
            .expect("unsigned software");
        assert_eq!(unsigned.certificates[0].state, SignatureState::Unsigned);
        assert_eq!(unsigned.certificates[0].products.len(), 1);
    }

    #[test]
    fn signature_status_labels_are_compact() {
        assert_eq!(SignatureState::Valid.label(), "Valid");
        assert_eq!(SignatureState::Unsigned.label(), "Unsigned");
        assert_eq!(SignatureState::Revoked.label(), "Revoked");
        assert_eq!(SignatureState::Expired.label(), "Expired");
        assert_eq!(SignatureState::NotYetValid.label(), "Not Yet Valid");
    }

    #[test]
    fn certificate_risk_orders_revoked_unsigned_then_expired() {
        assert!(SignatureState::Revoked.risk_rank() < SignatureState::Unsigned.risk_rank());
        assert!(SignatureState::Unsigned.risk_rank() < SignatureState::Expired.risk_rank());
        assert!(SignatureState::Expired.risk_rank() < SignatureState::Valid.risk_rank());

        let mut group = SoftwareIdentityGroup {
            product_name: "Example".into(),
            manufacturer: None,
            product_version: None,
            certificates: Vec::new(),
        };
        for state in [
            SignatureState::Expired,
            SignatureState::Unsigned,
            SignatureState::Revoked,
        ] {
            group.certificates.push(SignatureGroup {
                signer: format!("{state:?}"),
                certificate_sha256: None,
                state,
                not_before: None,
                not_after: None,
                products: Vec::new(),
            });
        }
        assert_eq!(group.risk_state(), SignatureState::Revoked);
    }

