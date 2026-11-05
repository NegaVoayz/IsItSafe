    use super::*;
    use crate::interaction::{
        DecisionSource, execute_user_decision, restore_quarantine_from_desktop,
    };
    use crate::report::{AnalysisReportV1, FileEvidence, PolicyAction, UserDecision};
    use sha2::{Digest, Sha256};

    #[test]
    fn risk_groups_cover_every_review_verdict() {
        assert_eq!(
            RiskGroup::from_verdict(Verdict::Malicious),
            RiskGroup::Critical
        );
        assert_eq!(
            RiskGroup::from_verdict(Verdict::Suspicious),
            RiskGroup::High
        );
        assert_eq!(
            RiskGroup::from_verdict(Verdict::Incomplete),
            RiskGroup::Review
        );
        assert_eq!(
            RiskGroup::from_verdict(Verdict::BasicCheckOnly),
            RiskGroup::Limited
        );
    }

    #[test]
    fn quarantine_name_recovers_the_searchable_original_name() {
        assert_eq!(
            quarantine_original_name(Path::new(
                r"C:\data\quarantine\setup.exe.abcdef123456.quarantined"
            )),
            "setup.exe"
        );
        assert_eq!(
            quarantine_original_name(Path::new(
                r"C:\data\quarantine\setup.exe.abcdef123456-2.quarantined"
            )),
            "setup.exe"
        );
    }

    #[test]
    fn review_reasons_are_short_labels() {
        assert_eq!(
            compact_reason("VirusTotal: 3/93 engines flagged this file"),
            "VirusTotal 3/93"
        );
        assert_eq!(
            compact_reason("VirusTotal reported one or more malicious detections"),
            "VirusTotal: malicious"
        );
        assert_eq!(
            compact_reason(
                "Downloaded file name ddu.exe differs from embedded original filename SqlSetupBootstrapper.exe"
            ),
            "Name differs from embedded file"
        );
        assert_eq!(
            compact_reason("File extension .jpg does not match its contents (detected: pe)"),
            "Extension does not match content"
        );
        assert_eq!(
            compact_reason("The file exceeded a deep-analysis resource threshold"),
            "Too large for deep scan"
        );
        assert_eq!(
            compact_reason(
                "Potential decompression bomb: payload.dat, ratio 1026:1, 6731776 bytes declared"
            ),
            "Possible zip bomb"
        );
        assert_eq!(
            compact_reason(
                "vcomp140.dll uses a .dll extension but its PE header marks it as an EXE"
            ),
            "EXE hidden as .dll"
        );
        assert_eq!(
            compact_reason("patch.dat is a PE executable disguised with the .dat extension"),
            "Executable hidden as .dat"
        );
        assert_eq!(
            compact_reason("SqlSetupBootstrapper.dll is an EXE disguised as .dll"),
            "EXE hidden as .dll"
        );
        assert_eq!(
            compact_reason("metadata.dat is a DLL disguised as .dat"),
            "DLL hidden as .dat"
        );
        assert_eq!(
            compact_reason("payload.metadata has no file extension but is an EXE"),
            "EXE without extension"
        );
        assert_eq!(
            compact_reason("Certificate is expired or invalid"),
            "Expired certificate"
        );
        assert_eq!(
            compact_reason("Certificate has expired"),
            "Expired certificate"
        );
        assert_eq!(
            compact_reason("Certificate chain is invalid"),
            "Invalid certificate chain"
        );
        assert_eq!(
            compact_reason("Certificate is revoked"),
            "Revoked certificate"
        );
        assert_eq!(
            compact_reason("file exceeds snapshot_max_bytes (536870912)"),
            ""
        );
    }

    #[test]
    fn reputation_subjects_name_the_download_or_embedded_file() {
        let mut report = AnalysisReportV1::new(FileEvidence {
            display_path: r"C:\Users\example\Downloads\bundle.zip".into(),
            sha256: Some("a".repeat(64)),
            ..FileEvidence::default()
        });
        report.components.push(crate::report::ComponentEvidence {
            nesting_path: "bundle/tool.exe".into(),
            name: "bundle/tool.exe".into(),
            size: 1,
            sha256: Some("b".repeat(64)),
            formats: Vec::new(),
            severity: Severity::Info,
            signed: None,
            evidence: Vec::new(),
        });

        assert_eq!(
            reputation_subject(&report, &"a".repeat(64)),
            "Download file: bundle.zip"
        );
        assert_eq!(
            reputation_subject(&report, &"B".repeat(64)),
            "Inside: bundle/tool.exe"
        );
        assert_eq!(
            reputation_subject(&report, &"c".repeat(64)),
            "Hash: cccccccccccc..."
        );
    }

