    #[cfg(feature = "yara")]
    #[test]
    fn yara_matches_are_evidence_not_execution() {
        let analysis = analyze_bytes_with_rules(
            Path::new("script.txt"),
            b"Invoke-WebRequest https://example.invalid/a.exe",
            &limits(),
            true,
            None,
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "yara_match")
        );
    }
