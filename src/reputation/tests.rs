    use super::*;

    #[test]
    fn parses_vt_stats() {
        let body = serde_json::json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "undetected": 10,
                        "harmless": 0
                    },
                    "signature_info": {"product": "Example"}
                }
            }
        });
        let evidence = parse_cached(&"a".repeat(64), &body, Utc::now());
        assert_eq!(evidence.state, ReputationState::Malicious);
        assert_eq!(evidence.detections, Some(3));
    }

    #[test]
    fn large_files_trigger_prechild_lookup() {
        let mut config = Config::default();
        config.limits.snapshot_max_bytes = 10;
        config.limits.basic_check_threshold_bytes = 20;
        let triggers = pre_child_triggers(
            &Classification::default(),
            MotwState::Absent,
            21,
            &OriginEvidence::default(),
            &config,
        );
        assert!(triggers.contains(&PreChildTrigger::AboveThreshold));
    }
