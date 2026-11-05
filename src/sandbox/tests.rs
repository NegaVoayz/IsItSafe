    use super::*;
    use crate::report::{Confidence, Evidence, Severity};

    #[test]
    fn oversized_output_remains_valid_json_and_is_incomplete() {
        let mut analysis = ChildAnalysis::default();
        for index in 0..200 {
            analysis.facts.push(Evidence {
                id: format!("fact:{index}"),
                category: "test".into(),
                severity: Severity::Low,
                summary: "x".repeat(200),
                detail: Some("detail".repeat(100)),
                provenance: "test".into(),
                confidence: Confidence::Inferred,
            });
        }
        let bytes = serialize_bounded(analysis, 4096).unwrap();
        assert!(bytes.len() <= 4096);
        let decoded: ChildAnalysis = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.output_truncated);
        assert!(decoded.facts.is_empty() || decoded.facts.iter().all(|item| item.detail.is_none()));
    }
