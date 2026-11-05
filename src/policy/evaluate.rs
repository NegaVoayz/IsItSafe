pub fn evaluate(report: &mut AnalysisReportV1, config: &Config) {
    report.policy.reasons.clear();
    report.policy.allowlist_downgraded = allowlisted(report, config);

    let confirmed_malicious = report
        .reputation
        .iter()
        .any(|entry| entry.state == ReputationState::Malicious);
    let vt_suspicious = report
        .reputation
        .iter()
        .any(|entry| entry.state == ReputationState::Suspicious);
    let certificate_problem = report.certificate_problem_reason();
    let high_evidence = report
        .facts
        .iter()
        .any(|evidence| evidence.severity >= Severity::High);
    let remote_access = report
        .authenticity
        .as_ref()
        .is_some_and(|value| value.publisher_reputation == PublisherReputation::RemoteAccess)
        || report.components.iter().any(|component| {
            component
                .evidence
                .iter()
                .any(|evidence| evidence.category == "remote_access")
        });
    let sensitive_endpoint = report.facts.iter().any(|evidence| {
        matches!(
            evidence.category.as_str(),
            "remote_access_endpoint" | "autostart" | "credential_material"
        )
    });
    let blocked_origin = report.origin.source_url.as_deref().is_some_and(|url| {
        config
            .policy
            .blocked_origins
            .iter()
            .any(|blocked| origin_matches(url, blocked, None))
    });
    let review_origin = report.origin.source_url.as_deref().is_some_and(|url| {
        config
            .policy
            .review_origins
            .iter()
            .any(|review| origin_matches(url, review, None))
    });
    let browser_danger = report
        .origin
        .browser_danger
        .as_deref()
        .is_some_and(|danger| {
            matches!(
                danger.to_ascii_lowercase().as_str(),
                "dangerous" | "untrusted" | "unwanted" | "uncommon"
            )
        });
    let incomplete = report.boundaries.iter().any(|boundary| {
        matches!(
            boundary.kind,
            BoundaryKind::LockAcquisitionTimeout
                | BoundaryKind::LockNotAvailable
                | BoundaryKind::ReadOnlyContent
                | BoundaryKind::FileChangedDuringRead
                | BoundaryKind::OutputTruncated
                | BoundaryKind::BudgetExceeded
                | BoundaryKind::ChildCrashed
                | BoundaryKind::ChildTimedOut
                | BoundaryKind::ChildKilledByJob
                | BoundaryKind::SandboxViolation
                | BoundaryKind::QuarantineFailed
                | BoundaryKind::RemovalFailed
        )
    });
    let downgraded = report.boundaries.iter().any(|boundary| {
        matches!(
            boundary.kind,
            BoundaryKind::BasicCheckOnly | BoundaryKind::Limited
        )
    });
    let query_pending = report.reputation.iter().any(|entry| {
        matches!(
            entry.state,
            ReputationState::Pending | ReputationState::RateLimited
        )
    });
    let reputation_unavailable = report.reputation.iter().any(|entry| {
        matches!(
            entry.state,
            ReputationState::Unavailable | ReputationState::NotQueried
        )
    });
    let is_ooxml = report
        .classification
        .formats
        .iter()
        .any(|format| format.kind.starts_with("ooxml:"));
    let high_risk_type = report.classification.extension_mismatch
        || report.classification.risky_trailing_data
        || report.classification.formats.iter().any(|format| {
            (format.kind != "zip" || !is_ooxml)
                && (matches!(
                    format.kind.as_str(),
                    "pe" | "msi"
                        | "ole_cfb"
                        | "zip"
                        | "cab"
                        | "7z"
                        | "rar"
                        | "powershell"
                        | "batch"
                        | "vbscript"
                        | "javascript"
                        | "hta"
                        | "lnk"
                        | "svg"
                ) || format.kind.starts_with("installer:"))
        });

    if confirmed_malicious {
        report.verdict = Verdict::Malicious;
        report.policy.action = if config.policy.quarantine_enabled {
            PolicyAction::Quarantine
        } else {
            PolicyAction::Notify
        };
        report
            .policy
            .reasons
            .push("VirusTotal reported one or more malicious detections".into());
    } else if vt_suspicious {
        report.verdict = Verdict::Suspicious;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("VirusTotal reported suspicious detections".into());
    } else if let Some(reason) = certificate_problem {
        report.verdict = Verdict::Suspicious;
        report.policy.action = review_action(config);
        report.policy.reasons.push(reason.into());
    } else if high_evidence || blocked_origin || browser_danger {
        report.verdict = Verdict::Suspicious;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("High-severity structural evidence was found".into());
    } else if (remote_access && sensitive_endpoint) || review_origin {
        report.verdict = Verdict::ReviewRequired;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("The installer combines review-required origin or remote-access behavior".into());
    } else if incomplete {
        report.verdict = Verdict::Incomplete;
        report.policy.action = review_action(config);
        report
            .policy
            .reasons
            .push("One or more safety checks did not complete".into());
    } else if downgraded {
        report.verdict = if report.threshold_decisions.basic_check_only {
            Verdict::BasicCheckOnly
        } else {
            Verdict::Limited
        };
        report.policy.action = PolicyAction::Notify;
        report
            .policy
            .reasons
            .push("The file exceeded a deep-analysis resource threshold".into());
    } else if query_pending || (high_risk_type && reputation_unavailable) {
        report.verdict = Verdict::Unverified;
        report.policy.action = PolicyAction::Notify;
        report
            .policy
            .reasons
            .push("Some required network reputation checks are not complete".into());
    } else {
        report.verdict = Verdict::NoHighRiskFound;
        report.policy.action = PolicyAction::NoAction;
        report
            .policy
            .reasons
            .push("No high-risk evidence was found by completed checks".into());
    }

    if report.policy.allowlist_downgraded && report.verdict != Verdict::Malicious {
        report.policy.reasons.push(
            "A configured origin/signer allowlist downgraded the notification level; checks were not skipped"
                .into(),
        );
        if report.policy.action != PolicyAction::NoAction {
            report.policy.action = PolicyAction::Notify;
            report.policy.quarantine_requested = false;
        }
    }

    if report.policy.action == PolicyAction::Quarantine {
        report.policy.quarantine_requested = true;
    }
}

fn review_action(config: &Config) -> PolicyAction {
    if config.policy.quarantine_enabled && config.policy.quarantine_review_required {
        PolicyAction::Quarantine
    } else {
        PolicyAction::RequireReview
    }
}

