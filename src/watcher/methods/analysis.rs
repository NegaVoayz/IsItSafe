impl Watcher {
    fn analyze_captured(&self, captured: CapturedFile) -> Result<AnalysisReportV1> {
        let mut report = AnalysisReportV1::new(captured.file.clone());
        report.source_path = Some(captured.path.clone());
        report.threshold_decisions = captured.thresholds.clone();
        report.lock_acquisition = captured.lock.clone();
        report.motw = captured.motw.clone();
        report.alternate_streams = captured.alternate_streams.clone();
        report.boundaries = captured.boundaries.clone();
        report.origin = origin::correlate(
            &self.database,
            &captured.path,
            captured.sha256.as_deref(),
            &self.config,
        )?;

        let sniff_result = sniff(
            &captured.path,
            &captured.head,
            &captured.tail,
            captured.file.size,
        );
        report.classification = sniff_result.classification.clone();
        report.facts.extend(sniff_result.evidence);
        let pre_triggers = pre_child_triggers(
            &report.classification,
            report.motw.state,
            captured.file.size,
            &report.origin,
            &self.config,
        );
        let reputation = ReputationManager::new(&self.config, &self.database)?;
        if let Some(hash) = &captured.sha256 {
            if !pre_triggers.is_empty() || captured.depth == CaptureDepth::BasicCheckOnly {
                let evidence = reputation.query(hash, VtBatch::PreChild)?;
                reputation.merge_result(&mut report.reputation, evidence);
            } else {
                report.reputation.push(crate::report::ReputationEvidence {
                    sha256: hash.clone(),
                    state: ReputationState::NotQueried,
                    vt_batch: None,
                    used_by_batch: Vec::new(),
                    detections: None,
                    engines_total: None,
                    checked_at: None,
                    signature_info: Vec::new(),
                    detail: Some("no pre-child VirusTotal trigger applied".into()),
                });
            }
        }
        let vt_malicious = report
            .reputation
            .iter()
            .any(|entry| entry.state == ReputationState::Malicious);
        if !vt_malicious
            && captured.depth == CaptureDepth::Deep
            && let Some(snapshot) = &captured.snapshot
        {
            let custom_rules = if self.config.yara.enabled {
                rules::load_active_rules(&self.paths, 16 * 1024 * 1024)?
            } else {
                None
            };
            let sandbox = run_sandboxed(
                &self.config,
                &captured.path,
                snapshot,
                custom_rules.as_deref(),
            )?;
            report.child_execution = Some(sandbox.execution);
            report.boundaries.extend(sandbox.boundaries);
            if let Some(child) = sandbox.analysis {
                self.merge_child(&mut report, child);
            } else if let Some(error) = sandbox.error {
                report.add_boundary(BoundaryKind::ChildCrashed, error);
            }
        }
        self.apply_signer_categories(&mut report);
        revocation::update_revocation(&mut report, &self.config)?;

        if let Some(hash) = &captured.sha256 {
            let mut candidates =
                post_child_candidates(&report.components, report.authenticity.as_ref());
            if report.authenticity.as_ref().is_some_and(|auth| {
                matches!(
                    auth.publisher_reputation,
                    PublisherReputation::RemoteAccess | PublisherReputation::BundlerOrPup
                )
            }) {
                candidates.push(hash.clone());
            }
            candidates.sort();
            candidates.dedup();
            for candidate in candidates {
                let evidence = reputation.query(&candidate, VtBatch::PostChild)?;
                reputation.merge_result(&mut report.reputation, evidence);
            }
        }
        Ok(report)
    }

    fn merge_child(&self, report: &mut AnalysisReportV1, child: ChildAnalysis) {
        if let (Some(execution), Some(proof)) = (
            report.child_execution.as_mut(),
            child.sandbox_proof.as_ref(),
        ) {
            execution.network_capability = if proof.is_app_container {
                crate::report::SandboxCapability::None
            } else {
                crate::report::SandboxCapability::Unknown
            };
            execution.filesystem_capability = if proof.is_app_container {
                crate::report::SandboxCapability::Restricted
            } else {
                crate::report::SandboxCapability::Unknown
            };
            execution
                .sandbox_self_tests
                .insert("network_connect".into(), proof.network_connect);
            execution
                .sandbox_self_tests
                .insert("process_create".into(), proof.process_create);
            if !proof.is_app_container
                || proof.network_connect == crate::report::SandboxSelfTest::Allowed
                || proof.process_create == crate::report::SandboxSelfTest::Allowed
            {
                report.add_boundary(
                    BoundaryKind::SandboxViolation,
                    "analysis child did not satisfy the expected AppContainer/network/process isolation guarantees",
                );
            }
        }
        if !child.classification.formats.is_empty() {
            report.classification = child.classification;
        }
        report.facts.extend(child.facts);
        report.inference.extend(child.inference);
        deduplicate_evidence(&mut report.facts);
        deduplicate_evidence(&mut report.inference);
        report.boundaries.extend(child.boundaries);
        report.components.extend(child.components);
        report.products.extend(child.products);
        deduplicate_products(&mut report.products);
        report.certificates.extend(child.certificates);
        if child.authenticity.is_some() {
            report.authenticity = child.authenticity;
        }
        if child.output_truncated {
            report.add_boundary(
                BoundaryKind::OutputTruncated,
                "child analysis exceeded its output limit",
            );
        }
    }

    fn apply_signer_categories(&self, report: &mut AnalysisReportV1) {
        let Some(authenticity) = report.authenticity.as_mut() else {
            return;
        };
        let leaf = report
            .certificates
            .iter()
            .find(|certificate| certificate.role == crate::report::CertificateRole::Leaf);
        if let Some(leaf) = leaf
            && let Some(category) = self
                .config
                .policy
                .signer_categories
                .get(&leaf.sha256_fingerprint.to_ascii_lowercase())
        {
            authenticity.publisher_reputation = match category.as_str() {
                "trusted" => PublisherReputation::Trusted,
                "remote_access" => PublisherReputation::RemoteAccess,
                "bundler" | "pup" => PublisherReputation::BundlerOrPup,
                "untrusted" => PublisherReputation::Untrusted,
                _ => PublisherReputation::Known,
            };
        }
        let unsigned = report
            .components
            .iter()
            .filter(|component| {
                component.formats.iter().any(|format| format.kind == "pe")
                    && component.signed == Some(false)
            })
            .count() as u32;
        authenticity.unsigned_components = unsigned;
        if unsigned > 0 {
            report.facts.push(crate::report::Evidence {
                id: "authenticode:unsigned-components".into(),
                category: "authenticode".into(),
                severity: Severity::High,
                summary: format!("{unsigned} nested executable component(s) are unsigned"),
                detail: None,
                provenance: "child component inventory".into(),
                confidence: crate::report::Confidence::Structural,
            });
        }
    }

}
