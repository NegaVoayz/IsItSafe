fn analyze_nsis(
    data: &[u8],
    nesting_path: &str,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let installer = match nsis::NsisInstaller::from_bytes(data) {
        Ok(value) => value,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("NSIS parser rejected the structure: {error}"),
            });
            return;
        }
    };
    for command in installer.exec_commands().flatten() {
        analysis.inference.push(evidence(
            format!("nsis:exec:{}", analysis.inference.len()),
            "installer_exec",
            Severity::Medium,
            format!("NSIS installer can execute a command: {command:?}"),
            "NSIS static parser",
            Confidence::Structural,
        ));
    }
    for registry in installer.registry_ops().flatten() {
        analysis.inference.push(evidence(
            format!("nsis:registry:{}", analysis.inference.len()),
            "registry_change",
            Severity::Low,
            format!("NSIS installer contains a registry operation: {registry:?}"),
            "NSIS static parser",
            Confidence::Structural,
        ));
    }
    for file in installer.files().flatten() {
        if !budget.can_enter(1) {
            break;
        }
        let name = file
            .name()
            .map(|value| escape_component_name(&value.to_string()))
            .unwrap_or_else(|_| "<unnamed>".into());
        if file.data().len() as u64 > budget.limits.entry_max_bytes {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("NSIS member {name} exceeds the entry budget"),
            });
            continue;
        }
        let member = match file.decompress() {
            Ok(value) => value,
            Err(error) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("NSIS member {name} could not be decompressed: {error}"),
                });
                continue;
            }
        };
        if !budget.account(member.len() as u64) {
            break;
        }
        let child_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
        let head = &member[..member.len().min(64 * 1024)];
        let tail = &member[member.len().saturating_sub(1024 * 1024)..];
        let sniff = detect::sniff(Path::new(&name), head, tail, member.len() as u64);
        let severity = if sniff
            .classification
            .formats
            .iter()
            .any(|format| format.kind == "pe")
        {
            Severity::Medium
        } else {
            Severity::Info
        };
        let signed = sign_status(&member);
        record_pe_product(&member, &child_path, analysis);
        analysis.components.push(ComponentEvidence {
            nesting_path: child_path,
            name,
            size: member.len() as u64,
            sha256: Some(hex::encode(Sha256::digest(&member))),
            formats: sniff.classification.formats,
            severity,
            signed,
            evidence: sniff.evidence,
        });
    }
}

