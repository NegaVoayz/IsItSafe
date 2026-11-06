fn analyze_inno(
    data: &[u8],
    nesting_path: &str,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let cursor = Cursor::new(data);
    let mut installer = match inno::Inno::new(cursor) {
        Ok(value) => value,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("Inno parser rejected the structure: {error}"),
            });
            return;
        }
    };
    let app_name = installer
        .inner
        .header
        .app_name()
        .unwrap_or("<unnamed>")
        .to_string();
    analysis.products.push(ProductIdentityEvidence {
        product_name: metadata_value(Some(&app_name)),
        source: "Inno Setup application metadata".into(),
        nesting_path: (!nesting_path.is_empty()).then(|| nesting_path.to_string()),
        ..ProductIdentityEvidence::default()
    });
    analysis.inference.push(evidence(
        "inno:app-name",
        "installer_identity",
        Severity::Info,
        format!("Inno installer declares application name: {app_name}"),
        "Inno static parser",
        Confidence::Structural,
    ));
    let mut extracted = Vec::new();
    for item in installer.files() {
        let Ok((entry, bytes)) = item else {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: "Inno payload could not be decompressed".into(),
            });
            continue;
        };
        if !budget.can_enter(1) {
            break;
        }
        if bytes.len() as u64 > budget.limits.entry_max_bytes || !budget.account(bytes.len() as u64)
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "Inno payload exceeded the decompression budget".into(),
            });
            continue;
        }
        let name = escape_component_name(
            entry
                .file()
                .destination()
                .filter(|value| !value.is_empty())
                .unwrap_or("<unnamed>"),
        );
        extracted.push((name, bytes));
    }
    for (name, member) in extracted {
        let member_path = PathBuf::from(&name);
        let sniff = detect::sniff(
            &member_path,
            &member[..member.len().min(64 * 1024)],
            &member[member.len().saturating_sub(1024 * 1024)..],
            member.len() as u64,
        );
        let severity = if sniff
            .evidence
            .iter()
            .any(|item| item.severity >= Severity::Medium)
            || sniff
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
        let child_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
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
    for entry in installer.run_entries() {
        analysis.inference.push(evidence(
            format!("inno:run:{}", analysis.inference.len()),
            "installer_exec",
            Severity::Medium,
            format!(
                "Inno installer contains a run entry: {}",
                entry.name().unwrap_or("<unnamed>")
            ),
            "Inno static parser",
            Confidence::Inferred,
        ));
    }
}

