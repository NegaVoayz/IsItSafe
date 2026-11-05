fn analyze_cab(
    path: &Path,
    data: &[u8],
    nesting_path: &str,
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let cursor = Cursor::new(data);
    let mut cabinet = match cab::Cabinet::new(cursor) {
        Ok(value) => value,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("CAB header could not be parsed: {error}"),
            });
            return;
        }
    };
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|entry| entry.name().to_string())
        .collect();
    for name in names {
        if !budget.can_enter(depth + 1) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "CAB entry limit exceeded".into(),
            });
            break;
        }
        let safe_name = escape_component_name(&name);
        if safe_name.contains("..") || safe_name.starts_with(['/', '\\']) {
            analysis.facts.push(evidence(
                format!("cab:unsafe:{}", analysis.facts.len()),
                "archive_path_traversal",
                Severity::High,
                format!("CAB member uses an unsafe path: {safe_name}"),
                "child CAB parser",
                Confidence::Structural,
            ));
            continue;
        }
        let mut reader = match cabinet.read_file(&name) {
            Ok(value) => value,
            Err(error) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("CAB member {safe_name} could not be read: {error}"),
                });
                continue;
            }
        };
        let mut member = Vec::new();
        if reader
            .by_ref()
            .take(budget.limits.entry_max_bytes.saturating_add(1))
            .read_to_end(&mut member)
            .is_err()
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("CAB member {safe_name} could not be decompressed"),
            });
            continue;
        }
        if member.len() as u64 > budget.limits.entry_max_bytes
            || !budget.account(member.len() as u64)
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("CAB member {safe_name} exceeded the decompression budget"),
            });
            continue;
        }
        let child_path = if nesting_path.is_empty() {
            safe_name.clone()
        } else {
            format!("{nesting_path}/{safe_name}")
        };
        let member_path = PathBuf::from(&safe_name);
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
        record_pe_product(&member, &child_path, analysis);
        analysis.components.push(ComponentEvidence {
            nesting_path: child_path,
            name: safe_name,
            size: member.len() as u64,
            sha256: Some(hex::encode(Sha256::digest(&member))),
            formats: sniff.classification.formats,
            severity,
            signed,
            evidence: sniff.evidence,
        });
        let _ = path;
    }
}

