fn analyze_archive_member(
    name: &str,
    child_path: &str,
    member: &[u8],
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let member_path = PathBuf::from(name);
    let head = &member[..member.len().min(64 * 1024)];
    let tail = &member[member.len().saturating_sub(1024 * 1024)..];
    let sniff = detect::sniff(&member_path, head, tail, member.len() as u64);
    let mut child_evidence = sniff.evidence;
    let child_classification = sniff.classification.clone();
    if is_ooxml_macro_part(child_path) {
        child_evidence.push(evidence(
            format!("ooxml:macro:{}", child_path),
            "ooxml_macro",
            Severity::High,
            "Office package contains a VBA macro project",
            "child OOXML package inventory",
            Confidence::Structural,
        ));
    }
    if is_ooxml_external_link_part(child_path) {
        child_evidence.push(evidence(
            format!("ooxml:external-link:{}", child_path),
            "ooxml_external_link",
            Severity::High,
            "Office package contains an external-link part",
            "child OOXML package inventory",
            Confidence::Structural,
        ));
    }
    if is_ooxml_activex_part(child_path) {
        child_evidence.push(evidence(
            format!("ooxml:activex:{}", child_path),
            "ooxml_activex",
            Severity::High,
            "Office package contains an ActiveX part",
            "child OOXML package inventory",
            Confidence::Structural,
        ));
    }
    let mut feature_analysis = ChildAnalysis {
        classification: child_classification.clone(),
        ..ChildAnalysis::default()
    };
    inspect_document_features(member, &child_classification, &mut feature_analysis);
    if !is_ooxml_package_part(child_path) {
        inspect_scripts(&member_path, member, &mut feature_analysis);
    }
    child_evidence.extend(feature_analysis.facts);
    let hash = hex::encode(Sha256::digest(member));
    let signed = sign_status(member);
    if let Some(mismatch) = pe_extension_mismatch(&member_path, member) {
        child_evidence.push(mismatch);
    }
    record_pe_product(member, child_path, analysis);
    let severity = if child_evidence
        .iter()
        .any(|item| item.severity >= Severity::High)
    {
        Severity::High
    } else if child_evidence
        .iter()
        .any(|item| item.severity == Severity::Medium)
    {
        Severity::Medium
    } else {
        Severity::Info
    };
    if member.len() > 1024 * 1024 && member.iter().all(|byte| *byte == 0) {
        child_evidence.push(evidence(
            format!("component:sparse:{}", analysis.components.len()),
            "compression_anomaly",
            Severity::Medium,
            format!("{child_path} expands mostly to zero bytes"),
            "child component scan",
            Confidence::Inferred,
        ));
    }
    analysis.components.push(ComponentEvidence {
        nesting_path: child_path.into(),
        name: name.into(),
        size: member.len() as u64,
        sha256: Some(hash),
        formats: child_classification.formats.clone(),
        severity,
        signed,
        evidence: child_evidence.clone(),
    });
    analysis.facts.extend(child_evidence);

    if depth < budget.limits.max_depth && contains_container(member) {
        analyze_containers(&member_path, member, child_path, depth, budget, analysis);
    }
}

fn contains_container(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"Rar!\x1A\x07")
        || data.starts_with(b"MSCF")
        || data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        || detect::scan_all(data)
            .iter()
            .any(|format| matches!(format.kind.as_str(), "zip" | "rar"))
}

