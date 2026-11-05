fn human_report(report: &AnalysisReportV1) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "[{}] {}\n",
        serde_json::to_string(&report.verdict)
            .unwrap_or_default()
            .trim_matches('"'),
        report.file.display_path
    ));
    if let Some(hash) = &report.file.sha256 {
        output.push_str(&format!("SHA-256: {hash}\n"));
    }
    output.push_str(&format!(
        "Origin: {}\n",
        serde_json::to_string(&report.origin.state)
            .unwrap_or_default()
            .trim_matches('"')
    ));
    for format in &report.classification.formats {
        output.push_str(&format!("  format: {} @ {}\n", format.kind, format.offset));
    }
    for boundary in &report.boundaries {
        output.push_str(&format!(
            "  boundary: {:?}: {}\n",
            boundary.kind, boundary.detail
        ));
    }
    for evidence in &report.facts {
        if evidence.severity >= Severity::Medium {
            output.push_str(&format!(
                "  {:?}: {}\n",
                evidence.severity, evidence.summary
            ));
        }
    }
    for component in &report.components {
        output.push_str(&format!(
            "  component: {} ({} bytes, {:?})\n",
            component.nesting_path, component.size, component.severity
        ));
    }
    if !report.products.is_empty() {
        output.push_str("Detected software identity (declared by the installer):\n");
        for product in report.products.iter().take(24) {
            let name = product
                .product_name
                .as_deref()
                .unwrap_or("<unnamed product>");
            let manufacturer = product
                .manufacturer
                .as_deref()
                .unwrap_or("unknown manufacturer");
            let version = product
                .product_version
                .as_deref()
                .map(|value| format!(", version {value}"))
                .unwrap_or_default();
            let source = product
                .nesting_path
                .as_deref()
                .unwrap_or(product.source.as_str());
            output.push_str(&format!(
                "  {name} ({manufacturer}{version}) from {source}\n"
            ));
        }
    }
    if let Some(owner) = report
        .authenticity
        .as_ref()
        .and_then(|authenticity| authenticity.publisher_identity.as_deref())
    {
        output.push_str(&format!("Certificate owner: {owner}\n"));
    }
    if !report.components.is_empty() {
        let names = report
            .components
            .iter()
            .take(24)
            .map(|component| component.nesting_path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "Install inventory (embedded/declared; runtime behavior is not guaranteed): {names}\n"
        ));
    }
    output.push_str(&format!(
        "Policy: {:?}; {}\n",
        report.policy.action,
        report.policy.reasons.join("; ")
    ));
    if let Some(decision) = report.policy.user_decision {
        output.push_str(&format!("User decision: {decision:?}\n"));
    }
    if let Some(path) = &report.policy.quarantine_path {
        output.push_str(&format!("Quarantine: {path}\n"));
        if let Some(hash) = &report.file.sha256 {
            output.push_str(&format!(
                "Restore: isitsafe quarantine restore {hash} <destination>\n"
            ));
        }
    }
    if matches!(
        report.verdict,
        Verdict::NoHighRiskFound | Verdict::BasicCheckOnly | Verdict::Limited
    ) {
        output.push_str(&format!("{}\n", report.limitations_notice));
    }
    output
}

fn deduplicate_evidence(evidence: &mut Vec<crate::report::Evidence>) {
    let mut seen = std::collections::HashSet::new();
    evidence.retain(|item| {
        seen.insert((
            item.id.clone(),
            item.category.clone(),
            item.summary.clone(),
            item.detail.clone(),
        ))
    });
}

fn deduplicate_products(products: &mut Vec<crate::report::ProductIdentityEvidence>) {
    let mut seen = std::collections::HashSet::new();
    products.retain(|product| {
        seen.insert((
            product.nesting_path.clone(),
            product.source.clone(),
            product.product_name.clone(),
            product.manufacturer.clone(),
            product.product_version.clone(),
            product.product_code.clone(),
        ))
    });
}
