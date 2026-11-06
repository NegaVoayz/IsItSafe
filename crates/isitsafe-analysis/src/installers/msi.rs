fn analyze_msi(
    data: &[u8],
    nesting_path: &str,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    use msi::Select;

    let cursor = Cursor::new(data);
    let mut package = match msi::Package::open(cursor) {
        Ok(value) => value,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("MSI database could not be parsed: {error}"),
            });
            return;
        }
    };
    let mut product = ProductIdentityEvidence {
        source: "MSI Property table and summary information".into(),
        nesting_path: (!nesting_path.is_empty()).then(|| nesting_path.to_string()),
        ..ProductIdentityEvidence::default()
    };
    {
        let summary = package.summary_info();
        product.product_name = metadata_value(summary.title());
        product.manufacturer = metadata_value(summary.author());
        product.file_description = metadata_value(summary.subject());
    }
    if let Ok(rows) = package.select_rows(Select::table("Property")) {
        for row in rows.take(512) {
            if row.len() < 2 {
                continue;
            }
            let key = row[0].to_string().to_ascii_uppercase();
            let value = metadata_value(Some(&row[1].to_string()));
            match key.as_str() {
                "PRODUCTNAME" => product.product_name = value,
                "MANUFACTURER" => product.manufacturer = value,
                "PRODUCTVERSION" => product.product_version = value,
                "PRODUCTCODE" => product.product_code = value,
                "UPGRADECODE" => product.upgrade_code = value,
                _ => {}
            }
        }
    }
    if product.is_meaningful() {
        analysis.products.push(product);
    }
    if let Ok(rows) = package.select_rows(Select::table("File")) {
        for row in rows {
            if !budget.can_enter(1) {
                break;
            }
            let name = if row.len() > 1 {
                escape_component_name(&row[1].to_string())
            } else {
                "<unnamed>".into()
            };
            let size = if row.len() > 2 {
                row[2].to_string().parse::<u64>().unwrap_or(0)
            } else {
                0
            };
            let child_path = if nesting_path.is_empty() {
                name.clone()
            } else {
                format!("{nesting_path}/{name}")
            };
            analysis.components.push(ComponentEvidence {
                nesting_path: child_path,
                name,
                size,
                sha256: None,
                formats: Vec::new(),
                severity: if size > budget.limits.entry_max_bytes {
                    Severity::Medium
                } else {
                    Severity::Info
                },
                signed: None,
                evidence: vec![evidence(
                    format!("msi:file:{}", analysis.components.len()),
                    "installer_file",
                    Severity::Info,
                    "MSI File table declares an installed file",
                    "MSI database parser",
                    Confidence::Structural,
                )],
            });
        }
    }
    for (table, category, severity, summary) in [
        (
            "Registry",
            "registry_change",
            Severity::Medium,
            "MSI Registry table declares registry changes",
        ),
        (
            "ServiceInstall",
            "service_install",
            Severity::Medium,
            "MSI ServiceInstall table declares services",
        ),
        (
            "Shortcut",
            "shortcut_install",
            Severity::Low,
            "MSI Shortcut table declares shortcuts",
        ),
        (
            "CustomAction",
            "installer_exec",
            Severity::Medium,
            "MSI CustomAction table declares installer actions",
        ),
        (
            "LaunchCondition",
            "launch_condition",
            Severity::Low,
            "MSI LaunchCondition table contains conditions",
        ),
    ] {
        if let Ok(rows) = package.select_rows(Select::table(table)) {
            let count = rows.count();
            if count > 0 {
                analysis.inference.push(evidence(
                    format!("msi:{table}"),
                    category,
                    severity,
                    format!("{summary} ({count} rows)"),
                    "MSI database parser",
                    Confidence::Structural,
                ));
            }
        }
    }
    let stream_names: Vec<String> = package.streams().collect();
    for stream_name in stream_names {
        if !budget.can_enter(1) {
            break;
        }
        let mut reader = match package.read_stream(&stream_name) {
            Ok(reader) => reader,
            Err(error) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("MSI stream {stream_name} could not be read: {error}"),
                });
                continue;
            }
        };
        let mut bytes = Vec::new();
        if std::io::Read::by_ref(&mut reader)
            .take(budget.limits.entry_max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > budget.limits.entry_max_bytes
            || !budget.account(bytes.len() as u64)
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("MSI stream {stream_name} exceeded the decompression budget"),
            });
            continue;
        }
        let name = escape_component_name(&stream_name);
        let member_path = PathBuf::from(&name);
        let sniff = detect::sniff(
            &member_path,
            &bytes[..bytes.len().min(64 * 1024)],
            &bytes[bytes.len().saturating_sub(1024 * 1024)..],
            bytes.len() as u64,
        );
        let severity = if sniff
            .evidence
            .iter()
            .any(|item| item.severity >= Severity::Medium)
            || sniff
                .classification
                .formats
                .iter()
                .any(|format| matches!(format.kind.as_str(), "pe" | "cab"))
        {
            Severity::Medium
        } else {
            Severity::Info
        };
        let signed = sign_status(&bytes);
        let stored_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
        record_pe_product(&bytes, &stored_path, analysis);
        analysis.components.push(ComponentEvidence {
            nesting_path: stored_path,
            name,
            size: bytes.len() as u64,
            sha256: Some(hex::encode(Sha256::digest(&bytes))),
            formats: sniff.classification.formats,
            severity,
            signed,
            evidence: sniff.evidence,
        });
    }
}

