struct Budget<'a> {
    limits: &'a AnalysisLimits,
    entries_seen: usize,
    total_output: u64,
}

impl Budget<'_> {
    fn can_enter(&mut self, nesting_depth: usize) -> bool {
        self.entries_seen = self.entries_seen.saturating_add(1);
        self.entries_seen <= self.limits.max_entries && nesting_depth <= self.limits.max_depth
    }

    fn account(&mut self, size: u64) -> bool {
        self.total_output = self.total_output.saturating_add(size);
        self.total_output <= self.limits.total_output_max_bytes
    }
}

fn analyze_containers(
    path: &Path,
    data: &[u8],
    nesting_path: &str,
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    if !budget.can_enter(depth) {
        analysis.boundaries.push(Boundary {
            kind: BoundaryKind::BudgetExceeded,
            detail: format!(
                "entry/depth budget exceeded at {}",
                if nesting_path.is_empty() {
                    "<root>"
                } else {
                    nesting_path
                }
            ),
        });
        return;
    }

    let is_zip = data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06");
    if is_zip {
        analyze_zip(path, data, nesting_path, depth, budget, analysis);
    }
    let is_rar = data.starts_with(b"Rar!\x1A\x07");
    if is_rar {
        analyze_rar(data, nesting_path, depth, budget, analysis);
    }
    if data.starts_with(b"MSCF") {
        analyze_cab(path, data, nesting_path, depth, budget, analysis);
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        && (path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("msi"))
            || analysis
                .classification
                .formats
                .iter()
                .any(|format| format.kind == "msi"))
    {
        analyze_msi(data, nesting_path, budget, analysis);
    }
    if depth == 0 {
        if analysis
            .classification
            .formats
            .iter()
            .any(|format| format.kind == "7z")
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: "7z extraction is not implemented; the container was identified only"
                    .into(),
            });
        }
        if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
            && !analysis
                .classification
                .formats
                .iter()
                .any(|format| format.kind == "msi")
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: "Compound-file container is not an MSI package and was not unpacked".into(),
            });
        }
    }

    if !is_zip && !is_rar && depth < budget.limits.max_depth {
        let embedded_archives: Vec<(String, u64)> = detect::scan_all(data)
            .into_iter()
            .filter(|format| matches!(format.kind.as_str(), "zip" | "rar") && format.offset > 0)
            .map(|format| (format.kind, format.offset))
            .collect();
        for (kind, offset) in embedded_archives.into_iter().take(8) {
            let Some(offset) = usize::try_from(offset).ok() else {
                continue;
            };
            if offset >= data.len() {
                continue;
            }
            let archive_path = if nesting_path.is_empty() {
                format!("embedded.{kind}@{offset}")
            } else {
                format!("{nesting_path}/embedded.{kind}@{offset}")
            };
            if kind == "zip" {
                analyze_zip(
                    Path::new(&archive_path),
                    &data[offset..],
                    &archive_path,
                    depth + 1,
                    budget,
                    analysis,
                );
            } else {
                analyze_rar(&data[offset..], &archive_path, depth + 1, budget, analysis);
            }
        }
    }

    let installer = analysis
        .classification
        .installer_family
        .clone()
        .or_else(|| {
            let head = &data[..data.len().min(2 * 1024 * 1024)];
            let tail = &data[data.len().saturating_sub(2 * 1024 * 1024)..];
            detect::sniff(path, head, tail, data.len() as u64)
                .classification
                .installer_family
        });
    if let Some(family) = installer
        && depth == 0
    {
        analysis.classification.installer_family = Some(family.clone());
        match family.as_str() {
            "nsis" => analyze_nsis(data, nesting_path, budget, analysis),
            "inno_setup" => analyze_inno(data, nesting_path, budget, analysis),
            "wix_burn" | "installshield" | "squirrel" => {
                analysis.boundaries.push(Boundary {
                        kind: BoundaryKind::UnsupportedFormat,
                        detail: format!(
                            "{family} was identified, but its complete action plan is not statically decodable"
                        ),
                    });
            }
            _ => {}
        }
    }
}

