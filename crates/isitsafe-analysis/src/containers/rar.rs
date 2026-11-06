fn analyze_rar(
    data: &[u8],
    nesting_path: &str,
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let archive = match RarArchive::open(data) {
        Ok(archive) => archive,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("RAR container could not be parsed: {error}"),
            });
            return;
        }
    };
    if archive.encrypted {
        analysis.boundaries.push(Boundary {
            kind: BoundaryKind::EncryptedMember,
            detail: "RAR headers are encrypted and its members cannot be inspected".into(),
        });
        return;
    }

    let mut seen_names = HashSet::new();
    for (index, entry) in archive.entries().iter().enumerate() {
        if !budget.can_enter(depth + 1) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "RAR entry limit exceeded".into(),
            });
            break;
        }
        let raw_name = entry.name.to_string();
        let name = escape_component_name(&raw_name);
        if !is_enclosed_component_name(&raw_name) {
            analysis.facts.push(evidence(
                format!("rar:traversal:{index}"),
                "archive_path_traversal",
                Severity::High,
                format!("RAR member uses an unsafe path: {name}"),
                "child RAR parser",
                Confidence::Structural,
            ));
            continue;
        }
        if !seen_names.insert(name.to_ascii_lowercase()) {
            analysis.facts.push(evidence(
                format!("rar:duplicate:{index}"),
                "archive_duplicate",
                Severity::Medium,
                format!("Duplicate RAR member name: {name}"),
                "child RAR parser",
                Confidence::Structural,
            ));
        }
        if name.contains(':') || is_reserved_windows_name(&name) {
            analysis.facts.push(evidence(
                format!("rar:unsafe-name:{index}"),
                "archive_unsafe_name",
                Severity::Medium,
                format!("RAR member has an unsafe Windows name: {name}"),
                "child RAR parser",
                Confidence::Structural,
            ));
        }
        match entry.kind {
            RarEntryKind::Directory | RarEntryKind::Service => continue,
            RarEntryKind::Symlink | RarEntryKind::Hardlink => {
                analysis.facts.push(evidence(
                    format!("rar:link:{index}"),
                    "archive_symlink",
                    Severity::High,
                    format!("RAR contains a link member: {name}"),
                    "child RAR parser",
                    Confidence::Structural,
                ));
                continue;
            }
            RarEntryKind::File => {}
        }
        if entry.encrypted {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::EncryptedMember,
                detail: format!("RAR member is encrypted and was not inspected: {name}"),
            });
            continue;
        }
        if entry.split_before || entry.split_after {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("RAR member spans volumes and was not inspected: {name}"),
            });
            continue;
        }
        if entry.size_unknown {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("RAR member has no declared size and was not inspected: {name}"),
            });
            continue;
        }
        let packed_size = entry.packed_size.max(1);
        let ratio = entry.unpacked_size.saturating_div(packed_size);
        if ratio > budget.limits.compression_ratio_warning
            || entry.unpacked_size > budget.limits.entry_max_bytes
        {
            analysis.facts.push(evidence(
                format!("rar:bomb:{index}"),
                "zip_bomb",
                Severity::High,
                format!(
                    "Potential RAR decompression bomb: {name}, ratio {ratio}:1, {} bytes declared",
                    entry.unpacked_size
                ),
                "child RAR parser",
                Confidence::Structural,
            ));
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("stopped decompressing oversized RAR entry {name}"),
            });
            continue;
        }
        if budget.total_output.saturating_add(entry.unpacked_size)
            > budget.limits.total_output_max_bytes
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "total RAR decompression budget exceeded".into(),
            });
            break;
        }
        let member = match archive.extract(entry) {
            Ok(member) => member,
            Err(error) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("could not decompress RAR member {name}: {error}"),
                });
                continue;
            }
        };
        if member.len() as u64 > budget.limits.entry_max_bytes {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("RAR member exceeded the per-entry budget: {name}"),
            });
            continue;
        }
        if !budget.account(member.len() as u64) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "total RAR decompression budget exceeded".into(),
            });
            break;
        }
        let child_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
        analyze_archive_member(&name, &child_path, &member, depth + 1, budget, analysis);
    }
}

