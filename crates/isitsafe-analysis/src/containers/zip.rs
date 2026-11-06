fn analyze_zip(
    _path: &Path,
    data: &[u8],
    nesting_path: &str,
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let cursor = Cursor::new(data);
    let mut archive = match ZipArchive::new(cursor) {
        Ok(archive) => archive,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("ZIP container could not be parsed: {error}"),
            });
            return;
        }
    };
    let mut seen_names = HashSet::new();
    let mut ranges = Vec::new();
    for index in 0..archive.len() {
        if !budget.can_enter(depth + 1) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "ZIP entry limit exceeded".into(),
            });
            break;
        }
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(zip::result::ZipError::UnsupportedArchive(message)) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("unsupported ZIP entry: {message}"),
                });
                continue;
            }
            Err(error) => {
                analysis.facts.push(evidence(
                    format!("container:error:{index}"),
                    "container",
                    Severity::Medium,
                    format!("ZIP entry {index} could not be read: {error}"),
                    "child ZIP parser",
                    Confidence::Structural,
                ));
                continue;
            }
        };
        let raw_name = match entry.name() {
            Ok(name) => name.into_owned(),
            Err(error) => {
                analysis.facts.push(evidence(
                    format!("container:invalid_name:{index}"),
                    "archive_unsafe_name",
                    Severity::Medium,
                    format!("ZIP entry {index} has an invalid UTF-8 name: {error}"),
                    "child ZIP parser",
                    Confidence::Structural,
                ));
                continue;
            }
        };
        let name = escape_component_name(&raw_name);
        if entry.enclosed_name().is_none() {
            analysis.facts.push(evidence(
                format!("container:traversal:{index}"),
                "archive_path_traversal",
                Severity::High,
                format!("Archive member uses an unsafe path: {name}"),
                "child ZIP parser",
                Confidence::Structural,
            ));
            continue;
        }
        if !seen_names.insert(name.to_ascii_lowercase()) {
            analysis.facts.push(evidence(
                format!("container:duplicate:{index}"),
                "archive_duplicate",
                Severity::Medium,
                format!("Duplicate archive member name: {name}"),
                "child ZIP parser",
                Confidence::Structural,
            ));
        }
        if name.contains(':') || is_reserved_windows_name(&name) {
            analysis.facts.push(evidence(
                format!("container:unsafe_name:{index}"),
                "archive_unsafe_name",
                Severity::Medium,
                format!("Archive member has an unsafe Windows name: {name}"),
                "child ZIP parser",
                Confidence::Structural,
            ));
        }
        if entry.is_dir() {
            continue;
        }
        if entry.encrypted() {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::EncryptedMember,
                detail: format!("ZIP member is encrypted and was not inspected: {name}"),
            });
            continue;
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            analysis.facts.push(evidence(
                format!("container:symlink:{index}"),
                "archive_symlink",
                Severity::High,
                format!("Archive contains a symbolic-link member: {name}"),
                "child ZIP parser",
                Confidence::Structural,
            ));
            continue;
        }
        let compressed = entry.compressed_size().max(1);
        let ratio = entry.size().saturating_div(compressed);
        if ratio > budget.limits.compression_ratio_warning
            || entry.size() > budget.limits.entry_max_bytes
        {
            analysis.facts.push(evidence(
                format!("container:bomb:{index}"),
                "zip_bomb",
                Severity::High,
                format!(
                    "Potential decompression bomb: {name}, ratio {ratio}:1, {} bytes declared",
                    entry.size()
                ),
                "child ZIP parser",
                Confidence::Structural,
            ));
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("stopped decompressing oversized entry {name}"),
            });
            continue;
        }
        let Some(data_start) = entry.data_start() else {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("ZIP entry data offset is unavailable: {name}"),
            });
            continue;
        };
        ranges.push((data_start, data_start + entry.compressed_size()));
        let take_limit = budget.limits.entry_max_bytes.min(
            budget
                .limits
                .total_output_max_bytes
                .saturating_sub(budget.total_output),
        );
        let mut member = Vec::new();
        let read_result = (&mut entry)
            .take(take_limit.saturating_add(1))
            .read_to_end(&mut member);
        if let Err(error) = read_result {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("could not decompress {name}: {error}"),
            });
            continue;
        }
        if member.len() as u64 > take_limit {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("decompression budget exceeded while reading {name}"),
            });
            continue;
        }
        if !budget.account(member.len() as u64) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "total decompression budget exceeded".into(),
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
    ranges.sort_unstable();
    if ranges
        .windows(2)
        .any(|window| window[1].0 < window[0].1 && window[0].0 != window[1].0)
    {
        analysis.facts.push(evidence(
            "container:overlap",
            "archive_overlap",
            Severity::High,
            "ZIP entries contain overlapping compressed-data ranges",
            "child ZIP parser",
            Confidence::Structural,
        ));
    }
    if String::from_utf8_lossy(archive.comment())
        .to_ascii_lowercase()
        .contains("zip")
        && archive.len() > 100
    {
        analysis.inference.push(evidence(
            "container:many_entries",
            "archive_complexity",
            Severity::Low,
            "Archive contains a large number of entries",
            "child ZIP parser",
            Confidence::Inferred,
        ));
    }
}

