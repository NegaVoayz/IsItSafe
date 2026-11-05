pub fn most_risky_component_first(components: &mut [crate::report::ComponentEvidence]) {
    components.sort_by(|left, right| {
        std::cmp::Reverse(left.severity)
            .cmp(&std::cmp::Reverse(right.severity))
            .then_with(|| left.nesting_path.cmp(&right.nesting_path))
    });
}

pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

pub fn reputation_subject(report: &AnalysisReportV1, sha256: &str) -> String {
    if report
        .file
        .sha256
        .as_deref()
        .is_some_and(|hash| hash.eq_ignore_ascii_case(sha256))
    {
        return format!(
            "Download file: {}",
            Path::new(&report.file.display_path)
                .file_name()
                .map_or_else(
                    || report.file.display_path.clone(),
                    |name| name.to_string_lossy().into_owned()
                )
        );
    }
    if let Some(component) = report.components.iter().find(|component| {
        component
            .sha256
            .as_deref()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(sha256))
    }) {
        return format!("Inside: {}", component.nesting_path);
    }
    format!("Hash: {}...", &sha256[..sha256.len().min(12)])
}

pub fn compact_reason(reason: &str) -> String {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("virustotal") {
        if lower.contains("reported one or more malicious") {
            return "VirusTotal: malicious".into();
        }
        if lower.contains("reported suspicious") {
            return "VirusTotal: suspicious".into();
        }
        let detections = reason
            .split_whitespace()
            .find(|part| {
                part.split_once('/').is_some_and(|(found, total)| {
                    found.chars().all(|character| character.is_ascii_digit())
                        && total
                            .trim_end_matches(|character: char| !character.is_ascii_digit())
                            .chars()
                            .all(|character| character.is_ascii_digit())
                })
            })
            .map(|part| {
                part.trim_end_matches(|character: char| !character.is_ascii_digit())
                    .to_string()
            });
        return detections.map_or_else(
            || "VirusTotal finding".into(),
            |count| format!("VirusTotal {count}"),
        );
    }
    if lower.contains("downloaded file name") && lower.contains("embedded original filename") {
        return "Name differs from embedded file".into();
    }
    if lower.contains("multiple file formats") {
        return "Multiple embedded formats".into();
    }
    if lower.contains("extension") && lower.contains("does not match") {
        return "Extension does not match content".into();
    }
    if lower.contains("pdf") && lower.contains("active") {
        return "Active PDF content".into();
    }
    if lower.contains("script references endpoint") {
        return "Embedded endpoint".into();
    }
    if lower.contains("executable has no authenticode signature") {
        return "Unsigned executable".into();
    }
    if lower.contains("certificate is revoked")
        || lower.contains("authenticity evidence is invalid or revoked")
    {
        return "Revoked certificate".into();
    }
    if lower.contains("signature digest is invalid") {
        return "Invalid signature".into();
    }
    if lower.contains("certificate has expired")
        || lower.contains("certificate is expired or invalid")
    {
        return "Expired certificate".into();
    }
    if lower.contains("certificate chain is invalid") {
        return "Invalid certificate chain".into();
    }
    if lower.contains("signature timestamp is invalid") {
        return "Invalid signature timestamp".into();
    }
    if lower.contains(" is an exe disguised as .") || lower.contains(" is a dll disguised as .") {
        let kind = if lower.contains(" is an exe disguised as .") {
            "EXE"
        } else {
            "DLL"
        };
        let extension = reason
            .split_once(" disguised as .")
            .map_or("other", |(_, extension)| {
                extension.split_whitespace().next().unwrap_or("other")
            });
        return format!("{kind} hidden as .{extension}");
    }
    // Preserve the concise label for reports written before the PE wording change.
    if lower.contains("pe executable disguised with the .") {
        let extension = reason
            .split("with the .")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or("other");
        return format!("Executable hidden as .{extension}");
    }
    if lower.contains("uses a .dll extension") && lower.contains("marks it as an exe") {
        return "EXE hidden as .dll".into();
    }
    if lower.contains("uses a .exe extension") && lower.contains("marks it as a dll") {
        return "DLL hidden as .exe".into();
    }
    if lower.contains("has no file extension but is an exe")
        || lower.contains("has no file extension but is a dll")
    {
        return if lower.contains("but is an exe") {
            "EXE without extension".into()
        } else {
            "DLL without extension".into()
        };
    }
    if lower.contains("pe executable with no file extension") {
        return "EXE without extension".into();
    }
    if lower.contains("decompression bomb") {
        return "Possible zip bomb".into();
    }
    if lower.contains("exceeded") && lower.contains("threshold") {
        return "Too large for deep scan".into();
    }
    if lower.contains("snapshot_max_bytes") || lower.contains("basic_check_threshold_bytes") {
        return String::new();
    }
    if lower.contains("temporary download") {
        return "Incomplete download".into();
    }
    if lower.contains("network reputation") {
        return "Online reputation incomplete".into();
    }
    if lower.contains("structural evidence") {
        return "Structural risk".into();
    }
    if lower.contains("user chose to keep") {
        return "Kept by user".into();
    }

    let first_clause = reason.split([';', '•']).next().unwrap_or(reason).trim();
    let mut compact = first_clause.chars().take(42).collect::<String>();
    if first_clause.chars().count() > 42 {
        compact.push('…');
    }
    compact
}

pub fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

fn is_current_download(path: &str, download_dir: &Path) -> bool {
    let path = Path::new(path);
    let parent_matches = path.parent().is_some_and(|parent| {
        normalize_path(&parent.to_string_lossy()) == normalize_path(&download_dir.to_string_lossy())
    });
    if !parent_matches {
        return false;
    }
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & 0x400 == 0
            }
            #[cfg(not(windows))]
            {
                !metadata.file_type().is_symlink()
            }
        }
    })
}

fn quarantine_original_name(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    let Some(stem) = name.strip_suffix(".quarantined") else {
        return name;
    };
    let Some((original, hash_segment)) = stem.rsplit_once('.') else {
        return stem.to_string();
    };
    let hash = hash_segment
        .split_once('-')
        .map_or(hash_segment, |(hash, _)| hash);
    if hash.len() == 12 && hash.chars().all(|character| character.is_ascii_hexdigit()) {
        original.to_string()
    } else {
        stem.to_string()
    }
}

