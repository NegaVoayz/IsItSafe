
const MAX_MAGIC_HITS: usize = 128;

#[derive(Debug, Clone, Default)]
pub struct SniffResult {
    pub classification: Classification,
    pub evidence: Vec<Evidence>,
}

pub fn sniff(path: &Path, head: &[u8], tail: &[u8], total_size: u64) -> SniffResult {
    let extension = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let tail_start = total_size.saturating_sub(tail.len() as u64);
    let mut formats = Vec::new();

    if is_pe(head) {
        formats.push(format_hit("pe", 0, "pe-header"));
    }
    if head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        formats.push(format_hit("ole_cfb", 0, "cfb-header"));
        if has_ascii(head, b"Windows Installer") || has_ascii(head, b"MSI") {
            formats.push(format_hit("msi", 0, "cfb-msi-marker"));
        }
    }
    let zip_at_head = is_zip_head(head);
    if zip_at_head {
        formats.push(format_hit("zip", 0, "zip-eocd"));
    } else if let Some(eocd) = find_zip_eocd(tail) {
        let zip_start = tail[..eocd]
            .windows(4)
            .rposition(|window| window == b"PK\x03\x04")
            .unwrap_or(eocd);
        formats.push(format_hit("zip", tail_start + zip_start as u64, "zip-eocd"));
    }
    if head.starts_with(b"MSCF") {
        formats.push(format_hit("cab", 0, "cab-header"));
    }
    if head.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        formats.push(format_hit("7z", 0, "7z-header"));
    }
    if head.starts_with(b"Rar!\x1A\x07") {
        formats.push(format_hit("rar", 0, "rar-header"));
    }
    if head.starts_with(b"%PDF-") {
        let complete = tail.windows(5).any(|window| window == b"%%EOF");
        formats.push(DetectedFormat {
            kind: "pdf".into(),
            offset: 0,
            confidence: if complete {
                Confidence::Structural
            } else {
                Confidence::Inferred
            },
            parser: "pdf-markers".into(),
        });
    }
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        let complete = tail.windows(2).any(|window| window == [0xFF, 0xD9]);
        formats.push(DetectedFormat {
            kind: "jpeg".into(),
            offset: 0,
            confidence: if complete {
                Confidence::Structural
            } else {
                Confidence::Inferred
            },
            parser: "jpeg-markers".into(),
        });
    }
    if head.starts_with(b"\x89PNG\r\n\x1A\n") {
        let complete = tail.windows(12).any(|window| &window[4..8] == b"IEND");
        formats.push(DetectedFormat {
            kind: "png".into(),
            offset: 0,
            confidence: if complete {
                Confidence::Structural
            } else {
                Confidence::Inferred
            },
            parser: "png-markers".into(),
        });
    }
    if is_webp(head) {
        let complete = webp_declared_size(head).is_some_and(|size| size == total_size);
        formats.push(DetectedFormat {
            kind: "webp".into(),
            offset: 0,
            confidence: if complete {
                Confidence::Structural
            } else {
                Confidence::Inferred
            },
            parser: "webp-riff".into(),
        });
    }
    if looks_like_svg(head, &extension) {
        formats.push(format_hit("svg", 0, "xml-svg-marker"));
    }
    if is_lnk(head) {
        formats.push(format_hit("lnk", 0, "lnk-header"));
    }
    if looks_like_hta(&extension, head) {
        formats.push(format_hit("hta", 0, "hta-content"));
    }
    if let Some(script_kind) = script_kind(&extension, head) {
        formats.push(format_hit(script_kind, 0, "script-extension-or-shebang"));
    }

    if zip_at_head {
        // Local headers from the container's own members are not embedded
        // archives. Only inspect bytes following the end-of-central-directory
        // record for a second, appended archive.
        scan_zip_trailing_data(tail, tail_start, &mut formats);
    } else {
        scan_embedded(head, 0, &mut formats);
        scan_embedded(tail, tail_start, &mut formats);
    }
    formats.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.kind.cmp(&b.kind)));
    formats.dedup_by(|a, b| a.kind == b.kind && a.offset == b.offset);

    let installer_family = installer_family(head, tail);
    if let Some(family) = &installer_family {
        formats.push(DetectedFormat {
            kind: format!("installer:{family}"),
            offset: 0,
            confidence: Confidence::Structural,
            parser: "installer-marker".into(),
        });
    }

    // OOXML files are ZIP containers with a content-types part. The parent has
    // only head/tail bytes, so this is an intentional inference confirmed by
    // the child parser.
    if matches!(
        extension.as_str(),
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm"
    ) && formats.iter().any(|f| f.kind == "zip")
    {
        formats.push(DetectedFormat {
            kind: format!("ooxml:{extension}"),
            offset: 0,
            confidence: Confidence::Inferred,
            parser: "extension+zip".into(),
        });
    }

    let actual_primary = formats
        .first()
        .map(|f| f.kind.as_str())
        .unwrap_or("unknown");
    let primary_is_container = matches!(
        actual_primary,
        "zip" | "rar" | "7z" | "cab" | "ole_cfb" | "msi"
    );
    let extension_mismatch = extension_mismatch(&extension, actual_primary);
    let webp_trailing_data = extension == "webp"
        && formats.iter().any(|format| format.kind == "webp")
        && webp_declared_size(head).is_some_and(|size| total_size > size);
    let embedded_after_terminator = (!primary_is_container
        && formats.iter().any(|hit| hit.offset > 0))
        || webp_trailing_data
        || has_risky_trailer(&extension, head, tail);
    let is_text = std::str::from_utf8(head).is_ok()
        && !head.contains(&0)
        && !formats.iter().any(|f| f.kind == "pe");
    let is_markdown = matches!(extension.as_str(), "md" | "markdown");

    let mut evidence = Vec::new();
    if extension_mismatch {
        evidence.push(Evidence {
            id: "detect:extension-mismatch".into(),
            category: "format".into(),
            severity: Severity::Medium,
            summary: format!(
                "File extension .{extension} does not match its contents (detected: {actual_primary})"
            ),
            detail: None,
            provenance: "parent magic sniff".into(),
            confidence: Confidence::Structural,
        });
    }
    if formats.iter().filter(|f| f.offset > 0).count() > 0 {
        evidence.push(Evidence {
            id: "detect:polyglot".into(),
            category: "polyglot".into(),
            severity: if primary_is_container {
                Severity::Medium
            } else {
                Severity::High
            },
            summary: if primary_is_container {
                "Embedded container signatures occur inside an archive".into()
            } else {
                "Multiple file formats occur at distinct offsets".into()
            },
            detail: Some(
                formats
                    .iter()
                    .map(|hit| format!("{}@{}", hit.kind, hit.offset))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            provenance: "parent magic scan".into(),
            confidence: Confidence::Inferred,
        });
    }

    SniffResult {
        classification: Classification {
            formats,
            extension_mismatch,
            risky_trailing_data: embedded_after_terminator,
            installer_family,
            is_markdown,
            is_text,
        },
        evidence,
    }
}

