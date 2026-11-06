fn inspect_document_features(
    data: &[u8],
    classification: &Classification,
    analysis: &mut ChildAnalysis,
) {
    let kinds: BTreeSet<_> = classification
        .formats
        .iter()
        .map(|format| format.kind.as_str())
        .collect();
    if kinds.contains("pdf") {
        for marker in [
            "/JavaScript",
            "/JS",
            "/Launch",
            "/EmbeddedFile",
            "/OpenAction",
            "/AA",
        ] {
            if pdf_marker_present(data, marker.as_bytes()) {
                let severity = if matches!(marker, "/JavaScript" | "/JS" | "/Launch") {
                    Severity::High
                } else {
                    Severity::Medium
                };
                analysis.facts.push(evidence(
                    format!("pdf:{}", marker.trim_start_matches('/')),
                    "pdf_active_content",
                    severity,
                    format!("PDF contains active or embedded-content marker {marker}"),
                    "child PDF marker scan",
                    Confidence::Inferred,
                ));
            }
        }
    }
    if kinds.contains("svg") {
        let text = String::from_utf8_lossy(data).to_ascii_lowercase();
        for marker in [
            "<script",
            "onload=",
            "onclick=",
            "javascript:",
            "xlink:href",
        ] {
            if text.contains(marker) {
                analysis.facts.push(evidence(
                    format!("svg:{}", marker.replace(['<', '=', ':'], "_")),
                    "svg_active_content",
                    Severity::High,
                    format!("SVG contains active-content marker {marker}"),
                    "child SVG scan",
                    Confidence::Structural,
                ));
            }
        }
    }
    if kinds.iter().any(|kind| kind.starts_with("ooxml:"))
        || classification
            .formats
            .iter()
            .any(|format| format.kind == "zip")
    {
        for marker in [b"vbaProject.bin".as_slice(), b"externalLink".as_slice()] {
            if contains_ascii(data, marker) {
                analysis.facts.push(evidence(
                    format!("ooxml:{}", String::from_utf8_lossy(marker)),
                    if marker == b"vbaProject.bin" {
                        "ooxml_macro"
                    } else {
                        "ooxml_external_link"
                    },
                    Severity::High,
                    format!(
                        "Office container contains {}",
                        String::from_utf8_lossy(marker)
                    ),
                    "child OOXML marker scan",
                    Confidence::Structural,
                ));
            }
        }
    }
    if kinds.contains("lnk") {
        let text = String::from_utf8_lossy(data).to_ascii_lowercase();
        if [".exe", ".ps1", ".bat", ".cmd", ".vbs", "powershell"]
            .iter()
            .any(|marker| text.contains(marker))
        {
            analysis.facts.push(evidence(
                "lnk:executable-target",
                "lnk_execution",
                Severity::High,
                "Windows shortcut references an executable or script",
                "child LNK scan",
                Confidence::Inferred,
            ));
        }
    }
}

fn pdf_marker_present(data: &[u8], marker: &[u8]) -> bool {
    let stream_ranges = detect::pdf_stream_ranges(data);
    let mut cursor = 0usize;
    while let Some(relative) = data[cursor..]
        .windows(marker.len())
        .position(|window| window == marker)
    {
        let offset = cursor + relative;
        if !stream_ranges
            .iter()
            .any(|(start, end)| offset as u64 >= *start && (offset as u64) < *end)
        {
            return true;
        }
        cursor = offset.saturating_add(marker.len());
        if cursor >= data.len() {
            break;
        }
    }
    false
}

fn is_ooxml_package_part(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path == "[content_types].xml"
        || path.starts_with("_rels/")
        || path.starts_with("docprops/")
        || path.starts_with("customxml/")
        || path.starts_with("word/")
        || path.starts_with("xl/")
        || path.starts_with("ppt/")
        || path.contains("/_rels/")
        || path.contains("/docprops/")
        || path.contains("/customxml/")
        || path.contains("/word/")
        || path.contains("/xl/")
        || path.contains("/ppt/")
}

fn is_ooxml_macro_part(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path == "vbaproject.bin" || path.ends_with("/vbaproject.bin")
}

fn is_ooxml_external_link_part(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path.starts_with("externallinks/") || path.contains("/externallinks/")
}

fn is_ooxml_activex_part(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path.starts_with("activex/") || path.contains("/activex/")
}

