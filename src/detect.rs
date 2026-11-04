use std::collections::HashSet;
use std::io::Cursor;
use std::path::Path;

use zip::ZipArchive;

use crate::report::{Classification, Confidence, DetectedFormat, Evidence, Severity};

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
                "Filename extension .{extension} does not match detected content {actual_primary}"
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

pub fn scan_all(data: &[u8]) -> Vec<DetectedFormat> {
    let mut out = Vec::new();
    let zip_headers = zip_local_header_offsets(data);
    let pdf_streams = if data.starts_with(b"%PDF-") {
        pdf_stream_ranges(data)
    } else {
        Vec::new()
    };
    scan_embedded_with_exclusions(data, 0, &zip_headers, &pdf_streams, &mut out);
    out.sort_by_key(|hit| hit.offset);
    out.dedup_by(|a, b| a.kind == b.kind && a.offset == b.offset);
    out
}

fn scan_embedded(data: &[u8], base: u64, out: &mut Vec<DetectedFormat>) {
    scan_embedded_with_exclusions(data, base, &HashSet::new(), &[], out);
}

fn scan_embedded_with_exclusions(
    data: &[u8],
    base: u64,
    skip_offsets: &HashSet<u64>,
    hidden_ranges: &[(u64, u64)],
    out: &mut Vec<DetectedFormat>,
) {
    if data.is_empty() {
        return;
    }
    let patterns: &[(&str, &[u8], &str)] = &[
        ("pe", b"MZ", "magic-scan"),
        ("zip", b"PK\x03\x04", "magic-scan"),
        ("rar", b"Rar!\x1A\x07", "magic-scan"),
        (
            "ole_cfb",
            &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
            "magic-scan",
        ),
    ];
    let mut hits = 0usize;
    for (kind, needle, parser) in patterns {
        for (offset, _) in data
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| *window == *needle)
        {
            let offset = base + offset as u64;
            // A signature at zero is represented by the dedicated detector.
            if offset == 0
                || skip_offsets.contains(&offset)
                || hidden_ranges
                    .iter()
                    .any(|(start, end)| offset >= *start && offset < *end)
            {
                continue;
            }
            let candidate = &data[(offset - base) as usize..];
            let plausible = match *kind {
                "pe" => is_pe(candidate),
                "zip" => is_plausible_zip(candidate),
                "rar" => is_plausible_rar(candidate),
                "ole_cfb" => is_plausible_cfb(candidate),
                _ => false,
            };
            if !plausible {
                continue;
            }
            out.push(DetectedFormat {
                kind: (*kind).into(),
                offset,
                confidence: Confidence::Inferred,
                parser: (*parser).into(),
            });
            hits += 1;
            if hits >= MAX_MAGIC_HITS {
                return;
            }
        }
    }
}

fn zip_local_header_offsets(data: &[u8]) -> HashSet<u64> {
    let mut offsets = HashSet::new();
    if !is_zip_head(data) {
        return offsets;
    }
    let Ok(mut archive) = ZipArchive::new(Cursor::new(data)) else {
        return offsets;
    };
    for index in 0..archive.len() {
        if let Ok(entry) = archive.by_index_raw(index) {
            offsets.insert(entry.header_start());
        }
    }
    offsets
}

pub(crate) fn pdf_stream_ranges(data: &[u8]) -> Vec<(u64, u64)> {
    const STREAM: &[u8] = b"stream";
    const END_STREAM: &[u8] = b"endstream";
    let mut ranges = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = data[cursor..]
        .windows(STREAM.len())
        .position(|window| window == STREAM)
    {
        let start = cursor + relative;
        let before_is_token = start == 0 || !is_pdf_name_byte(data[start - 1]);
        let after = start + STREAM.len();
        let after_is_token = data.get(after).is_none_or(|byte| !is_pdf_name_byte(*byte));
        if !before_is_token || !after_is_token {
            cursor = after;
            continue;
        }
        let payload_start = match data.get(after..) {
            Some([b'\r', b'\n', ..]) => after + 2,
            Some([b'\n', ..]) | Some([b'\r', ..]) => after + 1,
            _ => {
                // "stream" is also ordinary prose. In PDF syntax a stream
                // payload starts on the next line.
                cursor = after;
                continue;
            }
        };
        let payload_end = data[payload_start..]
            .windows(END_STREAM.len())
            .position(|window| window == END_STREAM)
            .map(|offset| payload_start + offset)
            .unwrap_or(data.len());
        ranges.push((payload_start as u64, payload_end as u64));
        cursor = payload_end.saturating_add(END_STREAM.len()).min(data.len());
        if cursor >= data.len() {
            break;
        }
    }
    ranges
}

fn is_pdf_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-')
}

fn scan_zip_trailing_data(tail: &[u8], tail_start: u64, formats: &mut Vec<DetectedFormat>) {
    let Some(eocd) = find_zip_eocd(tail) else {
        return;
    };
    let Some(record_end) = eocd
        .checked_add(22)
        .and_then(|fixed_end| {
            let comment_len =
                u16::from_le_bytes(tail.get(eocd + 20..eocd + 22)?.try_into().ok()?) as usize;
            fixed_end.checked_add(comment_len)
        })
        .filter(|end| *end < tail.len())
    else {
        return;
    };
    scan_embedded(&tail[record_end..], tail_start + record_end as u64, formats);
}

fn is_plausible_zip(data: &[u8]) -> bool {
    if data.len() < 30 || !data.starts_with(b"PK\x03\x04") {
        return false;
    }
    let name_len = u16::from_le_bytes([data[26], data[27]]) as usize;
    let extra_len = u16::from_le_bytes([data[28], data[29]]) as usize;
    if name_len == 0 || name_len > 4096 || extra_len > 4096 {
        return false;
    }
    let data_start = 30usize.saturating_add(name_len).saturating_add(extra_len);
    if data_start > data.len() {
        return false;
    }

    let Some(eocd) = data.windows(4).rposition(|window| window == b"PK\x05\x06") else {
        return false;
    };
    let Some(fixed) = data.get(eocd..eocd + 22) else {
        return false;
    };
    let total_entries = u16::from_le_bytes([fixed[10], fixed[11]]);
    let central_size = u32::from_le_bytes([fixed[12], fixed[13], fixed[14], fixed[15]]);
    let central_offset = u32::from_le_bytes([fixed[16], fixed[17], fixed[18], fixed[19]]);

    // A central-directory offset is relative to the start of this candidate.
    // Local headers inside a valid ZIP also have an EOCD later in the outer
    // buffer, but their inherited central offset points past the candidate
    // and therefore cannot be mistaken for a second ZIP archive.
    if total_entries == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return true;
    }
    if total_entries == 0 {
        return central_size == 0 && central_offset <= eocd as u32;
    }
    let central_offset = central_offset as usize;
    let central_end = central_offset.saturating_add(central_size as usize);
    central_offset < eocd
        && central_end <= eocd
        && data.get(central_offset..central_offset + 4) == Some(b"PK\x01\x02")
}

fn is_plausible_rar(data: &[u8]) -> bool {
    data.len() >= 20
        && (data.starts_with(b"Rar!\x1A\x07\x00") || data.starts_with(b"Rar!\x1A\x07\x01\x00"))
}

fn is_plausible_cfb(data: &[u8]) -> bool {
    data.len() >= 512
        && data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        && matches!(u16::from_le_bytes([data[30], data[31]]), 9 | 12)
}

fn format_hit(kind: &str, offset: u64, parser: &str) -> DetectedFormat {
    DetectedFormat {
        kind: kind.into(),
        offset,
        confidence: Confidence::Structural,
        parser: parser.into(),
    }
}

pub fn is_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return false;
    }
    let offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    offset.checked_add(24).is_some_and(|end| end <= bytes.len())
        && bytes.get(offset..offset + 4) == Some(b"PE\0\0")
}

fn is_zip_head(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06")
}

fn is_webp(head: &[u8]) -> bool {
    head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP"
}

fn webp_declared_size(head: &[u8]) -> Option<u64> {
    if !is_webp(head) {
        return None;
    }
    Some(u32::from_le_bytes(head[4..8].try_into().ok()?) as u64 + 8)
}

fn find_zip_eocd(tail: &[u8]) -> Option<usize> {
    tail.windows(4).rposition(|window| window == b"PK\x05\x06")
}

fn has_risky_trailer(extension: &str, head: &[u8], tail: &[u8]) -> bool {
    let has_container = head.starts_with(b"PK\x03\x04")
        || head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    match extension {
        "jpg" | "jpeg" => {
            !has_container
                && !tail
                    .windows(2)
                    .last()
                    .is_some_and(|window| window == [0xFF, 0xD9])
        }
        "png" => !has_container && !tail.windows(12).any(|window| &window[4..8] == b"IEND"),
        "pdf" => !has_container && !tail.windows(5).any(|window| window == b"%%EOF"),
        _ => false,
    }
}

fn extension_mismatch(extension: &str, primary: &str) -> bool {
    if extension.is_empty() {
        return false;
    }
    if primary == "unknown" {
        return !matches!(
            extension,
            "txt"
                | "text"
                | "utf8"
                | "md"
                | "markdown"
                | "json"
                | "yaml"
                | "yml"
                | "toml"
                | "ini"
                | "xml"
                | "c"
                | "cc"
                | "cpp"
                | "cxx"
                | "h"
                | "hpp"
                | "sln"
                | "vcxproj"
                | "filters"
                | "comp"
                | "frag"
                | "vert"
                | "obj"
                | "rels"
        );
    }
    let compatible: &[&str] = match extension {
        "exe" | "dll" | "sys" => &["pe", "ole_cfb", "msi"],
        "msi" => &["ole_cfb", "msi"],
        "zip" | "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" => &["zip"],
        "cab" => &["cab"],
        "7z" => &["7z"],
        "rar" => &["rar"],
        "pdf" => &["pdf"],
        "jpg" | "jpeg" => &["jpeg"],
        "png" => &["png"],
        "webp" => &["webp"],
        "svg" => &["svg"],
        "lnk" => &["lnk"],
        "ps1" => &["powershell", "script"],
        "bat" | "cmd" => &["batch", "script"],
        "vbs" => &["vbscript", "script"],
        "js" => &["javascript", "script"],
        "hta" => &["hta", "script"],
        "md" | "markdown" | "txt" => &["text", "unknown"],
        "rels" => &["text", "unknown"],
        "py" | "pyw" | "utf8" | "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "sln" | "vcxproj"
        | "filters" | "comp" | "frag" | "vert" | "obj" => &["text", "unknown", "script", "python"],
        _ => return false,
    };
    !compatible.contains(&primary)
}

fn installer_family(head: &[u8], tail: &[u8]) -> Option<String> {
    let combined = [head, tail].concat();
    if has_ascii_case(&combined, b"Inno Setup Setup Data")
        || has_ascii_case(&combined, b"InnoSetup")
    {
        Some("inno_setup".into())
    } else if has_ascii_case(&combined, b"NullsoftInstaller")
        || has_ascii_case(&combined, b"Nullsoft Install System")
    {
        Some("nsis".into())
    } else if has_ascii_case(&combined, b"WixBundle") || has_ascii_case(&combined, b"BurnStub") {
        Some("wix_burn".into())
    } else if has_ascii_case(&combined, b"InstallShield") {
        Some("installshield".into())
    } else if has_ascii_case(&combined, b"Squirrel") {
        Some("squirrel".into())
    } else {
        None
    }
}

fn script_kind(extension: &str, head: &[u8]) -> Option<&'static str> {
    match extension {
        "ps1" => Some("powershell"),
        "bat" | "cmd" => Some("batch"),
        "vbs" => Some("vbscript"),
        "js" | "mjs" | "cjs" => Some("javascript"),
        "py" | "pyw" => Some("python"),
        _ if head.starts_with(b"#!") => Some("script"),
        _ => None,
    }
}

fn looks_like_hta(extension: &str, head: &[u8]) -> bool {
    extension == "hta" || has_ascii_case(head, b"<hta:application")
}

fn looks_like_svg(head: &[u8], extension: &str) -> bool {
    if extension == "svg" {
        return true;
    }
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    text.contains("<svg") || (text.trim_start().starts_with("<?xml") && text.contains("svg"))
}

fn is_lnk(head: &[u8]) -> bool {
    const LNK_CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    head.len() >= 20 && head.starts_with(&[0x4C, 0x00, 0x00, 0x00]) && head[4..20] == LNK_CLSID
}

fn has_ascii(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| window == needle)
}

fn has_ascii_case(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_fake_mz() {
        assert!(!is_pe(b"MZ"));
        let mut bytes = vec![0u8; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(!is_pe(&bytes));
    }

    #[test]
    fn finds_trailing_zip() {
        let mut zip_bytes = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_bytes);
            zip.start_file("payload.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, b"trailing content").unwrap();
            zip.finish().unwrap();
        }
        let head = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        let mut tail = b"\0\0\0\0IEND\xaeB`\x82".to_vec();
        tail.extend_from_slice(zip_bytes.get_ref());
        let total_size = (head.len() + tail.len()) as u64;
        let result = sniff(Path::new("photo.png"), head, &tail, total_size);
        assert!(
            result
                .classification
                .formats
                .iter()
                .any(|f| f.kind == "zip")
        );
        assert!(result.classification.risky_trailing_data);
    }

    #[test]
    fn zip_member_headers_are_not_treated_as_embedded_archives() {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("first.txt", options).unwrap();
            std::io::Write::write_all(&mut zip, b"first").unwrap();
            zip.start_file("second.rar", options).unwrap();
            std::io::Write::write_all(&mut zip, b"Rar!\x1A\x07\x01\x00").unwrap();
            zip.finish().unwrap();
        }

        let hits = scan_all(bytes.get_ref());
        assert!(!hits.iter().any(|hit| hit.kind == "zip" && hit.offset > 0));
    }

    #[test]
    fn all_local_headers_of_a_valid_zip_belong_to_the_outer_archive() {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            for index in 0..40 {
                let options = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);
                zip.start_file(format!("ppt/slides/slide{index}.xml"), options)
                    .unwrap();
                std::io::Write::write_all(
                    &mut zip,
                    format!("<p:sld><a:t>{index}</a:t></p:sld>").as_bytes(),
                )
                .unwrap();
            }
            zip.finish().unwrap();
        }

        let hits = scan_all(bytes.get_ref());
        assert!(!hits.iter().any(|hit| hit.kind == "zip"));
    }

    #[test]
    fn pdf_stream_payload_is_not_mistaken_for_embedded_formats() {
        let mut pdf = b"%PDF-1.7\n1 0 obj\n<< /Length 17 >>\nstream\n".to_vec();
        pdf.extend_from_slice(b"random /JS PK\x03\x04 bytes");
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF");

        let hits = scan_all(&pdf);
        assert!(hits.is_empty());
    }

    #[test]
    fn finds_zip_appended_outside_pdf_stream_data() {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            zip.start_file("payload.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, b"hello").unwrap();
            zip.finish().unwrap();
        }
        let mut pdf = b"%PDF-1.7\n".to_vec();
        pdf.extend_from_slice(bytes.get_ref());
        pdf.extend_from_slice(b"\n%%EOF");

        let hits = scan_all(&pdf);
        assert!(
            hits.iter().any(|hit| hit.kind == "zip" && hit.offset > 0),
            "hits={hits:?}, streams={:?}",
            pdf_stream_ranges(&pdf)
        );
    }

    #[test]
    fn office_relationship_extensions_are_recognized_as_text() {
        assert!(!extension_mismatch("rels", "unknown"));
    }

    #[test]
    fn validates_webp_riff_header_without_an_extension_mismatch() {
        let webp = b"RIFF\x04\0\0\0WEBP";
        let result = sniff(Path::new("comic.webp"), webp, webp, webp.len() as u64);
        assert!(
            result
                .classification
                .formats
                .iter()
                .any(|format| format.kind == "webp")
        );
        assert!(!result.classification.extension_mismatch);
        assert!(!result.classification.risky_trailing_data);
    }
}
