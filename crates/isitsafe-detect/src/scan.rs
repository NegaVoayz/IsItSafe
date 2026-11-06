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

pub fn pdf_stream_ranges(data: &[u8]) -> Vec<(u64, u64)> {
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

