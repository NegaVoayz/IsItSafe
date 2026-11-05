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

