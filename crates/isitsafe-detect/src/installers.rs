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

