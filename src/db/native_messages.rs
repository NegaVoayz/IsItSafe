pub fn normalize_path(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

pub fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Malicious => "malicious",
        Verdict::Suspicious => "suspicious",
        Verdict::ReviewRequired => "review_required",
        Verdict::Unverified => "unverified",
        Verdict::Limited => "limited",
        Verdict::Incomplete => "incomplete",
        Verdict::BasicCheckOnly => "basic_check_only",
        Verdict::NoHighRiskFound => "no_high_risk_found",
    }
}

pub fn read_native_message<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length)?;
    let size = u32::from_le_bytes(length) as usize;
    if size == 0 || size > max_bytes {
        anyhow::bail!("native message size {size} exceeds limit {max_bytes}");
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub fn write_native_message<W: Write>(writer: &mut W, body: &[u8]) -> Result<()> {
    let size = u32::try_from(body.len()).context("native message is too large")?;
    writer.write_all(&size.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}
