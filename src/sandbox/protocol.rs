fn serialize_bounded(mut analysis: ChildAnalysis, max_bytes: usize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&analysis)?;
    if bytes.len() <= max_bytes {
        return Ok(bytes);
    }
    analysis.components.clear();
    bytes = serde_json::to_vec(&analysis)?;
    if bytes.len() <= max_bytes {
        analysis.output_truncated = true;
        return Ok(serde_json::to_vec(&analysis)?);
    }
    for evidence in analysis
        .facts
        .iter_mut()
        .chain(analysis.inference.iter_mut())
    {
        evidence.detail = None;
    }
    bytes = serde_json::to_vec(&analysis)?;
    if bytes.len() <= max_bytes {
        analysis.output_truncated = true;
        return Ok(serde_json::to_vec(&analysis)?);
    }
    for certificate in &mut analysis.certificates {
        certificate.subject = truncate(&certificate.subject, 128);
        certificate.issuer = truncate(&certificate.issuer, 128);
        certificate.ocsp_urls.clear();
        certificate.crl_urls.clear();
    }
    analysis.output_truncated = true;
    bytes = serde_json::to_vec(&analysis)?;
    if bytes.len() <= max_bytes {
        return Ok(bytes);
    }
    let minimal = ChildAnalysis {
        classification: analysis.classification,
        output_truncated: true,
        boundaries: vec![Boundary {
            kind: BoundaryKind::OutputTruncated,
            detail: "child output exceeded the hard cap".into(),
        }],
        ..ChildAnalysis::default()
    };
    let bytes = serde_json::to_vec(&minimal)?;
    if bytes.len() > max_bytes {
        bail!("minimal child report exceeds configured output cap");
    }
    Ok(bytes)
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
