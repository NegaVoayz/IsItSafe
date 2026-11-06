fn pe_overlay(data: &[u8]) -> Option<(u64, Vec<String>)> {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return None;
    }
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if data.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = u16::from_le_bytes(data.get(pe + 6..pe + 8)?.try_into().ok()?) as usize;
    let optional_size = u16::from_le_bytes(data.get(pe + 20..pe + 22)?.try_into().ok()?) as usize;
    let optional = pe.checked_add(24)?;
    let section_table = optional.checked_add(optional_size)?;
    let mut end = section_table.checked_add(sections.checked_mul(40)?)?;
    let mut names = Vec::new();
    for index in 0..sections {
        let entry = section_table.checked_add(index.checked_mul(40)?)?;
        let name = data.get(entry..entry + 8)?;
        names.push(
            String::from_utf8_lossy(name)
                .trim_end_matches('\0')
                .to_string(),
        );
        let raw_size = u32::from_le_bytes(data.get(entry + 16..entry + 20)?.try_into().ok()?);
        let raw_offset = u32::from_le_bytes(data.get(entry + 20..entry + 24)?.try_into().ok()?);
        end = end.max(raw_offset as usize + raw_size as usize);
    }
    Some((end as u64, names))
}

fn pe_has_signature_table(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
    let optional = pe.saturating_add(24);
    let magic = data.get(optional..optional + 2);
    let data_dir = match magic {
        Some([0x0B, 0x01]) => optional + 96,
        Some([0x0B, 0x02]) => optional + 112,
        _ => return false,
    };
    let security = data_dir.saturating_add(4 * 8);
    let offset = data
        .get(security..security + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);
    let size = data
        .get(security + 4..security + 8)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);
    offset != 0 && size != 0
}

fn sign_status(data: &[u8]) -> Option<bool> {
    if !detect::is_pe(data) {
        return None;
    }
    Some(pe_has_signature_table(data))
}

struct PeSignerIdentity {
    identity: String,
    sha256: String,
    digest_valid: Option<bool>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct SignerCandidate {
    identity: String,
    sha256: String,
    code_signing: bool,
    time_stamping: bool,
    self_signed: bool,
    is_ca: bool,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

fn pe_signer_identity(data: &[u8]) -> Option<PeSignerIdentity> {
    let info = AuthenticodeInfo::try_from(data).ok()?;
    let digest_valid = info.verify().ok();
    let mut candidates = Vec::new();
    for certificate in info.certificates.iter() {
        let Ok(encoded) = certificate.certificate.to_der() else {
            continue;
        };
        let parsed = parse_certificate(&encoded);
        let (code_signing, time_stamping) = certificate_usage(&encoded);
        let is_ca = match X509Certificate::from_der(&encoded) {
            Ok((_, certificate)) => certificate
                .basic_constraints()
                .ok()
                .flatten()
                .is_some_and(|constraints| constraints.value.ca),
            Err(_) => false,
        };
        candidates.push(SignerCandidate {
            self_signed: parsed.subject == parsed.issuer,
            identity: parsed.subject,
            sha256: certificate.sha256.to_hex(),
            code_signing,
            time_stamping,
            is_ca,
            not_before: parsed.not_before,
            not_after: parsed.not_after,
        });
    }
    let selected = select_signer_candidate(&candidates)?;
    Some(PeSignerIdentity {
        identity: selected.identity.clone(),
        sha256: selected.sha256.clone(),
        digest_valid,
        not_before: selected.not_before,
        not_after: selected.not_after,
    })
}

fn select_signer_candidate(candidates: &[SignerCandidate]) -> Option<&SignerCandidate> {
    candidates
        .iter()
        .find(|candidate| {
            candidate.code_signing
                && !candidate.time_stamping
                && !candidate.self_signed
                && !candidate.is_ca
        })
        .or_else(|| {
            candidates
                .iter()
                .find(|candidate| candidate.code_signing && !candidate.is_ca)
        })
        .or_else(|| {
            candidates
                .iter()
                .find(|candidate| !candidate.time_stamping && !candidate.is_ca)
        })
        .or_else(|| {
            candidates
                .iter()
                .find(|candidate| candidate.code_signing && !candidate.time_stamping)
        })
        .or_else(|| candidates.first())
}

fn record_pe_product(data: &[u8], nesting_path: &str, analysis: &mut ChildAnalysis) {
    let fallback_name = Path::new(nesting_path)
        .file_name()
        .map(|value| value.to_string_lossy().into_owned());
    if let Some(product) = pe_product_identity(data, Some(nesting_path.to_string()), fallback_name)
    {
        analysis.products.push(product);
    }
}

fn pe_product_identity(
    data: &[u8],
    nesting_path: Option<String>,
    fallback_name: Option<String>,
) -> Option<ProductIdentityEvidence> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    let version = pe.resource_data.and_then(|resource| resource.version_info);
    let strings = version.as_ref().map(|value| &value.string_info);
    let signer = pe_signer_identity(data);
    let product = ProductIdentityEvidence {
        product_name: strings
            .and_then(|value| metadata_value(value.product_name().as_deref()))
            .or(fallback_name),
        manufacturer: strings.and_then(|value| metadata_value(value.company_name().as_deref())),
        product_version: strings
            .and_then(|value| metadata_value(value.product_version().as_deref()))
            .or_else(|| {
                version
                    .and_then(|value| value.fixed_info)
                    .map(|fixed| fixed.product_version().to_string())
                    .and_then(|value| metadata_value(Some(&value)))
            }),
        original_filename: strings
            .and_then(|value| metadata_value(value.original_filename().as_deref())),
        file_description: strings
            .and_then(|value| metadata_value(value.file_description().as_deref())),
        legal_copyright: strings
            .and_then(|value| metadata_value(value.legal_copyright().as_deref())),
        signer_identity: signer.as_ref().map(|value| value.identity.clone()),
        signer_sha256: signer.as_ref().map(|value| value.sha256.clone()),
        signature_digest_valid: signer.as_ref().and_then(|value| value.digest_valid),
        signature_not_before: signer.as_ref().and_then(|value| value.not_before),
        signature_not_after: signer.as_ref().and_then(|value| value.not_after),
        source: if version.is_some() {
            "PE version information".into()
        } else {
            "PE filename fallback; version metadata unavailable".into()
        },
        nesting_path,
        ..ProductIdentityEvidence::default()
    };
    product.is_meaningful().then_some(product)
}

fn metadata_value(value: Option<&str>) -> Option<String> {
    value
        .map(escape_component_name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn note_product_identity_mismatch(
    path: &Path,
    product: &ProductIdentityEvidence,
    analysis: &mut ChildAnalysis,
) {
    let Some(downloaded_name) = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(escape_component_name)
    else {
        return;
    };
    let Some(original_name) = product.original_filename.as_deref() else {
        return;
    };
    if downloaded_name.eq_ignore_ascii_case(original_name) {
        return;
    }
    let product_name = product.product_name.as_deref().unwrap_or("not declared");
    let manufacturer = product.manufacturer.as_deref().unwrap_or("not declared");
    analysis.facts.push(Evidence {
        id: "identity:filename-mismatch".into(),
        category: "product_identity".into(),
        severity: Severity::Medium,
        summary: format!(
            "Downloaded file name {downloaded_name} differs from embedded original filename {original_name}"
        ),
        detail: Some(format!(
            "Declared product: {product_name}; declared manufacturer: {manufacturer}"
        )),
        provenance: "child PE version resource".into(),
        confidence: Confidence::Structural,
    });
}

fn evidence(
    id: impl Into<String>,
    category: &str,
    severity: Severity,
    summary: impl Into<String>,
    provenance: &str,
    confidence: Confidence,
) -> Evidence {
    Evidence {
        id: id.into(),
        category: category.into(),
        severity,
        summary: summary.into(),
        detail: None,
        provenance: provenance.into(),
        confidence,
    }
}

fn escape_component_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '\u{FFFD}' } else { ch })
        .take(1024)
        .collect()
}

