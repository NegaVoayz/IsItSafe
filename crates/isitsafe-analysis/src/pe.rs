fn analyze_pe(path: &Path, data: &[u8], _limits: &AnalysisLimits, analysis: &mut ChildAnalysis) {
    if let Some(mismatch) = pe_extension_mismatch(path, data) {
        analysis.facts.push(mismatch);
    }
    if let Some(product) = pe_product_identity(
        data,
        None,
        path.file_name()
            .map(|value| value.to_string_lossy().into_owned()),
    ) {
        note_product_identity_mismatch(path, &product, analysis);
        analysis.products.push(product);
    }
    if let Some((overlay_offset, sections)) = pe_overlay(data) {
        analysis.facts.push(evidence(
            "pe:structure",
            "pe_structure",
            Severity::Info,
            format!(
                "PE contains {} sections; overlay begins at offset {overlay_offset}",
                sections.len()
            ),
            "child PE parser",
            Confidence::Structural,
        ));
        if let Some(last) = analysis.facts.last_mut() {
            last.detail = Some(format!("sections: {}", sections.join(", ")));
        }
        if overlay_offset < data.len() as u64 {
            let overlay = &data[overlay_offset as usize..];
            if detect::scan_all(overlay)
                .iter()
                .any(|item| item.kind == "zip")
                || overlay.starts_with(b"PK\x03\x04")
            {
                analysis.facts.push(evidence(
                    "pe:overlay-archive",
                    "pe_overlay",
                    Severity::High,
                    "PE has an embedded archive after its mapped sections",
                    "child PE parser",
                    Confidence::Structural,
                ));
            }
        }
    }

    let remote_access_indicator = [
        b"teamviewer".as_slice(),
        b"anydesk".as_slice(),
        b"remoteaccess".as_slice(),
        b"tcpclient".as_slice(),
        b"reverse shell".as_slice(),
    ]
    .iter()
    .any(|needle| contains_ascii_case(data, needle));
    if remote_access_indicator {
        for url in extract_urls(data).into_iter().take(16) {
            analysis.facts.push(evidence(
                format!("pe:url:{}", analysis.facts.len()),
                "remote_access_endpoint",
                Severity::Medium,
                format!("Executable contains endpoint {url}"),
                "child PE string scan",
                Confidence::Inferred,
            ));
        }
    }

    match AuthenticodeInfo::try_from(data) {
        Ok(info) => {
            let digest_valid = info.verify().ok();
            let timestamp_present = data.windows(10).any(|window| {
                window == [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03]
            });
            let mut leaf_usage = HashMap::new();
            for certificate in info.certificates.iter() {
                let encoded = match certificate.certificate.to_der() {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let parsed = parse_certificate(&encoded);
                let (code_signing, time_stamping) = certificate_usage(&encoded);
                leaf_usage.insert(parsed.subject.clone(), (code_signing, time_stamping));
                analysis.certificates.push(CertificateChainEvidence {
                    subject: parsed.subject,
                    issuer: parsed.issuer,
                    serial_number: parsed.serial,
                    sha256_fingerprint: certificate.sha256.to_hex(),
                    ocsp_urls: parsed.ocsp_urls,
                    crl_urls: parsed.crl_urls,
                    role: CertificateRole::Unknown,
                    root_trusted: None,
                    timestamp_present,
                    timestamp_time: None,
                    not_before: parsed.not_before,
                    not_after: parsed.not_after,
                    revocation: RevocationEvidence {
                        state: RevocationState::NotChecked,
                        ..RevocationEvidence::default()
                    },
                });
            }
            let issuers: HashSet<String> = analysis
                .certificates
                .iter()
                .map(|certificate| certificate.issuer.clone())
                .collect();
            let mut leaf_candidates = Vec::new();
            for certificate in &mut analysis.certificates {
                certificate.role = if !issuers.contains(&certificate.subject) {
                    let (code_signing, time_stamping) = leaf_usage
                        .get(&certificate.subject)
                        .copied()
                        .unwrap_or((false, false));
                    leaf_candidates.push((
                        certificate.subject.clone(),
                        code_signing,
                        time_stamping,
                    ));
                    CertificateRole::Leaf
                } else if certificate.issuer == certificate.subject {
                    CertificateRole::Root
                } else {
                    CertificateRole::Intermediate
                };
            }
            let publisher = select_publisher(&leaf_candidates);
            analysis.authenticity = Some(AuthenticityEvidence {
                signature_digest_valid: digest_valid,
                chain_valid: None,
                timestamp_state: if timestamp_present {
                    TimestampState::Unknown
                } else {
                    TimestampState::Missing
                },
                publisher_identity: publisher,
                publisher_reputation: PublisherReputation::Unknown,
                unsigned_components: 0,
                detail: Some(
                    "Authenticode digest was validated in memory; offline chain and online revocation are reported separately"
                        .into(),
                ),
            });
            if digest_valid == Some(false) {
                analysis.facts.push(evidence(
                    "authenticode:invalid-digest",
                    "authenticode",
                    Severity::High,
                    "PE Authenticode digest does not match its signature",
                    "cross-authenticode in-memory verifier",
                    Confidence::Structural,
                ));
            }
        }
        Err(error) => {
            analysis.authenticity = Some(AuthenticityEvidence {
                signature_digest_valid: if pe_has_signature_table(data) {
                    Some(false)
                } else {
                    None
                },
                chain_valid: None,
                timestamp_state: TimestampState::Unknown,
                publisher_identity: None,
                publisher_reputation: PublisherReputation::Unknown,
                unsigned_components: 0,
                detail: Some(format!(
                    "PE is unsigned or its signature is unreadable: {error}"
                )),
            });
            if !pe_has_signature_table(data) {
                analysis.facts.push(evidence(
                    "authenticode:unsigned",
                    "authenticode",
                    Severity::High,
                    "Executable has no Authenticode signature",
                    "child PE parser",
                    Confidence::Structural,
                ));
            }
        }
    }
}

fn pe_extension_mismatch(path: &Path, data: &[u8]) -> Option<Evidence> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .filter(|value| !value.is_empty());
    let pe = goblin::pe::PE::parse(data).ok()?;
    let severity = pe_type_mismatch_severity(extension.as_deref(), pe.is_lib)?;
    let display_name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    let summary = pe_type_mismatch_summary(&display_name, extension.as_deref(), pe.is_lib);
    Some(evidence(
        format!("pe:type-mismatch:{display_name}"),
        "pe_extension_mismatch",
        severity,
        summary,
        "child PE header",
        Confidence::Structural,
    ))
}

fn pe_type_mismatch_summary(
    display_name: &str,
    extension: Option<&str>,
    is_library: bool,
) -> String {
    let kind = if is_library { "a DLL" } else { "an EXE" };
    match extension {
        Some(extension) => format!("{display_name} is {kind} disguised as .{extension}"),
        None => format!("{display_name} has no file extension but is {kind}"),
    }
}

fn pe_type_mismatch_severity(extension: Option<&str>, is_library: bool) -> Option<Severity> {
    const EXPECTED_PE_EXTENSIONS: &[&str] =
        &["exe", "dll", "sys", "ocx", "cpl", "scr", "efi", "acm", "ax"];
    match (extension, is_library) {
        (None, _) => Some(Severity::High),
        (Some(extension), _) if !EXPECTED_PE_EXTENSIONS.contains(&extension) => {
            (extension != "winmd" || !is_library).then_some(Severity::High)
        }
        (Some("dll"), false) => Some(Severity::High),
        (Some("exe"), true) => Some(Severity::Medium),
        _ => None,
    }
}

