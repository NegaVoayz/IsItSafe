pub fn group_products_by_software(report: &AnalysisReportV1) -> Vec<SoftwareIdentityGroup> {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<String, SoftwareIdentityGroup> = BTreeMap::new();
    for product in &report.products {
        let product_name = display_product_name(product);
        let key = software_identity_key(product, &product_name);
        let certificate = signature_group_for_product(report, product);
        let group = groups.entry(key).or_insert_with(|| SoftwareIdentityGroup {
            product_name,
            manufacturer: nonempty(product.manufacturer.as_deref()).map(str::to_string),
            product_version: nonempty(product.product_version.as_deref()).map(str::to_string),
            certificates: Vec::new(),
        });
        if let Some(existing) = group.certificates.iter_mut().find(|existing| {
            existing.state == certificate.state
                && existing.certificate_sha256 == certificate.certificate_sha256
                && existing.signer == certificate.signer
        }) {
            existing.products.extend(certificate.products);
        } else {
            group.certificates.push(certificate);
        }
    }

    for group in groups.values_mut() {
        for certificate in &mut group.certificates {
            certificate.products.sort_by(|left, right| {
                carrier_name(left)
                    .to_ascii_lowercase()
                    .cmp(&carrier_name(right).to_ascii_lowercase())
                    .then_with(|| left.nesting_path.cmp(&right.nesting_path))
            });
        }
        group.certificates.sort_by(|left, right| {
            left.state
                .risk_rank()
                .cmp(&right.state.risk_rank())
                .then_with(|| {
                    left.signer
                        .to_ascii_lowercase()
                        .cmp(&right.signer.to_ascii_lowercase())
                })
        });
    }

    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by(|left, right| {
        left.risk_state()
            .risk_rank()
            .cmp(&right.risk_state().risk_rank())
            .then_with(|| {
                left.product_name
                    .to_ascii_lowercase()
                    .cmp(&right.product_name.to_ascii_lowercase())
            })
            .then_with(|| {
                left.product_version
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(right.product_version.as_deref().unwrap_or_default())
            })
    });
    groups
}

fn signature_group_for_product(
    report: &AnalysisReportV1,
    product: &ProductIdentityEvidence,
) -> SignatureGroup {
    let top_level_fingerprint = report
        .certificates
        .iter()
        .find(|certificate| certificate.role == CertificateRole::Leaf)
        .map(|certificate| certificate.sha256_fingerprint.clone());
    let component = product.nesting_path.as_deref().and_then(|path| {
        report
            .components
            .iter()
            .find(|component| component.nesting_path == path)
    });
    let top_level = product.nesting_path.is_none();
    let authenticity = top_level.then_some(report.authenticity.as_ref()).flatten();
    let signer = product
        .signer_identity
        .clone()
        .or_else(|| authenticity.and_then(|value| value.publisher_identity.clone()));
    let fingerprint = product
        .signer_sha256
        .clone()
        .or_else(|| top_level.then_some(top_level_fingerprint.clone()).flatten());
    let digest_valid = product
        .signature_digest_valid
        .or_else(|| authenticity.and_then(|value| value.signature_digest_valid));
    let certificate = fingerprint.as_deref().and_then(|fingerprint| {
        report.certificates.iter().find(|certificate| {
            certificate
                .sha256_fingerprint
                .eq_ignore_ascii_case(fingerprint)
        })
    });
    let not_before = product
        .signature_not_before
        .or_else(|| certificate.and_then(|value| value.not_before));
    let not_after = product
        .signature_not_after
        .or_else(|| certificate.and_then(|value| value.not_after));
    let signed = component.and_then(|value| value.signed).or_else(|| {
        (top_level
            && authenticity.is_some_and(|value| {
                value.publisher_identity.is_some() || value.signature_digest_valid.is_some()
            }))
        .then_some(true)
    });
    let now = Utc::now();
    let state = if digest_valid == Some(false) {
        SignatureState::Invalid
    } else if certificate
        .is_some_and(|value| value.revocation.state == crate::report::RevocationState::Revoked)
    {
        SignatureState::Revoked
    } else if signed == Some(false) {
        SignatureState::Unsigned
    } else if not_after.is_some_and(|value| now > value) {
        SignatureState::Expired
    } else if not_before.is_some_and(|value| now < value) {
        SignatureState::NotYetValid
    } else if digest_valid == Some(true) {
        SignatureState::Valid
    } else if signer.is_some() || signed == Some(true) {
        SignatureState::Unverified
    } else {
        SignatureState::Unknown
    };
    let signer = signer
        .as_deref()
        .map(compact_signer_name)
        .unwrap_or_else(|| match state {
            SignatureState::Invalid => "Invalid signature".into(),
            SignatureState::Unsigned => "No signature".into(),
            SignatureState::Unknown => "Signer unknown".into(),
            SignatureState::Unverified => "Signer unavailable".into(),
            SignatureState::Valid => "Verified signer".into(),
            SignatureState::Revoked => "Revoked certificate".into(),
            SignatureState::Expired => "Expired certificate".into(),
            SignatureState::NotYetValid => "Certificate not yet valid".into(),
        });
    SignatureGroup {
        signer,
        certificate_sha256: fingerprint,
        state,
        not_before,
        not_after,
        products: vec![product.clone()],
    }
}

fn software_identity_key(product: &ProductIdentityEvidence, product_name: &str) -> String {
    [
        product_name,
        product.manufacturer.as_deref().unwrap_or_default(),
        product.product_version.as_deref().unwrap_or_default(),
        product.product_code.as_deref().unwrap_or_default(),
        product.upgrade_code.as_deref().unwrap_or_default(),
    ]
    .join("\0")
    .to_ascii_lowercase()
}

fn display_product_name(product: &ProductIdentityEvidence) -> String {
    nonempty(product.product_name.as_deref())
        .or_else(|| nonempty(product.file_description.as_deref()))
        .or_else(|| nonempty(product.original_filename.as_deref()))
        .map(str::to_string)
        .or_else(|| {
            product
                .nesting_path
                .as_deref()
                .and_then(|path| Path::new(path).file_name())
                .map(|value| value.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "<unnamed software>".into())
}

fn carrier_name(product: &ProductIdentityEvidence) -> &str {
    product
        .original_filename
        .as_deref()
        .or(product.nesting_path.as_deref())
        .unwrap_or_default()
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn format_certificate_date(value: Option<DateTime<Utc>>) -> Option<String> {
    value.map(|date| date.format("%Y-%m-%d %H:%M UTC").to_string())
}

impl SignatureGroup {
    pub fn validity_label(&self) -> Option<String> {
        match (
            format_certificate_date(self.not_before),
            format_certificate_date(self.not_after),
        ) {
            (Some(not_before), Some(not_after)) => Some(format!("{not_before} to {not_after}")),
            (Some(not_before), None) => Some(format!("From {not_before}")),
            (None, Some(not_after)) => Some(format!("Until {not_after}")),
            (None, None) => None,
        }
    }
}

fn compact_signer_name(identity: &str) -> String {
    for attribute in ["CN=", "O="] {
        if let Some(start) = identity.find(attribute) {
            let value = &identity[start + attribute.len()..];
            let value = value.split(',').next().unwrap_or(value).trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    identity.to_string()
}

