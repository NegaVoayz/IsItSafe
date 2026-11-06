struct ParsedCertificate {
    subject: String,
    issuer: String,
    serial: String,
    ocsp_urls: Vec<String>,
    crl_urls: Vec<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

fn parse_certificate(der: &[u8]) -> ParsedCertificate {
    let fallback_fingerprint = hex::encode(Sha256::digest(der));
    let mut urls = extract_urls(der);
    urls.sort();
    urls.dedup();
    let ocsp_urls = urls
        .iter()
        .filter(|url| url.to_ascii_lowercase().contains("ocsp"))
        .cloned()
        .collect();
    let crl_urls = urls
        .iter()
        .filter(|url| !url.to_ascii_lowercase().contains("ocsp"))
        .cloned()
        .collect();
    match X509Certificate::from_der(der) {
        Ok((_, certificate)) => ParsedCertificate {
            subject: certificate.subject().to_string(),
            issuer: certificate.issuer().to_string(),
            serial: certificate.raw_serial_as_string(),
            ocsp_urls,
            crl_urls,
            not_before: DateTime::from_timestamp(certificate.validity().not_before.timestamp(), 0),
            not_after: DateTime::from_timestamp(certificate.validity().not_after.timestamp(), 0),
        },
        Err(_) => ParsedCertificate {
            subject: "<unreadable certificate>".into(),
            issuer: "<unreadable issuer>".into(),
            serial: fallback_fingerprint,
            ocsp_urls,
            crl_urls,
            not_before: None,
            not_after: None,
        },
    }
}

fn certificate_usage(der: &[u8]) -> (bool, bool) {
    let Ok((_, certificate)) = X509Certificate::from_der(der) else {
        return (false, false);
    };
    let Ok(Some(usage)) = certificate.extended_key_usage() else {
        return (false, false);
    };
    (usage.value.code_signing, usage.value.time_stamping)
}

fn select_publisher(leaf_candidates: &[(String, bool, bool)]) -> Option<String> {
    leaf_candidates
        .iter()
        .find(|(_, code_signing, time_stamping)| *code_signing && !*time_stamping)
        .or_else(|| leaf_candidates.iter().find(|(_, _, timestamp)| !timestamp))
        .or_else(|| leaf_candidates.first())
        .map(|(subject, _, _)| subject.clone())
}

fn extract_urls(data: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    for scheme in [b"https://".as_slice(), b"http://".as_slice()] {
        let mut start = 0;
        while let Some(relative) = find_bytes(&data[start..], scheme) {
            let offset = start + relative;
            let end = data[offset..]
                .iter()
                .position(|byte| {
                    byte.is_ascii_whitespace()
                        || matches!(*byte, b'"' | b'\'' | b'<' | b'>' | b')' | b']')
                })
                .map(|value| offset + value)
                .unwrap_or(data.len());
            if end.saturating_sub(offset) <= 2048
                && let Ok(value) = std::str::from_utf8(&data[offset..end])
                && value.contains('.')
            {
                urls.push(value.to_string());
            }
            start = end.max(offset + scheme.len());
            if start >= data.len() {
                break;
            }
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

