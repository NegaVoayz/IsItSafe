fn allowlisted(report: &AnalysisReportV1, config: &Config) -> bool {
    let signer = report
        .certificates
        .iter()
        .find(|certificate| certificate.role == crate::report::CertificateRole::Leaf)
        .map(|certificate| certificate.sha256_fingerprint.as_str());
    config.policy.allowlist.iter().any(|entry| {
        let origin_match = report
            .origin
            .source_url
            .as_deref()
            .or(report.origin.final_url.as_deref())
            .is_some_and(|url| origin_matches(url, &entry.origin, entry.path_prefix.as_deref()));
        let signer_match = entry
            .signer_sha256
            .as_deref()
            .zip(signer)
            .is_some_and(|(expected, actual)| expected.eq_ignore_ascii_case(actual));
        origin_match && (entry.signer_sha256.is_none() || signer_match)
    })
}

fn origin_matches(url: &str, expected: &str, path_prefix: Option<&str>) -> bool {
    let Ok(actual) = url::Url::parse(url) else {
        return false;
    };
    let Ok(expected) = url::Url::parse(expected) else {
        return false;
    };
    if actual.scheme() != expected.scheme()
        || actual.host_str() != expected.host_str()
        || actual.port_or_known_default() != expected.port_or_known_default()
    {
        return false;
    }
    path_prefix.is_none_or(|prefix| actual.path().starts_with(prefix))
}

#[cfg(windows)]
fn deny_execute_acl(path: &Path) -> Result<()> {
    let user = std::env::var("USERNAME").context("USERNAME is unavailable")?;
    let output = hidden_command("icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:(R,W,D)"))
        .output()
        .context("failed to run icacls for quarantine ACL")?;
    if !output.status.success() {
        bail!("icacls failed to set quarantine ACL");
    }
    Ok(())
}

#[cfg(not(windows))]
fn deny_execute_acl(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn allow_execute_acl(path: &Path) -> Result<()> {
    let user = std::env::var("USERNAME").context("USERNAME is unavailable")?;
    let output = hidden_command("icacls.exe")
        .arg(path)
        .arg("/grant")
        .arg(format!("{user}:(RX)"))
        .output()
        .context("failed to run icacls while restoring quarantine")?;
    if !output.status.success() {
        bail!("quarantine file was restored but its execute ACL could not be restored");
    }
    Ok(())
}

fn restore_destination_acl(path: &Path, config: &Config) -> Result<()> {
    if config.security.block_execution_in_download_dir && path_is_under(path, &config.download_dir)
    {
        deny_execute_acl(path)
    } else {
        allow_execute_acl(path)
    }
}

fn path_is_under(path: &Path, directory: &Path) -> bool {
    let path = normalize_path(&path.to_string_lossy());
    let directory = normalize_path(&directory.to_string_lossy())
        .trim_end_matches('\\')
        .to_string();
    path.starts_with(&(directory + "\\"))
}

#[cfg(not(windows))]
fn allow_execute_acl(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn sort_categories(config: &Config) -> Vec<(String, String)> {
    config
        .policy
        .signer_categories
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub fn benchmark_normalization(bytes: u64) -> f64 {
    bytes as f64 / GIB as f64
}

