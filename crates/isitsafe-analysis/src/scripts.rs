fn inspect_scripts(path: &Path, data: &[u8], analysis: &mut ChildAnalysis) {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let script = matches!(
        extension.as_str(),
        "ps1" | "bat" | "cmd" | "vbs" | "js" | "mjs" | "hta" | "py" | "pyw"
    );
    let config_file = matches!(
        extension.as_str(),
        "ini" | "conf" | "cfg" | "json" | "yaml" | "yml" | "xml" | "toml"
    );
    if !script && !config_file {
        return;
    }
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    if script {
        let checks = [
            (
                "download",
                &["invoke-webrequest", "wget ", "curl ", "bitsadmin"][..],
                Severity::High,
            ),
            (
                "execution",
                &[
                    "start-process",
                    "invoke-expression",
                    "iex(",
                    "wscript.shell",
                ][..],
                Severity::High,
            ),
            (
                "evasion",
                &["-enc", "frombase64string", "hidden"][..],
                Severity::Medium,
            ),
            (
                "persistence",
                &["schtasks", "currentversion\\run", "new-service"][..],
                Severity::High,
            ),
            (
                "remote_access",
                &["reverse shell", "tcpclient", "connect(", "listener"][..],
                Severity::High,
            ),
            (
                "credential_material",
                &["password=", "passwd=", "api_key=", "token="][..],
                Severity::High,
            ),
        ];
        for (category, needles, severity) in checks {
            if needles.iter().any(|needle| text.contains(needle)) {
                analysis.facts.push(evidence(
                    format!("script:{category}"),
                    category,
                    severity,
                    format!("Script contains {category} behavior"),
                    "child script scan",
                    Confidence::Inferred,
                ));
            }
        }
        for url in extract_urls(data).into_iter().take(32) {
            analysis.facts.push(evidence(
                format!("script:url:{}", analysis.facts.len()),
                if text.contains("tcpclient") || text.contains("reverse shell") {
                    "remote_access_endpoint"
                } else {
                    "network_endpoint"
                },
                Severity::Medium,
                format!("Script references endpoint {url}"),
                "child URL extraction",
                Confidence::Structural,
            ));
        }
    }
    if config_file {
        for needle in ["password=", "passwd=", "api_key=", "token=", "secret="] {
            if text.contains(needle) {
                analysis.facts.push(evidence(
                    format!("config:credential:{needle}"),
                    "credential_material",
                    Severity::High,
                    format!("Configuration contains a credential-like field ({needle})"),
                    "child config scan",
                    Confidence::Inferred,
                ));
            }
        }
        if ["run=", "startup", "autostart", "currentversion\\run"]
            .iter()
            .any(|needle| text.contains(needle))
        {
            analysis.facts.push(evidence(
                "config:autostart",
                "autostart",
                Severity::High,
                "Configuration contains an autostart directive",
                "child config scan",
                Confidence::Inferred,
            ));
        }
    }
}

fn inspect_magic_polyglots(data: &[u8], analysis: &mut ChildAnalysis) {
    let formats = detect::scan_all(data);
    let top_level: HashSet<_> = analysis
        .classification
        .formats
        .iter()
        .filter(|format| format.offset == 0)
        .map(|format| format.kind.as_str())
        .collect();
    let unexpected: Vec<_> = formats
        .into_iter()
        .filter(|format| format.offset > 0 && !top_level.contains(format.kind.as_str()))
        .collect();
    if !unexpected.is_empty()
        && !analysis
            .facts
            .iter()
            .any(|fact| fact.category == "polyglot")
    {
        let primary_is_container = analysis
            .classification
            .formats
            .first()
            .is_some_and(|format| {
                matches!(
                    format.kind.as_str(),
                    "zip" | "rar" | "7z" | "cab" | "ole_cfb" | "msi"
                )
            });
        analysis.facts.push(Evidence {
            id: "polyglot:full-scan".into(),
            category: "polyglot".into(),
            severity: if primary_is_container {
                Severity::Medium
            } else {
                Severity::High
            },
            summary: if primary_is_container {
                "Nested container signatures occur inside the archive".into()
            } else {
                "Embedded file signatures occur at non-zero offsets".into()
            },
            detail: Some(
                unexpected
                    .iter()
                    .map(|format| format!("{}@{}", format.kind, format.offset))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            provenance: "child full-buffer signature scan".into(),
            confidence: Confidence::Structural,
        });
    }
}

