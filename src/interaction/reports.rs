fn show_status_notification(title: &str, message: &str) -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::show_status(title, message)
    }
    #[cfg(not(windows))]
    {
        let _ = (title, message);
        Ok(())
    }
}

fn append_report(paths: &AppPaths, report: &AnalysisReportV1) -> Result<()> {
    let json = serde_json::to_string(report)?;
    let day = Utc::now().format("%Y-%m-%d");
    let report_path = paths.reports_dir.join(format!("{day}.jsonl"));
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&report_path)
        .with_context(|| format!("failed to open {}", report_path.display()))?;
    writeln!(file, "{json}")?;
    Ok(())
}

fn display_name(report: &AnalysisReportV1) -> String {
    report
        .source_path
        .as_deref()
        .and_then(Path::file_name)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            Path::new(&report.file.display_path)
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| report.file.display_path.clone())
        })
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

