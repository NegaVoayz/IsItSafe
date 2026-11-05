impl DesktopSnapshot {
    pub fn review_count(&self, group: RiskGroup) -> usize {
        self.questionable
            .iter()
            .filter(|entry| entry.group == group)
            .count()
    }

    pub fn quarantine_count(&self, group: RiskGroup) -> usize {
        self.quarantine
            .iter()
            .filter(|entry| entry.group == group)
            .count()
    }
}

pub fn load_snapshot(
    config: &Config,
    database: &Database,
    _paths: &AppPaths,
) -> Result<DesktopSnapshot> {
    let summaries = database.latest_report_summaries()?;
    let mut questionable = Vec::new();
    for mut summary in summaries {
        summary.reasons = summary
            .reasons
            .into_iter()
            .map(|reason| escape_controls(&reason))
            .collect();
        if summary.user_decision.is_some() || summary.verdict == Verdict::NoHighRiskFound {
            continue;
        }
        if !is_current_download(&summary.path, &config.download_dir) {
            continue;
        }
        let group = RiskGroup::from_verdict(summary.verdict);
        questionable.push(QuestionableFile { summary, group });
    }
    questionable.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then_with(|| right.summary.observed_at.cmp(&left.summary.observed_at))
            .then_with(|| {
                left.summary
                    .file_name
                    .to_ascii_lowercase()
                    .cmp(&right.summary.file_name.to_ascii_lowercase())
            })
    });

    let mut quarantine = Vec::new();
    for entry in database.list_quarantine_entries()? {
        let (display_name, reasons, group) = if let Some(summary) = &entry.summary {
            (
                summary.file_name.clone(),
                summary.reasons.clone(),
                RiskGroup::from_verdict(summary.verdict),
            )
        } else {
            (
                quarantine_original_name(&entry.path),
                vec!["The original analysis report is unavailable".into()],
                RiskGroup::Unknown,
            )
        };
        quarantine.push(QuarantineItem {
            sha256: entry.sha256,
            path: entry.path,
            moved_at: entry.moved_at,
            summary: entry.summary,
            display_name,
            reasons,
            group,
        });
    }
    quarantine.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then_with(|| right.moved_at.cmp(&left.moved_at))
    });

    Ok(DesktopSnapshot {
        questionable,
        quarantine,
    })
}

