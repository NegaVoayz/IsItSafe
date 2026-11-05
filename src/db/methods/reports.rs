impl Database {
    pub fn store_report(&self, report: &AnalysisReportV1) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        let verdict = serde_json::to_string(&report.verdict)?
            .trim_matches('"')
            .to_string();
        let summary = serde_json::to_string(&report.summary())?;
        connection.execute(
            "INSERT INTO reports
             (report_id, sha256, path, verdict, created_at, json, summary_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(report_id) DO UPDATE SET
               sha256=excluded.sha256,
               path=excluded.path,
               json=excluded.json,
               verdict=excluded.verdict,
               summary_json=excluded.summary_json",
            params![
                report.report_id.to_string(),
                report.file.sha256,
                report.file.display_path,
                verdict,
                report.observed_at.to_rfc3339(),
                serde_json::to_string(report)?,
                summary,
            ],
        )?;
        Ok(())
    }

    pub fn report_by_id(&self, report_id: &str) -> Result<Option<AnalysisReportV1>> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT json FROM reports WHERE report_id=?1",
                [report_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|json| {
                serde_json::from_str(&json)
                    .with_context(|| format!("stored report {report_id} is not valid JSON"))
            })
            .transpose()
    }

    pub fn latest_report_summaries(&self) -> Result<Vec<ReportSummary>> {
        let connection = self.connection.lock().unwrap();
        let rows = {
            let mut statement = connection.prepare(
                "SELECT report_id, summary_json FROM reports
                 WHERE summary_json IS NOT NULL
                 ORDER BY created_at DESC",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut seen = HashSet::new();
        let mut summaries = Vec::new();
        for (report_id, summary_json) in rows {
            let mut summary: ReportSummary = serde_json::from_str(&summary_json)
                .context("stored report summary is not valid JSON")?;
            if summary.schema_version != REPORT_SUMMARY_SCHEMA_VERSION {
                let report_json = connection.query_row(
                    "SELECT json FROM reports WHERE report_id=?1",
                    [&report_id],
                    |row| row.get::<_, String>(0),
                )?;
                let report: AnalysisReportV1 = serde_json::from_str(&report_json)
                    .context("stored report cannot be re-summarized")?;
                summary = report.summary();
                connection.execute(
                    "UPDATE reports SET summary_json=?1 WHERE report_id=?2",
                    params![
                        serde_json::to_string(&summary)?,
                        summary.report_id.to_string()
                    ],
                )?;
            }
            if seen.insert(normalize_path(&summary.path)) {
                summaries.push(summary);
            }
        }
        Ok(summaries)
    }

    pub fn report_by_sha256(&self, sha256: &str) -> Result<Option<AnalysisReportV1>> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT json FROM reports WHERE sha256=?1
                 ORDER BY created_at DESC LIMIT 1",
                [sha256],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|json| {
                serde_json::from_str(&json)
                    .with_context(|| format!("stored report for {sha256} is not valid JSON"))
            })
            .transpose()
    }

    pub fn report_verdict_counts(&self) -> Result<Vec<(String, i64)>> {
        let connection = self.connection.lock().unwrap();
        let mut statement =
            connection.prepare("SELECT verdict, COUNT(*) FROM reports GROUP BY verdict")?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn prune_reports(&self, age: Duration) -> Result<usize> {
        let connection = self.connection.lock().unwrap();
        let cutoff = DateTime::<Utc>::from(std::time::SystemTime::now())
            - chrono::Duration::from_std(age).unwrap_or_default();
        Ok(connection.execute(
            "DELETE FROM reports WHERE created_at<?1",
            [cutoff.to_rfc3339()],
        )?)
    }

}
