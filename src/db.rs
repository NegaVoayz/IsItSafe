use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::report::{AnalysisReportV1, REPORT_SUMMARY_SCHEMA_VERSION, ReportSummary, Verdict};

#[derive(Debug)]
pub struct Database {
    connection: Mutex<Connection>,
    pub path: PathBuf,
    pub recovered_from: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub path: String,
    pub volume_identity: Option<String>,
    pub file_id: Option<String>,
    pub size: u64,
    pub modified_ns: Option<i64>,
    pub sha256: Option<String>,
    pub state: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadOrigin {
    pub schema_version: u32,
    pub download_id: String,
    pub source_url: String,
    pub final_url: Option<String>,
    pub referrer: Option<String>,
    pub final_path: String,
    pub timestamp: DateTime<Utc>,
    pub expected_size: Option<u64>,
    pub browser_danger: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedReputation {
    pub body: serde_json::Value,
    pub checked_at: DateTime<Utc>,
    pub query_batch: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub sha256: String,
    pub path: PathBuf,
    pub moved_at: DateTime<Utc>,
    pub report_id: Option<Uuid>,
    pub summary: Option<ReportSummary>,
}

#[derive(Debug, Clone, Default)]
pub struct IntegrityResult {
    pub ok: bool,
    pub detail: String,
}

impl Database {
    pub fn open_with_recovery(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        match Self::open(path) {
            Ok(db) => {
                let integrity = db.integrity_check()?;
                if integrity.ok {
                    Ok(db)
                } else {
                    drop(db);
                    let backup = backup_corrupt(path, &integrity.detail)?;
                    let db = Self::open(path)?;
                    Ok(Self {
                        recovered_from: Some(backup),
                        ..db
                    })
                }
            }
            Err(error) => {
                let backup = backup_corrupt(path, &error.to_string())?;
                let db = Self::open(path)?;
                Ok(Self {
                    recovered_from: Some(backup),
                    ..db
                })
            }
        }
    }

    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open database {}", path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1000)?;
        initialize_schema(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            path: path.to_path_buf(),
            recovered_from: None,
        })
    }

    pub fn integrity_check(&self) -> Result<IntegrityResult> {
        let connection = self.connection.lock().unwrap();
        let detail: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(IntegrityResult {
            ok: detail == "ok",
            detail,
        })
    }

    pub fn checkpoint(&self, truncate: bool) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        let mode = if truncate { "TRUNCATE" } else { "PASSIVE" };
        connection.execute_batch(&format!("PRAGMA wal_checkpoint({mode});"))?;
        Ok(())
    }

    pub fn upsert_observation(&self, observation: &Observation) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO observations
             (path, volume_identity, file_id, size, modified_ns, sha256, state, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(path) DO UPDATE SET
               volume_identity=excluded.volume_identity,
               file_id=excluded.file_id,
               size=excluded.size,
               modified_ns=excluded.modified_ns,
               sha256=excluded.sha256,
               state=excluded.state,
               updated_at=excluded.updated_at",
            params![
                observation.path,
                observation.volume_identity,
                observation.file_id,
                observation.size as i64,
                observation.modified_ns,
                observation.sha256,
                observation.state,
                observation.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn observation(&self, path: &str) -> Result<Option<Observation>> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT path, volume_identity, file_id, size, modified_ns, sha256, state, updated_at
                 FROM observations WHERE path=?1",
                [path],
                |row| {
                    let updated: String = row.get(7)?;
                    Ok(Observation {
                        path: row.get(0)?,
                        volume_identity: row.get(1)?,
                        file_id: row.get(2)?,
                        size: row.get::<_, i64>(3)? as u64,
                        modified_ns: row.get(4)?,
                        sha256: row.get(5)?,
                        state: row.get(6)?,
                        updated_at: DateTime::parse_from_rfc3339(&updated)
                            .map(|value| value.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn update_observation_state(&self, path: &str, state: &str) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE observations SET state=?2, updated_at=?3 WHERE path=?1",
            params![path, state, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn enqueue_job(&self, path: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO jobs (id, path, state, created_at, attempts)
             VALUES (?1, ?2, 'pending', ?3, 0)
             ON CONFLICT(path) DO UPDATE SET
               state='pending',
               created_at=excluded.created_at",
            params![id.to_string(), path, Utc::now().to_rfc3339()],
        )?;
        Ok(id)
    }

    pub fn pending_jobs(&self, limit: usize) -> Result<Vec<(Uuid, String)>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT id, path FROM jobs WHERE state='pending' ORDER BY created_at LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            let id: String = row.get(0)?;
            Ok((
                Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::new_v4()),
                row.get(1)?,
            ))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn job_started(&self, id: Uuid) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE jobs SET state='running', attempts=attempts+1 WHERE id=?1",
            [id.to_string()],
        )?;
        Ok(())
    }

    pub fn job_finished(&self, id: Uuid, error: Option<&str>) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE jobs SET state=?2, last_error=?3 WHERE id=?1",
            params![
                id.to_string(),
                if error.is_some() { "failed" } else { "done" },
                error
            ],
        )?;
        Ok(())
    }

    pub fn requeue_interrupted_jobs(&self) -> Result<usize> {
        let connection = self.connection.lock().unwrap();
        Ok(connection.execute("UPDATE jobs SET state='pending' WHERE state='running'", [])?)
    }

    pub fn mark_path_running(&self, path: &str) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE jobs SET state='running', attempts=attempts+1 WHERE path=?1",
            [path],
        )?;
        Ok(())
    }

    pub fn mark_path_finished(&self, path: &str, error: Option<&str>) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE jobs SET state=?2, last_error=?3 WHERE path=?1",
            params![path, if error.is_some() { "failed" } else { "done" }, error],
        )?;
        Ok(())
    }

    pub fn insert_origin(&self, origin: &DownloadOrigin) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        let normalized_path = normalize_path(&origin.final_path);
        connection.execute(
            "INSERT INTO origins
             (download_id, normalized_path, source_url, final_url, referrer, timestamp,
              expected_size, browser_danger, final_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(download_id) DO UPDATE SET
               normalized_path=excluded.normalized_path,
               source_url=excluded.source_url,
               final_url=excluded.final_url,
               referrer=excluded.referrer,
               timestamp=excluded.timestamp,
               expected_size=excluded.expected_size,
               browser_danger=excluded.browser_danger,
               final_path=excluded.final_path",
            params![
                origin.download_id,
                normalized_path,
                origin.source_url,
                origin.final_url,
                origin.referrer,
                origin.timestamp.to_rfc3339(),
                origin.expected_size.map(|value| value as i64),
                origin.browser_danger,
                origin.final_path,
            ],
        )?;
        Ok(())
    }

    pub fn find_origin(
        &self,
        final_path: &str,
        window: Duration,
    ) -> Result<Option<DownloadOrigin>> {
        let connection = self.connection.lock().unwrap();
        let normalized = normalize_path(final_path);
        let threshold = Utc::now() - chrono::Duration::from_std(window).unwrap_or_default();
        connection
            .query_row(
                "SELECT download_id, source_url, final_url, referrer, timestamp,
                        expected_size, browser_danger, final_path
                 FROM origins
                 WHERE normalized_path=?1 AND timestamp>=?2
                 ORDER BY timestamp DESC LIMIT 1",
                params![normalized, threshold.to_rfc3339()],
                |row| {
                    let timestamp: String = row.get(4)?;
                    Ok(DownloadOrigin {
                        schema_version: 1,
                        download_id: row.get(0)?,
                        source_url: row.get(1)?,
                        final_url: row.get(2)?,
                        referrer: row.get(3)?,
                        timestamp: DateTime::parse_from_rfc3339(&timestamp)
                            .map(|value| value.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        expected_size: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
                        browser_danger: row.get(6)?,
                        final_path: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn bind_origin_hash(&self, final_path: &str, sha256: &str) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "UPDATE origins SET resolved_sha256=?2
             WHERE normalized_path=?1 AND resolved_sha256 IS NULL",
            params![normalize_path(final_path), sha256],
        )?;
        Ok(())
    }

    pub fn find_origin_by_hash(
        &self,
        sha256: &str,
        window: Duration,
    ) -> Result<Option<DownloadOrigin>> {
        let connection = self.connection.lock().unwrap();
        let threshold = Utc::now() - chrono::Duration::from_std(window).unwrap_or_default();
        connection
            .query_row(
                "SELECT download_id, source_url, final_url, referrer, timestamp,
                        expected_size, browser_danger, final_path
                 FROM origins
                 WHERE resolved_sha256=?1 AND timestamp>=?2
                 ORDER BY timestamp DESC LIMIT 1",
                params![sha256, threshold.to_rfc3339()],
                |row| {
                    let timestamp: String = row.get(4)?;
                    Ok(DownloadOrigin {
                        schema_version: 1,
                        download_id: row.get(0)?,
                        source_url: row.get(1)?,
                        final_url: row.get(2)?,
                        referrer: row.get(3)?,
                        timestamp: DateTime::parse_from_rfc3339(&timestamp)
                            .map(|value| value.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        expected_size: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
                        browser_danger: row.get(6)?,
                        final_path: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn cached_reputation(
        &self,
        sha256: &str,
        ttl: Duration,
    ) -> Result<Option<CachedReputation>> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT body, checked_at, query_batch FROM reputation_cache WHERE sha256=?1",
                [sha256],
                |row| {
                    let body: String = row.get(0)?;
                    let checked: String = row.get(1)?;
                    Ok(CachedReputation {
                        body: serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
                        checked_at: DateTime::parse_from_rfc3339(&checked)
                            .map(|value| value.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        query_batch: row.get(2)?,
                    })
                },
            )
            .optional()
            .map(|value| {
                value.filter(|entry| {
                    Utc::now()
                        .signed_duration_since(entry.checked_at)
                        .to_std()
                        .unwrap_or(Duration::MAX)
                        <= ttl
                })
            })
            .map_err(Into::into)
    }

    pub fn claim_rate_slot(&self, key: &str, requests_per_minute: u32) -> Result<bool> {
        let interval_ms = 60_000u64 / u64::from(requests_per_minute.max(1));
        loop {
            let now_ms = Utc::now().timestamp_millis() as u64;
            let connection = self.connection.lock().unwrap();
            let last_ms: Option<u64> = connection
                .query_row(
                    "SELECT last_at_ms FROM rate_limits WHERE key=?1",
                    [key],
                    |row| row.get::<_, i64>(0).map(|value| value as u64),
                )
                .optional()?;
            if last_ms.is_none_or(|last| now_ms.saturating_sub(last) >= interval_ms) {
                connection.execute(
                    "INSERT INTO rate_limits (key, last_at_ms) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET last_at_ms=excluded.last_at_ms",
                    params![key, now_ms as i64],
                )?;
                return Ok(true);
            }
            drop(connection);
            let wait = interval_ms.saturating_sub(now_ms.saturating_sub(last_ms.unwrap_or(0)));
            std::thread::sleep(Duration::from_millis(wait.min(1_000)));
        }
    }

    pub fn cache_reputation(
        &self,
        sha256: &str,
        body: &serde_json::Value,
        checked_at: DateTime<Utc>,
        query_batch: Option<&str>,
    ) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO reputation_cache (sha256, body, checked_at, query_batch)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(sha256) DO UPDATE SET
               body=excluded.body,
               checked_at=excluded.checked_at,
               query_batch=excluded.query_batch",
            params![
                sha256,
                serde_json::to_string(body)?,
                checked_at.to_rfc3339(),
                query_batch
            ],
        )?;
        Ok(())
    }

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

    pub fn quarantine_record(&self, sha256: &str, path: &Path, report_id: Uuid) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO quarantine (sha256, path, moved_at, report_id)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                sha256,
                path.to_string_lossy(),
                Utc::now().to_rfc3339(),
                report_id.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn remove_quarantine_record(&self, sha256: &str) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        connection.execute("DELETE FROM quarantine WHERE sha256=?1", [sha256])?;
        Ok(())
    }

    pub fn quarantine_path(&self, sha256: &str) -> Result<Option<PathBuf>> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT path FROM quarantine WHERE sha256=?1",
                [sha256],
                |row| Ok(PathBuf::from(row.get::<_, String>(0)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_quarantine(&self) -> Result<Vec<(String, PathBuf, DateTime<Utc>)>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection
            .prepare("SELECT sha256, path, moved_at FROM quarantine ORDER BY moved_at DESC")?;
        let rows = statement.query_map([], |row| {
            let timestamp: String = row.get(2)?;
            Ok((
                row.get::<_, String>(0)?,
                PathBuf::from(row.get::<_, String>(1)?),
                DateTime::parse_from_rfc3339(&timestamp)
                    .map(|value| value.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            ))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn list_quarantine_entries(&self) -> Result<Vec<QuarantineEntry>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT q.sha256, q.path, q.moved_at, q.report_id,
                    COALESCE(
                      (SELECT r.summary_json FROM reports r
                       WHERE r.report_id=q.report_id),
                      (SELECT r.summary_json FROM reports r
                       WHERE r.sha256=q.sha256
                       ORDER BY r.created_at DESC LIMIT 1)
                    )
             FROM quarantine q
             ORDER BY q.moved_at DESC",
        )?;
        let rows = statement.query_map([], |row| {
            let moved_at: String = row.get(2)?;
            let report_id: Option<String> = row.get(3)?;
            let summary_json: Option<String> = row.get(4)?;
            let summary = summary_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            Ok(QuarantineEntry {
                sha256: row.get(0)?,
                path: PathBuf::from(row.get::<_, String>(1)?),
                moved_at: DateTime::parse_from_rfc3339(&moved_at)
                    .map(|value| value.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                report_id: report_id.and_then(|value| Uuid::parse_str(&value).ok()),
                summary,
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }
}

fn initialize_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS observations (
          path TEXT PRIMARY KEY,
          volume_identity TEXT,
          file_id TEXT,
          size INTEGER NOT NULL,
          modified_ns INTEGER,
          sha256 TEXT,
          state TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY,
          path TEXT NOT NULL UNIQUE,
          state TEXT NOT NULL,
          created_at TEXT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          last_error TEXT
        );
        CREATE TABLE IF NOT EXISTS origins (
          download_id TEXT PRIMARY KEY,
          normalized_path TEXT NOT NULL,
          source_url TEXT NOT NULL,
          final_url TEXT,
          referrer TEXT,
          timestamp TEXT NOT NULL,
          expected_size INTEGER,
          browser_danger TEXT,
          final_path TEXT NOT NULL,
          resolved_sha256 TEXT
        );
        CREATE INDEX IF NOT EXISTS origins_path_time
          ON origins(normalized_path, timestamp);
        CREATE TABLE IF NOT EXISTS reputation_cache (
          sha256 TEXT PRIMARY KEY,
          body TEXT NOT NULL,
          checked_at TEXT NOT NULL,
          query_batch TEXT
        );
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT PRIMARY KEY,
          last_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
          report_id TEXT PRIMARY KEY,
          sha256 TEXT,
          path TEXT NOT NULL,
          verdict TEXT NOT NULL,
          created_at TEXT NOT NULL,
          json TEXT NOT NULL,
          summary_json TEXT
        );
        CREATE TABLE IF NOT EXISTS quarantine (
          sha256 TEXT PRIMARY KEY,
          path TEXT NOT NULL,
          moved_at TEXT NOT NULL,
          report_id TEXT
        );
        ",
    )?;
    let has_sha_column = connection
        .prepare("PRAGMA table_info(origins)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "resolved_sha256");
    if !has_sha_column {
        connection.execute("ALTER TABLE origins ADD COLUMN resolved_sha256 TEXT", [])?;
    }
    let has_batch_column = connection
        .prepare("PRAGMA table_info(reputation_cache)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "query_batch");
    if !has_batch_column {
        connection.execute(
            "ALTER TABLE reputation_cache ADD COLUMN query_batch TEXT",
            [],
        )?;
    }
    let has_summary_column = connection
        .prepare("PRAGMA table_info(reports)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "summary_json");
    if !has_summary_column {
        connection.execute("ALTER TABLE reports ADD COLUMN summary_json TEXT", [])?;
    }
    let has_quarantine_report_column = connection
        .prepare("PRAGMA table_info(quarantine)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == "report_id");
    if !has_quarantine_report_column {
        connection.execute("ALTER TABLE quarantine ADD COLUMN report_id TEXT", [])?;
    }
    connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS origins_hash_time
           ON origins(resolved_sha256, timestamp);
         CREATE INDEX IF NOT EXISTS reports_path_time
           ON reports(path, created_at);
         CREATE INDEX IF NOT EXISTS reports_sha_time
           ON reports(sha256, created_at);",
    )?;
    backfill_report_summaries(connection)?;
    Ok(())
}

fn backfill_report_summaries(connection: &Connection) -> Result<()> {
    loop {
        let rows = {
            let mut statement = connection
                .prepare("SELECT rowid, json FROM reports WHERE summary_json IS NULL LIMIT 100")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.filter_map(Result::ok).collect::<Vec<_>>()
        };
        if rows.is_empty() {
            break;
        }
        for (rowid, json) in rows {
            let report: AnalysisReportV1 = serde_json::from_str(&json)
                .context("stored report cannot be summarized during migration")?;
            connection.execute(
                "UPDATE reports SET summary_json=?2 WHERE rowid=?1",
                params![rowid, serde_json::to_string(&report.summary())?],
            )?;
        }
    }
    Ok(())
}

fn backup_corrupt(path: &Path, detail: &str) -> Result<PathBuf> {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup = path.with_file_name(format!("state.corrupt.{timestamp}.db"));
    fs::copy(path, &backup)?;
    fs::write(
        backup.with_extension("corruption.txt"),
        format!("corruption detail: {detail}\n"),
    )?;
    fs::remove_file(path)?;
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", path.display()));
    }
    Ok(backup)
}

pub fn normalize_path(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

pub fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Malicious => "malicious",
        Verdict::Suspicious => "suspicious",
        Verdict::ReviewRequired => "review_required",
        Verdict::Unverified => "unverified",
        Verdict::Limited => "limited",
        Verdict::Incomplete => "incomplete",
        Verdict::BasicCheckOnly => "basic_check_only",
        Verdict::NoHighRiskFound => "no_high_risk_found",
    }
}

pub fn read_native_message<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length)?;
    let size = u32::from_le_bytes(length) as usize;
    if size == 0 || size > max_bytes {
        anyhow::bail!("native message size {size} exceeds limit {max_bytes}");
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub fn write_native_message<W: Write>(writer: &mut W, body: &[u8]) -> Result<()> {
    let size = u32::try_from(body.len()).context("native message is too large")?;
    writer.write_all(&size.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("state.db")).unwrap();
        let observation = Observation {
            path: "C:\\Downloads\\a.exe".into(),
            volume_identity: Some("1".into()),
            file_id: Some("2".into()),
            size: 42,
            modified_ns: None,
            sha256: Some("abc".into()),
            state: "complete".into(),
            updated_at: Utc::now(),
        };
        db.upsert_observation(&observation).unwrap();
        assert_eq!(db.observation(&observation.path).unwrap().unwrap().size, 42);
    }

    #[test]
    fn origin_correlation_handles_file_event_first() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("state.db")).unwrap();
        assert!(
            db.find_origin("C:\\Downloads\\first.exe", Duration::from_secs(60))
                .unwrap()
                .is_none()
        );
        db.insert_origin(&DownloadOrigin {
            schema_version: 1,
            download_id: "download-1".into(),
            source_url: "https://example.invalid/file".into(),
            final_url: Some("https://cdn.example.invalid/file.exe".into()),
            referrer: Some("https://example.invalid/".into()),
            final_path: "C:\\Downloads\\first.exe".into(),
            timestamp: Utc::now(),
            expected_size: Some(10),
            browser_danger: Some("safe".into()),
        })
        .unwrap();
        let found = db
            .find_origin("c:/downloads/FIRST.EXE", Duration::from_secs(60))
            .unwrap()
            .unwrap();
        assert_eq!(found.download_id, "download-1");
    }

    #[test]
    fn latest_summary_and_quarantine_reason_are_linked_to_the_report() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("state.db")).unwrap();
        let path = directory.path().join("bad.exe");
        fs::write(&path, b"sample").unwrap();
        let mut older = AnalysisReportV1::new(crate::report::FileEvidence {
            display_path: path.to_string_lossy().into_owned(),
            sha256: Some("a".repeat(64)),
            size: 6,
            ..crate::report::FileEvidence::default()
        });
        older.verdict = Verdict::Suspicious;
        older.policy.reasons.push("older reason".into());
        db.store_report(&older).unwrap();

        let mut current = AnalysisReportV1::new(crate::report::FileEvidence {
            display_path: path.to_string_lossy().into_owned(),
            sha256: Some("b".repeat(64)),
            size: 7,
            ..crate::report::FileEvidence::default()
        });
        current.verdict = Verdict::Malicious;
        current
            .policy
            .reasons
            .push("current malicious reason".into());
        db.store_report(&current).unwrap();

        let summaries = db.latest_report_summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].report_id, current.report_id);
        assert_eq!(summaries[0].reasons, vec!["current malicious reason"]);

        let quarantine_path = directory.path().join("bad.exe.aaaaaaaaaaaa.quarantined");
        db.quarantine_record("a".repeat(64).as_str(), &quarantine_path, older.report_id)
            .unwrap();
        let entries = db.list_quarantine_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].report_id, Some(older.report_id));
        assert_eq!(
            entries[0].summary.as_ref().unwrap().reasons,
            vec!["older reason"]
        );
    }

    #[test]
    fn latest_summaries_refresh_after_the_summary_schema_changes() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("state.db")).unwrap();
        let mut report = AnalysisReportV1::new(crate::report::FileEvidence {
            display_path: directory
                .path()
                .join("metadata.winmd")
                .to_string_lossy()
                .into_owned(),
            ..crate::report::FileEvidence::default()
        });
        report.authenticity = Some(crate::report::AuthenticityEvidence {
            signature_digest_valid: Some(true),
            chain_valid: Some(true),
            timestamp_state: crate::report::TimestampState::Unknown,
            ..crate::report::AuthenticityEvidence::default()
        });
        report
            .certificates
            .push(crate::report::CertificateChainEvidence {
                subject: "CN=Example Publisher".into(),
                issuer: "CN=Example Root".into(),
                serial_number: "01".into(),
                sha256_fingerprint: "a".repeat(64),
                ocsp_urls: Vec::new(),
                crl_urls: Vec::new(),
                role: crate::report::CertificateRole::Leaf,
                root_trusted: Some(true),
                timestamp_present: true,
                timestamp_time: None,
                not_before: Some(Utc::now() - chrono::Duration::days(365)),
                not_after: Some(Utc::now() - chrono::Duration::days(1)),
                revocation: crate::report::RevocationEvidence {
                    state: crate::report::RevocationState::Valid,
                    ..crate::report::RevocationEvidence::default()
                },
            });
        db.store_report(&report).unwrap();

        let mut old_summary = report.summary();
        old_summary.schema_version = "1.0".into();
        old_summary.reasons = vec!["Online reputation incomplete".into()];
        db.connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE reports SET summary_json=?1 WHERE report_id=?2",
                params![
                    serde_json::to_string(&old_summary).unwrap(),
                    report.report_id.to_string()
                ],
            )
            .unwrap();

        let summaries = db.latest_report_summaries().unwrap();

        assert_eq!(summaries[0].schema_version, REPORT_SUMMARY_SCHEMA_VERSION);
        assert_eq!(summaries[0].reasons, vec!["Certificate has expired"]);
    }
}
