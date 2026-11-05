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

