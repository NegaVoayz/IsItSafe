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

include!("model.rs");
include!("methods/connection.rs");
include!("methods/jobs.rs");
include!("methods/origins.rs");
include!("methods/reputation.rs");
include!("methods/reports.rs");
include!("methods/quarantine.rs");

include!("schema.rs");
include!("native_messages.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
