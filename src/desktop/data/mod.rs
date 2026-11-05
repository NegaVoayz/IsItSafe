use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::capture::escape_controls;
use crate::config::{AppPaths, Config};
use crate::db::{Database, normalize_path};
use crate::report::{
    AnalysisReportV1, CertificateRole, ProductIdentityEvidence, ReportSummary, Severity, Verdict,
};

include!("model.rs");
include!("signatures.rs");
include!("grouping.rs");
include!("snapshot.rs");
include!("formatting.rs");

#[cfg(test)]
mod tests {
    include!("tests/core.rs");
    include!("tests/signatures.rs");
    include!("tests/grouping.rs");
    include!("tests/snapshot.rs");
}
