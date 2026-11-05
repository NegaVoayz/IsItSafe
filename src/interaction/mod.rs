use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use url::Url;
use uuid::Uuid;

use crate::config::{AppPaths, Config};
use crate::db::Database;
use crate::policy::{apply_quarantine, remove_verified};
use crate::report::{
    AnalysisReportV1, PolicyAction, ReputationState, Severity, UserDecision, Verdict,
};

pub const APP_USER_MODEL_ID: &str = "IsItSafe.Desktop";
pub const ACTION_SCHEME: &str = "isitsafe";
const LEGACY_ACTION_SCHEME: &str = "isitsafe-action";
#[cfg(windows)]
const LEGACY_BROKEN_ACTIVATOR_CLSID: &str = "980b8b22-b56a-4bf3-a73e-44d157f9a3b7";

include!("notifications.rs");
include!("decisions.rs");
include!("reports.rs");
include!("windows.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
