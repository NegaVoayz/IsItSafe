use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;

use crate::capture::{CaptureDepth, capture, remove_if_hash_matches};
use crate::config::{Config, GIB};
use crate::db::{Database, normalize_path};
use crate::process::hidden_command;
use crate::report::{
    AnalysisReportV1, BoundaryKind, PolicyAction, PublisherReputation, ReputationState, Severity,
    Verdict,
};

include!("evaluate.rs");
include!("quarantine.rs");
include!("access.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
