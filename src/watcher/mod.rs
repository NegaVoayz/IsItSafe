use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use chrono::Utc;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};
use walkdir::WalkDir;

use crate::analysis::ChildAnalysis;
use crate::capture::{CaptureDepth, CaptureError, CapturedFile, capture, escape_controls};
use crate::config::{AppPaths, Config};
use crate::db::{Database, Observation};
use crate::detect::sniff;
use crate::interaction::{should_notify, show_review_notification};
use crate::origin;
use crate::policy::{apply_quarantine, evaluate};
use crate::report::{
    AnalysisReportV1, Boundary, BoundaryKind, FileEvidence, LockAcquisitionEvidence,
    LockAcquisitionOutcome, PolicyAction, PublisherReputation, ReputationState, Severity,
    UserDecision, Verdict, VtBatch,
};
use crate::reputation::{ReputationManager, post_child_candidates, pre_child_triggers};
use crate::revocation;
use crate::rules;
use crate::sandbox::run_sandboxed;

include!("types.rs");
include!("methods/lifecycle.rs");
include!("methods/processing.rs");
include!("methods/analysis.rs");
include!("methods/actions.rs");
include!("methods/events.rs");
include!("support.rs");
include!("human_report.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
