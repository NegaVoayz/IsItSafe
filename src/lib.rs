#![cfg_attr(not(windows), allow(dead_code))]

pub mod analysis;
pub mod capture;
pub mod config;
pub mod db;
pub mod desktop;
pub mod detect;
pub mod interaction;
pub mod logging;
pub mod origin;
pub mod policy;
mod process;
pub mod report;
pub mod reputation;
pub mod revocation;
pub mod rules;
pub mod sandbox;
pub mod secrets;
pub mod security;
pub mod watcher;

pub use analysis::analyze_bytes;
pub use config::Config;
pub use report::{
    AnalysisReportV1, Boundary, BoundaryKind, FileEvidence, LockAcquisitionOutcome, MotwState,
    OriginState, ReputationState, Verdict,
};
pub use watcher::Watcher;
