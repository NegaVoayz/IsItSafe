#![cfg_attr(not(windows), allow(dead_code))]

pub mod analysis;
pub mod capture;
pub mod config;
pub mod db;
pub mod desktop;
pub mod detect;
pub mod interaction;
pub mod policy;
pub mod report;
pub mod reputation;
pub mod sandbox;
pub mod watcher;

mod integration;
mod network;
mod platform;

pub use integration::origin;
pub use network::{revocation, rules};
pub(crate) use platform::process;
pub use platform::{context_menu, logging, notification_activator, secrets, security, startup};

pub use analysis::analyze_bytes;
pub use config::Config;
pub use report::{
    AnalysisReportV1, Boundary, BoundaryKind, FileEvidence, LockAcquisitionOutcome, MotwState,
    OriginState, ReputationState, Verdict,
};
pub use watcher::Watcher;
