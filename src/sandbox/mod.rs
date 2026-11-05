use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt;

use crate::analysis::{AnalysisLimits, ChildAnalysis, ChildSandboxProof, analyze_bytes_with_rules};
use crate::config::Config;
use crate::report::{Boundary, BoundaryKind, ChildExecution, SandboxCapability, SandboxSelfTest};

pub const INTERNAL_CHILD_ARGUMENT: &str = "__isitsafe_analysis_child";
const PROTOCOL_VERSION: u32 = 1;

include!("model.rs");
include!("child.rs");
include!("runner.rs");
include!("protocol.rs");

#[cfg(windows)]
include!("windows/admission.rs");
#[cfg(windows)]
include!("windows/app_container_launch.rs");
#[cfg(windows)]
include!("windows/app_container.rs");
#[cfg(windows)]
include!("windows/proof.rs");
#[cfg(windows)]
include!("windows/job.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
