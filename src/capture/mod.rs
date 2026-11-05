use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::report::{
    AlternateStream, Boundary, BoundaryKind, FileEvidence, LockAcquisitionEvidence,
    LockAcquisitionOutcome, MotwEvidence, MotwState, ThresholdDecisions,
};

include!("model.rs");
include!("snapshot.rs");
include!("handles.rs");
include!("metadata.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
