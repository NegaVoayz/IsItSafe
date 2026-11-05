use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

include!("types.rs");
include!("defaults.rs");
include!("loader.rs");
include!("paths.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
