use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use isitsafe::Watcher;
use isitsafe::config::{AppPaths, Config};
use isitsafe::db::Database;
use isitsafe::interaction::{NotificationAction, parse_notification_action};
use isitsafe::policy::{prune_quarantine, restore_quarantine};
use isitsafe::sandbox::{is_internal_child_invocation, run_child_main};
use isitsafe::secrets::store_virus_total_api_key;
use isitsafe::security::ensure_download_execution_barrier;

include!("cli/types.rs");
include!("cli/run.rs");
include!("cli/maintenance.rs");
