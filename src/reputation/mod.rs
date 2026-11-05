use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};

use crate::config::Config;
use crate::db::Database;
use crate::report::{
    AuthenticityEvidence, Classification, ComponentEvidence, MotwState, OriginEvidence,
    PublisherReputation, ReputationEvidence, ReputationState, Severity, VtBatch,
};
use crate::secrets::virus_total_api_key;

include!("manager.rs");
include!("triggers.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
