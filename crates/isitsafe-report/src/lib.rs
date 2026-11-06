use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

include!("model.rs");
include!("file.rs");
include!("certificates.rs");
include!("verdicts.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
