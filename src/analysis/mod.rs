use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use cross_authenticode::{AuthenticodeInfo, ToHex};
use der::Encode;
use rar_codec::{Archive as RarArchive, EntryKind as RarEntryKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use zip::ZipArchive;

use crate::config::{Config, LimitsConfig};
use crate::detect;
use crate::report::{
    AuthenticityEvidence, Boundary, BoundaryKind, CertificateChainEvidence, CertificateRole,
    Classification, ComponentEvidence, Confidence, Evidence, ProductIdentityEvidence,
    PublisherReputation, RevocationEvidence, RevocationState, SandboxSelfTest, Severity,
    TimestampState,
};

include!("core.rs");
include!("containers.rs");
include!("containers/zip.rs");
include!("containers/rar.rs");
include!("containers/members.rs");
include!("pe.rs");
include!("installers/cab.rs");
include!("installers/msi.rs");
include!("installers/nsis.rs");
include!("installers/inno.rs");
include!("documents.rs");
include!("scripts.rs");
include!("certificates.rs");
include!("pe_products.rs");
include!("common/helpers.rs");

#[cfg(test)]
mod tests {
    include!("tests/core.rs");
    include!("tests/documents.rs");
    include!("tests/yara.rs");
}
