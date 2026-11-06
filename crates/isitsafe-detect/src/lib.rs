use std::collections::HashSet;
use std::io::Cursor;
use std::path::Path;

use zip::ZipArchive;

use isitsafe_report::{Classification, Confidence, DetectedFormat, Evidence, Severity};

include!("sniff.rs");
include!("scan.rs");
include!("format.rs");
include!("installers.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
