#![no_main]

use std::path::Path;

use isitsafe::analysis::{AnalysisLimits, analyze_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = AnalysisLimits {
        entry_max_bytes: 64 * 1024,
        total_output_max_bytes: 256 * 1024,
        max_entries: 32,
        max_depth: 3,
        compression_ratio_warning: 50,
    };
    let _ = analyze_bytes(Path::new("sample.zip"), data, &limits);
});

