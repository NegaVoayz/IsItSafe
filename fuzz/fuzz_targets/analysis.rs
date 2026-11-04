#![no_main]

use std::path::Path;

use isitsafe::analysis::{AnalysisLimits, analyze_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = AnalysisLimits {
        entry_max_bytes: 64 * 1024,
        total_output_max_bytes: 512 * 1024,
        max_entries: 64,
        max_depth: 4,
        compression_ratio_warning: 100,
    };
    let _ = analyze_bytes(Path::new("fuzz.bin"), data, &limits);
});

