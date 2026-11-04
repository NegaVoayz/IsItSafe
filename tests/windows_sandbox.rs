#![cfg(windows)]

use std::path::Path;

use isitsafe::config::Config;
use isitsafe::report::{BoundaryKind, SandboxCapability, SandboxSelfTest};
use isitsafe::sandbox::run_sandboxed;

#[test]
fn app_container_analysis_has_no_network_or_process_creation() {
    let mut config = Config::default();
    config.child.executable = Some(
        std::env::var_os("CARGO_BIN_EXE_isitsafe")
            .map(std::path::PathBuf::from)
            .expect("cargo test should provide the isitsafe binary"),
    );
    config.limits.motw_read_timeout_ms = 0;
    let result = run_sandboxed(
        &config,
        Path::new("sandbox-smoke.txt"),
        b"ordinary text",
        None,
    )
    .expect("sandboxed child should launch");
    assert!(result.analysis.is_some());
    assert_eq!(result.execution.network_capability, SandboxCapability::None);
    assert_eq!(
        result.execution.filesystem_capability,
        SandboxCapability::Restricted
    );
    assert_eq!(
        result.execution.sandbox_self_tests.get("network_connect"),
        Some(&SandboxSelfTest::Denied)
    );
    assert_eq!(
        result.execution.sandbox_self_tests.get("process_create"),
        Some(&SandboxSelfTest::Denied)
    );
    assert!(
        !result
            .boundaries
            .iter()
            .any(|boundary| boundary.kind == BoundaryKind::SandboxViolation)
    );
}
