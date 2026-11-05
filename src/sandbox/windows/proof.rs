fn apply_child_sandbox_proof(execution: &mut ChildExecution, analysis: Option<&ChildAnalysis>) {
    let Some(proof) = analysis.and_then(|analysis| analysis.sandbox_proof.as_ref()) else {
        return;
    };
    execution.network_capability = if proof.is_app_container {
        SandboxCapability::None
    } else {
        SandboxCapability::Unknown
    };
    execution.filesystem_capability = if proof.is_app_container {
        SandboxCapability::Restricted
    } else {
        SandboxCapability::Unknown
    };
    execution
        .sandbox_self_tests
        .insert("network_connect".into(), proof.network_connect);
    execution
        .sandbox_self_tests
        .insert("process_create".into(), proof.process_create);
    execution.sandbox_self_tests.insert(
        "app_container".into(),
        if proof.is_app_container {
            SandboxSelfTest::Allowed
        } else {
            SandboxSelfTest::Unknown
        },
    );
}
