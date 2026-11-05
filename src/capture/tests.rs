    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn depth_matrix_requires_both_gates() {
        let mut config = Config::default();
        config.limits.snapshot_max_bytes = 10;
        config.limits.basic_check_threshold_bytes = 20;
        assert_eq!(select_depth(10, &config), CaptureDepth::Deep);
        assert_eq!(select_depth(15, &config), CaptureDepth::Limited);
        assert_eq!(select_depth(21, &config), CaptureDepth::BasicCheckOnly);
    }

    #[test]
    fn captures_and_hashes_snapshot() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"MZ").unwrap();
        temp.flush().unwrap();
        let temp_path = temp.into_temp_path();
        let mut config = Config::default();
        config.limits.lock_acquisition_retry_backoff_ms = 1;
        let captured = capture(&temp_path, &config).unwrap();
        assert_eq!(captured.lock.outcome, LockAcquisitionOutcome::Acquired);
        assert!(captured.sha256.is_some());
        assert_eq!(captured.head, b"MZ");
    }

    #[test]
    fn escapes_control_characters() {
        assert_eq!(escape_controls("a\nb\r\t"), "a\\nb\\r\\t");
    }

    #[test]
    fn basic_check_uses_two_gate_matrix_and_streams() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.bin");
        let file = File::create(&path).unwrap();
        file.set_len(3 * 1024 * 1024).unwrap();
        drop(file);
        let mut config = Config::default();
        config.limits.snapshot_max_bytes = 1024 * 1024;
        config.limits.basic_check_threshold_bytes = 2 * 1024 * 1024;
        config.limits.lock_acquisition_retry_backoff_ms = 1;
        config.limits.motw_read_timeout_ms = 0;
        let captured = capture(&path, &config).unwrap();
        assert_eq!(captured.depth, CaptureDepth::BasicCheckOnly);
        assert!(captured.snapshot.is_none());
        assert!(captured.thresholds.basic_check_only);
        assert!(!captured.thresholds.deep_analysis_eligible);
        assert_eq!(captured.sha256.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn active_writer_prevents_readiness_until_timeout() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("writing.bin");
        let writer = File::create(&path).unwrap();
        let mut config = Config::default();
        config.limits.lock_acquisition_timeout_ms = 30;
        config.limits.lock_acquisition_retry_backoff_ms = 5;
        config.limits.motw_read_timeout_ms = 0;
        let result = capture(&path, &config);
        assert!(matches!(result, Err(CaptureError::LockTimeout { .. })));
        drop(writer);
    }

    #[test]
    #[ignore = "creates and hashes an 8 GiB sparse fixture; run explicitly for the BasicCheckOnly benchmark"]
    fn basic_check_benchmark_eight_gibibytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.bin");
        let file = File::create(&path).unwrap();
        let size = 8 * 1024 * 1024 * 1024u64;
        file.set_len(size).unwrap();
        drop(file);
        let mut config = Config::default();
        config.limits.snapshot_max_bytes = 512 * 1024 * 1024;
        config.limits.basic_check_threshold_bytes = 2 * 1024 * 1024 * 1024;
        config.limits.motw_read_timeout_ms = 0;
        let started = Instant::now();
        let captured = capture(&path, &config).unwrap();
        assert_eq!(captured.depth, CaptureDepth::BasicCheckOnly);
        // 100 Mbps transfer time is about 11 minutes for 8 GiB; 20% is 132 seconds.
        assert!(started.elapsed() < Duration::from_secs(132));
    }
