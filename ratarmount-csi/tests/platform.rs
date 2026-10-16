#![cfg(not(target_os = "linux"))]

/// Regression: non-Linux CSI builds must fail clearly before parsing Linux node options.
#[test]
fn regression_csi_non_linux_reports_unsupported_platform() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ratarmount-csi"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("CSI node plugin requires Linux"));
}
