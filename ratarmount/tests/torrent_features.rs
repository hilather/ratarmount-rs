use std::process::Command;

/// Regression: CLI feature diagnostics omitted the torrent backend or its upload policy.
#[test]
fn regression_torrent_feature_diagnostics() {
    let binary = env!("CARGO_BIN_EXE_ratarmount");
    let output = Command::new(binary)
        .arg("--print-features")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    if cfg!(feature = "bittorrent") {
        assert!(stdout.contains("bittorrent: compiled"));
        assert!(stdout.contains("uploads disabled"));
        let output = Command::new(binary)
            .arg("--oss-attributions")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("librqbit"));
    } else {
        assert!(stdout.contains("bittorrent: not compiled"));
    }
}
