#![cfg(target_os = "linux")]

use serde_json::Value;

/// Regression: managed-plugin mountpoints must be below PropagatedMount and have FUSE access.
#[test]
fn regression_managed_plugin_mount_propagation_and_fuse_device() {
    let config: Value = serde_json::from_str(include_str!(
        "../../packaging/docker-volume-plugin/config.json"
    ))
    .unwrap();
    assert_eq!(config["Interface"]["Socket"], "ratarmount.sock");
    assert_eq!(config["Interface"]["Types"][0], "docker.volumedriver/1.0");
    assert_eq!(config["Entrypoint"][0], "/usr/bin/ratarmount-volume-plugin");
    assert!(
        std::path::Path::new("/var/lib/ratarmount-volume-plugin/mnt/data")
            .starts_with(config["PropagatedMount"].as_str().unwrap())
    );
    assert_eq!(config["Linux"]["Devices"][0]["Path"], "/dev/fuse");
    assert!(config["Linux"]["Capabilities"]
        .as_array()
        .unwrap()
        .contains(&Value::String("CAP_SYS_ADMIN".into())));
    assert!(
        config["Env"].is_null(),
        "credentials must not be stored as managed-plugin metadata"
    );
}
