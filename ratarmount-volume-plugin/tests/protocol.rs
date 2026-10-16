#![cfg(target_os = "linux")]

use ratarmount_volume_plugin::{
    http,
    options::{mount_args, Options},
    Driver, Mounter,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct FakeState {
    mounts: usize,
    stops: usize,
    reconciles: usize,
    live: BTreeMap<PathBuf, bool>,
    fail_mount: bool,
    fail_unmount: bool,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<FakeState>>);
impl Mounter for Fake {
    fn mount(&mut self, _: &Options, path: &Path) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state.fail_mount {
            return Err("mount failed".into());
        }
        state.mounts += 1;
        state.live.insert(path.to_owned(), true);
        Ok(())
    }
    fn unmount(&mut self, path: &Path, _: bool) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state.fail_unmount {
            return Err("unmount failed".into());
        }
        state.stops += 1;
        state.live.remove(path);
        Ok(())
    }
    fn alive(&mut self, path: &Path) -> Result<bool, String> {
        Ok(*self.0.lock().unwrap().live.get(path).unwrap_or(&false))
    }
    fn reconcile(&mut self, _: &Path) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        state.reconciles += 1;
        state.live.clear();
        Ok(())
    }
}

struct Exchange {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Read for Exchange {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}
impl Write for Exchange {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn raw(driver: &mut Driver<Fake>, request: &[u8]) -> Value {
    let mut exchange = Exchange {
        input: Cursor::new(request.to_vec()),
        output: Vec::new(),
    };
    http::serve_one(&mut exchange, |path, body| driver.handle(path, body)).unwrap();
    let response = String::from_utf8(exchange.output).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(headers.contains(&format!("Content-Length: {}\r\n", body.len())));
    serde_json::from_str(body).unwrap()
}
fn call(driver: &mut Driver<Fake>, endpoint: &str, value: Value) -> Value {
    let body = serde_json::to_string(&value).unwrap();
    raw(driver, format!("POST {endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
}
fn ok(response: Value) -> Value {
    assert_eq!(response["Err"], "", "{response}");
    response
}
fn error(response: Value) {
    assert!(!response["Err"].as_str().unwrap().is_empty(), "{response}");
}
fn volume(driver: &mut Driver<Fake>) {
    ok(call(
        driver,
        "/VolumeDriver.Create",
        json!({"Name":"data", "Opts":{"source":"/tmp/source.tar"}}),
    ));
}
fn mount(driver: &mut Driver<Fake>, id: &str) -> Value {
    call(
        driver,
        "/VolumeDriver.Mount",
        json!({"Name":"data", "ID":id}),
    )
}
fn unmount(driver: &mut Driver<Fake>, id: &str) -> Value {
    call(
        driver,
        "/VolumeDriver.Unmount",
        json!({"Name":"data", "ID":id}),
    )
}
fn get(driver: &mut Driver<Fake>) -> Value {
    ok(call(driver, "/VolumeDriver.Get", json!({"Name":"data"})))
}

/// Regression: duplicate IDs and unknown unmounts must not release another container's mount.
#[test]
fn regression_http_lifecycle_duplicate_ids_do_not_unmount_other_containers() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::default();
    let mut driver = Driver::open(dir.path(), fake.clone()).unwrap();
    assert_eq!(
        ok(call(&mut driver, "/Plugin.Activate", json!({})))["Implements"],
        json!(["VolumeDriver"])
    );
    assert_eq!(
        ok(call(&mut driver, "/VolumeDriver.Capabilities", json!({})))["Capabilities"]["Scope"],
        "local"
    );
    volume(&mut driver);
    volume(&mut driver);
    ok(call(
        &mut driver,
        "/VolumeDriver.Create",
        json!({"Name":"data"}),
    ));
    error(call(
        &mut driver,
        "/VolumeDriver.Create",
        json!({"Name":"data", "Opts":{"source":"other"}}),
    ));
    ok(call(
        &mut driver,
        "/VolumeDriver.Create",
        json!({"Name":"data", "Opts":null}),
    ));
    let path = dir.path().join("mnt/data");
    assert_eq!(
        ok(call(
            &mut driver,
            "/VolumeDriver.Path",
            json!({"Name":"data"})
        ))["Mountpoint"],
        json!(path)
    );
    assert_eq!(get(&mut driver)["Volume"]["Status"]["Mounted"], false);
    assert_eq!(ok(mount(&mut driver, "a"))["Mountpoint"], json!(path));
    ok(mount(&mut driver, "a"));
    ok(mount(&mut driver, "b"));
    assert_eq!(fake.0.lock().unwrap().mounts, 1);
    assert_eq!(get(&mut driver)["Volume"]["Status"]["References"], 2);
    error(call(
        &mut driver,
        "/VolumeDriver.Remove",
        json!({"Name":"data"}),
    ));
    ok(unmount(&mut driver, "unknown"));
    ok(unmount(&mut driver, "a"));
    ok(unmount(&mut driver, "a"));
    assert_eq!(fake.0.lock().unwrap().stops, 0);
    assert_eq!(
        ok(call(&mut driver, "/VolumeDriver.List", json!({})))["Volumes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    ok(unmount(&mut driver, "b"));
    assert_eq!(fake.0.lock().unwrap().stops, 1);
    assert_eq!(get(&mut driver)["Volume"]["Status"]["Mounted"], false);
    ok(call(
        &mut driver,
        "/VolumeDriver.Remove",
        json!({"Name":"data"}),
    ));
    assert_eq!(
        ok(call(&mut driver, "/VolumeDriver.List", json!({})))["Volumes"],
        json!([])
    );
    error(call(
        &mut driver,
        "/VolumeDriver.Get",
        json!({"Name":"data"}),
    ));
    error(call(
        &mut driver,
        "/VolumeDriver.Path",
        json!({"Name":"data"}),
    ));
}

/// Regression: failed mount/unmount must leave reference accounting retryable.
#[test]
fn regression_failed_mount_and_busy_unmount_keep_reference_accounting() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::default();
    let mut driver = Driver::open(dir.path(), fake.clone()).unwrap();
    volume(&mut driver);
    fake.0.lock().unwrap().fail_mount = true;
    error(mount(&mut driver, "a"));
    assert_eq!(get(&mut driver)["Volume"]["Status"]["References"], 0);
    fake.0.lock().unwrap().fail_mount = false;
    ok(mount(&mut driver, "a"));
    fake.0.lock().unwrap().fail_unmount = true;
    error(unmount(&mut driver, "a"));
    assert_eq!(get(&mut driver)["Volume"]["Status"]["References"], 1);
    fake.0.lock().unwrap().fail_unmount = false;
    ok(unmount(&mut driver, "a"));
    assert_eq!(fake.0.lock().unwrap().stops, 1);
}

/// Regression: child death must clear stale references and allow a fresh mount.
#[test]
fn regression_child_death_marks_unmounted_and_reaps_before_remount() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::default();
    let mut driver = Driver::open(dir.path(), fake.clone()).unwrap();
    volume(&mut driver);
    ok(mount(&mut driver, "a"));
    *fake
        .0
        .lock()
        .unwrap()
        .live
        .get_mut(&dir.path().join("mnt/data"))
        .unwrap() = false;
    driver.supervise();
    let status = get(&mut driver);
    assert_eq!(status["Volume"]["Status"]["Mounted"], false);
    assert_eq!(status["Volume"]["Status"]["References"], 0);
    ok(mount(&mut driver, "b"));
    assert_eq!(fake.0.lock().unwrap().mounts, 2);
    assert_eq!(fake.0.lock().unwrap().stops, 1);
}

/// Regression: definitions survive restarts, while stale mounts are reconciled before serving.
#[test]
fn regression_restart_persists_definitions_and_reconciles_stale_mounts() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::default();
    {
        let mut driver = Driver::open(dir.path(), fake.clone()).unwrap();
        volume(&mut driver);
        ok(mount(&mut driver, "a"));
        assert!(Driver::open(dir.path(), fake.clone()).is_err());
    }
    let mut driver = Driver::open(dir.path(), fake.clone()).unwrap();
    assert_eq!(fake.0.lock().unwrap().reconciles, 2);
    assert!(fake.0.lock().unwrap().live.is_empty());
    assert_eq!(get(&mut driver)["Volume"]["Status"]["Mounted"], false);
    assert_eq!(get(&mut driver)["Volume"]["Status"]["References"], 0);
    let state = dir.path().join("volumes.json");
    assert_eq!(
        std::fs::metadata(state).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!dir.path().join("volumes.json.tmp").exists());
    ok(mount(&mut driver, "b"));
    ok(unmount(&mut driver, "b"));
    ok(call(
        &mut driver,
        "/VolumeDriver.Remove",
        json!({"Name":"data"}),
    ));
    drop(driver);
    let mut driver = Driver::open(dir.path(), fake).unwrap();
    assert_eq!(
        ok(call(&mut driver, "/VolumeDriver.List", json!({})))["Volumes"],
        json!([])
    );
}

/// Regression: a failed atomic state write must not publish an in-memory definition or deletion.
#[test]
fn regression_state_write_failure_keeps_previous_definition() {
    let dir = tempfile::tempdir().unwrap();
    let mut driver = Driver::open(dir.path(), Fake::default()).unwrap();
    std::fs::create_dir(dir.path().join("volumes.json.tmp")).unwrap();
    error(call(
        &mut driver,
        "/VolumeDriver.Create",
        json!({"Name":"data", "Opts":{"source":"/a.tar"}}),
    ));
    assert_eq!(
        ok(call(&mut driver, "/VolumeDriver.List", json!({})))["Volumes"],
        json!([])
    );
    std::fs::remove_dir(dir.path().join("volumes.json.tmp")).unwrap();
    volume(&mut driver);
    std::fs::create_dir(dir.path().join("volumes.json.tmp")).unwrap();
    error(call(
        &mut driver,
        "/VolumeDriver.Remove",
        json!({"Name":"data"}),
    ));
    get(&mut driver);
}

/// Regression: invalid or credential-bearing options must never reach disk or argv.
#[test]
fn regression_validation_rejects_credentials_traversal_and_invalid_options() {
    let dir = tempfile::tempdir().unwrap();
    let mut driver = Driver::open(dir.path(), Fake::default()).unwrap();
    for opts in [
        json!({}),
        json!({"source":""}),
        json!({"source":"https://user:secret@example.com/a"}),
        json!({"source":"https://example.com/a?token=secret"}),
        json!({"source":"https://example.com/a#secret"}),
        json!({"source":"a", "HF_TOKEN":"secret"}),
        json!({"source":"a", "overlay":"relative"}),
        json!({"source":"a", "overlay":"tmpfs:"}),
        json!({"source":"a", "overlay":"tmpfs:18446744073709551615T"}),
        json!({"source":"a", "overlay":"tmpfs:1M", "ro":"true"}),
        json!({"source":"a", "ro":"maybe"}),
        json!({"source":"a", "uid":"1,allow_other"}),
        json!({"source":"a", "gid":"4294967296"}),
        json!({"source":"a", "umask":"888"}),
        json!({"source":"a", "umask":"1777"}),
        json!({"source":"a", "readonly_globs":"tests/**"}),
        json!({"source":"a", "quota":"1G"}),
        json!({"source":"a", "overlay":"tmpfs", "quota":"-1"}),
        json!({"source":"a", "overlay":"tmpfs", "readonly_globs":"../tests"}),
        json!({"source":"a", "overlay":"tmpfs", "readonly_globs":"te**sts"}),
        json!({"source":"a", "passthrough":"true"}),
        json!({"source":"a\nsecret"}),
    ] {
        let response = call(
            &mut driver,
            "/VolumeDriver.Create",
            json!({"Name":"data", "Opts":opts}),
        );
        assert!(!response.to_string().contains("secret"));
        error(response);
    }
    for name in ["", "..", "../a", "/absolute", "a/b", "-option", "a\nsecret"] {
        error(call(
            &mut driver,
            "/VolumeDriver.Create",
            json!({"Name":name, "Opts":{"source":"a"}}),
        ));
    }
    assert!(!dir.path().join("volumes.json").exists());
    volume(&mut driver);
    error(mount(&mut driver, ""));
    error(unmount(&mut driver, ""));
    error(call(&mut driver, "/unknown", json!({"Name":"data"})));
}

/// Regression: options must be separate argv elements, with no shell or credential expansion.
#[test]
fn regression_argv_maps_cli_flags_and_keeps_credentials_out() {
    let opts: Options = serde_json::from_value(json!({
        "source":"hf://datasets/org/repo@main", "overlay":"tmpfs:2G", "uid":"1000", "gid":"1001", "umask":"027",
        "readonly_globs":"tests/**,docs/**", "quota":"1G", "git_synthetic_head":"true", "recursive":"1", "passthrough":"off"
    })).unwrap();
    assert_eq!(
        mount_args(&opts, Path::new("/mnt/data")).unwrap(),
        vec![
            "--foreground",
            "-o",
            "allow_other,noatime,uid=1000,gid=1001,umask=027",
            "--overlay-tmpfs=2G",
            "--overlay-readonly=tests/**,docs/**",
            "--overlay-quota=1G",
            "--passthrough=off",
            "--recursive",
            "--git-synthetic-head",
            "--",
            "hf://datasets/org/repo@main",
            "/mnt/data"
        ]
    );
    for (overlay, expected) in [
        ("tmpfs", vec!["--overlay-tmpfs"]),
        (
            "/host/overlay with spaces",
            vec!["-w", "/host/overlay with spaces"],
        ),
    ] {
        let opts: Options =
            serde_json::from_value(json!({"source":"repo.git@REV", "overlay":overlay})).unwrap();
        let args = mount_args(&opts, Path::new("/mnt/data")).unwrap();
        assert_eq!(&args[3..3 + expected.len()], expected);
    }
    let opts: Options =
        serde_json::from_value(json!({"source":"--help", "ro":"false", "recursive":"false"}))
            .unwrap();
    assert_eq!(
        mount_args(&opts, Path::new("/mnt/data")).unwrap(),
        [
            "--foreground",
            "-o",
            "allow_other,noatime,ro",
            "--",
            "--help",
            "/mnt/data"
        ]
    );
    // No env token API exists: callers cannot accidentally serialize one.
    assert!(mount_args(
        &serde_json::from_value(json!({"source":"a", "token":"secret"})).unwrap(),
        Path::new("/mnt/data")
    )
    .is_err());
}

/// Regression: malformed HTTP, oversized bodies and ambiguous framing must return JSON Err.
#[test]
fn regression_http_framing_rejects_oversize_truncated_and_ambiguous_requests() {
    let dir = tempfile::tempdir().unwrap();
    let mut driver = Driver::open(dir.path(), Fake::default()).unwrap();
    for request in [
        "GET /Plugin.Activate HTTP/1.1\r\n\r\n",
        "POST /Plugin.Activate HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n",
        "POST /Plugin.Activate HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        "POST /Plugin.Activate HTTP/1.1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        "POST /Plugin.Activate HTTP/1.1\r\nContent-Length: 5\r\n\r\n{}",
        "POST /Plugin.Activate HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
        "POST /Plugin.Activate HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
        "POST /Plugin.Activate HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}xx",
    ] { error(raw(&mut driver, request.as_bytes())); }
    error(raw(
        &mut driver,
        format!(
            "POST /Plugin.Activate HTTP/1.1\r\nX: {}\r\n\r\n",
            "a".repeat(16384)
        )
        .as_bytes(),
    ));
    assert_eq!(ok(raw(&mut driver, b"POST /Plugin.Activate HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n"))["Implements"], json!(["VolumeDriver"]));
}

/// Regression: restart must reject corrupt state and symlink mountpoints.
#[test]
fn regression_corrupt_state_and_symlink_mountpoint_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("volumes.json"), "{broken").unwrap();
    assert!(Driver::open(dir.path(), Fake::default()).is_err());
    std::fs::write(
        dir.path().join("volumes.json"),
        r#"{"../escape":{"opts":{"source":"a"}}}"#,
    )
    .unwrap();
    assert!(Driver::open(dir.path(), Fake::default()).is_err());
    std::fs::remove_file(dir.path().join("volumes.json")).unwrap();
    let mut driver = Driver::open(dir.path(), Fake::default()).unwrap();
    volume(&mut driver);
    let target = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(target.path(), dir.path().join("mnt/data")).unwrap();
    error(mount(&mut driver, "a"));
    std::fs::remove_file(dir.path().join("mnt/data")).unwrap();
    std::fs::write(dir.path().join("mnt/data"), b"not a directory").unwrap();
    error(mount(&mut driver, "a"));
}
