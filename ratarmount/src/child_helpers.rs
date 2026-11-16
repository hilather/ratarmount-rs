//! Guards for `#[ignore]`d tests that are subprocess helpers (#310).
//!
//! A parent test re-executes the test binary with `--exact NAME --ignored`
//! to run such a helper in its own process. `cargo test -- --ignored` or
//! `--include-ignored` would also run the helper directly, outside the setup
//! its parent provides, so each parent sets the helper's dedicated variable
//! and the helper skips without it.

use std::ffi::OsStr;

/// Set by `regression_subprocess_deadline_reaps_child`.
pub(crate) const SANDBOX_WAITING_CHILD: &str = "RATARMOUNT_TEST_SANDBOX_WAITING_CHILD";
/// Set by `regression_296_helper_exec_survives_a_paused_forked_child`.
pub(crate) const SANDBOX_PAUSED_FORKED_CHILD: &str = "RATARMOUNT_TEST_SANDBOX_PAUSED_FORKED_CHILD";
/// Set by `regression_run_child_dies_with_supervisor`.
pub(crate) const RUN_DEATH_PROBE_CHILD: &str = "RATARMOUNT_TEST_RUN_DEATH_PROBE_CHILD";
/// Set by `regression_snapshot_restic_dedup_roundtrip`.
pub(crate) const SNAPSHOT_RESTIC_READER_CHILD: &str =
    "RATARMOUNT_TEST_SNAPSHOT_RESTIC_READER_CHILD";
/// Set by `regression_mount_in_base_bind_alias_verdicts_in_user_namespace`.
pub(crate) const MIB_BIND_ALIAS_CHILD: &str = "RATARMOUNT_TEST_MIB_BIND_ALIAS_CHILD";

/// The first words of a guard skip; a parent asserts it never sees them.
pub(crate) const GUARD_SKIP: &str = "runs only as a child of";

/// Whether the helper `name` was spawned by its parent (`var` is `1`).
/// Prints `skip:` and returns false otherwise.
pub(crate) fn spawned_by_parent(var: &str, name: &str, parent: &str) -> bool {
    if std::env::var_os(var).as_deref() == Some(OsStr::new("1")) {
        return true;
    }
    eprintln!("skip: {name} {GUARD_SKIP} {parent} ({var}=1 is not set)");
    false
}

/// Runs the ignored helper `test` (full path) directly, with `envs` but
/// without `guard`, and asserts that it ran exactly one test that skipped.
pub(crate) fn run_without_guard(
    test: &str,
    guard: &str,
    envs: &[(&str, &OsStr)],
) -> std::process::Output {
    use std::process::Command;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--ignored", "--nocapture"])
        .env_remove(guard);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = crate::test_child::TestChild::spawn(&mut command)
        .unwrap()
        .output(std::time::Duration::from_secs(5))
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{test}: {stdout}\n{stderr}");
    // A filter matching nothing also exits 0.
    assert!(stdout.contains("1 passed"), "{test} did not run: {stdout}");
    assert!(
        stderr.contains("skip: ") && stderr.contains(GUARD_SKIP),
        "{test} did not skip: {stderr}"
    );
    assert!(stderr.contains(guard), "{test}: {stderr}");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: #310 an `#[ignore]`d subprocess helper run directly
    /// (`cargo test -- --ignored`/`--include-ignored`) did its work outside
    /// its parent's setup. Each helper is run with its data variables but
    /// without its guard: it skips and leaves no trace of its work.
    #[test]
    fn regression_310_ignored_helpers_skip_without_their_parent() {
        let _processes = ratarmount_index::test_process::spawning();
        let temp = tempfile::tempdir().unwrap();

        // Would sleep 30 s.
        run_without_guard(
            "sandbox::process::tests::sandbox_waiting_child",
            SANDBOX_WAITING_CHILD,
            &[],
        );

        // This helper is also present on macOS. Would open the repository
        // and fail (panic) on a missing one.
        let repo = temp.path().join("missing-repo");
        let out = run_without_guard(
            "snapshot::tests::snapshot_restic_reader_child",
            SNAPSHOT_RESTIC_READER_CHILD,
            &[("AI_SNAP_TEST_REPO", repo.as_os_str())],
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("restic reader verified"));

        // The remaining helpers are Linux only (no target cfg here: #201 N4).
        if !cfg!(target_os = "linux") {
            eprintln!("skip: the remaining guarded subprocess helpers are Linux only");
            return;
        }

        // Would run ProcessMounter::stop and print its marker.
        let out = run_without_guard(
            "sandbox::process::tests::sandbox_paused_forked_child",
            SANDBOX_PAUSED_FORKED_CHILD,
            &[],
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("#296 helper executed"));

        // Would spawn a supervised sleep and record it in the marker.
        let marker = temp.path().join("child.json");
        run_without_guard(
            "sandbox::run::tests::run_child_death_probe",
            RUN_DEATH_PROBE_CHILD,
            &[("RATARMOUNT_RUN_DEATH_PROBE", marker.as_os_str())],
        );
        assert!(!marker.exists());

        // Would create its fixture tree and bind mounts under the directory.
        let ns = temp.path().join("ns");
        std::fs::create_dir(&ns).unwrap();
        run_without_guard(
            "mount_guard::tests::helper_bind_alias_verdicts",
            MIB_BIND_ALIAS_CHILD,
            &[("RATARMOUNT_MIB_NS_DIR", ns.as_os_str())],
        );
        assert_eq!(std::fs::read_dir(&ns).unwrap().count(), 0);
    }
}
