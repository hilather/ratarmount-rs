//! R1c-2: reconstruction of retained attempts under the supervisor lock.

use super::finalize::Seams;
use super::finalize_tests::{linux, snapshot, writable, Env};
use super::process::StopOutcome;
use super::protocol::{BaseOptions, Operation, OperationV2, Overlay};
use super::retained::TEST_STARTUP_SEAMS;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn clean(mut env: Env) {
    env.sup.destroy_all().unwrap();
    // Retained trees are intentionally sealed; let the temporary directory
    // remove them after the assertions have finished.
    writable(env.state.path());
}

fn diff(env: &mut Env, id: &str, version: u8) -> Value {
    let request = json!({"version":version, "op":"diff", "id":id, "git":true});
    let response: Value = serde_json::from_slice(&super::daemon::respond(
        &mut env.sup,
        request.to_string().as_bytes(),
    ))
    .unwrap();
    assert_eq!(response["ok"], true, "{response}");
    response["result"].clone()
}

fn stats(env: &mut Env, id: &str, version: u8) -> Value {
    let request = json!({"version":version, "op":"stats", "id":id});
    let response: Value = serde_json::from_slice(&super::daemon::respond(
        &mut env.sup,
        request.to_string().as_bytes(),
    ))
    .unwrap();
    assert_eq!(response["ok"], true, "{response}");
    response["result"].clone()
}

/// Regression: restart used to reserve retained attempts without serving their
/// reports, ordered bundle-cache prefix, diffs, stats or list entries.
#[test]
fn regression_supervisor_restart_serve_round_trip() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let plain = env.attempt(true, true);
    fs::write(
        plain.path.parent().unwrap().join("journal.jsonl"),
        "{\"journal\":1}\n{\"op\":\"read\",\"path\":\"/f\",\"ts\":1,\"bytes\":9}\n",
    )
    .unwrap();
    let plain_report = env.finalize(&plain.id, false, Some("plain-done")).unwrap();
    let lower = env.layer("first", &[], &[("a.txt", "a\n")]);
    let (_, bundle) = env.bundle_over("second", &[&lower], &[("b.txt", "b\n")]);
    let cache = env.dir().join("cache");
    env.cache_at(&cache);
    let layered = env.layered(&[&lower, &bundle], true);
    let records = env.sup.taken_lowers[&layered.id].clone().unwrap();
    assert_eq!(records.len(), 2);
    assert!(records[1].path.starts_with(cache.join("ratarmount/layers")));
    let layered_report = env
        .finalize(&layered.id, true, Some("layered-done"))
        .unwrap();
    env.sup
        .handle(Operation::CreateBase {
            name: "other".into(),
            source: env.base.to_str().unwrap().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    let ids = [&plain.id, &layered.id];
    let expected: Vec<_> = ids
        .iter()
        .map(|id| (diff(&mut env, id, 1), stats(&mut env, id, 1)))
        .collect();
    let all = env.list_bytes(2, true);
    let reports = [plain_report, layered_report];
    let outputs: Vec<_> = reports
        .iter()
        .map(|r| {
            let root = Path::new(r["attempt"]["overlay_dir"].as_str().unwrap())
                .parent()
                .unwrap();
            snapshot(root)
        })
        .collect();
    let counters = {
        let f = env.fake.0.lock().unwrap();
        (f.spawns, f.stops.len(), f.cleaned.len(), f.forgotten.len())
    };
    let mut env = env.reopen();
    {
        let f = env.fake.0.lock().unwrap();
        assert_eq!(
            (f.spawns, f.stops.len(), f.cleaned.len(), f.forgotten.len()),
            counters,
            "restoration must not adopt, stop, clean or spawn a child"
        );
    }
    assert_eq!(
        env.sup.seams.syncs,
        [env.sup.root.join("retained"), env.sup.root.join("attempts")]
    );
    assert_eq!(env.list_bytes(2, true), all);
    for (base, expected_count) in [("task", 2), ("other", 0)] {
        let query = json!({"version":2,"op":"list","all":true,"base":base});
        let reply: Value = serde_json::from_slice(&super::daemon::respond(
            &mut env.sup,
            query.to_string().as_bytes(),
        ))
        .unwrap();
        assert_eq!(reply["result"].as_array().unwrap().len(), expected_count);
    }
    for version in [1, 2] {
        let list = String::from_utf8(env.list_bytes(version, false)).unwrap();
        for id in ids {
            assert!(!list.contains(id), "{list}");
        }
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(diff(&mut env, id, version), expected[i].0);
            assert_eq!(stats(&mut env, id, version), expected[i].1);
        }
    }
    assert_eq!(
        env.sup.retained[&layered.id].records.as_ref(),
        Some(&records)
    );
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(snapshot(&env.kept(id)), outputs[i]);
        assert_eq!(
            serde_json::to_vec(&env.sup.retained[*id].report).unwrap(),
            serde_json::to_vec(&reports[i]).unwrap()
        );
        assert_eq!(env.sup.destroy(id).unwrap_err().code, "retained");
    }
    // Replays run no S; a fresh or ID-less request syncs the recorded trees.
    env.sup.seams.syncs.clear();
    assert_eq!(
        env.finalize(&layered.id, true, Some("layered-done"))
            .unwrap(),
        reports[1]
    );
    assert!(env.sup.seams.syncs.is_empty());
    assert_eq!(env.finalize(&layered.id, false, None).unwrap(), reports[1]);
    for path in [
        &records[0].path,
        &records[1].path,
        &env.kept(&layered.id),
        &env.sup.root.join("indexes/task"),
    ] {
        assert!(
            env.sup.seams.syncs.contains(path),
            "missing {path:?}: {:?}",
            env.sup.seams.syncs
        );
    }
    assert_eq!(
        env.finalize(&plain.id, false, Some("plain-fresh")).unwrap(),
        reports[0]
    );
    assert_eq!(
        env.finalize(&plain.id, true, None).unwrap_err().code,
        "invalid_request"
    );
    env.sup.max_retained = 2;
    assert_eq!(
        env.new_v2("task", &[], Overlay::Disk, true, None)
            .unwrap_err()
            .code,
        "capacity"
    );
    let mut env = env.reopen_max(1);
    env.sup
        .test_ids
        .as_mut()
        .unwrap()
        .queue
        .push_back(plain.id.clone());
    let new = env.new_v2("task", &[], Overlay::Disk, false, None).unwrap();
    assert_ne!(new[0]["id"], plain.id);
    clean(env);
}

/// Regression: a failed startup R4 could acknowledge a rename prematurely,
/// poison on open failure, or leave an fsync failure unpoisoned.
#[test]
fn regression_supervisor_restart_serve_batch_r4_failures() {
    if !linux() {
        return;
    }
    // No candidate means no R4, even if an injected R4 fsync would fail.
    let env = Env::new();
    let mut seams = Seams::default();
    seams.fsync_errors.insert(env.sup.root.join("retained"), 5);
    TEST_STARTUP_SEAMS.with(|s| *s.borrow_mut() = Some(seams));
    let env = env.reopen();
    assert!(env.sup.poisoned.is_empty());
    assert!(env.sup.seams.syncs.is_empty());
    clean(env);
    let mut env = Env::new();
    let bad = env.attempt(true, false);
    env.finalize(&bad.id, false, None).unwrap();
    let mut record = env.sup.retained_log.live(&bad.id).unwrap().clone();
    record.report["status"] = json!("invalid");
    env.sup.retained_log.append_retained(&record).unwrap();
    let mut seams = Seams::default();
    seams.fsync_errors.insert(env.sup.root.join("retained"), 5);
    TEST_STARTUP_SEAMS.with(|s| *s.borrow_mut() = Some(seams));
    let env = env.reopen();
    assert!(env.sup.retained.is_empty());
    assert!(env.sup.held().contains(&bad.id));
    assert!(env.sup.poisoned.is_empty());
    assert!(env.sup.seams.syncs.is_empty());
    clean(env);
    for failed_dir in ["retained", "attempts"] {
        for fsync in [false, true] {
            let mut env = Env::new();
            env.tar_base("tar", b"base\n");
            let one = env.archive_new("tar", &[], true, true).unwrap();
            let two = env.archive_new("tar", &[], true, true).unwrap();
            let report = env.finalize(&one.id, false, None).unwrap();
            env.finalize(&two.id, false, None).unwrap();
            let mut seams = Seams::default();
            let failure = env.sup.root.join(failed_dir);
            if fsync {
                seams.fsync_errors.insert(failure, 5);
            } else {
                seams.open_errors.insert(failure, 5);
            }
            TEST_STARTUP_SEAMS.with(|s| *s.borrow_mut() = Some(seams));
            let mut env = env.reopen();
            assert_eq!(
                env.listed_all(),
                vec![
                    (one.id.clone(), "finalizing".into()),
                    (two.id.clone(), "finalizing".into())
                ]
            );
            assert_eq!(env.sup.poisoned.is_empty(), !fsync);
            let expected = if failed_dir == "attempts" {
                vec![env.sup.root.join("retained")]
            } else {
                vec![]
            };
            assert_eq!(env.sup.seams.syncs, expected);
            assert!(env
                .sup
                .handle(OperationV2::Stats { id: one.id.clone() })
                .is_ok());
            assert!(env
                .sup
                .handle(OperationV2::Diff {
                    id: one.id.clone(),
                    git: true,
                })
                .is_ok());
            let overlay = env.kept(&one.id).join("overlay");
            assert_eq!(
                env.new_v2("tar", &[&overlay], Overlay::Disk, false, None)
                    .unwrap_err()
                    .code,
                "invalid_request"
            );
            assert_eq!(env.sup.destroy(&one.id).unwrap_err().code, "retained");
            env.sup.seams.open_errors.clear();
            env.sup.seams.fsync_errors.clear();
            if fsync {
                let error = env.finalize(&one.id, false, None).unwrap_err();
                assert_eq!(error.code, "io", "{}", error.message);
                assert!(
                    error.message.contains("failed earlier"),
                    "{}",
                    error.message
                );
                env = env.reopen();
                assert!(env.sup.poisoned.is_empty());
                assert!(env.sup.retained.values().all(|e| e.acknowledged));
            } else {
                env.sup.seams.syncs.clear();
                assert_eq!(env.finalize(&one.id, false, None).unwrap(), report);
                let synced = &env.sup.seams.syncs;
                assert!(synced
                    .ends_with(&[env.sup.root.join("retained"), env.sup.root.join("attempts")]));
                assert!(synced[..synced.len() - 2].contains(&env.kept(&one.id)));
                assert!(env.sup.retained[&one.id].acknowledged);
                assert!(!env.sup.retained[&two.id].acknowledged);
            }
            env.archive_new("tar", &[&overlay], false, false).unwrap();
            clean(env);
        }
    }
}

/// Regression: malformed, missing, symlinked or differently sealed retained
/// trees must stay reserved and unserved while an independent valid tree works.
#[test]
fn regression_supervisor_restart_serve_validation() {
    if !linux() {
        return;
    }
    for case in [
        "report_id",
        "report_base",
        "report_status",
        "attempt_status",
        "mnt",
        "alias_mnt",
        "overlay",
        "manifest",
        "bundle",
        "summary",
        "missing_report_field",
        "malformed_patch_hash",
        "record_overlay",
        "record_bundle",
        "report_digest",
        "digest",
        "report_seal",
        "seal",
        "unsealed",
        "prefix",
        "prefix_alias",
        "missing_tree",
        "missing_overlay",
        "symlink_overlay",
        "missing_db",
    ] {
        let mut env = Env::new();
        let bad = if case == "prefix_alias" {
            let lower = env.layer("alias-lower", &[], &[("a.txt", "a\n")]);
            env.layered(&[&lower], true)
        } else {
            env.attempt(true, false)
        };
        env.finalize(&bad.id, true, None).unwrap();
        let good = env.attempt(true, false);
        let good_report = env.finalize(&good.id, false, None).unwrap();
        let kept = env.kept(&bad.id);
        let overlay = kept.join("overlay");
        let mut record = env.sup.retained_log.live(&bad.id).unwrap().clone();
        match case {
            "report_id" => record.report["attempt"]["id"] = json!("wrong"),
            "report_base" => record.report["attempt"]["base"] = json!("wrong"),
            "report_status" => record.report["status"] = json!("finalized"),
            "attempt_status" => record.report["attempt"]["status"] = json!("ready"),
            "mnt" => record.report["attempt"]["path"] = json!(kept.join("other")),
            "alias_mnt" => {
                record.report["attempt"]["path"] = json!(format!("{}/mnt/.", kept.display()))
            }
            "overlay" => record.report["attempt"]["overlay_dir"] = json!(kept.join("other")),
            "manifest" => record.report["manifest_path"] = json!(kept.join("other")),
            "bundle" => record.report["bundle"] = json!(kept.join("other")),
            "summary" => record.report["journal_summary"] = json!({"path":kept.join("other")}),
            "missing_report_field" => {
                record.report.as_object_mut().unwrap().remove("patch_hash");
            }
            "malformed_patch_hash" => record.report["patch_hash"] = json!({}),
            "record_overlay" => record.paths.overlay = kept.join("other"),
            "record_bundle" => record.paths.bundle = None,
            "report_digest" => record.report["layer_digest"] = json!("wrong"),
            "digest" => {
                record.layer_digest = "wrong".into();
                record.report["layer_digest"] = json!("wrong");
            }
            "report_seal" => record.report["sealed_at"] = json!("wrong"),
            "seal" => {
                record.sealed_at = "other".into();
                record.report["sealed_at"] = json!("other");
            }
            "unsealed" => {
                writable(&overlay);
                let db = overlay.join(ratarmount_compositing::HIDDEN_DB);
                let mode = fs::metadata(&db).unwrap().permissions().mode();
                fs::set_permissions(&db, fs::Permissions::from_mode(mode | 0o200)).unwrap();
                let conn = rusqlite::Connection::open(&db).unwrap();
                conn.execute("DELETE FROM meta WHERE key='sealed_at'", [])
                    .unwrap();
                drop(conn);
            }
            "prefix" => record.prefix.push(super::finalize_tests::record(&overlay)),
            "prefix_alias" => {
                record.prefix[0].path = format!("{}/.", record.prefix[0].path.display()).into();
            }
            "missing_tree" => fs::rename(&kept, env.dir().join("moved-tree")).unwrap(),
            "missing_overlay" | "symlink_overlay" => {
                let mode = fs::metadata(&kept).unwrap().permissions().mode();
                fs::set_permissions(&kept, fs::Permissions::from_mode(mode | 0o700)).unwrap();
                writable(&overlay);
                let moved = env.dir().join("moved-overlay");
                fs::rename(&overlay, &moved).unwrap();
                if case == "symlink_overlay" {
                    symlink(moved, &overlay).unwrap();
                }
            }
            "missing_db" => {
                writable(&overlay);
                fs::rename(
                    overlay.join(ratarmount_compositing::HIDDEN_DB),
                    env.dir().join("moved-db"),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        env.sup.retained_log.append_retained(&record).unwrap();
        let before = snapshot(env.state.path().join("retained").as_path());
        let mut env = env.reopen();
        assert!(!env.sup.retained.contains_key(&bad.id), "{case}");
        assert!(env.sup.held().contains(&bad.id), "{case}");
        assert_eq!(
            env.sup.destroy(&bad.id).unwrap_err().code,
            "retained",
            "{case}"
        );
        for op in [
            OperationV2::Diff {
                id: bad.id.clone(),
                git: true,
            },
            OperationV2::Stats { id: bad.id.clone() },
            OperationV2::Finalize {
                id: bad.id.clone(),
                pack: false,
                request_id: Some("fresh".into()),
            },
        ] {
            assert_eq!(
                env.sup.handle(op).unwrap_err().code,
                "invalid_request",
                "{case}"
            );
        }
        assert_eq!(env.sup.requests.status("fresh"), None, "{case}");
        assert_eq!(
            env.finalize(&good.id, false, None).unwrap(),
            good_report,
            "{case}"
        );
        assert_eq!(
            snapshot(env.state.path().join("retained").as_path()),
            before,
            "{case}"
        );
        clean(env);
    }
}

/// Regression: output files are not needed to validate the stored report and
/// must not prevent serving its attempt during startup.
#[test]
fn regression_supervisor_restart_serve_missing_outputs() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    let report = env.finalize(&attempt.id, true, Some("done")).unwrap();
    for name in ["manifest.jsonl", "bundle.tar.zst"] {
        fs::remove_file(env.kept(&attempt.id).join(name)).unwrap();
    }
    let mut env = env.reopen();
    assert!(env.sup.retained[&attempt.id].acknowledged);
    assert_eq!(
        env.finalize(&attempt.id, true, Some("done")).unwrap(),
        report
    );
    clean(env);
}

/// Regression: an existing attempts/ID must not hide a fully validated
/// retained/ID; reconciliation removes only the stale source.
#[test]
fn regression_supervisor_restart_serve_both_paths() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    let report = env.finalize(&attempt.id, false, None).unwrap();
    let retained = env.kept(&attempt.id);
    let before = snapshot(&retained);
    let stale = env.sup.root.join("attempts").join(&attempt.id);
    fs::create_dir_all(stale.join("mnt")).unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(stale.join("marker"), "stale").unwrap();
    let mut env = env.reopen();
    assert!(!stale.exists());
    assert_eq!(snapshot(&retained), before);
    assert_eq!(env.finalize(&attempt.id, false, None).unwrap(), report);
    clean(env);
}

/// Regression: restart must not pre-gate a base or lower, and later diff and
/// finalize must still detect changed dependencies while stats stays offline.
#[test]
fn regression_supervisor_restart_serve_dependency_checks() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let plain = env.attempt(true, false);
    env.finalize(&plain.id, false, None).unwrap();
    let lower = env.layer("lower", &[], &[("a.txt", "before\n")]);
    let layered = env.layered(&[&lower], true);
    env.finalize(&layered.id, false, None).unwrap();
    let plain_stats = stats(&mut env, &plain.id, 1);
    let layered_stats = stats(&mut env, &layered.id, 1);
    let modified = fs::metadata(env.base.join("f"))
        .unwrap()
        .modified()
        .unwrap();
    fs::write(env.base.join("f"), "changed base and size\n").unwrap();
    let moved_base = env.dir().join("base-moved");
    fs::rename(&env.base, &moved_base).unwrap();
    let moved = env.dir().join("lower-moved");
    fs::rename(&lower, &moved).unwrap();
    // Neither the missing base nor the missing lower prevents restoration.
    let mut env = env.reopen();
    assert!(env.sup.retained.contains_key(&plain.id));
    assert!(env.sup.retained.contains_key(&layered.id));
    let error = env
        .sup
        .handle(Operation::Diff {
            id: plain.id.clone(),
            git: true,
        })
        .unwrap_err();
    assert_eq!(error.code, "base_open_failed", "{}", error.message);
    assert_eq!(stats(&mut env, &plain.id, 2), plain_stats);
    fs::rename(&moved_base, &env.base).unwrap();
    let error = env
        .sup
        .handle(Operation::Diff {
            id: plain.id.clone(),
            git: true,
        })
        .unwrap_err();
    assert_eq!(error.code, "diff_failed", "{}", error.message);
    assert_eq!(stats(&mut env, &plain.id, 1), plain_stats);
    fs::write(env.base.join("f"), "original\n").unwrap();
    fs::File::options()
        .write(true)
        .open(env.base.join("f"))
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    // Lower checking precedes base access for diff and retained finalize.
    let error = env
        .sup
        .handle(Operation::Diff {
            id: layered.id.clone(),
            git: true,
        })
        .unwrap_err();
    assert_eq!(error.code, "diff_failed", "{}", error.message);
    env.sup.seams.syncs.clear();
    assert_eq!(
        env.finalize(&layered.id, false, None).unwrap_err().code,
        "lower_changed"
    );
    assert!(env.sup.seams.syncs.is_empty());
    assert_eq!(stats(&mut env, &layered.id, 1), layered_stats);
    fs::rename(&moved, &lower).unwrap();
    env.reseal(&lower, &[], "a.txt");
    assert_eq!(
        env.finalize(&layered.id, false, None).unwrap_err().code,
        "lower_changed"
    );
    assert_eq!(stats(&mut env, &layered.id, 2), layered_stats);
    clean(env);
}

/// Regression: retries after restoration must match both the attempt ID and
/// instance, while stored answers replay without re-running any sync.
#[test]
fn regression_supervisor_restart_serve_retry_instance() {
    if !linux() {
        return;
    }
    let mut env = Env::new();
    let attempt = env.attempt(true, false);
    env.fake
        .0
        .lock()
        .unwrap()
        .stop_outcomes
        .push_back(StopOutcome::Busy);
    assert_eq!(
        env.finalize(&attempt.id, false, Some("retry"))
            .unwrap_err()
            .code,
        "writers_active"
    );
    let report = env.finalize(&attempt.id, false, Some("done")).unwrap();
    let mut record = env.sup.retained_log.live(&attempt.id).unwrap().clone();
    record.instance = "f".repeat(32);
    env.sup.retained_log.append_retained(&record).unwrap();
    let mut env = env.reopen();
    env.sup.seams.syncs.clear();
    assert_eq!(
        env.finalize(&attempt.id, false, Some("done")).unwrap(),
        report
    );
    assert!(env.sup.seams.syncs.is_empty());
    assert_eq!(
        env.finalize(&attempt.id, false, Some("retry"))
            .unwrap_err()
            .code,
        "not_found"
    );
    assert_eq!(
        env.finalize(&attempt.id, false, Some("fresh")).unwrap(),
        report
    );
    clean(env);
}
