//! Prepared local indexes: process-level enforcement without a FUSE dependency.
#![cfg(target_os = "linux")]

use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn tar(path: &Path) {
    let mut file = fs::File::create(path).unwrap();
    write_ustar_members(
        &mut file,
        &[UstarMember {
            path: "base.txt",
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
            payload: UstarPayload::File {
                bytes: b"original\n",
            },
        }],
    )
    .unwrap();
    write_tar_eof(&mut file).unwrap();
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            path.is_file()
                .then(|| (path.file_name().unwrap().into(), fs::read(path).unwrap()))
        })
        .collect()
}

fn run(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "CLI timeout {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn prepare(base: &Path, index: &Path) {
    let out = run(&[
        "--no-mount",
        "--index-file",
        index.to_str().unwrap(),
        base.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Regression: contradictory write requests must be rejected before archive/index I/O.
#[test]
fn regression_prepared_index_cli_rejects_mutating_options() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    let index = dir.path().join("base.sqlite");
    tar(&base);
    prepare(&base, &index);
    let before = snapshot(dir.path());
    for flags in [
        vec!["-c"],
        vec!["--hashes", "sha256"],
        vec!["--commit-overlay"],
        vec!["--commit-overlay-on-exit"],
        vec!["--commit-overlay-interval", "1s"],
        vec!["--roll-every", "1M"],
        vec!["--publish-index"],
        vec![
            "--publish-index-to",
            "/tmp/keystone-must-not-publish.sqlite",
        ],
        vec!["--repack-seekable"],
        vec!["--index-file", ":memory:"],
    ] {
        let overlay = dir.path().join("overlay");
        let mut args = vec!["--no-recreate-index", "-w", overlay.to_str().unwrap()];
        args.extend(flags.iter().copied());
        args.push(base.to_str().unwrap());
        let out = run(&args);
        let error = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{flags:?}: {error}");
        assert!(error.contains("--no-recreate-index"), "{flags:?}: {error}");
        let expected_flag = if flags[0] == "-c" {
            "--recreate-index"
        } else {
            flags[0]
        };
        assert!(error.contains(expected_flag), "{flags:?}: {error}");
        assert!(!overlay.exists(), "{flags:?} created an overlay");
        assert_eq!(
            snapshot(dir.path()),
            before,
            "{flags:?} mutated prepared state"
        );
    }
}

/// Regression: strict writable mounts must never create a missing base.
#[test]
fn regression_prepared_index_cli_missing_base_is_not_created() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("missing.tar");
    let index = dir.path().join("missing.sqlite");
    let overlay = dir.path().join("overlay");
    let out = run(&[
        "--no-mount",
        "--no-recreate-index",
        "--index-file",
        index.to_str().unwrap(),
        "-w",
        overlay.to_str().unwrap(),
        base.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(!base.exists());
    assert!(!index.exists());
    assert!(!overlay.exists());
}

/// Regression: detected invalid preparation must fail before mounting, without repair.
#[test]
fn regression_prepared_index_cli_invalid_cache_fails_before_mount() {
    for fault in ["missing", "corrupt", "size", "backend", "journal", "wal"] {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.tar");
        let index = dir.path().join("base.sqlite");
        let mount = dir.path().join("mnt");
        fs::create_dir(&mount).unwrap();
        tar(&base);
        prepare(&base, &index);
        match fault {
            "missing" => fs::remove_file(&index).unwrap(),
            "corrupt" => fs::write(&index, b"invalid SQLite index").unwrap(),
            "journal" | "wal" => fs::write(
                format!("{}-{fault}", index.display()),
                b"unfinished preparation",
            )
            .unwrap(),
            "size" | "backend" => {
                let db = rusqlite::Connection::open(&index).unwrap();
                if fault == "size" {
                    db.execute("UPDATE metadata SET value = json_set(value, '$.st_size', 1) WHERE key = 'tarstats'", []).unwrap();
                } else {
                    db.execute(
                        "UPDATE metadata SET value = 'wrong-backend' WHERE key = 'backendName'",
                        [],
                    )
                    .unwrap();
                }
            }
            _ => unreachable!(),
        }
        let before = snapshot(dir.path());
        let overlay = dir.path().join("overlay");
        let out = run(&[
            "--foreground",
            "--no-recreate-index",
            "--index-file",
            index.to_str().unwrap(),
            "-w",
            overlay.to_str().unwrap(),
            base.to_str().unwrap(),
            mount.to_str().unwrap(),
        ]);
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{fault}");
        assert!(
            error.contains("index") || error.contains("prepar"),
            "{fault}: {error}"
        );
        assert!(
            !error.contains("/dev/fuse"),
            "index policy did not precede FUSE: {error}"
        );
        assert_eq!(snapshot(dir.path()), before, "{fault} was repaired");
    }
}

/// Regression: no-mount preparation must complete before immutable workers open it.
#[test]
fn regression_prepared_index_no_mount_finishes_before_workers() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    let index = dir.path().join("base.sqlite");
    tar(&base);
    prepare(&base, &index);
    let before = snapshot(dir.path());
    let out = run(&[
        "--no-mount",
        "--no-recreate-index",
        "--index-file",
        index.to_str().unwrap(),
        base.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(snapshot(dir.path()), before);
    assert!(!PathBuf::from(format!("{}-wal", index.display())).exists());
}

/// Regression: CLI file URL preparation must checkpoint primary and bind indexes.
#[test]
fn regression_prepared_index_file_url_no_mount_finishes_before_workers() {
    for classified in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("temporary.tar");
        tar(&plain);
        let compressed = zstd::encode_all(fs::File::open(&plain).unwrap(), 1).unwrap();
        fs::remove_file(plain).unwrap();
        let base = dir.path().join("base # input.tar.zst");
        let bound = dir.path().join("bound # input.tar.zst");
        fs::write(&base, &compressed).unwrap();
        fs::write(&bound, &compressed).unwrap();
        let input = url::Url::from_file_path(&base).unwrap().to_string();
        let binding = format!("/other={}", url::Url::from_file_path(&bound).unwrap());
        let cache = dir.path().join("indexes");
        fs::create_dir(&cache).unwrap();
        let overlay = dir.path().join("overlay");
        let mut args = vec![
            "--no-mount",
            "--no-file-versions",
            "--index-folders",
            cache.to_str().unwrap(),
            "--bind",
            &binding,
        ];
        if classified {
            args.extend(["-w", overlay.to_str().unwrap()]);
        }
        args.push(&input);
        let out = run(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let before = snapshot(&cache);
        assert_eq!(
            before
                .keys()
                .filter(|p| p.extension().is_some_and(|e| e == "sqlite"))
                .count(),
            2
        );
        let base_before = snapshot(dir.path());
        args.insert(0, "--no-recreate-index");
        let out = run(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(snapshot(&cache), before);
        assert_eq!(snapshot(dir.path()), base_before);
    }
}

/// Regression: direct find uses only prepared catalog/FTS state and never cold-builds.
#[test]
fn regression_prepared_index_find_uses_only_prepared_state() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    let index = dir.path().join("base.sqlite");
    tar(&base);
    prepare(&base, &index);
    for fts_present in [false, true] {
        if fts_present {
            let idx = ratarmount_index::SqliteIndex::open_writable(&index).unwrap();
            idx.ensure_fts5().unwrap();
            drop(idx);
            ratarmount_index::SqliteIndex::finalize_prepared(&index).unwrap();
        }
        let before = snapshot(dir.path());
        for pattern in ["*.txt", "fts:base"] {
            let out = run(&[
                "find",
                "--no-recreate-index",
                "--index-file",
                index.to_str().unwrap(),
                pattern,
                base.to_str().unwrap(),
            ]);
            let error = String::from_utf8_lossy(&out.stderr);
            if pattern.starts_with("fts:") && !fts_present {
                assert_eq!(out.status.code(), Some(2));
                assert!(error.contains("prepared FTS"), "{error}");
            } else {
                assert!(out.status.success(), "{error}");
                assert!(String::from_utf8_lossy(&out.stdout).contains("base.txt"));
            }
            assert_eq!(snapshot(dir.path()), before);
        }
    }
    for fault in ["missing", "corrupt", "stale"] {
        prepare(&base, &index);
        match fault {
            "missing" => fs::remove_file(&index).unwrap(),
            "corrupt" => fs::write(&index, b"broken").unwrap(),
            _ => {
                let db = rusqlite::Connection::open(&index).unwrap();
                db.execute("UPDATE metadata SET value = json_set(value, '$.st_size', 1) WHERE key = 'tarstats'", []).unwrap();
            }
        }
        let before = snapshot(dir.path());
        let out = run(&[
            "find",
            "--no-recreate-index",
            "--index-file",
            index.to_str().unwrap(),
            "*.txt",
            base.to_str().unwrap(),
        ]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{fault}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(snapshot(dir.path()), before);
    }
    let cache = dir.path().join("absent-cache");
    let out = run(&[
        "find",
        "--no-recreate-index",
        "--index-folders",
        cache.to_str().unwrap(),
        "*.txt",
        base.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!cache.exists());
    let out = run(&[
        "find",
        "--no-recreate-index",
        "--hashes",
        "sha256",
        "*.txt",
        base.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
}

/// Regression: a single-block bzip2 preparation cannot claim a reusable worker index.
#[test]
fn regression_prepared_index_single_block_bzip2_preparation_refuses_unchanged() {
    assert_single_block_bzip2_preparation_refuses_unchanged(false, false);
}

/// Regression: file URLs must not bypass the preparer's single-block bzip2 refusal.
#[test]
fn regression_prepared_index_single_block_bzip2_file_url_refuses_unchanged() {
    assert_single_block_bzip2_preparation_refuses_unchanged(true, false);
}

/// Regression: a file URL bind must be preflighted before any index is changed.
#[test]
fn regression_prepared_index_single_block_bzip2_file_url_bind_refuses_unchanged() {
    assert_single_block_bzip2_preparation_refuses_unchanged(true, true);
}

fn assert_single_block_bzip2_preparation_refuses_unchanged(file_url: bool, bind: bool) {
    // Fixed bzip2 streams for b"payload" and a USTAR containing member.txt.
    for (name, hex) in [
        ("single.bz2", "425a68393141592653591d1b8a0d00000281802404c0202000221868300958130bb9229c28480e8dc50680"),
        ("single.tar.bz2", "425a6839314159265359d87d6d51000071fb80c98000084001578001007606de600808200054429a64d3047a99193d43ca092440d34d0001a1f7701c841a5084223d4ac318c2b4086062a93c4f611939030a1c41dbb34cc3b233be5843c78af6a2aa2ecf211100fc5dc914e1424361f5b544"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        // Spaces and '#' also require URL decoding before probing the local file.
        let base = dir.path().join(format!("local # {name}"));
        let index = dir.path().join("prepared.sqlite");
        let bytes: Vec<_> = hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect();
        fs::write(&base, bytes).unwrap();
        let input = if file_url {
            url::Url::from_file_path(&base).unwrap().to_string()
        } else {
            base.to_str().unwrap().to_owned()
        };
        let primary = dir.path().join("primary.tar");
        tar(&primary);
        let binding = format!("/other={input}");
        for existing in [true, false] {
            if existing {
                fs::write(&index, b"existing artifact must not be touched").unwrap();
            } else {
                fs::remove_file(&index).unwrap();
            }
            let before = snapshot(dir.path());
            let mut args = vec!["--no-mount", "--index-file", index.to_str().unwrap()];
            if bind {
                args.extend(["--bind", &binding, primary.to_str().unwrap()]);
            } else {
                args.push(&input);
            }
            let out = run(&args);
            let error = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "{name}, existing={existing}: {error}");
            assert!(error.contains("single-block bzip2 cannot be prepared for read-only workers"), "{name}, existing={existing}: {error}");
            assert_eq!(snapshot(dir.path()), before);
            assert_eq!(index.exists(), existing);
        }
    }
}
