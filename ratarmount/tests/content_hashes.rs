//! Regression #303: real CLI hashing must use decoded member content.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ratarmount_index::hash_hex;
use rusqlite::Connection;

fn parts() -> Vec<(&'static str, Vec<u8>)> {
    let mut state = 303u32;
    let random = (0..1_010_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    vec![
        ("blob.bin", random),
        ("cross.bin", (0..70_000).map(|i| (i % 251) as u8).collect()),
        ("text.txt", b"content hash\n".repeat(500)),
    ]
}

fn tar_bytes(parts: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, data) in parts {
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, &data[..]).unwrap();
    }
    tar.into_inner().unwrap()
}

fn run(path: &Path, flags: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(flags)
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{flags:?} {}: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn index(path: &Path) -> Connection {
    Connection::open(PathBuf::from(format!("{}.index.sqlite", path.display()))).unwrap()
}

fn digest(path: &Path, name: &str, algo: &str) -> Option<Vec<u8>> {
    use rusqlite::OptionalExtension;
    index(path).query_row("SELECT x.value FROM files f JOIN xattrs x USING(offsetheader) WHERE f.name=?1 AND x.key=?2", rusqlite::params![name, format!("user.hash.{algo}")], |r| r.get(0)).optional().unwrap()
}

fn check(path: &Path, parts: &[(&str, Vec<u8>)], algo: &str) {
    for (name, data) in parts {
        assert_eq!(
            digest(path, name, algo),
            Some(hash_hex(algo, data).unwrap().into_bytes()),
            "{}: {name} {algo} must hash decoded member content",
            path.display()
        );
    }
}

fn available(tool: &str) -> bool {
    match Command::new(tool).arg("--version").output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skip: {tool} is absent");
            false
        }
        Err(e) => panic!("probe {tool}: {e}"),
        Ok(_) => true,
    }
}

/// Regression: fresh and warm CLI fills cover all outer codecs and preserve ZIP/7z.
#[test]
fn regression_303_cli_hashes_match_member_content() {
    let dir = tempfile::tempdir().unwrap();
    let parts = parts();
    let tar = tar_bytes(&parts);
    let input = dir.path().join("A.tar");
    fs::write(&input, &tar).unwrap();
    let zst = dir.path().join("A.tar.zst");
    fs::write(&zst, zstd::encode_all(&tar[..], 1).unwrap()).unwrap();
    let mut paths = vec![input.clone(), zst];
    for (ext, tool, args) in [
        ("gz", "gzip", vec!["-c", "-1"]),
        ("xz", "xz", vec!["-c", "-1"]),
        ("bz2", "bzip2", vec!["-c", "-1"]),
        ("lz4", "lz4", vec!["-c", "-q"]),
        ("lzma", "xz", vec!["--format=lzma", "-c", "-1"]),
        ("lz", "lzip", vec!["-c", "-0"]),
        ("lzo", "lzop", vec!["-c"]),
        ("Z", "compress", vec!["-c"]),
        ("lrz", "lrzip", vec!["-q", "-L", "1"]),
    ] {
        if !available(tool) {
            continue;
        }
        let path = dir.path().join(format!("A.tar.{ext}"));
        let mut command = Command::new(tool);
        command.args(args);
        if tool == "lrzip" {
            command.arg("-o").arg(&path);
        }
        let out = command.arg(&input).output().unwrap();
        assert!(
            out.status.success(),
            "{tool}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if tool != "lrzip" {
            fs::write(&path, &out.stdout).unwrap();
        }
        paths.push(path);
    }
    for path in paths {
        run(&path, &["--no-mount", "--hashes", "sha256"]);
        check(&path, &parts, "sha256");
        run(&path, &["--no-mount", "--hashes", "sha256,crc32"]);
        check(&path, &parts, "sha256");
        check(&path, &parts, "crc32");
    }
    for (tool, ext) in [("zip", "zip"), ("7z", "7z")] {
        if !available(tool) {
            continue;
        }
        for (name, data) in &parts {
            fs::write(dir.path().join(name), data).unwrap();
        }
        let path = dir.path().join(format!("members.{ext}"));
        let commands = if tool == "zip" {
            vec![
                vec!["-q", "-0", "members.zip", "blob.bin"],
                vec!["-q", "-9", "members.zip", "cross.bin", "text.txt"],
            ]
        } else {
            vec![vec![
                "a",
                "-t7z",
                "-ms=off",
                "-mx=1",
                "members.7z",
                "blob.bin",
                "cross.bin",
                "text.txt",
            ]]
        };
        for args in commands {
            let out = Command::new(tool)
                .current_dir(dir.path())
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{tool}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        run(&path, &["--no-mount", "--hashes", "sha256"]);
        check(&path, &parts, "sha256");
        let out = run(&path, &["--no-mount", "--hashes", "sha256,crc32"]);
        check(&path, &parts, "sha256");
        assert!(String::from_utf8_lossy(&out.stderr).contains("--recreate-index --hashes"));
        for (name, data) in &parts {
            let expected = (tool == "zip" && *name == "blob.bin")
                .then(|| hash_hex("crc32", data).unwrap().into_bytes());
            assert_eq!(
                digest(&path, name, "crc32"),
                expected,
                "{tool}: warm {name}"
            );
        }
        if tool == "zip" {
            run(&path, &["--no-mount", "--recreate-index"]);
            run(&path, &["--no-mount", "--hashes", "sha256"]);
            assert_eq!(
                digest(&path, "blob.bin", "sha256"),
                Some(hash_hex("sha256", &parts[0].1).unwrap().into_bytes())
            );
            assert!(digest(&path, "text.txt", "sha256").is_none());
        }
        run(
            &path,
            &["--no-mount", "--recreate-index", "--hashes", "sha256,crc32"],
        );
        check(&path, &parts, "sha256");
        check(&path, &parts, "crc32");
    }
}

/// Regression: value-taking find --hashes fills a warm compressed index.
#[test]
fn regression_303_cli_find_fills_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let parts = parts();
    let path = dir.path().join("A.tar.zst");
    fs::write(&path, zstd::encode_all(&tar_bytes(&parts)[..], 1).unwrap()).unwrap();
    run(&path, &["--no-mount", "--hashes", "sha256"]);
    assert!(digest(&path, "blob.bin", "crc32").is_none());
    run(&path, &["find", "--hashes", "crc32", "*"]);
    check(&path, &parts, "crc32");
}

/// Regression: real recursive TAR indexing retains nested absolute payload offsets.
#[test]
fn regression_303_cli_nested_member_filled() {
    let dir = tempfile::tempdir().unwrap();
    let content = vec![b'n'; 700];
    let inner = tar_bytes(&[("nested.txt", content.clone())]);
    let outer = tar_bytes(&[("inner.tar", inner)]);
    for codec in ["tar", "tar.zst"] {
        let path = dir.path().join(format!("outer.{codec}"));
        fs::write(
            &path,
            if codec == "tar" {
                outer.clone()
            } else {
                zstd::encode_all(&outer[..], 1).unwrap()
            },
        )
        .unwrap();
        run(
            &path,
            &[
                "--no-mount",
                "-r",
                "--recursion-depth",
                "1",
                "--hashes",
                "sha256,crc32",
            ],
        );
        let depth: i64 = index(&path)
            .query_row(
                "SELECT recursiondepth FROM files WHERE name='nested.txt'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(depth >= 1);
        check(&path, &[("nested.txt", content.clone())], "sha256");
        check(&path, &[("nested.txt", content.clone())], "crc32");
    }
}

/// Regression: the CLI's actual TAR parser applies PAX size before filling hashes.
#[test]
fn regression_303_cli_pax_effective_size_filled() {
    let dir = tempfile::tempdir().unwrap();
    let content = vec![b'p'; 700];
    let mut tar = tar::Builder::new(Vec::new());
    tar.append_pax_extensions([("size", b"700".as_slice())])
        .unwrap();
    let mut h = tar::Header::new_ustar();
    h.set_path("pax.bin").unwrap();
    h.set_mode(0o644);
    h.set_size(0);
    h.set_cksum();
    tar.get_mut().write_all(h.as_bytes()).unwrap();
    tar.get_mut().extend(&content);
    tar.get_mut().resize(2560, 0);
    let bytes = tar.into_inner().unwrap();
    for codec in ["tar", "tar.zst"] {
        let path = dir.path().join(format!("pax.{codec}"));
        fs::write(
            &path,
            if codec == "tar" {
                bytes.clone()
            } else {
                zstd::encode_all(&bytes[..], 1).unwrap()
            },
        )
        .unwrap();
        run(&path, &["--no-mount", "--hashes", "sha256,crc32"]);
        for algo in ["sha256", "crc32"] {
            check(&path, &[("pax.bin", content.clone())], algo);
        }
    }
}
