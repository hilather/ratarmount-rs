//! Offline overlay commands. Keep each verb's implementation independent.

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use ratarmount_compositing::{OverlayMeta, OverlayStats};

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount overlay",
    about = "Inspect and manage write overlays offline"
)]
pub struct OverlayArgs {
    #[command(subcommand)]
    pub command: OverlayCommand,
}

#[derive(Debug, Subcommand)]
pub enum OverlayCommand {
    /// Show metadata, counts, and writability without modifying the overlay.
    Info(InfoArgs),
    /// Check overlay consistency. Exit 0: clean/repaired, 1: inconsistencies, 2: error.
    Fsck {
        directory: PathBuf,
        #[arg(long)]
        repair: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
pub struct InfoArgs {
    pub directory: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &OverlayArgs) -> Result<(String, i32), String> {
    match &args.command {
        OverlayCommand::Info(args) => info(args).map(|output| (output, 0)),
        OverlayCommand::Fsck {
            directory,
            repair,
            json,
        } => fsck(directory, *repair, *json),
    }
}

pub fn fsck(directory: &Path, repair: bool, json: bool) -> Result<(String, i32), String> {
    let report = ratarmount_compositing::overlay_fsck::fsck(directory, repair)
        .map_err(|e| format!("fsck {}: {e}", directory.display()))?;
    let code = i32::from(!report.is_clean());
    let mut fields = serde_json::to_value(&report).expect("fsck report");
    fields["result"] = report.result().into();
    let output = if json {
        fields.to_string()
    } else {
        fields
            .as_object()
            .expect("fsck fields")
            .iter()
            .map(|(key, value)| {
                format!(
                    "{key}: {}",
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok((output, code))
}

pub fn info(args: &InfoArgs) -> Result<String, String> {
    let meta = OverlayMeta::read(&args.directory)
        .map_err(|e| super::overlay_open_error(&args.directory, &e))?;
    let stats = OverlayStats::read(&args.directory)
        .map_err(|e| super::overlay_open_error(&args.directory, &e))?;
    // Reuse overlay-stats' public counts and JSON field names.
    let mut fields: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&super::overlay_stats::render(stats, true)).expect("stats JSON");
    if let Some(meta) = &meta {
        fields.extend(
            meta.values()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone().into())),
        );
    }
    fields.insert(
        "legacy".into(),
        meta.as_ref().is_none_or(OverlayMeta::legacy).into(),
    );
    fields.insert("tombstone_count".into(), stats.files_deleted.into());
    fields.insert(
        "files_dir_writable".into(),
        directory_writable(&args.directory).into(),
    );
    fields.insert("db_opens_read_only".into(), true.into());
    if args.json {
        Ok(format!("{}\n", serde_json::Value::Object(fields)))
    } else {
        let mut output = String::new();
        for (key, value) in fields {
            let value = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            output.push_str(&format!("{key}: {value}\n"));
        }
        Ok(output)
    }
}

fn directory_writable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

/// Resolve once before the factory opens a Git source, so a moving branch
/// cannot produce metadata for a different tree from the mounted source.
pub fn pin_git_base(
    paths: &mut [PathBuf],
    options: &mut ratarmount_core::OpenOptions,
) -> Result<Option<String>, String> {
    use ratarmount_formats_git::{looks_like_git, split_inline_reference, GitMountSource};
    let [path] = paths else {
        return Ok(None);
    };
    let inline = split_inline_reference(path);
    let git_path = inline.as_ref().map_or(path.as_path(), |(p, _)| p.as_path());
    let is_bare = git_path.join("HEAD").is_file()
        && git_path.join("objects").is_dir()
        && git_path.join("refs").is_dir()
        && !git_path.join(".git").exists();
    let selected = options.git
        || options.git_ref.is_some()
        || inline.is_some()
        || is_bare
        || (looks_like_git(git_path) && std::env::var_os("RATARMOUNT_FORCE_GIT").is_some());
    if !selected {
        return Ok(None);
    }
    if inline.is_some() && options.git_ref.is_some() {
        return Err("use either repo@REV or --git-ref, not both".into());
    }
    let reference = options
        .git_ref
        .as_deref()
        .or_else(|| inline.as_ref().map(|(_, r)| r.as_str()));
    let mut git = GitMountSource::open(git_path, reference).map_err(|e| e.to_string())?;
    if let Some(prefix) = &options.git_prefix {
        git = git.with_prefix(prefix).map_err(|e| e.to_string())?;
    }
    options.git_ref = Some(git.resolved_commit().to_string());
    *path = git_path.to_path_buf();
    Ok(Some(git.tree_id()))
}

/// HEAD only: failure or an unsupported scheme falls back to the known URL.
/// Credentials follow the remote parser; no authenticated redirect is replayed.
pub fn remote_base_token(url: &str) -> Option<String> {
    if url.starts_with("s3://") {
        let head = ratarmount_remote::head_s3_object(url).ok()?;
        return Some(serde_json::json!({"etag":head.etag,"size":head.len}).to_string());
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return None;
    }
    let location = ratarmount_remote::parse_http_url(url).ok()?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(3))
        .redirects(0)
        .build();
    let mut request = agent.head(&location.url);
    if let Some(auth) = location.auth {
        request = request.set("Authorization", &auth.authorization_header());
    }
    if let Some(cookie) = location.cookie {
        request = request.set("Cookie", &cookie);
    }
    let response = request.call().ok()?;
    if !(200..300).contains(&response.status()) {
        return None;
    }
    let etag = response.header("ETag");
    let size = response.header("Content-Length");
    let modified = response.header("Last-Modified");
    if etag.is_none() && size.is_none() && modified.is_none() {
        return None;
    }
    Some(serde_json::json!({"etag":etag,"size":size,"last_modified":modified}).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_compositing::{FolderMountSource, OverlayCreateInfo, WriteOverlay};
    use std::sync::Arc;

    /// Regression: `overlay info DIR` stole DIR as the ordinary mountpoint.
    #[test]
    fn regression_overlay_meta_info_dispatch_keeps_directory() {
        let parsed =
            crate::parse_args_from(["ratarmount", "overlay", "info", "DIR", "--json"]).unwrap();
        assert!(parsed.paths.is_empty());
        let OverlayCommand::Info(args) = parsed.overlay.unwrap().command else {
            panic!("expected info")
        };
        assert_eq!(args.directory, Path::new("DIR"));
        assert!(args.json);
        assert!(crate::parse_args_from(["ratarmount", "overlay", "info"]).is_err());
        assert!(crate::parse_args_from(["ratarmount", "overlay", "info", "one", "two"]).is_err());
        assert!(
            crate::parse_args_from(["ratarmount", "--no-mount", "overlay"])
                .unwrap()
                .overlay
                .is_none()
        );
    }

    /// Regression: base identity flags must require an overlay and validate SHA-256 syntax.
    #[test]
    fn regression_overlay_meta_flags_require_overlay() {
        assert!(
            crate::parse_args_from(["ratarmount", "--base-digest", "none", "a.tar", "mnt"])
                .is_err()
        );
        assert!(
            crate::parse_args_from(["ratarmount", "--force-base-mismatch", "a.tar", "mnt"])
                .is_err()
        );
        for flag in ["--sandbox", "--overlay-tmpfs"] {
            assert!(crate::parse_args_from([
                "ratarmount",
                flag,
                "--base-digest",
                "none",
                "a.tar",
                "mnt"
            ])
            .is_ok());
        }
        for value in ["sha256:abc", "sha1:1234", "None", "random"] {
            assert!(crate::parse_args_from([
                "ratarmount",
                "-w",
                "ov",
                "--base-digest",
                value,
                "a.tar",
                "mnt"
            ])
            .is_err());
        }
        let value = format!("sha256:{}", "A".repeat(64));
        let parsed = crate::parse_args_from([
            "ratarmount",
            "-w",
            "ov",
            "--base-digest",
            &value,
            "--force-base-mismatch",
            "a.tar",
            "mnt",
        ])
        .unwrap();
        assert_eq!(
            parsed.base_digest,
            Some(ratarmount_compositing::BaseDigestRequest::Supplied(
                value.to_ascii_lowercase()
            ))
        );
        assert!(parsed.force_base_mismatch);
    }

    /// Regression: info must include every metadata key and the existing stats fields without writes.
    #[test]
    fn regression_overlay_meta_info_json_and_legacy() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("deleted"), b"old").unwrap();
        let overlay = root.path().join("overlay");
        let ov = WriteOverlay::new_with_create_info(
            Arc::new(FolderMountSource::new(&source).unwrap()),
            &overlay,
            &OverlayCreateInfo {
                base_url: source.to_str().unwrap().into(),
                ..Default::default()
            },
        )
        .unwrap();
        ov.unlink("/deleted").unwrap();
        drop(ov);
        std::fs::write(overlay.join("new"), b"payload").unwrap();
        let db = overlay.join(ratarmount_compositing::HIDDEN_DB);
        let conn = rusqlite::Connection::open(&db).unwrap();
        OverlayMeta::set(&conn, "future_key", "also reported").unwrap();
        drop(conn);
        let before = std::fs::read(&db).unwrap();
        let args = InfoArgs {
            directory: overlay.clone(),
            json: true,
        };
        let output: serde_json::Value = serde_json::from_str(&info(&args).unwrap()).unwrap();
        assert_eq!(output["legacy"], false);
        assert_eq!(output["future_key"], "also reported");
        assert_eq!(output["base_digest_kind"], "strong");
        assert_eq!(output["files_present"], 1);
        assert_eq!(output["bytes_in_overlay"], 7);
        assert_eq!(output["tombstone_count"], 1);
        assert_eq!(output["files_deleted"], 1);
        assert_eq!(output["db_opens_read_only"], true);
        assert_eq!(output["files_dir_writable"], true);
        assert_eq!(std::fs::read(&db).unwrap(), before);
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("DROP TABLE meta").unwrap();
        drop(conn);
        let output: serde_json::Value = serde_json::from_str(&info(&args).unwrap()).unwrap();
        assert_eq!(output["legacy"], true);
        drop(
            WriteOverlay::new(Arc::new(FolderMountSource::new(&source).unwrap()), &overlay)
                .unwrap(),
        );
        let output: serde_json::Value = serde_json::from_str(&info(&args).unwrap()).unwrap();
        assert_eq!(output["legacy"], true);
        assert_eq!(output["format_version"], "1");
        assert!(output.get("base_digest").is_none());
    }

    /// Regression: a Git branch moving during startup must not change the mounted base tree.
    #[test]
    fn regression_overlay_meta_git_tree_matches_pinned_source() {
        let root = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(root.path()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.test").unwrap();
        let tree_oid = repo.treebuilder(None).unwrap().write().unwrap();
        let tree = repo.find_tree(tree_oid).unwrap();
        let commit = repo
            .commit(Some("HEAD"), &sig, &sig, "base", &tree, &[])
            .unwrap();
        let mut options = ratarmount_core::OpenOptions::default();
        let mut paths = [PathBuf::from(format!("{}@HEAD", root.path().display()))];
        assert_eq!(
            pin_git_base(&mut paths, &mut options).unwrap(),
            Some(tree_oid.to_string())
        );
        assert_eq!(options.git_ref, Some(commit.to_string()));
        assert_eq!(paths[0], root.path());
        let source = ratarmount_session::factory::open_path(&paths[0], &options, false).unwrap();
        let fi = source.lookup("/", 0).unwrap();
        assert_eq!(
            source.get_xattr(&fi, ratarmount_formats_git::COMMIT_XATTR),
            Some(commit.to_string().into_bytes())
        );
    }

    /// Regression: remote metadata probing must use HEAD only and preserve validators.
    #[test]
    fn regression_overlay_meta_remote_head_no_payload() {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/base.tar", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(socket.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            assert!(first.starts_with("HEAD /base.tar "), "{first}");
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12345\r\nETag: \"v1\"\r\nLast-Modified: Sat, 17 Oct 2026 00:00:00 GMT\r\nConnection: close\r\n\r\n").unwrap();
        });
        let value: serde_json::Value =
            serde_json::from_str(&remote_base_token(&url).unwrap()).unwrap();
        assert_eq!(value["etag"], "\"v1\"");
        assert_eq!(value["size"], "12345");
        assert!(value["last_modified"].is_string());
        server.join().unwrap();
        assert_eq!(remote_base_token("hf://datasets/org/repo@main/a"), None);
    }
}
