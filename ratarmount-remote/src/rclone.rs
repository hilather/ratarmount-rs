//! Ingest `rclone://` remotes via the rclone CLI (P-9).
//!
//! Unlocks Drive / OneDrive / B2 / Swift / HDFS without reimplementing OAuth.
//! Config is left to rclone (`RCLONE_CONFIG` or `~/.config/rclone/rclone.conf`).
//!
//! - **URL:** `rclone://remote:path` (colon after the remote name). This form is
//!   WHATWG-invalid (`Url::parse` treats `:path` as a port) so parsing is custom.
//!   Alias: `rclone://remote/path` (slash, no colon).
//! - **File:** `rclone cat --offset --count remote:path` as a `Command` argv array
//!   (never `sh -c`). One process per [`RcloneHandle`] open — materialize at open
//!   so later seeks/reads do not spawn. Not RC `/operations/cat`.
//! - **Size / dir probe:** `rclone lsjson --stat remote:path`.
//! - **Folder:** `rclone lsjson remote:dir` → [`RemoteListing`] (listing TTL 30s
//!   via [`RemoteFolderMountSource`]).
//! - **Missing binary:** `` rclone not found on PATH; install rclone or use a native scheme ``

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use log::debug;
use ratarmount_core::{ArchiveRead, MountSource};
use tempfile::NamedTempFile;

use crate::folder::{RemoteDirent, RemoteFolderMountSource, RemoteListing};
use crate::{RemoteError, Result};

/// Env: absolute path to the `rclone` binary. When set, PATH is not searched.
pub const RCLONE_BIN_ENV: &str = "RATARMOUNT_RCLONE";

const MISSING_RCLONE: &str = "rclone not found on PATH; install rclone or use a native scheme";

/// Parsed `rclone://remote:path` (or slash alias `rclone://remote/path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcloneLocation {
    pub remote: String,
    /// Path within the remote (no leading slash; may be empty for the remote root).
    pub path: String,
}

impl RcloneLocation {
    /// `remote:path` argument for rclone argv (empty path → `remote:`).
    pub fn spec(&self) -> String {
        format!("{}:{}", self.remote, self.path.trim_end_matches('/'))
    }
}

/// Seekable handle for one rclone object. Body is materialized once at open.
pub struct RcloneHandle {
    loc: RcloneLocation,
    size: u64,
    file: NamedTempFile,
}

impl std::fmt::Debug for RcloneHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RcloneHandle")
            .field("remote", &self.loc.remote)
            .field("path", &self.loc.path)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl RcloneHandle {
    pub fn open(url_str: &str) -> Result<Self> {
        let loc = parse_rclone_url(url_str)?;
        Self::open_location(&loc)
    }

    pub fn open_location(loc: &RcloneLocation) -> Result<Self> {
        if loc.path.trim_end_matches('/').is_empty() {
            return Err(rclone_io(
                "rclone URL missing file path (expected rclone://remote:path)",
            ));
        }
        let st = lsjson_stat(loc)?;
        if st.is_dir {
            return Err(rclone_io(format!(
                "rclone {} is a directory; use a folder mount",
                loc.spec()
            )));
        }
        Self::cat_materialize(loc, st.size)
    }

    /// Materialize with a known size (skips `lsjson`; one `cat` process).
    pub fn cat_materialize(loc: &RcloneLocation, size: u64) -> Result<Self> {
        let file = rclone_cat_to_temp(loc, 0, size)?;
        let actual = file.as_file().metadata()?.len();
        Ok(Self {
            loc: loc.clone(),
            size: actual,
            file,
        })
    }

    pub fn location(&self) -> &RcloneLocation {
        &self.loc
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Always false: v1 materializes at open (no process per `read`).
    pub fn uses_ranges(&self) -> bool {
        false
    }
}

/// Open `rclone://…` as a seekable file (materialize via `rclone cat`).
pub fn open_rclone(url_str: &str) -> Result<RcloneHandle> {
    RcloneHandle::open(url_str)
}

/// Open `rclone://…` as a remote folder when the path is a directory.
///
/// `Ok(None)` if the path is a file (factory should fall through to [`open_rclone`]).
pub fn open_rclone_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_rclone_url(s)?;
    find_rclone().ok_or_else(rclone_missing)?;
    let trimmed = loc.path.trim_matches('/');
    let is_dir = if trimmed.is_empty() {
        true
    } else {
        match lsjson_stat(&loc) {
            Ok(st) => st.is_dir,
            Err(e) if is_not_found(&e) => loc.path.ends_with('/'),
            Err(e) => return Err(e),
        }
    };
    if !is_dir {
        return Ok(None);
    }
    let root = loc.path.trim_end_matches('/').to_string();
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        root,
        RcloneListing { remote: loc.remote },
    ))))
}

/// Parse `rclone://remote:path` without [`url::Url`] (WHATWG-invalid colon form).
///
/// - Primary: strip `rclone://`, split on the **first** `:`.
///   `rclone://gdrive:bucket/path` → remote=`gdrive`, path=`bucket/path`.
/// - Alias: `rclone://remote/path` (no colon) → remote=`remote`, path=`path`.
pub fn parse_rclone_url(url_str: &str) -> Result<RcloneLocation> {
    let Some((scheme, rest)) = url_str.split_once("://") else {
        return Err(RemoteError::Url(
            "rclone URL must start with rclone://".into(),
        ));
    };
    if !scheme.eq_ignore_ascii_case("rclone") {
        return Err(RemoteError::UnsupportedScheme(scheme.to_string()));
    }
    if rest.is_empty() {
        return Err(RemoteError::Url(
            "rclone URL missing remote name (expected rclone://remote:path)".into(),
        ));
    }

    // Do not call Url::parse: `rclone://gdrive:bucket/path` is an invalid port,
    // and `rclone://gdrive:123/path` would steal `123` as a port.
    if let Some((remote, path)) = rest.split_once(':') {
        return finish_loc(remote, path);
    }
    if let Some((remote, path)) = rest.split_once('/') {
        return finish_loc(remote, path);
    }
    finish_loc(rest, "")
}

fn finish_loc(remote: &str, path: &str) -> Result<RcloneLocation> {
    if remote.is_empty() {
        return Err(RemoteError::Url(
            "rclone URL missing remote name (expected rclone://remote:path)".into(),
        ));
    }
    if remote.contains('/') {
        return Err(RemoteError::Url(format!(
            "rclone remote name {remote:?} must not contain '/'"
        )));
    }
    Ok(RcloneLocation {
        remote: remote.to_string(),
        path: path.trim_start_matches('/').to_string(),
    })
}

/// `rclone cat --offset N --count M remote:path` (separate argv tokens).
pub fn rclone_cat_args(loc: &RcloneLocation, offset: u64, count: u64) -> Vec<String> {
    vec![
        "cat".into(),
        "--offset".into(),
        offset.to_string(),
        "--count".into(),
        count.to_string(),
        loc.spec(),
    ]
}

/// `rclone lsjson remote:path` (directory listing).
pub fn rclone_lsjson_args(loc: &RcloneLocation) -> Vec<String> {
    vec!["lsjson".into(), loc.spec()]
}

/// `rclone lsjson --stat remote:path` (single object / dir probe).
pub fn rclone_lsjson_stat_args(loc: &RcloneLocation) -> Vec<String> {
    vec!["lsjson".into(), "--stat".into(), loc.spec()]
}

/// Locate `rclone` (`RATARMOUNT_RCLONE` else PATH).
pub fn find_rclone() -> Option<PathBuf> {
    match std::env::var(RCLONE_BIN_ENV) {
        Ok(p) if !p.trim().is_empty() => {
            let pb = PathBuf::from(p.trim());
            if pb.is_file() {
                Some(pb)
            } else {
                None
            }
        }
        _ => which_bin("rclone"),
    }
}

fn which_bin(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = candidate.metadata() {
                    if meta.permissions().mode() & 0o111 == 0 {
                        continue;
                    }
                }
            }
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

struct LsEntry {
    name: String,
    is_dir: bool,
    size: u64,
}

fn lsjson_stat(loc: &RcloneLocation) -> Result<LsEntry> {
    let out = run_rclone(&rclone_lsjson_stat_args(loc))?;
    let entries = parse_lsjson(&out)?;
    entries.into_iter().next().ok_or_else(|| {
        rclone_io(format!(
            "rclone lsjson --stat {} returned no object",
            loc.spec()
        ))
    })
}

fn lsjson_list(loc: &RcloneLocation) -> Result<Vec<LsEntry>> {
    let out = run_rclone(&rclone_lsjson_args(loc))?;
    parse_lsjson(&out)
}

fn parse_lsjson(stdout: &[u8]) -> Result<Vec<LsEntry>> {
    let text = std::str::from_utf8(stdout)
        .map_err(|e| rclone_io(format!("rclone lsjson is not UTF-8: {e}")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let v: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| rclone_io(format!("rclone lsjson JSON parse error: {e}")))?;
    let items: Vec<&serde_json::Value> = if let Some(arr) = v.as_array() {
        arr.iter().collect()
    } else if v.is_object() {
        vec![&v]
    } else {
        return Err(rclone_io("rclone lsjson expected a JSON object or array"));
    };
    Ok(items.into_iter().filter_map(parse_ls_entry).collect())
}

fn parse_ls_entry(v: &serde_json::Value) -> Option<LsEntry> {
    let obj = v.as_object()?;
    let name = obj
        .get("Name")
        .and_then(|n| n.as_str())
        .or_else(|| obj.get("Path").and_then(|p| p.as_str()))
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return None;
    }
    let is_dir = obj.get("IsDir").and_then(|d| d.as_bool()).unwrap_or(false);
    let size = if is_dir {
        0
    } else {
        obj.get("Size").and_then(|s| s.as_i64()).unwrap_or(0).max(0) as u64
    };
    Some(LsEntry { name, is_dir, size })
}

fn rclone_cat_to_temp(loc: &RcloneLocation, offset: u64, count: u64) -> Result<NamedTempFile> {
    let bin = find_rclone().ok_or_else(rclone_missing)?;
    let args = rclone_cat_args(loc, offset, count);
    debug!("rclone {}", args.join(" "));
    let mut child = Command::new(&bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_spawn)?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| rclone_io("rclone stdout not piped"))?;
    let mut tmp = NamedTempFile::new()?;
    io::copy(&mut stdout, &mut tmp)?;
    let mut err_buf = Vec::new();
    if let Some(mut err) = child.stderr.take() {
        err.read_to_end(&mut err_buf)?;
    }
    let status = child.wait()?;
    if !status.success() {
        let detail = String::from_utf8_lossy(&err_buf);
        return Err(rclone_io(format!(
            "rclone cat failed for {}: {}",
            loc.spec(),
            detail.trim()
        )));
    }
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok(tmp)
}

fn run_rclone(args: &[String]) -> Result<Vec<u8>> {
    let bin = find_rclone().ok_or_else(rclone_missing)?;
    debug!("rclone {}", args.join(" "));
    let output = Command::new(&bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(map_spawn)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            stdout.trim().to_string()
        };
        return Err(rclone_io(format!(
            "rclone {} failed: {detail}",
            args.first().map(String::as_str).unwrap_or("rclone")
        )));
    }
    Ok(output.stdout)
}

fn map_spawn(e: io::Error) -> RemoteError {
    if e.kind() == io::ErrorKind::NotFound {
        rclone_missing()
    } else {
        rclone_io(format!("failed to spawn rclone: {e}"))
    }
}

fn rclone_missing() -> RemoteError {
    rclone_io(MISSING_RCLONE)
}

fn rclone_io(msg: impl Into<String>) -> RemoteError {
    RemoteError::Io(io::Error::other(msg.into()))
}

fn is_not_found(err: &RemoteError) -> bool {
    let s = err.to_string().to_ascii_lowercase();
    s.contains("not found") || s.contains("directory not found") || s.contains("object not found")
}

struct RcloneListing {
    remote: String,
}

impl RemoteListing for RcloneListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        let loc = RcloneLocation {
            remote: self.remote.clone(),
            path: remote_path.trim_matches('/').to_string(),
        };
        let entries = lsjson_list(&loc)?;
        Ok(entries
            .into_iter()
            .filter_map(|e| {
                if e.name.is_empty() || e.name == "." || e.name == ".." || e.name.contains('/') {
                    return None;
                }
                let child = if loc.path.is_empty() {
                    e.name.clone()
                } else {
                    format!("{}/{}", loc.path, e.name)
                };
                Some(RemoteDirent {
                    name: e.name,
                    remote_path: child,
                    is_dir: e.is_dir,
                    size: e.size,
                    mtime: 0.0,
                })
            })
            .collect())
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        if remote_path.trim_matches('/').is_empty() {
            return Ok(true);
        }
        let loc = RcloneLocation {
            remote: self.remote.clone(),
            path: remote_path.trim_matches('/').to_string(),
        };
        match lsjson_stat(&loc) {
            Ok(st) => Ok(st.is_dir),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>> {
        let loc = RcloneLocation {
            remote: self.remote.clone(),
            path: remote_path.trim_matches('/').to_string(),
        };
        let handle = if size > 0 {
            RcloneHandle::cat_materialize(&loc, size)?
        } else {
            RcloneHandle::open_location(&loc)?
        };
        Ok(Box::new(handle))
    }
}

impl Read for RcloneHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for RcloneHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::Path;
    use std::sync::Mutex as StdMutex;

    use ratarmount_core::{S_IFDIR, S_IFMT, S_IFREG};

    static RCLONE_ENV_LOCK: StdMutex<()> = StdMutex::new(());

    struct EnvRestore {
        key: &'static str,
        old: Option<OsString>,
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.old.take() {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn set_env(key: &'static str, val: &str) -> EnvRestore {
        let old = std::env::var_os(key);
        std::env::set_var(key, val);
        EnvRestore { key, old }
    }

    fn remove_env(key: &'static str) -> EnvRestore {
        let old = std::env::var_os(key);
        std::env::remove_var(key);
        EnvRestore { key, old }
    }

    const FAKE_RCLONE_SH: &str = r#"#!/bin/sh
log_count() {
  if [ -n "$RCLONE_FAKE_COUNT" ]; then
    printf '%s\n' "$1" >> "$RCLONE_FAKE_COUNT"
  fi
}
if [ -n "$RCLONE_FAKE_ARGV" ]; then
  for a in "$@"; do
    printf '%s\n' "$a" >> "$RCLONE_FAKE_ARGV"
  done
  printf -- '---\n' >> "$RCLONE_FAKE_ARGV"
fi
cmd="$1"
if [ -z "$cmd" ]; then
  echo "rclone: missing command" >&2
  exit 1
fi
shift
log_count "$cmd"
offset=0
count=""
stat=0
spec=""
while [ $# -gt 0 ]; do
  case "$1" in
    --offset)
      offset="$2"
      shift 2
      ;;
    --count)
      count="$2"
      shift 2
      ;;
    --stat)
      stat=1
      shift
      ;;
    --config)
      shift 2
      ;;
    --*)
      echo "rclone: unexpected flag $1" >&2
      exit 1
      ;;
    *)
      spec="$1"
      shift
      ;;
  esac
done
if [ -z "$spec" ]; then
  echo "rclone: missing remote:path" >&2
  exit 1
fi
if [ -z "$RCLONE_FAKE_DATA" ]; then
  echo "rclone: RCLONE_FAKE_DATA unset" >&2
  exit 1
fi
remote="${spec%%:*}"
rpath="${spec#*:}"
target="$RCLONE_FAKE_DATA/$remote/$rpath"
case "$target" in
  */) target="${target%/}" ;;
esac
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}
emit_stat() {
  path="$1"
  name=$(basename "$path")
  [ -n "$name" ] || name="."
  if [ -d "$path" ]; then
    printf '{"Path":"%s","Name":"%s","Size":-1,"IsDir":true}' "$(json_escape "$name")" "$(json_escape "$name")"
  elif [ -f "$path" ]; then
    sz=$(wc -c < "$path" | tr -d ' ')
    printf '{"Path":"%s","Name":"%s","Size":%s,"IsDir":false}' "$(json_escape "$name")" "$(json_escape "$name")" "$sz"
  else
    echo "rclone: $spec: not found" >&2
    exit 1
  fi
}
case "$cmd" in
  cat)
    if [ ! -f "$target" ]; then
      echo "rclone: $spec: not a file" >&2
      exit 1
    fi
    if [ -z "$count" ]; then
      dd if="$target" bs=1 skip="$offset" 2>/dev/null || true
    else
      dd if="$target" bs=1 skip="$offset" count="$count" 2>/dev/null || true
    fi
    ;;
  lsjson)
    if [ "$stat" = 1 ]; then
      emit_stat "$target"
      printf '\n'
    else
      if [ -f "$target" ]; then
        printf '['
        emit_stat "$target"
        printf ']\n'
      elif [ -d "$target" ]; then
        printf '['
        first=1
        for p in "$target"/*; do
          [ -e "$p" ] || continue
          if [ "$first" = 1 ]; then
            first=0
          else
            printf ','
          fi
          emit_stat "$p"
        done
        printf ']\n'
      else
        echo "rclone: $spec: not found" >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "rclone: unsupported command $cmd" >&2
    exit 1
    ;;
esac
"#;

    struct FakeRclone {
        _dir: tempfile::TempDir,
        bin: PathBuf,
        data: PathBuf,
        count: PathBuf,
        argv: PathBuf,
        _env: Vec<EnvRestore>,
    }

    impl FakeRclone {
        fn cat_execs(&self) -> usize {
            self.cmd_execs("cat")
        }
        fn cmd_execs(&self, cmd: &str) -> usize {
            let Ok(text) = std::fs::read_to_string(&self.count) else {
                return 0;
            };
            text.lines().filter(|l| *l == cmd).count()
        }
        fn argv_log(&self) -> String {
            std::fs::read_to_string(&self.argv).unwrap_or_default()
        }
    }

    fn install_fake_rclone(setup: impl FnOnce(&Path)) -> Option<FakeRclone> {
        let dir = match tempfile::TempDir::new() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("skip: cannot create tempdir for fake rclone: {e}");
                return None;
            }
        };
        let bin = dir.path().join("rclone");
        if let Err(e) = std::fs::write(&bin, FAKE_RCLONE_SH) {
            eprintln!("skip: cannot write fake rclone: {e}");
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)) {
                eprintln!("skip: cannot chmod fake rclone: {e}");
                return None;
            }
        }
        let data = dir.path().join("data");
        if let Err(e) = std::fs::create_dir_all(&data) {
            eprintln!("skip: cannot create fake rclone data dir: {e}");
            return None;
        }
        setup(&data);
        let count = dir.path().join("count");
        let argv = dir.path().join("argv");
        let bin_s = bin.to_str()?.to_string();
        let data_s = data.to_str()?.to_string();
        let count_s = count.to_str()?.to_string();
        let argv_s = argv.to_str()?.to_string();
        let env = vec![
            set_env(RCLONE_BIN_ENV, &bin_s),
            set_env("RCLONE_FAKE_DATA", &data_s),
            set_env("RCLONE_FAKE_COUNT", &count_s),
            set_env("RCLONE_FAKE_ARGV", &argv_s),
        ];
        Some(FakeRclone {
            _dir: dir,
            bin,
            data,
            count,
            argv,
            _env: env,
        })
    }

    fn write_file(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn parse_colon_and_slash_forms() {
        let loc = parse_rclone_url("rclone://gdrive:bucket/path").unwrap();
        assert_eq!(loc.remote, "gdrive");
        assert_eq!(loc.path, "bucket/path");
        assert_eq!(loc.spec(), "gdrive:bucket/path");

        let loc = parse_rclone_url("rclone://my-remote/foo/bar").unwrap();
        assert_eq!(loc.remote, "my-remote");
        assert_eq!(loc.path, "foo/bar");

        let loc = parse_rclone_url("rclone://backup:").unwrap();
        assert_eq!(loc.remote, "backup");
        assert!(loc.path.is_empty());

        let loc = parse_rclone_url("rclone://backup").unwrap();
        assert_eq!(loc.remote, "backup");
        assert!(loc.path.is_empty());
    }

    /// Regression: rclone://gdrive:bucket/path parses (WHATWG-invalid port).
    #[test]
    fn rclone_gdrive_colon_path_parses() {
        assert!(
            url::Url::parse("rclone://gdrive:bucket/path").is_err(),
            "Url::parse must not be used for rclone://remote:path"
        );
        let loc = parse_rclone_url("rclone://gdrive:bucket/path").unwrap();
        assert_eq!(loc.remote, "gdrive");
        assert_eq!(loc.path, "bucket/path");
        // Numeric path must not be stolen as a TCP port.
        let loc = parse_rclone_url("rclone://gdrive:123/path").unwrap();
        assert_eq!(loc.remote, "gdrive");
        assert_eq!(loc.path, "123/path");
    }

    #[test]
    fn parse_rejects_other_scheme_and_empty_remote() {
        let err = parse_rclone_url("http://gdrive:bucket/path").unwrap_err();
        assert!(matches!(err, RemoteError::UnsupportedScheme(_)));
        let err = parse_rclone_url("rclone://").unwrap_err();
        assert!(err.to_string().contains("remote"));
        let err = parse_rclone_url("rclone://:path").unwrap_err();
        assert!(err.to_string().contains("remote"));
    }

    #[test]
    fn cat_args_are_separate_tokens() {
        let loc = parse_rclone_url("rclone://gdrive:bucket/file.bin").unwrap();
        let args = rclone_cat_args(&loc, 10, 20);
        assert_eq!(
            args,
            vec![
                "cat",
                "--offset",
                "10",
                "--count",
                "20",
                "gdrive:bucket/file.bin",
            ]
        );
        assert!(!args.iter().any(|a| a.contains(' ')));
        let ls = rclone_lsjson_args(&loc);
        assert_eq!(ls, vec!["lsjson", "gdrive:bucket/file.bin"]);
        let st = rclone_lsjson_stat_args(&loc);
        assert_eq!(st, vec!["lsjson", "--stat", "gdrive:bucket/file.bin"]);
    }

    /// Regression: missing rclone is a clear error, not panic.
    #[test]
    fn missing_rclone_is_a_clear_error() {
        let _lock = RCLONE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = set_env(RCLONE_BIN_ENV, "/no/such/ratarmount-rclone-binary");
        let err = open_rclone("rclone://gdrive:bucket/file.bin").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("rclone not found on PATH") && msg.contains("native scheme"),
            "unexpected message: {msg}"
        );
        let err = match open_rclone_folder("rclone://gdrive:bucket/") {
            Err(e) => e,
            Ok(_) => panic!("expected missing rclone error for folder open"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("rclone not found on PATH"),
            "unexpected folder message: {msg}"
        );
    }

    #[test]
    fn fake_rclone_on_path_opens_file() {
        let _lock = RCLONE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(fake) = install_fake_rclone(|data| {
            write_file(data, "gdrive/bucket/file.bin", b"hello-rclone-body");
        }) else {
            return;
        };
        // Prove PATH lookup: drop RATARMOUNT_RCLONE and prepend the fake dir.
        let _clear = remove_env(RCLONE_BIN_ENV);
        let old_path = std::env::var_os("PATH");
        let bin_dir = fake.bin.parent().unwrap();
        let mut path = OsString::from(bin_dir);
        path.push(":");
        if let Some(ref old) = old_path {
            path.push(old);
        }
        let _path = {
            let old = std::env::var_os("PATH");
            std::env::set_var("PATH", &path);
            EnvRestore { key: "PATH", old }
        };
        let found = find_rclone().expect("fake rclone on PATH");
        assert_eq!(found, fake.bin);

        let mut h = open_rclone("rclone://gdrive:bucket/file.bin").unwrap();
        assert_eq!(h.len(), 17);
        assert!(!h.uses_ranges());
        let mut buf = Vec::new();
        h.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello-rclone-body");
    }

    #[test]
    fn lsjson_folder_list_dirents() {
        let _lock = RCLONE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(_fake) = install_fake_rclone(|data| {
            write_file(data, "gdrive/bucket/hello.txt", b"hello-rclone");
            write_file(data, "gdrive/bucket/sub/x.bin", b"xx");
        }) else {
            return;
        };
        let ms = open_rclone_folder("rclone://gdrive:bucket/")
            .unwrap()
            .expect("folder");
        let dents = ms.list_dirents("/").expect("dirents");
        let hello = dents
            .iter()
            .find(|d| d.name == "hello.txt")
            .expect("hello.txt");
        assert_eq!(hello.size, 12);
        assert_eq!(hello.mode & S_IFMT, S_IFREG);
        let sub = dents.iter().find(|d| d.name == "sub").expect("sub");
        assert_eq!(sub.mode & S_IFMT, S_IFDIR);
        let fi = ms.lookup("/hello.txt", 0).unwrap();
        assert_eq!(fi.size, 12);
        let mut r = ms.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello-rclone");
    }

    #[test]
    fn open_folder_returns_none_for_file() {
        let _lock = RCLONE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(_fake) = install_fake_rclone(|data| {
            write_file(data, "gdrive/bucket/file.bin", b"abc");
        }) else {
            return;
        };
        assert!(open_rclone_folder("rclone://gdrive:bucket/file.bin")
            .unwrap()
            .is_none());
    }

    /// Regression: rclone argv is not shell-interpolated.
    #[test]
    fn rclone_argv_is_not_shell_interpolated() {
        let _lock = RCLONE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let evil_name = "x; touch pwned";
        let Some(fake) = install_fake_rclone(|data| {
            write_file(data, &format!("gdrive/bucket/{evil_name}"), b"safe-body");
        }) else {
            return;
        };
        let pwned = fake.data.join("pwned");
        let url = format!("rclone://gdrive:bucket/{evil_name}");
        let mut h = open_rclone(&url).expect("open with metacharacters in path");
        let mut buf = Vec::new();
        h.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"safe-body");
        assert!(
            !pwned.exists(),
            "shell interpolation would have created {}",
            pwned.display()
        );
        let argv = fake.argv_log();
        assert!(
            argv.lines().any(|l| l == "gdrive:bucket/x; touch pwned"),
            "spec must be one argv token; log:\n{argv}"
        );
        assert!(
            !argv.lines().any(|l| l == "touch" || l == "pwned"),
            "path was split as extra argv; log:\n{argv}"
        );
        let args = rclone_cat_args(&parse_rclone_url(&url).unwrap(), 0, 9);
        assert_eq!(args.last().unwrap(), "gdrive:bucket/x; touch pwned");
        assert!(!args.iter().any(|a| a.contains("sh") && a.contains("-c")));
    }

    #[test]
    fn one_cat_process_per_open_not_per_read() {
        let _lock = RCLONE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let body = b"0123456789abcdef";
        let Some(fake) = install_fake_rclone(|data| {
            write_file(data, "gdrive/bucket/file.bin", body);
        }) else {
            return;
        };
        let mut h = open_rclone("rclone://gdrive:bucket/file.bin").unwrap();
        let mut a = [0u8; 4];
        h.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"0123");
        h.seek(SeekFrom::Start(0)).unwrap();
        h.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"0123");
        h.seek(SeekFrom::End(-4)).unwrap();
        h.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"cdef");
        assert_eq!(
            fake.cat_execs(),
            1,
            "cat must run once at open, not per read; log cmds:\n{}",
            std::fs::read_to_string(&fake.count).unwrap_or_default()
        );
        assert!(
            fake.cmd_execs("lsjson") >= 1,
            "size probe should use lsjson"
        );
    }
}
