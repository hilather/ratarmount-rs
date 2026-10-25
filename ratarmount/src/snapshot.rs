//! Local restic snapshots and deterministic, seekable Git tree archives.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Args, Parser, Subcommand};
use ratarmount_core::{FileInfo, ListResult, MountSource, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use ratarmount_formats_git::GitMountSource;
use serde::Deserialize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount snapshot",
    about = "Export GIT_BASE OUT.tar.zst [--with-index] [--json], or add/list restic snapshots",
    long_about = "Export a committed Git tree as a deterministic seekable tar.zst, or use add/list to store and inspect local restic snapshots.",
    after_help = "Examples:\n  ratarmount snapshot repo@HEAD base.tar.zst --with-index\n  ratarmount snapshot add tree --repo backups --init\n  ratarmount snapshot list --repo backups\n\nExit status:\n  0  Success.\n  1  Operational error.\n  2  Invalid arguments.\n  Restic add/list forward nonzero restic status (including 3 for partial backup);\n  termination by a signal returns 128 + signal."
)]
pub(super) struct SnapshotArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Back up a directory or committed Git tree into a local restic repository.
    ///
    /// Materialize Git inputs without history, optionally initialize a missing repository, and print the resulting snapshot summary.
    #[command(
        after_help = "Example: ratarmount snapshot add tree --repo backups --init\n\nExit status:\n  0  Backup completed.\n  1  Operational error.\n  2  Invalid arguments.\n  Nonzero restic init/backup status is forwarded (including 3 for partial backup);\n  termination by a signal returns 128 + signal."
    )]
    Add(AddArgs),
    /// List snapshots in a local restic repository.
    ///
    /// Query restic for snapshot metadata and print the available snapshots without modifying the repository.
    #[command(
        after_help = "Example: ratarmount snapshot list --repo backups\n\nExit status:\n  0  Snapshots listed.\n  1  Operational error.\n  2  Invalid arguments.\n  Nonzero restic snapshots status is forwarded; termination by a signal returns\n  128 + signal."
    )]
    List(RepoArgs),
    #[command(skip)]
    Export(GitSnapshotArgs),
}

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount snapshot",
    about = "Export a committed Git tree as a deterministic seekable tar.zst",
    long_about = "Export the selected local Git tree without history as a deterministic seekable tar.zst. Optionally build a companion index and print a JSON summary; existing output files are refused.",
    after_help = "Example: ratarmount snapshot repo@HEAD base.tar.zst --with-index\n\nExit status:\n  0  Snapshot exported.\n  1  Operational error.\n  2  Invalid arguments."
)]
struct GitSnapshotArgs {
    git_base: String,
    output: PathBuf,
    #[arg(long)]
    with_index: bool,
    #[arg(long, default_value = "1M", value_parser = parse_frame_size)]
    frame_size: u64,
    #[arg(long)]
    json: bool,
}

fn parse_frame_size(value: &str) -> std::result::Result<u64, String> {
    let size = ratarmount_fuse::parse_byte_size(value)?;
    if size == 0 || size > u64::from(u32::MAX) {
        return Err("frame size must be positive and fit u32".into());
    }
    Ok(size)
}

impl SnapshotArgs {
    // Keep the restic parser intact; a positional source selects the Git exporter.
    pub(super) fn try_parse_from<I, T>(iter: I) -> std::result::Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let raw: Vec<OsString> = iter.into_iter().map(Into::into).collect();
        if raw.get(1).is_none_or(|arg| {
            ["add", "list", "help", "-h", "--help"]
                .iter()
                .any(|verb| arg == verb)
        }) {
            <Self as Parser>::try_parse_from(raw)
        } else {
            GitSnapshotArgs::try_parse_from(raw).map(|args| Self {
                action: Action::Export(args),
            })
        }
    }
}

fn open_git_base(spec: &str) -> Result<GitMountSource> {
    if let Some((path, reference)) = ratarmount_formats_git::parse_git_url(spec)? {
        return Ok(GitMountSource::open(
            &path,
            Some(reference.as_deref().unwrap_or("HEAD")),
        )?);
    }
    let path = Path::new(spec);
    let inline = ratarmount_formats_git::split_inline_reference(path);
    let (path, reference) = inline
        .as_ref()
        .map_or((path, None), |(p, r)| (p.as_path(), Some(r.as_str())));
    Ok(GitMountSource::open(path, reference)?)
}

fn collect_git_entries(
    source: &GitMountSource,
    path: &str,
    entries: &mut BTreeMap<String, FileInfo>,
) -> Result<()> {
    let Some(ListResult::Infos(children)) = source.list(path) else {
        return Err(format!("cannot list Git tree {path}").into());
    };
    for (name, info) in children {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err("invalid Git tree entry name".into());
        }
        if name == ".git" {
            continue;
        }
        let child = if path.is_empty() {
            name
        } else {
            format!("{path}/{name}")
        };
        if info.mode & S_IFMT == S_IFDIR {
            collect_git_entries(source, &child, entries)?;
        }
        entries.insert(child, info);
    }
    Ok(())
}

// The shared ustar writer takes unsigned mtimes. A global PAX override preserves
// signed Git commit times, including before 1970, without changing that API.
fn write_negative_mtime(output: &mut impl Write, mtime: i64) -> Result<()> {
    use ratarmount_formats_tar::{write_ustar_members, UstarMember, UstarPayload};
    let record = format!(" mtime={mtime}\n");
    let mut len = record.len() + 1;
    loop {
        let next = record.len() + len.to_string().len();
        if next == len {
            break;
        }
        len = next;
    }
    let body = format!("{len}{record}");
    let mut bytes = Vec::new();
    write_ustar_members(
        &mut bytes,
        &[UstarMember {
            path: "GlobalHead.0/mtime",
            payload: UstarPayload::File {
                bytes: body.as_bytes(),
            },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        }],
    )?;
    bytes[156] = b'g';
    bytes[148..156].fill(b' ');
    let checksum: u32 = bytes[..512].iter().map(|b| u32::from(*b)).sum();
    bytes[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    output.write_all(&bytes)?;
    Ok(())
}

fn export_git(args: &GitSnapshotArgs, output: &mut impl Write) -> Result<i32> {
    use ratarmount_compress::ZstdFrameWriter;
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};

    if !args.output.to_string_lossy().ends_with(".tar.zst") {
        return Err("Git snapshot output must end in .tar.zst".into());
    }
    let archive = absolute(&args.output)?;
    let index = PathBuf::from(format!("{}.index.sqlite", archive.display()));
    if archive.try_exists()? || (args.with_index && index.try_exists()?) {
        return Err("snapshot output already exists".into());
    }
    let source = open_git_base(&args.git_base)?;
    let mut entries = BTreeMap::new();
    collect_git_entries(&source, "", &mut entries)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0098-M01","item":"ratarmount::snapshot::export_git","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut tar = tempfile::tempfile()?;
    {
        let mut writer = BufWriter::new(&mut tar);
        if let Some(info) = entries.values().next().filter(|info| info.mtime < 0.0) {
            write_negative_mtime(&mut writer, info.mtime as i64)?;
        }
        for (path, info) in entries {
            let mut bytes = Vec::new();
            let payload = match info.mode & S_IFMT {
                S_IFDIR => UstarPayload::Directory,
                S_IFLNK => UstarPayload::Symlink {
                    target: &info.linkname,
                },
                S_IFREG => {
                    source.open(&info, 0)?.read_to_end(&mut bytes)?;
                    UstarPayload::File { bytes: &bytes }
                }
                _ => return Err(format!("unsupported Git tree entry {path}").into()),
            };
            write_ustar_members(
                &mut writer,
                &[UstarMember {
                    path: &path,
                    payload,
                    mode: info.mode & 0o777,
                    uid: 0,
                    gid: 0,
                    mtime: info.mtime.max(0.0) as u64,
                    xattrs: &[],
                }],
            )?;
        }
        write_tar_eof(&mut writer)?;
        writer.flush()?;
    }
    let len = tar.metadata()?.len();
    tar.seek(SeekFrom::Start(0))?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0099-M01","item":"ratarmount::snapshot::export_git","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut encoded =
        tempfile::NamedTempFile::new_in(archive.parent().ok_or("missing output parent")?)?;
    {
        let mut writer = ZstdFrameWriter::new(BufWriter::new(encoded.as_file_mut()), 3);
        let mut remaining = len;
        while remaining > 0 {
            let size = remaining.min(args.frame_size);
            writer.write_frame((&mut tar).take(size))?;
            remaining -= size;
        }
        writer.finish()?;
    }
    encoded.flush()?;
    encoded.persist_noclobber(&archive)?;
    if args.with_index {
        ratarmount_session::IndexJob::run(
            crate::shard::index_request(&archive, &index),
            Default::default(),
        )?;
    }
    let archive_digest = format!("sha256:{}", crate::shard::sha256(&archive)?);
    let base_digest = format!("git-tree:{}", source.tree_id());
    if args.json {
        serde_json::to_writer(
            &mut *output,
            &serde_json::json!({
                "archive_digest": archive_digest,
                "base_digest": base_digest,
            }),
        )?;
        writeln!(output)?;
    } else {
        writeln!(output, "{archive_digest}\n{base_digest}")?;
    }
    Ok(0)
}

#[derive(Debug, Args)]
struct RepoArgs {
    /// Local restic repository directory.
    #[arg(long)]
    repo: PathBuf,
    /// Password file; overrides inherited RESTIC_PASSWORD and RESTIC_PASSWORD_FILE.
    #[arg(long)]
    password_file: Option<PathBuf>,
    #[arg(long, default_value = "restic")]
    restic_bin: PathBuf,
}

#[derive(Debug, Args)]
struct AddArgs {
    #[command(flatten)]
    repository: RepoArgs,
    #[arg(required_unless_present = "git", conflicts_with = "git")]
    dir: Option<PathBuf>,
    /// Materialize a local Git tree, with no history: REPO@COMMIT.
    #[arg(long)]
    git: Option<String>,
    /// Initialize a missing repository. Existing repositories are never reinitialized.
    #[arg(long)]
    init: bool,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long)]
    host: Option<String>,
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}

fn password_file_path(
    explicit: Option<&Path>,
    inherited: Option<&OsStr>,
) -> io::Result<Option<PathBuf>> {
    explicit
        .or_else(|| inherited.filter(|file| !file.is_empty()).map(Path::new))
        .map(absolute)
        .transpose()
}

impl RepoArgs {
    fn command(&self, verb: &str) -> Result<Command> {
        let binary = if self.restic_bin.components().count() > 1 {
            absolute(&self.restic_bin)?
        } else {
            self.restic_bin.clone()
        };
        let mut command = Command::new(binary);
        command.arg("--repo").arg(absolute(&self.repo)?).arg(verb);
        command.stderr(Stdio::inherit());
        // Inherit passwords without ever copying their contents into argv or logs.
        if self.password_file.is_some() {
            command.env_remove("RESTIC_PASSWORD");
            command.env_remove("RESTIC_PASSWORD_COMMAND");
        }
        let inherited = std::env::var_os("RESTIC_PASSWORD_FILE");
        if let Some(file) = password_file_path(self.password_file.as_deref(), inherited.as_deref())?
        {
            command.env("RESTIC_PASSWORD_FILE", file);
        }
        Ok(command)
    }
}

fn backup_command(args: &AddArgs, dir: &Path, tags: &[String]) -> Result<Command> {
    let mut command = args.repository.command("backup")?;
    // A stable relative input gives each snapshot a root containing just the tree,
    // rather than a random temporary-directory hierarchy for Git snapshots.
    command.current_dir(dir).args(["--json", "."]);
    for tag in tags {
        command.arg("--tag").arg(tag);
    }
    if let Some(host) = &args.host {
        command.arg("--host").arg(host);
    }
    Ok(command)
}

#[derive(Debug, Deserialize)]
struct Summary {
    snapshot_id: String,
    data_added: u64,
    #[serde(default)]
    files_new: u64,
    #[serde(default)]
    files_changed: u64,
    #[serde(default)]
    files_unmodified: u64,
    #[serde(default)]
    total_bytes_processed: u64,
}

fn parse_summary(bytes: &[u8]) -> Result<Summary> {
    let mut summary = None;
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let value: serde_json::Value = serde_json::from_slice(line)?;
        if value["message_type"] == "summary" {
            let parsed: Summary = serde_json::from_value(value)?;
            if parsed.snapshot_id.len() < 8
                || parsed.snapshot_id.len() > 64
                || !parsed.snapshot_id.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err("restic returned an invalid snapshot id".into());
            }
            summary = Some(parsed);
        }
    }
    summary.ok_or_else(|| "restic backup did not return a JSON summary with a snapshot id".into())
}

#[derive(Debug, Deserialize)]
struct Snapshot {
    id: String,
    time: String,
    #[serde(default)]
    tags: Vec<String>,
    paths: Vec<String>,
}

fn print_snapshots(bytes: &[u8], output: &mut impl Write) -> Result<()> {
    // restic reports null for an empty repository in some versions.
    let snapshots: Option<Vec<Snapshot>> = serde_json::from_slice(bytes)?;
    writeln!(output, "ID\tTIME\tTAGS\tPATHS")?;
    for snapshot in snapshots.unwrap_or_default() {
        writeln!(
            output,
            "{}\t{}\t{}\t{}",
            snapshot.id,
            snapshot.time,
            serde_json::to_string(&snapshot.tags)?,
            serde_json::to_string(&snapshot.paths)?
        )?;
    }
    Ok(())
}

fn materialize_tree(source: &GitMountSource, path: &str, destination: &Path) -> Result<()> {
    let Some(ListResult::Infos(entries)) = source.list(path) else {
        return Err(format!("cannot list Git tree {path}").into());
    };
    for (name, info) in entries {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err("invalid Git tree entry name".into());
        }
        let target = destination.join(&name);
        match info.mode & S_IFMT {
            S_IFDIR => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0142-M01","item":"ratarmount::snapshot::materialize_tree","disposition":"output-owner","category":"snapshot-output-directory","reason":"Materialize a Git snapshot directory entry in the caller-owned output tree.","creation":{"policy":"exclusive-directory","basis":"create_dir refuses collisions; recursive materialization owns the output and retains existing directory permissions."}}"###
                )]
                fs::create_dir(&target)?;
                materialize_tree(source, &format!("{path}/{name}"), &target)?;
            }
            S_IFLNK => std::os::unix::fs::symlink(&info.linkname, target)?,
            S_IFREG => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0100-M01","item":"ratarmount::snapshot::materialize_tree","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                )]
                let mut file = fs::File::create(&target)?;
                io::copy(&mut source.open(&info, 0)?, &mut file)?;
                // Preserve the restic convenience export's existing read-only modes.
                fs::set_permissions(target, fs::Permissions::from_mode(info.mode & 0o555))?;
            }
            _ => return Err(format!("unsupported Git tree entry {path}/{name}").into()),
        }
    }
    Ok(())
}

fn git_tree(spec: &str, destination: &Path) -> Result<Vec<String>> {
    let (repo, reference) = spec
        .rsplit_once('@')
        .filter(|(repo, reference)| !repo.is_empty() && !reference.is_empty())
        .ok_or("--git requires REPO@COMMIT")?;
    let repo = fs::canonicalize(repo)?;
    let source = GitMountSource::open(&repo, Some(reference))?;
    materialize_tree(&source, "", destination)?;
    Ok(vec![
        format!("repo={}", repo.display()),
        format!("commit={}", source.resolved_commit()),
    ])
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

pub(super) fn run_cli(args: &SnapshotArgs) -> Result<i32> {
    if matches!(args.action, Action::Export(_)) {
        // Factory progress banners use stdout; keep digest output on the saved
        // descriptor and route those banners to stderr, as shard/export-index do.
        run(args, &mut crate::export_index::cli_stdout()?)
    } else {
        run(args, &mut io::stdout().lock())
    }
}

pub(super) fn run(args: &SnapshotArgs, output: &mut impl Write) -> Result<i32> {
    match &args.action {
        Action::Export(args) => export_git(args, output),
        Action::List(repo) => {
            let result = repo.command("snapshots")?.arg("--json").output()?;
            let code = exit_code(result.status);
            if code == 0 {
                print_snapshots(&result.stdout, output)?;
            }
            Ok(code)
        }
        Action::Add(args) => {
            // Validate/materialize input before initializing a repository.
            let temporary;
            let mut tags = args.tags.clone();
            let dir = if let Some(spec) = &args.git {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0101-M01","item":"ratarmount::snapshot::run","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                )]
                let __inventory_assigned = tempfile::tempdir()?;
                temporary = __inventory_assigned;
                tags.extend(git_tree(spec, temporary.path())?);
                temporary.path().to_owned()
            } else {
                fs::canonicalize(args.dir.as_ref().expect("clap requires dir or --git"))?
            };
            if !dir.is_dir() {
                return Err("snapshot input must be a directory".into());
            }
            let repo = &args.repository;
            if !repo.repo.join("config").try_exists()? {
                if !args.init {
                    return Err("restic repository is missing; use --init to create it".into());
                }
                let status = repo.command("init")?.stdout(Stdio::null()).status()?;
                if !status.success() {
                    return Ok(exit_code(status));
                }
            }
            let result = backup_command(args, &dir, &tags)?.output()?;
            let code = exit_code(result.status);
            // Even partial backups must preserve restic's exit code (e.g. unreadable files = 3).
            if code != 0 {
                return Ok(code);
            }
            let summary = parse_summary(&result.stdout)?;
            writeln!(output, "snapshot_id={}", summary.snapshot_id)?;
            writeln!(output, "data_added={} files_new={} files_changed={} files_unmodified={} total_bytes_processed={}",
                summary.data_added, summary.files_new, summary.files_changed,
                summary.files_unmodified, summary.total_bytes_processed)?;
            writeln!(
                output,
                "mount_source=restic:{}",
                fs::canonicalize(&repo.repo)?.display()
            )?;
            writeln!(output, "snapshot_path=/snapshots/{}", summary.snapshot_id)?;
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    /// Regression: leaf command help omitted the exit status documented for harnesses.
    #[test]
    fn regression_help_states_exit_status() {
        use clap::CommandFactory;

        fn check(mut command: clap::Command) {
            let name = command.get_name().to_owned();
            let help = command.render_long_help().to_string();
            assert!(help.contains("Exit status:"), "{name}: {help}");
            assert!(help.contains("Example"), "{name}: missing example");
        }

        check(crate::diff::DiffArgs::command());
        let overlay = crate::overlay_cmd::OverlayArgs::command();
        for name in [
            "info",
            "seal",
            "unseal",
            "verify",
            "fsck",
            "import",
            "import-upperdir",
            "pack",
            "unpack",
        ] {
            check(overlay.find_subcommand(name).unwrap().clone());
        }
        let journal = crate::journal_cmd::JournalArgs::command();
        for name in ["summarize", "mark"] {
            check(journal.find_subcommand(name).unwrap().clone());
        }
        check(
            crate::sandbox::SandboxArgs::command()
                .find_subcommand("run")
                .unwrap()
                .clone(),
        );
        let snapshot = SnapshotArgs::command();
        for name in ["add", "list"] {
            check(snapshot.find_subcommand(name).unwrap().clone());
        }
        check(snapshot);
        check(GitSnapshotArgs::command());
    }

    fn parse(extra: &[&str]) -> SnapshotArgs {
        SnapshotArgs::try_parse_from(
            std::iter::once("ratarmount snapshot").chain(extra.iter().copied()),
        )
        .unwrap()
    }

    fn export_fixture(mtime: i64) -> (tempfile::TempDir, String, String) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("repo @one");
        let repo = git2::Repository::init(&path).unwrap();
        let mut sub = repo.treebuilder(None).unwrap();
        sub.insert(
            "run",
            repo.blob(b"#!/bin/sh\necho hello\n").unwrap(),
            0o100755,
        )
        .unwrap();
        sub.insert("binary", repo.blob(&[0, 255, 1, 0, 254]).unwrap(), 0o100644)
            .unwrap();
        let mut root = repo.treebuilder(None).unwrap();
        root.insert("sub", sub.write().unwrap(), 0o040000).unwrap();
        root.insert(
            "empty",
            repo.treebuilder(None).unwrap().write().unwrap(),
            0o040000,
        )
        .unwrap();
        root.insert("plain", repo.blob(&vec![42; 32768]).unwrap(), 0o100644)
            .unwrap();
        root.insert("link", repo.blob(b"sub/run").unwrap(), 0o120000)
            .unwrap();
        let long = "long".repeat(40);
        root.insert(&long, repo.blob(b"long path").unwrap(), 0o100644)
            .unwrap();
        root.insert("long-link", repo.blob(long.as_bytes()).unwrap(), 0o120000)
            .unwrap();
        root.insert(
            "module",
            git2::Oid::from_str("1234567890123456789012345678901234567890").unwrap(),
            0o160000,
        )
        .unwrap();
        let tree = repo.find_tree(root.write().unwrap()).unwrap();
        let signature =
            git2::Signature::new("Test", "test@example.com", &git2::Time::new(mtime, 0)).unwrap();
        let first = if mtime < 0 {
            // libgit2's signature writer casts time to unsigned; write a signed
            // commit through its ODB so the fixture really predates the epoch.
            let text = format!("tree {}\nauthor Test <test@example.com> {mtime} +0000\ncommitter Test <test@example.com> {mtime} +0000\n\nsnapshot\n", tree.id());
            let id = repo
                .odb()
                .unwrap()
                .write(git2::ObjectType::Commit, text.as_bytes())
                .unwrap();
            repo.reference("refs/heads/master", id, true, "fixture")
                .unwrap();
            repo.set_head("refs/heads/master").unwrap();
            id
        } else {
            repo.commit(Some("HEAD"), &signature, &signature, "snapshot", &tree, &[])
                .unwrap()
        };
        let tree_id = tree.id().to_string();
        // Neither subsequent commits nor uncommitted files belong in the snapshot.
        root.insert("future", repo.blob(b"future").unwrap(), 0o100644)
            .unwrap();
        let tree = repo.find_tree(root.write().unwrap()).unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "future",
            &tree,
            &[&repo.find_commit(first).unwrap()],
        )
        .unwrap();
        fs::write(path.join("uncommitted"), b"working tree").unwrap();
        let spec = format!(
            "git://{}#{first}",
            path.display()
                .to_string()
                .replace(' ', "%20")
                .replace('@', "%40")
        );
        (temp, spec, tree_id)
    }

    type TreeManifest = BTreeMap<String, (u32, String, Vec<u8>)>;

    fn walk(source: &dyn MountSource, path: &str, manifest: &mut TreeManifest) {
        let Some(ListResult::Infos(entries)) = source.list(path) else {
            panic!("cannot list {path}")
        };
        for (name, info) in entries {
            let child = format!("{path}/{name}");
            let mut bytes = Vec::new();
            if info.mode & S_IFMT == S_IFREG {
                source
                    .open(&info, 0)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
            }
            manifest.insert(child.clone(), (info.mode, info.linkname.clone(), bytes));
            if info.mode & S_IFMT == S_IFDIR {
                walk(source, &child, manifest);
            }
        }
    }

    /// Regression: Git snapshot positionals must select export without changing restic parsing.
    #[test]
    fn regression_snapshot_git_export_positionals() {
        let parsed = crate::parse_args_from([
            "ratarmount",
            "snapshot",
            "git:///repo#HEAD",
            "out.tar.zst",
            "--with-index",
            "--frame-size",
            "4K",
            "--json",
        ])
        .unwrap();
        let Action::Export(export) = parsed.snapshot.unwrap().action else {
            panic!("expected Git mode")
        };
        assert_eq!(export.frame_size, 4096);
        assert!(export.with_index && export.json);
        assert!(parsed.paths.is_empty());
        for args in [
            vec!["snapshot", "git:///repo#HEAD"],
            vec!["snapshot", "repo@HEAD", "out.tar.zst", "--frame-size", "0"],
            vec!["snapshot", "repo@HEAD", "out.tar.zst", "--frame-size", "4G"],
            vec!["snapshot", "add", "input", "--repo", "repo", "--with-index"],
        ] {
            assert!(crate::parse_args_from(std::iter::once("ratarmount").chain(args)).is_err());
        }
    }

    /// Regression: indexed snapshots must equal the pinned Git view, preserve modes, and open warm.
    #[test]
    fn regression_snapshot_git_equivalent_composed_view_and_warm_index() {
        use ratarmount_core::{IndexBuildHooks, OpenOptions};
        use ratarmount_session::factory;
        use std::os::unix::fs::MetadataExt;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let (temp, spec, tree_id) = export_fixture(1234567890);
        let archive = temp.path().join("snapshot.tar.zst");
        let args = parse(&[
            &spec,
            archive.to_str().unwrap(),
            "--with-index",
            "--frame-size",
            "1K",
            "--json",
        ]);
        let mut output = Vec::new();
        assert_eq!(run(&args, &mut output).unwrap(), 0);
        let output: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(output["base_digest"], format!("git-tree:{tree_id}"));
        assert_eq!(
            output["archive_digest"],
            format!("sha256:{}", crate::shard::sha256(&archive).unwrap())
        );
        let map = ratarmount_compress::scan_zstd_frames_path(&archive).unwrap();
        assert!(map.seek_table.is_some());
        assert!(map.frames.len() > 1);
        assert!(map.frames.iter().all(|f| f.uncompressed_size <= 1024));
        let index = temp.path().join("snapshot.tar.zst.index.sqlite");
        let before = fs::metadata(&index).unwrap();
        let builds = Arc::new(AtomicUsize::new(0));
        let counted = builds.clone();
        let options = OpenOptions {
            write_index: false,
            read_only_index: true,
            index_build: IndexBuildHooks {
                on_progress: Some(Arc::new(move |_| {
                    counted.fetch_add(1, Ordering::Relaxed);
                })),
                ..Default::default()
            },
            ..Default::default()
        };
        let snapshot = factory::open_path(&archive, &options, false).unwrap();
        let git = factory::open_path(Path::new(&spec), &OpenOptions::default(), false).unwrap();
        let mut git_manifest = BTreeMap::new();
        let mut snapshot_manifest = BTreeMap::new();
        walk(git.as_ref(), "", &mut git_manifest);
        walk(snapshot.as_ref(), "", &mut snapshot_manifest);
        assert_eq!(snapshot_manifest, git_manifest);
        assert!(!git_manifest.contains_key("/.git"));
        assert!(!git_manifest.contains_key("/module"));
        assert!(!git_manifest.contains_key("/future"));
        let mut entries = BTreeMap::new();
        collect_git_entries(&open_git_base(&spec).unwrap(), "", &mut entries).unwrap();
        for path in entries.keys() {
            let info = snapshot.lookup(path, 0).unwrap();
            assert_eq!((info.uid, info.gid, info.mtime), (0, 0, 1234567890.0));
        }
        assert_eq!(
            builds.load(Ordering::Relaxed),
            0,
            "warm open must not rebuild the index"
        );
        let after = fs::metadata(&index).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        let git_overlay =
            crate::base_identity::fixtures::new_overlay(git, temp.path().join("git-overlay"))
                .unwrap();
        let tar_overlay =
            crate::base_identity::fixtures::new_overlay(snapshot, temp.path().join("tar-overlay"))
                .unwrap();
        for overlay in [&git_overlay, &tar_overlay] {
            overlay.unlink("/plain").unwrap();
            overlay.mkdir("/added", 0o755).unwrap();
            overlay.create_symlink("/added/link", "../sub/run").unwrap();
        }
        git_manifest.clear();
        snapshot_manifest.clear();
        walk(&git_overlay, "", &mut git_manifest);
        walk(&tar_overlay, "", &mut snapshot_manifest);
        assert_eq!(snapshot_manifest, git_manifest);
        let second = temp.path().join("again.tar.zst");
        let (repo, reference) = ratarmount_formats_git::parse_git_url(&spec)
            .unwrap()
            .unwrap();
        let inline = format!("{}@{}", repo.display(), reference.unwrap());
        let restic_tree = temp.path().join("restic-tree");
        fs::create_dir(&restic_tree).unwrap();
        git_tree(&inline, &restic_tree).unwrap();
        assert_eq!(
            fs::metadata(restic_tree.join("plain"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        assert_eq!(
            fs::metadata(restic_tree.join("sub/run"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        let mut text = Vec::new();
        assert_eq!(
            run(
                &parse(&[&inline, second.to_str().unwrap(), "--frame-size", "1K"]),
                &mut text
            )
            .unwrap(),
            0
        );
        assert_eq!(fs::read(&archive).unwrap(), fs::read(&second).unwrap());
        assert_eq!(
            String::from_utf8(text).unwrap(),
            format!(
                "{}\ngit-tree:{tree_id}\n",
                output["archive_digest"].as_str().unwrap()
            )
        );
        assert!(!temp.path().join("again.tar.zst.index.sqlite").exists());
        assert!(
            run(&args, &mut Vec::new()).is_err(),
            "existing outputs must be preserved"
        );
        let occupied = temp.path().join("occupied.tar.zst");
        let occupied_index = temp.path().join("occupied.tar.zst.index.sqlite");
        fs::write(&occupied_index, b"unrelated index").unwrap();
        assert!(run(
            &parse(&[&spec, occupied.to_str().unwrap(), "--with-index"]),
            &mut Vec::new()
        )
        .is_err());
        assert!(!occupied.exists());
        assert_eq!(fs::read(occupied_index).unwrap(), b"unrelated index");
    }

    /// Regression: --with-index progress banners must not corrupt snapshot JSON stdout.
    #[test]
    fn regression_snapshot_git_stdout_has_no_index_banners() {
        if let Ok(spec) = std::env::var("RATARMOUNT_SNAPSHOT_STDOUT_FIXTURE") {
            let archive = std::env::var("RATARMOUNT_SNAPSHOT_STDOUT_ARCHIVE").unwrap();
            assert_eq!(
                run_cli(&parse(&[&spec, &archive, "--with-index", "--json"])).unwrap(),
                0
            );
            eprintln!("snapshot regression: warm open");
            let source = ratarmount_session::factory::open_path(
                Path::new(&archive),
                &ratarmount_core::OpenOptions {
                    read_only_index: true,
                    write_index: false,
                    ..Default::default()
                },
                false,
            )
            .unwrap();
            assert!(source.lookup("/plain", 0).is_some());
            return;
        }
        let (temp, spec, tree_id) = export_fixture(1234567890);
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "snapshot::tests::regression_snapshot_git_stdout_has_no_index_banners",
                "--exact",
                "--nocapture",
            ])
            .env("RATARMOUNT_SNAPSHOT_STDOUT_FIXTURE", spec)
            .env(
                "RATARMOUNT_SNAPSHOT_STDOUT_ARCHIVE",
                temp.path().join("stdout.tar.zst"),
            )
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8(result.stdout).unwrap();
        assert!(!stdout.contains("Creating offset dictionary"), "{stdout}");
        let json: serde_json::Value =
            serde_json::from_str(stdout.lines().find(|line| line.starts_with('{')).unwrap())
                .unwrap();
        assert_eq!(json["base_digest"], format!("git-tree:{tree_id}"));
        assert!(String::from_utf8_lossy(&result.stderr).contains("Creating offset dictionary"));
        let stderr = String::from_utf8_lossy(&result.stderr);
        let warm = stderr
            .split_once("snapshot regression: warm open")
            .unwrap()
            .1;
        assert!(!warm.contains("Creating offset dictionary"), "{warm}");
        assert!(String::from_utf8_lossy(&result.stderr).contains("warning: skipping Git submodule"));
    }

    /// Regression: pre-epoch commit times must survive PAX and long-name metadata together.
    #[test]
    fn regression_snapshot_git_negative_commit_time() {
        let (temp, spec, _) = export_fixture(-123456789);
        assert_eq!(
            open_git_base(&spec)
                .unwrap()
                .lookup("/plain", 0)
                .unwrap()
                .mtime,
            -123456789.0
        );
        let archive = temp.path().join("negative.tar.zst");
        run(&parse(&[&spec, archive.to_str().unwrap()]), &mut Vec::new()).unwrap();
        let source = ratarmount_session::factory::open_path(
            &archive,
            &ratarmount_core::OpenOptions {
                index_in_memory: true,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        for path in [
            "plain".to_owned(),
            "long".repeat(40),
            "sub".into(),
            "long-link".into(),
        ] {
            assert_eq!(source.lookup(&path, 0).unwrap().mtime, -123456789.0);
        }
    }

    /// Regression: snapshot verb must not swallow mount positionals or accept missing inputs.
    #[test]
    fn regression_snapshot_verb_positionals() {
        let parsed = crate::parse_args_from([
            "ratarmount",
            "snapshot",
            "add",
            "input",
            "--repo",
            "repo",
            "--tag",
            "task=1",
        ])
        .unwrap();
        assert!(parsed.snapshot.is_some());
        assert!(parsed.paths.is_empty());
        let parsed = crate::parse_args_from(["ratarmount", "--no-mount", "snapshot"]).unwrap();
        assert!(parsed.snapshot.is_none());
        assert_eq!(parsed.paths, [Path::new("snapshot")]);
        for argv in [
            vec!["snapshot", "add", "--repo", "repo"],
            vec![
                "snapshot",
                "add",
                "input",
                "--repo",
                "repo",
                "--git",
                "repo@HEAD",
            ],
            vec!["snapshot", "list", "--repo", "repo", "mountpoint"],
            vec!["snapshot", "list"],
            vec![
                "snapshot",
                "add",
                "input",
                "--repo",
                "repo",
                "--password",
                "secret",
            ],
        ] {
            assert!(crate::parse_args_from(std::iter::once("ratarmount").chain(argv)).is_err());
        }
    }

    /// Regression: passwords belong in inherited environment/file, never subprocess argv.
    #[test]
    fn regression_snapshot_no_password_on_argv() {
        let args = parse(&[
            "add",
            "input",
            "--repo",
            "repo",
            "--password-file",
            "password",
            "--tag",
            "one",
            "--tag",
            "two",
            "--host",
            "worker",
            "--restic-bin",
            "/custom/restic",
        ]);
        let Action::Add(mut add) = args.action else {
            panic!()
        };
        let command = backup_command(&add, Path::new("/input"), &add.tags).unwrap();
        assert_eq!(command.get_program(), "/custom/restic");
        let argv: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            &argv[2..],
            ["backup", "--json", ".", "--tag", "one", "--tag", "two", "--host", "worker"]
        );
        assert!(!argv
            .iter()
            .any(|a| a == "--password" || a == "--password-file" || a == "password"));
        let env: Vec<_> = command.get_envs().collect();
        assert!(env.contains(&(std::ffi::OsStr::new("RESTIC_PASSWORD"), None)));
        assert!(env.iter().any(|(key, value)| *key == "RESTIC_PASSWORD_FILE"
            && *value == Some(absolute(Path::new("password")).unwrap().as_os_str())));
        // Regression: changing cwd for backup must not break a relative --restic-bin.
        add.repository.restic_bin = PathBuf::from("./tools/restic");
        assert_eq!(
            backup_command(&add, Path::new("/input"), &[])
                .unwrap()
                .get_program(),
            absolute(Path::new("./tools/restic")).unwrap()
        );
        let args = parse(&["list", "--repo", "repo"]);
        let Action::List(repo) = args.action else {
            panic!()
        };
        assert!(!repo
            .command("snapshots")
            .unwrap()
            .get_envs()
            .any(|(key, _)| key == "RESTIC_PASSWORD"));
    }

    /// Regression: a relative RESTIC_PASSWORD_FILE must survive backup's input-directory cwd.
    #[test]
    fn regression_snapshot_relative_password_file() {
        assert_eq!(
            password_file_path(None, Some(OsStr::new("relative/password"))).unwrap(),
            Some(absolute(Path::new("relative/password")).unwrap())
        );
        assert_eq!(
            password_file_path(Some(Path::new("explicit")), Some(OsStr::new("inherited"))).unwrap(),
            Some(absolute(Path::new("explicit")).unwrap())
        );
        assert_eq!(
            password_file_path(None, Some(OsStr::new("/absolute/password"))).unwrap(),
            Some(PathBuf::from("/absolute/password"))
        );
        assert_eq!(
            password_file_path(None, Some(OsStr::new(""))).unwrap(),
            None
        );
        assert_eq!(password_file_path(None, None).unwrap(), None);
    }

    /// Regression: progress records are not the backup summary; missing/malformed ids fail closed.
    #[test]
    fn regression_snapshot_json_summary_and_listing() {
        let summary = parse_summary(b"{\"message_type\":\"status\",\"percent_done\":1}\n{\"message_type\":\"summary\",\"snapshot_id\":\"01234567\",\"data_added\":42,\"files_new\":2}\n").unwrap();
        assert_eq!(summary.snapshot_id, "01234567");
        assert_eq!(summary.data_added, 42);
        assert_eq!(summary.files_new, 2);
        assert_eq!(summary.files_changed, 0);
        for bad in [
            b"{}".as_slice(),
            b"not json",
            b"{\"message_type\":\"summary\",\"data_added\":0}",
            b"{\"message_type\":\"summary\",\"data_added\":0,\"snapshot_id\":\"../../escape\"}",
        ] {
            assert!(parse_summary(bad).is_err());
        }
        let mut output = Vec::new();
        print_snapshots(br#"[{"id":"abc","time":"2026-10-16T00:00:00Z","tags":["task=1"],"paths":["/tree"]},{"id":"def","time":"later","paths":[]}]"#, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("abc\t2026-10-16T00:00:00Z\t[\"task=1\"]\t[\"/tree\"]"));
        assert!(output.contains("def\tlater\t[]\t[]"));
        for empty in [b"null".as_slice(), b"[]"] {
            let mut output = Vec::new();
            print_snapshots(empty, &mut output).unwrap();
            assert_eq!(output, b"ID\tTIME\tTAGS\tPATHS\n");
        }
    }

    /// Regression: init is opt-in, and init/backup/list failures must preserve restic exit codes.
    #[test]
    fn regression_snapshot_exit_codes_and_init_opt_in() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        let fake = temp.path().join("restic");
        fs::write(&fake, "#!/bin/sh\nexit 17\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let base = [
            "add",
            input.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
            "--restic-bin",
            fake.to_str().unwrap(),
        ];
        assert!(run(&parse(&base), &mut Vec::new()).is_err());
        assert!(!repo.exists());
        let mut init = base.to_vec();
        init.push("--init");
        assert_eq!(run(&parse(&init), &mut Vec::new()).unwrap(), 17);
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("config"), b"fake").unwrap();
        assert_eq!(run(&parse(&base), &mut Vec::new()).unwrap(), 17);
        assert_eq!(
            run(
                &parse(&[
                    "list",
                    "--repo",
                    repo.to_str().unwrap(),
                    "--restic-bin",
                    fake.to_str().unwrap()
                ]),
                &mut Vec::new()
            )
            .unwrap(),
            17
        );
    }

    /// Regression: Git convenience must use the requested tree, preserve exec/symlinks, and omit history.
    #[test]
    fn regression_snapshot_git_tree_has_no_history() {
        let temp = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(temp.path().join("git")).unwrap();
        let root = repo.workdir().unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/run"), b"original").unwrap();
        fs::set_permissions(root.join("sub/run"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("sub/run", root.join("link")).unwrap();
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();
        let first = repo
            .commit(Some("HEAD"), &sig, &sig, "first", &tree, &[])
            .unwrap();
        fs::write(root.join("sub/run"), b"new HEAD contents").unwrap();
        index.add_path(Path::new("sub/run")).unwrap();
        let second_tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            "second",
            &second_tree,
            &[&repo.find_commit(first).unwrap()],
        )
        .unwrap();
        fs::write(root.join("sub/run"), b"modified working tree").unwrap();
        let dest = temp.path().join("tree");
        fs::create_dir(&dest).unwrap();
        let tags = git_tree(&format!("{}@{first}", root.display()), &dest).unwrap();
        assert_eq!(fs::read(dest.join("sub/run")).unwrap(), b"original");
        assert_eq!(
            fs::metadata(dest.join("sub/run"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0o111
        );
        assert_eq!(
            fs::read_link(dest.join("link")).unwrap(),
            Path::new("sub/run")
        );
        assert!(!dest.join(".git").exists());
        assert_eq!(tags[1], format!("commit={first}"));
        assert!(tags[0].starts_with("repo=/"));
        assert!(git_tree(&format!("{}@bad-ref", root.display()), &dest).is_err());
        assert!(git_tree("missing-separator", &dest).is_err());
    }

    /// Regression: two near-identical snapshots must deduplicate and round-trip through Session.
    #[test]
    fn regression_snapshot_restic_dedup_roundtrip() {
        if Command::new("restic").arg("version").output().is_err() {
            eprintln!("skip: restic is not on PATH");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        // Keep the live CLI test independent of the user's restic cache permissions.
        let binary = temp.path().join("restic-no-cache");
        fs::write(&binary, "#!/bin/sh\nexec restic --no-cache \"$@\"\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let password = temp.path().join("password");
        fs::write(&password, "snapshot-test-password\n").unwrap();
        let mut seed = 123456789u64;
        let payload: Vec<u8> = (0..4 * 1024 * 1024)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        let mut summaries = Vec::new();
        for (name, changed) in [("one", "before"), ("two", "after")] {
            let dir = temp.path().join(name);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("shared.bin"), &payload).unwrap();
            fs::write(dir.join("changed.txt"), changed).unwrap();
            let args = parse(&[
                "add",
                dir.to_str().unwrap(),
                "--repo",
                repo.to_str().unwrap(),
                "--password-file",
                password.to_str().unwrap(),
                "--init",
                "--tag",
                name,
                "--restic-bin",
                binary.to_str().unwrap(),
            ]);
            let mut output = Vec::new();
            assert_eq!(run(&args, &mut output).unwrap(), 0);
            let output = String::from_utf8(output).unwrap();
            eprintln!("{name}: {output}");
            assert!(output.contains(&format!("mount_source=restic:{}", repo.display())));
            assert!(output.contains("snapshot_path=/snapshots/"));
            let id = output
                .lines()
                .find_map(|l| l.strip_prefix("snapshot_id="))
                .unwrap()
                .to_string();
            let added: u64 = output
                .lines()
                .find_map(|l| l.strip_prefix("data_added="))
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap();
            summaries.push((id, added));
        }
        assert!(summaries[0].1 >= payload.len() as u64);
        assert!(
            summaries[1].1 < 32 * 1024,
            "second data_added={}",
            summaries[1].1
        );
        let mut listing = Vec::new();
        assert_eq!(
            run(
                &parse(&[
                    "list",
                    "--repo",
                    repo.to_str().unwrap(),
                    "--password-file",
                    password.to_str().unwrap(),
                    "--restic-bin",
                    binary.to_str().unwrap(),
                ]),
                &mut listing
            )
            .unwrap(),
            0
        );
        let listing = String::from_utf8(listing).unwrap();
        assert!(listing.contains("[\"one\"]"));
        assert!(listing.contains("[\"two\"]"));
        // Isolate reader credentials in a subprocess instead of mutating the test runner's env.
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "snapshot::tests::snapshot_restic_reader_child",
                "--ignored",
                "--nocapture",
            ])
            .env("AI_SNAP_TEST_REPO", &repo)
            .env(
                "AI_SNAP_TEST_IDS",
                format!("{},{}", summaries[0].0, summaries[1].0),
            )
            .env("AI_SNAP_TEST_SHARED", temp.path().join("one/shared.bin"))
            .env_remove("RESTIC_PASSWORD")
            .env("RESTIC_PASSWORD_FILE", &password)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    #[ignore = "subprocess helper called by regression_snapshot_restic_dedup_roundtrip"]
    fn snapshot_restic_reader_child() {
        use ratarmount_session::{
            IndexPolicy, OpenRequest, ReadRequest, Recreate, Session, SourceSpec,
        };
        let repo = std::env::var_os("AI_SNAP_TEST_REPO").expect("reader subprocess repository");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Url(format!("restic:{}", Path::new(&repo).display())),
            index: IndexPolicy::Memory,
            explicit_index: None,
            extra_dirs: vec![],
            password: None,
            recursive: false,
            recursion_depth: None,
            parallelization: Default::default(),
            recreate: Recreate::IfInvalid,
        })
        .unwrap();
        let ids = std::env::var("AI_SNAP_TEST_IDS").unwrap();
        let shared = fs::read(std::env::var_os("AI_SNAP_TEST_SHARED").unwrap()).unwrap();
        for (id, changed) in ids.split(',').zip(["before", "after"]) {
            for (name, expected) in [
                ("shared.bin", shared.as_slice()),
                ("changed.txt", changed.as_bytes()),
            ] {
                let path = format!("/ids/{id}/{name}");
                let mut bytes = Vec::new();
                session
                    .read_range(ReadRequest {
                        path,
                        offset: 0,
                        max_len: expected.len() as u64 + 1,
                    })
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes, expected);
            }
        }
    }
}
