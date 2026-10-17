//! Local deduplicated snapshots, written by the external restic CLI.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Args, Parser, Subcommand};
use ratarmount_core::{ListResult, MountSource, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use ratarmount_formats_git::GitMountSource;
use serde::Deserialize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount snapshot",
    about = "Create and list local restic snapshots"
)]
pub(super) struct SnapshotArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    Add(AddArgs),
    List(RepoArgs),
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
                fs::create_dir(&target)?;
                materialize_tree(source, &format!("{path}/{name}"), &target)?;
            }
            S_IFLNK => std::os::unix::fs::symlink(&info.linkname, target)?,
            S_IFREG => {
                let mut file = fs::File::create(&target)?;
                io::copy(&mut source.open(&info, 0)?, &mut file)?;
                fs::set_permissions(target, fs::Permissions::from_mode(info.mode & 0o777))?;
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

pub(super) fn run(args: &SnapshotArgs, output: &mut impl Write) -> Result<i32> {
    match &args.action {
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
                temporary = tempfile::tempdir()?;
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

    fn parse(extra: &[&str]) -> SnapshotArgs {
        SnapshotArgs::try_parse_from(
            std::iter::once("ratarmount snapshot").chain(extra.iter().copied()),
        )
        .unwrap()
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
