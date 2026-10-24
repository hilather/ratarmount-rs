//! Fork-N (Option A), PR2a: N writable tops, N mountpoints, one process.
//!
//! `main` dispatches here when `--top` or `--mount` is set. This module owns
//! the CLI checks that clap cannot express, construction, and the handoff
//! into [`crate::fork_n_serve`].

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

use ratarmount_compositing::{ClassifiedBase, CreateOptions, WriteOverlay, HIDDEN_DB};
use ratarmount_core::{MountSource, OpenOptions, ParallelizationSpec};
use ratarmount_session::factory::{CompositingOptions, SourceBindings};

use crate::fork_n_serve::{self, TopHandle};
use crate::mount_guard::{self, Relation};

pub(crate) struct Assignment {
    pub name: String,
    pub top: PathBuf,
    pub mountpoint: PathBuf,
}

pub(crate) fn run(args: &crate::Args) -> ! {
    if let Err(message) = validate_cli(args, args.find) {
        fail(2, &message);
    }
    let assignments = match assignments(args) {
        Ok(rows) => rows,
        Err(message) => fail(2, &message),
    };
    let foreground = args.foreground;
    // Canonicalize ancestors that already exist so a symlink mountpoint matches
    // `admit`'s resolved path. A component that does not exist yet keeps its
    // absolute path; mkdir is still after the factory.
    install_assignments(&assignments);

    let mut open_opts = open_options(args);
    let (source, classified) = match open_source(args, &mut open_opts) {
        Ok(opened) => opened,
        Err(message) => {
            // Storage admission refusals are exit 2. A factory failure that
            // is not a fork-n refusal stays exit 1. Index errors display as
            // `io error: fork-n ...`, so the marker is a substring.
            let code = if message.contains("fork-n") { 2 } else { 1 };
            fail(code, &message);
        }
    };

    if let Err((code, message)) = create_directories(&assignments) {
        fail(code, &message);
    }
    let assignments = canonicalize_assignments(&assignments);
    install_assignments(&assignments);

    if let Err(message) = identity_matrix(&assignments) {
        fail(2, &message);
    }
    if let Err(message) = hardlink_walk(&assignments) {
        fail(2, &message);
    }

    let tops = match open_tops(args, &assignments, &source, &classified) {
        Ok(tops) => tops,
        Err(message) => {
            let code = if message.contains("fork-n") { 2 } else { 1 };
            fail(code, &message);
        }
    };
    // After admission so a companion symlink into a mountpoint is refused by
    // name, and before any session. An empty directory this process just
    // created is eligible.
    if let Err(message) = occupied_mounts(&assignments) {
        fail(2, &message);
    }

    if stop_after_admit() {
        #[cfg(debug_assertions)]
        if let Ok(path) = std::env::var("RATARMOUNT_TEST_FORK_N_ADMIT_MARKER") {
            let _ = fs::write(path, "admitted\n");
        }
        ratarmount_core::fork_n::flush_spies();
        process::exit(0);
    }

    fork_n_serve::serve(args, tops, foreground, open_opts.direct_io);
}

fn fail(code: i32, message: &str) -> ! {
    eprintln!("error: {message}");
    ratarmount_core::fork_n::flush_spies();
    process::exit(code);
}

/// Clap cannot express the name pairing or the "either flag" conflicts.
/// `find` is the stripped argv sugar; `args.find` is not set yet when
/// `parse_args_from` calls this.
pub(crate) fn validate_cli(args: &crate::Args, find: bool) -> Result<(), String> {
    if let Some(flag) = conflict_flag(args, find) {
        return Err(format!("fork-n cannot be combined with {flag}"));
    }
    let tops = parse_side(&args.top, "--top")?;
    let mounts = parse_side(&args.mount, "--mount")?;
    if tops.is_empty() || mounts.is_empty() {
        return Err("fork-n requires --top and --mount with the same names".into());
    }
    let top_names: BTreeSet<&str> = tops.iter().map(|(name, _)| name.as_str()).collect();
    let mount_names: BTreeSet<&str> = mounts.iter().map(|(name, _)| name.as_str()).collect();
    if top_names != mount_names {
        return Err("fork-n --top and --mount name sets differ".into());
    }
    Ok(())
}

fn conflict_flag(args: &crate::Args, find: bool) -> Option<&'static str> {
    if args.write_overlay.is_some() {
        return Some("-w");
    }
    if args.overlay_tmpfs.is_some() {
        return Some("--overlay-tmpfs");
    }
    if args.sandbox {
        return Some("--sandbox");
    }
    if args.no_mount {
        return Some("--no-mount");
    }
    if args.nfs {
        return Some("--nfs");
    }
    if args.http {
        return Some("--http");
    }
    if args.webdav {
        return Some("--webdav");
    }
    if args.smb {
        return Some("--smb");
    }
    if args.ninep {
        return Some("--ninep");
    }
    if args.sftp {
        return Some("--sftp");
    }
    if args.sftp_subsystem {
        return Some("--sftp-subsystem");
    }
    if args.control_interface {
        return Some("--control-interface");
    }
    if args.journal.is_some() {
        return Some("--journal");
    }
    if find || args.find {
        return Some("find");
    }
    if args.unmount {
        return Some("unmount");
    }
    if args.repack_seekable {
        return Some("repack");
    }
    if args.publish_index || args.publish_index_to.is_some() {
        return Some("publish");
    }
    None
}

/// Any of the four commit flags. Checked by the caller before the find/bind
/// block so `--roll-every` plus `--bind` is the flatten sentence.
pub(crate) fn commit_requested(args: &crate::Args) -> bool {
    args.commit_overlay
        || args.commit_overlay_on_exit
        || args.commit_overlay_interval != "0"
        || args.roll_every.is_some()
}

fn parse_side(raws: &[String], flag: &str) -> Result<Vec<(String, PathBuf)>, String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in raws {
        let Some((name, path)) = raw.split_once('=') else {
            return Err(format!("fork-n {flag} requires NAME=PATH"));
        };
        if name.is_empty() || path.is_empty() {
            return Err(format!("fork-n {flag} requires NAME=PATH"));
        }
        if !seen.insert(name.to_string()) {
            return Err(format!("fork-n {flag} name {name:?} is repeated"));
        }
        out.push((name.to_string(), PathBuf::from(path)));
    }
    Ok(out)
}

pub(crate) fn assignments(args: &crate::Args) -> Result<Vec<Assignment>, String> {
    let tops = parse_side(&args.top, "--top")?;
    let mounts = parse_side(&args.mount, "--mount")?;
    let mut out = Vec::new();
    for (name, top) in tops {
        let mountpoint = mounts
            .iter()
            .find(|(n, _)| n == &name)
            .map(|(_, path)| path.clone())
            .ok_or_else(|| "fork-n requires --top and --mount with the same names".to_string())?;
        out.push(Assignment {
            name,
            top,
            mountpoint,
        });
    }
    Ok(out)
}

fn install_assignments(rows: &[Assignment]) {
    ratarmount_core::fork_n::install(
        rows.iter()
            .map(|row| canonical_best_effort(&row.top))
            .collect(),
        rows.iter()
            .map(|row| canonical_best_effort(&row.mountpoint))
            .collect(),
    );
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// Canonicalize `path`, or the longest existing ancestor plus the lexical
/// remainder when a final component does not exist yet.
fn canonical_best_effort(path: &Path) -> PathBuf {
    let abs = absolute(path);
    if let Ok(canonical) = abs.canonicalize() {
        return canonical;
    }
    let mut missing = Vec::new();
    let mut cur = abs.clone();
    loop {
        if fs::symlink_metadata(&cur).is_ok() {
            let Ok(mut resolved) = cur.canonicalize() else {
                break;
            };
            for name in missing.into_iter().rev() {
                resolved.push(name);
            }
            return resolved;
        }
        let Some(parent) = cur.parent() else {
            break;
        };
        if parent.as_os_str().is_empty() || parent == cur {
            break;
        }
        if let Some(name) = cur.file_name() {
            missing.push(name.to_os_string());
        }
        cur = parent.to_path_buf();
    }
    abs
}

fn canonicalize_assignments(rows: &[Assignment]) -> Vec<Assignment> {
    rows.iter()
        .map(|row| Assignment {
            name: row.name.clone(),
            top: row
                .top
                .canonicalize()
                .unwrap_or_else(|_| absolute(&row.top)),
            mountpoint: row
                .mountpoint
                .canonicalize()
                .unwrap_or_else(|_| absolute(&row.mountpoint)),
        })
        .collect()
}

fn create_directories(rows: &[Assignment]) -> Result<(), (i32, String)> {
    for row in rows {
        if let Err(err) = fs::create_dir_all(&row.top) {
            return Err((
                1,
                format!("fork-n cannot create top {}: {err}", row.top.display()),
            ));
        }
        if row.mountpoint.exists() && !row.mountpoint.is_dir() {
            return Err((
                2,
                format!(
                    "fork-n refuses mount {}: not an empty directory",
                    row.mountpoint.display()
                ),
            ));
        }
        if !row.mountpoint.exists() {
            if let Err(err) = fs::create_dir_all(&row.mountpoint) {
                return Err((
                    1,
                    format!(
                        "fork-n cannot create mountpoint {}: {err}",
                        row.mountpoint.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn occupied_mounts(rows: &[Assignment]) -> Result<(), String> {
    for row in rows {
        if listed_as_mount(&row.mountpoint) {
            return Err(format!(
                "fork-n refuses mount {}: target is already a mountpoint",
                row.mountpoint.display()
            ));
        }
        let mut dir = fs::read_dir(&row.mountpoint)
            .map_err(|err| format!("fork-n refuses mount {}: {err}", row.mountpoint.display()))?;
        if dir.next().is_some() {
            return Err(format!(
                "fork-n refuses mount {}: not an empty directory",
                row.mountpoint.display()
            ));
        }
    }
    Ok(())
}

fn listed_as_mount(path: &Path) -> bool {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let want = path.canonicalize().unwrap_or_else(|_| absolute(path));
    let want = want.to_string_lossy().replace(' ', "\\040");
    for line in text.lines() {
        let mut fields = line.split(' ');
        let Some(mp) = fields.nth(4) else { continue };
        if mp == want {
            return true;
        }
    }
    false
}

/// Each mountpoint against its own top. On, inside, and over all refuse.
fn identity_matrix(rows: &[Assignment]) -> Result<(), String> {
    let fs = mount_guard::RealFs::new();
    for row in rows {
        if let Some((rel, _via)) = mount_guard::relation_of(&fs, &row.mountpoint, &row.top) {
            let which = match rel {
                Relation::Equal => "on",
                Relation::Inside => "inside",
                Relation::Contains => "over",
            };
            return Err(format!(
                "fork-n refuses mount {}: {which} {}",
                row.mountpoint.display(),
                row.top.display()
            ));
        }
    }
    Ok(())
}

fn hardlink_walk(rows: &[Assignment]) -> Result<(), String> {
    for row in rows {
        walk_top(&row.top)?;
    }
    Ok(())
}

pub(crate) fn walk_top(dir: &Path) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|err| format!("fork-n cannot read {}: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("fork-n cannot read {}: {err}", dir.display()))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|err| format!("fork-n cannot stat {}: {err}", path.display()))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk_top(&path)?;
            continue;
        }
        if meta.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    return Err(format!(
                        "fork-n refuses hardlinked regular file {}",
                        path.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

fn stop_after_admit() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT").is_some()
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

fn open_options(args: &crate::Args) -> OpenOptions {
    let (index_in_memory, index_file_path) = match args.index_file.as_deref() {
        Some(text) if text.trim() == ratarmount_index::MEMORY_INDEX => (true, None),
        Some(text) => (false, Some(PathBuf::from(text))),
        None => (false, None),
    };
    let parallelization = ParallelizationSpec::parse(&args.parallelization)
        .unwrap_or_else(|_| ParallelizationSpec::default());
    OpenOptions {
        recursive: args.recursive,
        ignore_zeros: args.ignore_zeros,
        parallelization,
        direct_io: args.direct_io,
        readahead_bytes: ratarmount_fuse::parse_byte_size(&args.readahead).unwrap_or(0),
        index_in_memory,
        index_file_path,
        index_folders: crate::index_folders_of(args),
        index_minimum_file_count: args.index_minimum_file_count,
        passwords: args.passwords.clone(),
        encoding: args.encoding.clone(),
        verify_modification_time: args.verify_mtime,
        use_backends: args
            .use_backend
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        git: args.git,
        git_ref: args.git_ref.clone(),
        git_prefix: args.git_prefix.clone(),
        git_synthetic_head: args.git_synthetic_head,
        // Cohort journal recovery is PR2b. Do not inherit the default `true`.
        recover_journals: false,
        read_only_index: args.no_recreate_index,
        write_index: !args.no_recreate_index,
        clear_index_cache: args.recreate_index && !args.no_recreate_index,
        ..OpenOptions::default()
    }
}

fn open_source(
    args: &crate::Args,
    open_opts: &mut OpenOptions,
) -> Result<(Arc<dyn MountSource>, ClassifiedBase), String> {
    let comp = CompositingOptions {
        recursive: args.recursive || args.recursion_depth != 0,
        lazy: args.lazy,
        file_versions: !args.no_file_versions,
        prefix: if args.prefix.is_empty() {
            None
        } else {
            Some(args.prefix.clone())
        },
        strip_recursive_extension: args.strip_recursive_tar_extension,
        disable_union_mount: args.disable_union_mount,
        recursive_extensions: Some(args.recursive_extensions.clone()),
        parallel_nested_threads: args.parallel_nested,
        ..CompositingOptions::default()
    };
    // `split_bound_inputs_mountpoint` is the positional source list. Binds
    // stay on `args.source_binds` and are not factory inputs: a missing bind
    // would be `not found` and `fork_n_bind_directory_stays_a_source` would
    // never reach the admit marker.
    let (paths, _mountpoint) = crate::split_bound_inputs_mountpoint(args);
    let bindings = SourceBindings::default();
    let typed: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut opener = crate::base_identity::FactoryOpener::new(
        typed,
        paths,
        open_opts,
        args.recreate_index && !args.no_recreate_index,
        comp,
        bindings,
        args.source_binds.is_empty(),
    );
    let classified = ClassifiedBase::open(&mut opener)?;
    let source = classified.source();
    Ok((source, classified))
}

fn open_tops(
    args: &crate::Args,
    rows: &[Assignment],
    source: &Arc<dyn MountSource>,
    classified: &ClassifiedBase,
) -> Result<Vec<TopHandle>, String> {
    let create = CreateOptions {
        base_digest: args.base_digest.clone().unwrap_or_default(),
        force_base_mismatch: args.force_base_mismatch,
        lower_layers: Vec::new(),
        weak_exclude: Vec::new(),
        index_writable: !args.no_recreate_index,
        remote_token: None,
    };
    for row in rows {
        let db = row.top.join(HIDDEN_DB);
        ratarmount_core::fork_n::admit_overlay_db(&db, &row.top).map_err(|err| err.to_string())?;
    }
    let mut tops = Vec::new();
    for row in rows {
        let overlay = WriteOverlay::open(classified, Arc::clone(source), &row.top, &create)
            .map_err(|err| err.to_string())?;
        tops.push(TopHandle {
            name: row.name.clone(),
            overlay_dir: row.top.clone(),
            mountpoint: row.mountpoint.clone(),
            overlay: Arc::new(overlay),
        });
    }
    Ok(tops)
}
