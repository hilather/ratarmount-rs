//! Fork-N (Option A): N writable tops, N mountpoints, one process.
//!
//! `main` dispatches here when `--top` or `--mount` is set. This module owns
//! parsing checks that need the filesystem, the construction order, and the
//! handoff into [`crate::fork_n_serve`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

use ratarmount_compositing::{
    BaseKind, BaseLocation, ClassifiedBase, CreateOptions, FrozenBaseExcludes, MountJournal,
    MountRecords, ObservedBaseExcludes, WriteOverlay, HIDDEN_DB,
};
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
    let assignments = match assignments(args) {
        Ok(rows) => rows,
        Err(message) => fail(2, &message),
    };
    let foreground = args.foreground;
    if foreground {
        ratarmount_core::fork_n::set_phase(ratarmount_core::fork_n::WorkerPhase::Serving);
    } else {
        ratarmount_core::fork_n::set_phase(ratarmount_core::fork_n::WorkerPhase::Preparing);
    }
    // Canonicalize ancestors that already exist so a symlink mountpoint matches
    // `admit`'s resolved path. A component that does not exist yet keeps its
    // absolute path; mkdir is still after the factory.
    let top_paths: Vec<PathBuf> = assignments
        .iter()
        .map(|a| canonical_best_effort(&a.top))
        .collect();
    let mount_paths: Vec<PathBuf> = assignments
        .iter()
        .map(|a| canonical_best_effort(&a.mountpoint))
        .collect();
    ratarmount_core::fork_n::install(top_paths, mount_paths);

    if let Err(message) = refuse_daemon_torrents(args, foreground) {
        fail(2, &message);
    }
    if let Err(message) = refuse_incomplete_journals(args, &assignments) {
        fail(2, &message);
    }

    if let Err(message) = read_existing_tops(&assignments) {
        let code = if message.starts_with("fork-n ") { 2 } else { 1 };
        fail(code, &message);
    }
    let observed = match capture_excludes(args, &assignments) {
        Ok(observed) => observed,
        Err(err) => {
            let message = err.to_string();
            let code = if message.starts_with("fork-n ") { 2 } else { 1 };
            fail(code, &message);
        }
    };
    let frozen = observed.bind();

    if let Err(message) = prepare_bundles(args) {
        let code = if message.starts_with("fork-n ") { 2 } else { 1 };
        fail(code, &message);
    }
    let mut open_opts = open_options(args);
    let (source, classified) = match open_source(args, &mut open_opts) {
        Ok(opened) => opened,
        Err(message) => {
            // Storage admission and coverage refusals are exit 2. A factory
            // failure that is not a fork-n refusal stays exit 1.
            let code = if message.starts_with("fork-n ") { 2 } else { 1 };
            fail(code, &message);
        }
    };

    if let Err(message) = create_directories(&assignments) {
        fail(message.0, &message.1);
    }
    let assignments = canonicalize_assignments(&assignments);
    ratarmount_core::fork_n::install(
        assignments.iter().map(|a| a.top.clone()).collect(),
        assignments.iter().map(|a| a.mountpoint.clone()).collect(),
    );

    if let Err(message) = identity_matrix(args, &assignments, &classified) {
        fail(2, &message);
    }
    if let Err(message) = hardlink_walk(&assignments) {
        fail(2, &message);
    }
    hold_after_hardlink_check();
    if let Err(err) = frozen.recheck() {
        fail(2, &err.to_string());
    }
    if let Err(message) = occupied_mounts(&assignments) {
        fail(2, &message);
    }

    let directory_base = directory_base_of(&classified);
    let frozen_excludes = frozen_for(&classified, &frozen);
    let tops = match open_tops(
        args,
        &assignments,
        &source,
        &classified,
        &open_opts,
        frozen_excludes.as_ref(),
        directory_base.as_deref(),
    ) {
        Ok(tops) => tops,
        Err(message) => {
            let code = if message.starts_with("fork-n ") { 2 } else { 1 };
            fail(code, &message);
        }
    };

    if stop_after_admit() {
        #[cfg(debug_assertions)]
        if let Ok(path) = std::env::var("RATARMOUNT_TEST_FORK_N_ADMIT_MARKER") {
            let _ = fs::write(path, "admitted\n");
        }
        process::exit(0);
    }

    fork_n_serve::serve(args, tops, foreground, open_opts.direct_io);
}

fn fail(code: i32, message: &str) -> ! {
    eprintln!("error: {message}");
    process::exit(code);
}

fn assignments(args: &crate::Args) -> Result<Vec<Assignment>, String> {
    let mut tops = Vec::new();
    for raw in &args.top {
        let (name, path) = split(raw)?;
        tops.push((name, path));
    }
    let mut mounts = Vec::new();
    for raw in &args.mount {
        let (name, path) = split(raw)?;
        mounts.push((name, path));
    }
    let mut out = Vec::new();
    for (name, top) in tops {
        let mountpoint = mounts
            .iter()
            .find(|(n, _)| n == &name)
            .map(|(_, p)| p.clone())
            .ok_or_else(|| format!("fork-n --mount is missing name {name:?}"))?;
        out.push(Assignment {
            name,
            top,
            mountpoint,
        });
    }
    Ok(out)
}

fn split(raw: &str) -> Result<(String, PathBuf), String> {
    let Some((name, path)) = raw.split_once('=') else {
        return Err(format!("fork-n requires NAME=PATH, got {raw:?}"));
    };
    if name.is_empty() || path.is_empty() {
        return Err(format!(
            "fork-n requires a non-empty name and path, got {raw:?}"
        ));
    }
    Ok((name.to_string(), PathBuf::from(path)))
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
/// remainder when the final component does not exist yet.
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

fn refuse_daemon_torrents(args: &crate::Args, foreground: bool) -> Result<(), String> {
    if foreground {
        return Ok(());
    }
    for path in sources(args) {
        let text = path.to_string_lossy();
        if ratarmount_remote::is_torrent_input(&text)
            || ratarmount_core::fork_n::torrent_spelling(&text)
        {
            return Err(format!(
                "fork-n daemon refuses torrent input {text}; use --foreground"
            ));
        }
    }
    Ok(())
}

fn prepare_bundles(args: &crate::Args) -> Result<(), String> {
    if !args.lower.iter().any(|path| path.is_file()) {
        return Ok(());
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or_else(|| "neither XDG_CACHE_HOME nor HOME is set".to_string())?
        .join("ratarmount/layers");
    for lower in &args.lower {
        if lower.is_file() {
            crate::overlay_pack::prepare_lower_bundle(lower, &cache).map_err(|err| {
                let message = err.to_string();
                if message.starts_with("fork-n ") {
                    message
                } else {
                    format!("fork-n refuses {}: {message}", lower.display())
                }
            })?;
        }
    }
    Ok(())
}

fn sources(args: &crate::Args) -> Vec<PathBuf> {
    let mut out = args.paths.clone();
    for bind in &args.source_binds {
        out.push(PathBuf::from(&bind.source));
    }
    out
}

fn refuse_incomplete_journals(
    args: &crate::Args,
    assignments: &[Assignment],
) -> Result<(), String> {
    for path in sources(args) {
        if !path.is_file() {
            continue;
        }
        let pending = ratarmount_compress::commit_journal::pending(&path).map_err(|err| {
            format!(
                "fork-n refuses {}: cannot read commit journal: {err}",
                path.display()
            )
        })?;
        let Some(journal) = pending else { continue };
        if !journal.complete {
            return Err(format!(
                "fork-n refuses {}: commit journal is incomplete; recover it on a single mount or with --no-mount",
                path.display()
            ));
        }
        for row in assignments {
            let records = MountRecords {
                top: Some(row.top.clone()),
                lowers: args.lower.iter().filter(|p| p.is_dir()).cloned().collect(),
                bundles: args.lower.iter().any(|p| p.is_file()),
            };
            match ratarmount_compositing::classify_mount_journal(&records, &path).map_err(
                |err| {
                    format!(
                        "fork-n refuses {}: cannot classify commit journal: {err}",
                        path.display()
                    )
                },
            )? {
                MountJournal::Deferred {
                    complete: false, ..
                } => {
                    return Err(format!(
                        "fork-n refuses {}: commit journal is incomplete; recover it on a single mount or with --no-mount",
                        path.display()
                    ));
                }
                MountJournal::Deferred { .. } | MountJournal::Own | MountJournal::None => {}
            }
        }
    }
    Ok(())
}

fn read_existing_tops(rows: &[Assignment]) -> Result<(), String> {
    for row in rows {
        let db = row.top.join(ratarmount_compositing::HIDDEN_DB);
        match fs::symlink_metadata(&db) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "fork-n refuses {}: cannot read overlay database: {err}",
                    row.top.display()
                ));
            }
            Ok(meta) if !meta.is_file() => {
                return Err(format!(
                    "fork-n refuses {}: overlay database is not a regular file",
                    row.top.display()
                ));
            }
            Ok(_) => {
                ratarmount_compositing::OverlayMeta::read_no_recovery(&row.top).map_err(|err| {
                    format!(
                        "fork-n refuses {}: overlay database is not readable: {err}",
                        row.top.display()
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn capture_excludes(
    args: &crate::Args,
    assignments: &[Assignment],
) -> io::Result<ObservedBaseExcludes> {
    use ratarmount_compositing::ExcludeRole;
    let mut paths = Vec::new();
    for row in assignments {
        paths.push((row.top.clone(), ExcludeRole::Artifact));
        paths.push((row.mountpoint.clone(), ExcludeRole::Artifact));
    }
    for lower in &args.lower {
        paths.push((lower.clone(), ExcludeRole::Artifact));
    }
    if let Some(journal) = &args.journal {
        paths.push((journal.clone(), ExcludeRole::Journal));
    }
    for folder in crate::index_folders_of(args) {
        if !folder.as_os_str().is_empty() {
            paths.push((folder, ExcludeRole::Artifact));
        }
    }
    ObservedBaseExcludes::capture_with_roles(&paths)
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
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(mp) = fields.nth(4) else { continue };
        if Path::new(mp) == want {
            return true;
        }
    }
    false
}

fn identity_matrix(
    args: &crate::Args,
    rows: &[Assignment],
    classified: &ClassifiedBase,
) -> Result<(), String> {
    let fs = mount_guard::RealFs::new();
    let mut subjects_against_mounts: Vec<PathBuf> = Vec::new();
    if let Some(base) = directory_base_of(classified) {
        subjects_against_mounts.push(base);
    }
    for bind in &args.source_binds {
        let path = PathBuf::from(&bind.source);
        if path.is_dir() {
            subjects_against_mounts.push(path);
        }
    }
    for row in rows {
        subjects_against_mounts.push(row.top.clone());
    }
    for (i, row) in rows.iter().enumerate() {
        let mut others = subjects_against_mounts.clone();
        for (j, peer) in rows.iter().enumerate() {
            if i != j {
                others.push(peer.mountpoint.clone());
            }
        }
        for other in &others {
            match mount_guard::path_relation(&fs, &row.mountpoint, other) {
                Ok(Some(rel)) => {
                    return Err(format!(
                        "fork-n refuses mount {}: {rel:?} {}",
                        row.mountpoint.display(),
                        other.display()
                    ));
                }
                Ok(None) => {}
                Err(message) => return Err(message),
            }
        }
    }
    for (i, row) in rows.iter().enumerate() {
        for peer in rows.iter().skip(i + 1) {
            if mount_guard::path_relation(&fs, &row.top, &peer.top)?.is_some() {
                return Err(format!(
                    "fork-n refuses top {}: overlaps {}",
                    row.top.display(),
                    peer.top.display()
                ));
            }
        }
        if let Some(base) = directory_base_of(classified) {
            match mount_guard::path_relation(&fs, &row.top, &base)? {
                Some(Relation::Inside) => {}
                Some(_) => {
                    return Err(format!(
                        "fork-n refuses top {}: overlaps directory base {}",
                        row.top.display(),
                        base.display()
                    ));
                }
                None => {}
            }
        }
        for lower in &args.lower {
            if !lower.is_dir() {
                continue;
            }
            if mount_guard::path_relation(&fs, &row.top, lower)?.is_some() {
                return Err(format!(
                    "fork-n refuses top {}: overlaps lower {}",
                    row.top.display(),
                    lower.display()
                ));
            }
        }
    }
    Ok(())
}

fn directory_base_of(classified: &ClassifiedBase) -> Option<PathBuf> {
    let actual = classified.actual();
    if actual.kind() != BaseKind::Dir {
        return None;
    }
    match actual.location() {
        Some(BaseLocation::Local(path)) if path.is_dir() => Some(path.clone()),
        _ => None,
    }
}

fn frozen_for(
    classified: &ClassifiedBase,
    frozen: &FrozenBaseExcludes,
) -> Option<FrozenBaseExcludes> {
    match classified.actual().kind() {
        BaseKind::Dir => Some(frozen.clone()),
        BaseKind::Archive | BaseKind::Git => None,
    }
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

fn hold_after_hardlink_check() {
    #[cfg(debug_assertions)]
    {
        let Ok(hold) = std::env::var("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_HARDLINK_CHECK") else {
            return;
        };
        let start = std::time::Instant::now();
        while Path::new(&hold).exists() && start.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
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
        recover_journals: false,
        read_only_index: args.no_recreate_index,
        write_index: !args.no_recreate_index,
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
        transform_recursive: None,
        transform: None,
        disable_union_mount: args.disable_union_mount,
        recursive_extensions: Some(args.recursive_extensions.clone()),
        union_cache: ratarmount_compositing::UnionMountOptions::default(),
        parallel_nested_threads: args.parallel_nested,
    };
    let bindings = SourceBindings {
        binds: args.source_binds.clone(),
        ..SourceBindings::default()
    };
    let typed: Vec<String> = args
        .paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut opener = crate::base_identity::FactoryOpener::new(
        typed,
        args.paths.clone(),
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
    open_opts: &OpenOptions,
    frozen: Option<&FrozenBaseExcludes>,
    directory_base: Option<&Path>,
) -> Result<Vec<TopHandle>, String> {
    let exclude_paths = match (frozen, directory_base) {
        (Some(set), Some(base)) => set.excludes_for_base(base),
        (Some(set), None) => set.aggregate().to_vec(),
        (None, _) => Vec::new(),
    };
    let lower_identity = crate::BaseIdentity {
        base: crate::MountedBase {
            extra_excludes: exclude_paths.clone(),
            existing_journals: Vec::new(),
            classified: Some(classified.clone()),
            supplied: match &args.base_digest {
                Some(ratarmount_compositing::BaseDigestRequest::Supplied(digest)) => {
                    Some(digest.clone())
                }
                _ => None,
            },
        },
        force: args.force_stack_mismatch,
    };
    // Step 4 is before step 5. Own recovery and None-locator cleanup run
    // before `MountLowerStack::open_with`. Deferred-complete (including a
    // member that any top defers) waits until the live connections exist.
    let deferred = recover_complete(args, rows)?;
    let (lower_stack, view) = ratarmount_compositing::lower_stack::MountLowerStack::open_with(
        source.clone(),
        None,
        &args.lower,
        args.allow_unsealed_lower,
        None,
        &crate::bottom_identity(&lower_identity),
        &crate::lower_stack_services(),
    )?;
    let create = CreateOptions {
        base_digest: args.base_digest.clone().unwrap_or_default(),
        force_base_mismatch: args.force_base_mismatch,
        lower_layers: lower_stack.records().to_vec(),
        index_writable: !open_opts.read_only_index,
        weak_exclude: exclude_paths.clone(),
        remote_token: None,
    };
    for row in rows {
        lower_stack.check_top(&row.top, args.force_stack_mismatch)?;
        let db = row.top.join(HIDDEN_DB);
        ratarmount_core::fork_n::admit_overlay_db(&db, &row.top).map_err(|err| err.to_string())?;
    }
    if stop_after_admit() {
        return Ok(Vec::new());
    }
    let mut tops = Vec::new();
    for row in rows {
        let exclude_set = frozen.map(|_| {
            let mut paths = exclude_paths.clone();
            paths.extend(rows.iter().map(|r| r.top.clone()));
            ratarmount_compositing::BaseExcludes::new(paths)
        });
        let mut overlay = WriteOverlay::open_with_frozen_excludes(
            classified,
            view.clone(),
            &row.top,
            &create,
            exclude_set.as_ref(),
        )
        .map_err(|err| err.to_string())?;
        overlay.set_encoding(&args.encoding);
        if args.overlay_quota.is_some() || args.overlay_quota_files.is_some() {
            let quota = ratarmount_compositing::OverlayQuota::new(
                overlay.root(),
                args.overlay_quota,
                args.overlay_quota_files,
            )
            .map_err(|err| err.to_string())?;
            overlay.set_policy(Some(Arc::new(quota)));
        }
        tops.push(TopHandle {
            name: row.name.clone(),
            overlay_dir: row.top.clone(),
            mountpoint: row.mountpoint.clone(),
            overlay: Arc::new(overlay),
        });
    }
    recover_deferred_live(args, rows, &deferred, &tops)?;
    Ok(tops)
}

fn journal_records(args: &crate::Args, top: &Path) -> MountRecords {
    MountRecords {
        top: Some(top.to_path_buf()),
        lowers: args.lower.iter().filter(|p| p.is_dir()).cloned().collect(),
        bundles: args.lower.iter().any(|p| p.is_file()),
    }
}

fn recover_complete(args: &crate::Args, rows: &[Assignment]) -> Result<Vec<PathBuf>, String> {
    let top_dirs: Vec<PathBuf> = rows.iter().map(|r| r.top.clone()).collect();
    let mut deferred = Vec::new();
    for path in sources(args) {
        if !path.is_file() {
            continue;
        }
        let mut saw_own = false;
        let mut saw_deferred = false;
        let mut own_records = None;
        for row in rows {
            let records = journal_records(args, &row.top);
            match ratarmount_compositing::classify_mount_journal(&records, &path).map_err(
                |err| {
                    format!(
                        "fork-n refuses {}: cannot classify commit journal: {err}",
                        path.display()
                    )
                },
            )? {
                MountJournal::Own => {
                    saw_own = true;
                    own_records = Some(records);
                }
                MountJournal::Deferred { complete: true, .. } => saw_deferred = true,
                MountJournal::Deferred {
                    complete: false, ..
                } => {
                    return Err(format!(
                        "fork-n refuses {}: commit journal is incomplete; recover it on a single mount or with --no-mount",
                        path.display()
                    ));
                }
                MountJournal::None => {}
            }
        }
        match early_journal_action(saw_own, saw_deferred) {
            EarlyJournal::DeferToStep6 => deferred.push(path.clone()),
            EarlyJournal::Cohort => {
                let records = own_records.unwrap_or_else(|| {
                    journal_records(
                        args,
                        &rows.first().map(|r| r.top.clone()).unwrap_or_default(),
                    )
                });
                // Own that becomes Deferred under the lock aborts this run.
                // The error does not queue the member for step 6.
                ratarmount_compositing::recover_journal_cohort(&path, &top_dirs, &records)
                    .map_err(|err| {
                        format!(
                            "fork-n refuses {}: commit journal changed while the mount classified it, retry ({err})",
                            path.display()
                        )
                    })?;
            }
            EarlyJournal::Locator => {
                if let Some(row) = rows.first() {
                    let records = journal_records(args, &row.top);
                    match ratarmount_compositing::recover_journal_locator(
                        &path, &top_dirs, &records,
                    ) {
                        Ok(_) => {}
                        Err(err) if err.to_string().contains("fork-n defers journal") => {
                            deferred.push(path.clone());
                        }
                        Err(err) => {
                            return Err(format!("fork-n refuses {}: {err}", path.display()));
                        }
                    }
                }
            }
        }
    }
    Ok(deferred)
}

/// A Deferred-complete voter waits for step 6, even when another top is Own.
/// Own recovery runs only when every top is Own or None and at least one is Own.
enum EarlyJournal {
    Cohort,
    DeferToStep6,
    Locator,
}

fn early_journal_action(saw_own: bool, saw_deferred_complete: bool) -> EarlyJournal {
    if saw_deferred_complete {
        EarlyJournal::DeferToStep6
    } else if saw_own {
        EarlyJournal::Cohort
    } else {
        EarlyJournal::Locator
    }
}

fn recover_deferred_live(
    args: &crate::Args,
    rows: &[Assignment],
    deferred: &[PathBuf],
    tops: &[TopHandle],
) -> Result<(), String> {
    if deferred.is_empty() {
        return Ok(());
    }
    let top_dirs: Vec<PathBuf> = rows.iter().map(|r| r.top.clone()).collect();
    let lowers: Vec<PathBuf> = args.lower.iter().filter(|p| p.is_dir()).cloned().collect();
    let bundles = args.lower.iter().any(|p| p.is_file());
    for path in deferred {
        ratarmount_compositing::recover_journal_deferred(
            path,
            &top_dirs,
            &lowers,
            bundles,
            &mut |applied| {
                for top in tops {
                    top.overlay.restamp_committed(path, applied).map_err(|err| {
                        io::Error::other(format!(
                            "fork-n refuses {}: restamp {}: {err}",
                            path.display(),
                            top.name
                        ))
                    })?;
                }
                Ok(())
            },
        )
        .map_err(|err| {
            format!(
                "fork-n refuses {}: commit journal changed while the mount classified it, retry ({err})",
                path.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{parse_args_from, split_bound_inputs_mountpoint};

    fn err(argv: &[&str]) -> String {
        parse_args_from(argv).unwrap_err().to_string()
    }

    /// Regression: Fork-N commit flags are refused before the find/bind check.
    #[test]
    fn fork_n_flatten_before_find_bind_and_one_flag_each() {
        for flag in [
            &["--commit-overlay"][..],
            &["--commit-overlay-on-exit"][..],
            &["--commit-overlay-interval", "1s"][..],
            &["--roll-every", "1d"][..],
        ] {
            let mut argv = vec!["ratarmount", "--top", "A=/overlay", "--mount", "A=/mnt"];
            argv.extend_from_slice(flag);
            argv.push("archive.tar");
            let message = err(&argv);
            assert!(
                message.contains("commit of a layered stack is not supported; flatten first"),
                "{flag:?}: {message}"
            );
        }
        let bound = err(&[
            "ratarmount",
            "--top",
            "A=/overlay",
            "--mount",
            "A=/mnt",
            "--roll-every",
            "1d",
            "--bind",
            "/sub=/somewhere",
            "archive.tar",
        ]);
        assert!(
            bound.contains("commit of a layered stack is not supported; flatten first"),
            "{bound}"
        );
        assert!(!bound.contains("untransformed archive series"), "{bound}");
    }

    #[test]
    fn fork_n_assignment_names_conflicts_and_positionals() {
        let args = parse_args_from([
            "ratarmount",
            "--mount",
            "B=/mnt-b",
            "--top",
            "A=/top-a",
            "--top",
            "B=/top-b",
            "--mount",
            "A=/mnt-a",
            "one.tar",
            "two.tar",
        ])
        .unwrap();
        assert!(args.write_overlay.is_none());
        let (inputs, mountpoint) = split_bound_inputs_mountpoint(&args);
        assert!(mountpoint.is_none());
        assert_eq!(inputs.len(), 2);

        let bound = parse_args_from([
            "ratarmount",
            "--top",
            "A=/top",
            "--mount",
            "A=/mnt",
            "--bind",
            "/inside=/src",
            "only-dir",
        ])
        .unwrap();
        let (inputs, mountpoint) = split_bound_inputs_mountpoint(&bound);
        assert!(mountpoint.is_none(), "bind must not steal the positional");
        assert_eq!(inputs, vec![std::path::PathBuf::from("only-dir")]);

        assert!(err(&["ratarmount", "--top", "A=/t", "a.tar"]).contains("same names"));
        assert!(err(&[
            "ratarmount",
            "--top",
            "nopath",
            "--mount",
            "nopath",
            "a.tar"
        ])
        .contains("NAME=PATH"));
        assert!(err(&[
            "ratarmount",
            "--top",
            "A=/t",
            "--top",
            "A=/u",
            "--mount",
            "A=/m",
            "a.tar"
        ])
        .contains("repeated"));
        assert!(
            err(&["ratarmount", "--top", "A=/t", "--mount", "B=/m", "a.tar"])
                .contains("name sets differ")
        );
        assert!(err(&[
            "ratarmount",
            "--top",
            "A=/t",
            "--mount",
            "A=/m",
            "-w",
            "/w",
            "a.tar"
        ])
        .contains("fork-n cannot be combined with -w/--write-overlay"));
        assert!(
            err(&["ratarmount", "corpus", "--top", "A=/t", "list", "mnt"])
                .contains("corpus cannot be combined with --top or --mount")
        );

        let legacy = parse_args_from(["ratarmount", "-w", "/ov", "a.tar", "mnt"]).unwrap();
        assert!(legacy.top.is_empty() && legacy.mount.is_empty());
        let n1 = parse_args_from([
            "ratarmount",
            "--top",
            "A=/top-a",
            "--mount",
            "A=/mnt-a",
            "--force-base-mismatch",
            "--overlay-quota",
            "10M",
            "a.tar",
        ])
        .unwrap();
        assert!(n1.force_base_mismatch);
        assert_eq!(n1.overlay_quota, Some(10 << 20));
        assert!(
            err(&["ratarmount", "corpus", "--mount", "A=/m", "list", "mnt"])
                .contains("corpus cannot be combined with --top or --mount")
        );
        assert!(err(&[
            "ratarmount",
            "corpus",
            "--top",
            "A=/t",
            "--mount",
            "A=/m",
            "list",
            "mnt"
        ])
        .contains("corpus cannot be combined with --top or --mount"));
        let plain = parse_args_from(["ratarmount", "corpus", "LIST", "MOUNT"]).unwrap();
        assert!(plain.corpus_list.is_some());
        let as_source = parse_args_from(["ratarmount", "./corpus"]).unwrap();
        assert!(as_source.corpus_list.is_none());
        assert!(err(&[
            "ratarmount",
            "--top",
            "A=/t",
            "--mount",
            "A=/m",
            "--nfs",
            "a.tar"
        ])
        .contains("fork-n cannot be combined with --nfs"));
        assert!(err(&[
            "ratarmount",
            "find",
            "--top",
            "A=/t",
            "--mount",
            "A=/m",
            "a.tar"
        ])
        .contains("fork-n cannot be combined with find"));
        let roll = err(&["ratarmount", "--roll-every", "1d", "traces.tar"]);
        assert!(
            roll.contains("--roll-every requires --write-overlay"),
            "{roll}"
        );
        let corpus = err(&[
            "ratarmount",
            "corpus",
            "LIST",
            "MOUNT",
            "--roll-every",
            "1d",
        ]);
        assert!(
            corpus.contains("--roll-every requires --write-overlay"),
            "{corpus}"
        );
    }

    /// Regression: a Deferred-complete voter is not Own-recovered.
    #[test]
    fn fork_n_journal_deferred_voter_waits_for_step_six() {
        assert!(matches!(
            super::early_journal_action(true, true),
            super::EarlyJournal::DeferToStep6
        ));
        assert!(matches!(
            super::early_journal_action(true, false),
            super::EarlyJournal::Cohort
        ));
        assert!(matches!(
            super::early_journal_action(false, false),
            super::EarlyJournal::Locator
        ));
    }
}
