//! Offline patch import through the same write and metadata APIs as a mount.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Args;
use ratarmount_compositing::{
    ClassifiedBase, CreateOptions, LowerLayerRecord, OverlayMetadata, WriteOverlay,
};
use ratarmount_core::{FileInfo, ListResult, MountSource, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};

use crate::base_identity::{classify_offline, GitIntent, OverlayRunContext};

mod parse;
#[cfg(test)]
mod tests;

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Lower overlays, bottom to top.
    #[arg(long, action = clap::ArgAction::Append)]
    pub lower: Vec<PathBuf>,
    #[arg(long)]
    pub allow_unsealed_lower: bool,
    /// Timestamp for written files (seconds since the Unix epoch, or now).
    #[arg(long, default_value = "now", allow_hyphen_values = true, value_parser = parse_mtime)]
    pub mtime: String,
    #[arg(long)]
    pub no_seal: bool,
    /// Keep the original file and write failed hunks to PATH.rej.
    #[arg(long)]
    pub reject: bool,
    #[arg(long)]
    pub json: bool,
    /// Bound patch input, each decoded literal and each pre/postimage in bytes.
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    pub max_patch_bytes: u64,
    /// Patch file, or - for stdin.
    pub patch: PathBuf,
    /// Must not exist, or must be an empty directory.
    pub directory: PathBuf,
    pub base: String,
}

fn parse_mtime(value: &str) -> Result<String, String> {
    if value != "now" {
        let time: f64 = value
            .parse()
            .map_err(|_| "mtime must be now or epoch seconds")?;
        // Match the host metadata API's finite signed-seconds representation.
        if !time.is_finite() || !(-9e15..9e15).contains(&time) {
            return Err(
                "mtime must be finite epoch seconds in the supported range (-9e15 to 9e15)".into(),
            );
        }
    }
    Ok(value.into())
}

fn mtime(value: &str) -> Result<f64, String> {
    parse_mtime(value)?;
    if value == "now" {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs_f64())
    } else {
        value
            .parse()
            .map_err(|e: std::num::ParseFloatError| e.to_string())
    }
}

fn read_bounded(reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(io::Error::other("content exceeds --max-patch-bytes"));
    }
    Ok(data)
}

/// The classified base and the composed view over it, retained for sealing:
/// rows are hashed against `view` (the base under its `--lower` layers), so a
/// file a lower layer added and the top modifies seals as Modified, not Added.
pub(super) struct ImportStack {
    pub base: ClassifiedBase,
    /// The base under its lower layers: what the overlay is served over.
    pub view: Arc<dyn MountSource>,
    pub lower_layers: Vec<LowerLayerRecord>,
    pub inputs: Vec<PathBuf>,
}

impl ImportStack {
    fn open(args: &ImportArgs, context: &OverlayRunContext) -> Result<Self, String> {
        Self::open_base(&args.base, &args.lower, args.allow_unsealed_lower, context)
    }

    /// Shared by patch and kernel upperdir imports; retain the stack for sealing.
    pub fn open_base(
        base: &str,
        lower: &[PathBuf],
        allow_unsealed_lower: bool,
        context: &OverlayRunContext,
    ) -> Result<Self, String> {
        // Import opens the base the way the user would mount it: a working
        // tree with a `.git` entry is Git.
        let classified = classify_offline(Path::new(base), GitIntent::Auto, context)?;
        let (lowers, view) = super::MountLowerStack::open(
            classified.source(),
            None,
            lower,
            allow_unsealed_lower,
            &super::lower_stack_services(),
        )?;
        Ok(Self {
            base: classified,
            view,
            lower_layers: lowers.records,
            inputs: vec![PathBuf::from(base)],
        })
    }
}

pub(super) fn validate_destination(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            if fs::read_dir(dir)
                .map_err(|e| e.to_string())?
                .next()
                .is_some()
            {
                return Err(format!(
                    "{} must be an empty directory or not exist",
                    dir.display()
                ));
            }
        }
        Ok(_) => {
            return Err(format!(
                "{} must be a directory, not a file or symlink",
                dir.display()
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(())
}

pub fn run(args: &ImportArgs, context: &OverlayRunContext) -> Result<(String, i32), String> {
    validate_destination(&args.directory)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0044-M01","item":"ratarmount::overlay_import::run","disposition":"out-of-family","category":"patch-or-bundle-input","reason":"patch input stream","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let bytes = if args.patch == Path::new("-") {
        read_bounded(io::stdin().lock(), args.max_patch_bytes)
    } else {
        read_bounded(
            fs::File::open(&args.patch).map_err(|e| format!("{}: {e}", args.patch.display()))?,
            args.max_patch_bytes,
        )
    }
    .map_err(|e| e.to_string())?;
    let patches = parse::parse(&bytes, args.max_patch_bytes).map_err(|e| e.to_string())?;
    let time = mtime(&args.mtime)?;
    // Factory and lazy archive progress must not contaminate JSON/digest stdout.
    let _progress = super::diff::ProgressToStderr::new().map_err(|e| e.to_string())?;
    let stack = ImportStack::open(args, context)?;
    import(args, &patches, stack, time)
}

fn import(
    args: &ImportArgs,
    patches: &[parse::FilePatch],
    stack: ImportStack,
    time: f64,
) -> Result<(String, i32), String> {
    validate_destination(&args.directory)?;
    // Claim the destination before opening the DB. Never clean up a directory
    // whose creation/empty check failed (including a symlink destination).
    if !args.directory.exists() {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0122-M01","item":"ratarmount::overlay_import::import","disposition":"output-owner","category":"overlay-import-directory","reason":"Claim the validated overlay import destination before opening its database.","creation":{"policy":"exclusive-directory","basis":"create_dir is called only for a missing destination; cleanup does not remove a directory whose claim/empty check failed."}}"###
        )]
        fs::create_dir(&args.directory)
            .map_err(|e| format!("{}: {e}", args.directory.display()))?;
    }
    let result = (|| {
        let overlay = super::overlay_create::create_overlay(
            &stack.base,
            stack.view.clone(),
            &args.directory,
            CreateOptions {
                lower_layers: stack.lower_layers.clone(),
                ..Default::default()
            },
            &stack.inputs,
            false,
        )
        .map_err(|e| e.to_string())?;
        begin_import(&overlay)?;
        overlay.test_hold_open_transaction();
        let mut written: BTreeSet<String> = BTreeSet::new();
        let mut rejected: BTreeSet<String> = BTreeSet::new();
        let mut rejects: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        // Deletions applied or rejected early as part of a directory that an
        // earlier section replaces with a file (#329).
        let mut hoisted = BTreeSet::new();
        for (index, patch) in patches.iter().enumerate() {
            if hoisted.contains(&index) {
                continue;
            }
            // Type changes can be separate delete/add sections. Once any
            // section fails, keep that whole file (and anything below a
            // rejected path) at its original lower state.
            let already_rejected = patch
                .old
                .iter()
                .chain(&patch.new)
                .any(|p| rejected_root(&rejected, p).is_some());
            for path in patch.old.iter().chain(&patch.new) {
                // Only a path below a rejected (restored) file skips the check:
                // that file is its lower self again and nothing is written below it.
                if !below_rejected_file(&overlay, &rejected, path) {
                    check_parents(&overlay, stack.view.as_ref(), path)?;
                }
            }
            let original = match &patch.old {
                Some(path) if below_rejected_file(&overlay, &rejected, path) => None,
                Some(path)
                    if rejected.contains(path)
                        && overlay
                            .lookup(&format!("/{path}"), 0)
                            .is_some_and(|fi| fi.mode & S_IFMT == S_IFDIR) =>
                {
                    None
                }
                Some(path) => read_entry(&overlay, path, args.max_patch_bytes)?,
                None => None,
            };
            let preimage = original
                .as_ref()
                .map_or(&[][..], |(_, bytes)| bytes.as_slice());
            let (content, failed) = apply_hunks(preimage, &patch.hunks, args.max_patch_bytes)?;
            if !failed.is_empty() {
                if !args.reject {
                    return Err(format!(
                        "{}: hunk #{} failed (exact context not found)",
                        patch.path(),
                        failed[0] + 1
                    ));
                }
                // The lower view is the original even if an earlier section in
                // this patch stream changed this path.
                for path in patch.old.iter().chain(&patch.new).collect::<BTreeSet<_>>() {
                    if rejected_root(&rejected, path).is_some_and(|root| root != path) {
                        continue; // An ancestor is already back at its lower state.
                    }
                    // A file this import turned into a directory goes back
                    // as a whole, with everything written below it.
                    let root = type_change_root(&overlay, stack.view.as_ref(), path)
                        .unwrap_or_else(|| path.clone());
                    restore(
                        &overlay,
                        stack.view.as_ref(),
                        &root,
                        &written,
                        args.max_patch_bytes,
                    )?;
                    written.retain(|w| !at_or_under(w, &root));
                    mark_rejected(&mut rejected, &mut rejects, root);
                }
                let name = reject_name(&rejected, patch.path());
                check_parents(&overlay, stack.view.as_ref(), &name)?;
                let reject = rejects.entry(name).or_insert_with(|| {
                    format!(
                        "diff a/{} b/{}\t(rejected hunks)\n",
                        patch.path(),
                        patch.path(),
                    )
                    .into_bytes()
                });
                for i in failed {
                    reject.extend_from_slice(&patch.hunks[i].raw);
                }
                continue;
            }
            if already_rejected {
                continue;
            }
            if patch.old.is_some() && original.is_none() {
                return Err(format!("{}: preimage does not exist", patch.path()));
            }
            if patch.old.is_none() {
                let path = patch.path();
                if overlay
                    .lookup(&format!("/{path}"), 0)
                    .is_some_and(|fi| fi.mode & S_IFMT == S_IFDIR)
                {
                    // Directory -> file: Git emits `add x` before `delete x/...`.
                    match replace_directory(
                        &overlay,
                        stack.view.as_ref(),
                        patches,
                        index,
                        path,
                        &rejected,
                        args.max_patch_bytes,
                    )? {
                        Replace::Removed(done) => {
                            for (j, child) in done {
                                hoisted.insert(j);
                                written.insert(child);
                            }
                        }
                        Replace::Failed { deletions, .. } if args.reject => {
                            // Keep the lower directory; the whole type change
                            // is rejected and later sections below it are
                            // skipped (their failed hunks join this .rej).
                            restore(
                                &overlay,
                                stack.view.as_ref(),
                                path,
                                &written,
                                args.max_patch_bytes,
                            )?;
                            written.retain(|w| !at_or_under(w, path));
                            mark_rejected(&mut rejected, &mut rejects, path.to_string());
                            let reject = rejects
                                .entry(reject_name(&rejected, path))
                                .or_insert_with(|| {
                                    format!("diff a/{path} b/{path}\t(rejected hunks)\n")
                                        .into_bytes()
                                });
                            for hunk in &patch.hunks {
                                reject.extend_from_slice(&hunk.raw);
                            }
                            // Keep the dry-run failures: restoring an earlier
                            // edit may make a formerly failing deletion match.
                            for (j, failed) in deletions {
                                hoisted.insert(j);
                                for i in failed {
                                    reject.extend_from_slice(&patches[j].hunks[i].raw);
                                }
                            }
                            continue;
                        }
                        Replace::Failed { message, .. } => return Err(message),
                        Replace::NotCovered => {}
                    }
                }
                if overlay.lookup(&format!("/{path}"), 0).is_some() {
                    return Err(format!("{path}: added file already exists"));
                }
            }
            if patch.old != patch.new
                && patch
                    .new
                    .as_ref()
                    .is_some_and(|p| overlay.lookup(&format!("/{p}"), 0).is_some())
            {
                return Err(format!("{}: destination already exists", patch.path()));
            }
            if patch.deleted && !patch.literal.as_deref().unwrap_or(&content).is_empty() {
                return Err(format!("{}: deletion leaves content", patch.path()));
            }
            if let Some(path) = &patch.new {
                let mode = patch
                    .new_mode
                    .or_else(|| original.as_ref().map(|(fi, _)| fi.mode))
                    .unwrap_or(S_IFREG | 0o644);
                write_entry(
                    &overlay,
                    path,
                    patch.literal.as_deref().unwrap_or(&content),
                    mode,
                    time,
                )?;
                written.insert(path.clone());
            }
            if !patch.copy && patch.old != patch.new {
                if let Some(path) = &patch.old {
                    overlay
                        .unlink(&format!("/{path}"))
                        .map_err(|e| format!("{path}: {e}"))?;
                    written.insert(path.clone());
                }
            }
        }
        for (name, reject) in rejects {
            check_parents(&overlay, stack.view.as_ref(), &name)?;
            write_entry(&overlay, &name, &reject, S_IFREG | 0o644, time)?;
        }
        finish_import(&overlay)?;
        drop(overlay); // seal requires the exclusive WriteOverlay connection closed.
        let digest = if args.no_seal {
            None
        } else {
            Some(
                ratarmount_compositing::overlay_seal::seal(
                    &args.directory,
                    &stack.base,
                    stack.view,
                )
                .map_err(|e| e.to_string())?
                .layer_digest,
            )
        };
        let output = if args.json {
            serde_json::json!({"overlay":args.directory,"files":written.len(),"rejected":rejected.len(),"layer_digest":digest}).to_string()
        } else if let Some(digest) = digest {
            digest
        } else {
            format!(
                "imported {} paths into {} ({} rejected)",
                written.len(),
                args.directory.display(),
                rejected.len()
            )
        };
        Ok((output, i32::from(!rejected.is_empty())))
    })();
    if let Err(error) = &result {
        // Sealing may have made directories read-only before an I/O failure.
        let _ = ratarmount_compositing::overlay_seal::unseal(&args.directory);
        if let Err(e) = fs::remove_dir_all(&args.directory) {
            return Err(format!(
                "{}; cleanup {} failed: {e}",
                error,
                args.directory.display()
            ));
        }
    }
    result
}

/// Mark the overlay as partially written before the first entry; a SIGKILL
/// leaves the row, `overlay fsck` reports `import_incomplete` and `seal` refuses.
fn begin_import(overlay: &WriteOverlay) -> Result<(), String> {
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    overlay
        .set_meta(
            "import_in_progress",
            &format!("{}:{started}", std::process::id()),
        )
        .map_err(|e| e.to_string())
}

/// Clear the marker after the last write, before the overlay closes or seals.
fn finish_import(overlay: &WriteOverlay) -> Result<(), String> {
    overlay
        .clear_meta("import_in_progress")
        .map_err(|e| e.to_string())
}

/// A deleted lower regular file can become a directory. Lower symlinks must
/// still be refused: folder-backed lookups can follow them even after the
/// merged view has hidden the symlink, exposing entries outside the base.
fn check_parents(
    overlay: &WriteOverlay,
    lower: &dyn MountSource,
    path: &str,
) -> Result<(), String> {
    for (i, _) in path.match_indices('/') {
        let parent = format!("/{}", &path[..i]);
        if lower
            .lookup(&parent, 0)
            .is_some_and(|fi| fi.mode & S_IFMT == S_IFLNK)
        {
            return Err(format!("{path}: symlink parent {parent} is refused"));
        }
        if let Some(fi) = overlay.lookup(&parent, 0) {
            if fi.mode & S_IFMT == S_IFLNK {
                return Err(format!("{path}: symlink parent {parent} is refused"));
            }
            if fi.mode & S_IFMT != S_IFDIR {
                return Err(format!("{path}: parent {parent} is not a directory"));
            }
        }
    }
    Ok(())
}

fn at_or_under(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The topmost rejected path at or above `path`.
fn rejected_root<'a>(rejected: &'a BTreeSet<String>, path: &str) -> Option<&'a String> {
    path.match_indices('/')
        .map(|(i, _)| &path[..i])
        .chain(std::iter::once(path))
        .find_map(|p| rejected.get(p))
}

fn below_rejected_file(overlay: &WriteOverlay, rejected: &BTreeSet<String>, path: &str) -> bool {
    rejected_root(rejected, path).is_some_and(|root| {
        root != path
            && overlay
                .lookup(&format!("/{root}"), 0)
                .is_some_and(|fi| fi.mode & S_IFMT != S_IFDIR)
    })
}

/// A rejected parent subsumes earlier child rejections and their reject files.
fn mark_rejected(
    rejected: &mut BTreeSet<String>,
    rejects: &mut BTreeMap<String, Vec<u8>>,
    root: String,
) {
    let name = format!("{root}.rej");
    let children: Vec<_> = rejects
        .keys()
        .filter(|key| {
            *key != &name
                && key
                    .strip_suffix(".rej")
                    .is_some_and(|path| at_or_under(path, &root))
        })
        .cloned()
        .collect();
    for child in children {
        let bytes = rejects.remove(&child).unwrap();
        rejects.entry(name.clone()).or_default().extend(bytes);
    }
    rejected.retain(|path| !at_or_under(path, &root));
    rejected.insert(root);
}

/// Failed hunks below a rejected type change go to the restored path's `.rej`.
fn reject_name(rejected: &BTreeSet<String>, path: &str) -> String {
    format!(
        "{}.rej",
        rejected_root(rejected, path).map_or(path, String::as_str)
    )
}

/// The topmost proper ancestor of `path` that is a non-directory in the lower
/// view but deleted or a directory in the overlay: a file this import replaced,
/// including a failed first child addition before mkdir has run.
fn type_change_root(overlay: &WriteOverlay, lower: &dyn MountSource, path: &str) -> Option<String> {
    path.match_indices('/').find_map(|(i, _)| {
        let full = format!("/{}", &path[..i]);
        let is_dir = |fi: FileInfo| fi.mode & S_IFMT == S_IFDIR;
        ((overlay.is_deleted(&full) || overlay.lookup(&full, 0).is_some_and(is_dir))
            && lower.lookup(&full, 0).is_some_and(|fi| !is_dir(fi)))
        .then(|| path[..i].to_string())
    })
}

/// Children of `dir` (no leading slash) in a view, with their modes.
fn children(source: &dyn MountSource, dir: &str) -> Vec<(String, u32)> {
    let names = match source.list(&format!("/{dir}")) {
        Some(ListResult::Infos(map)) => map.into_keys().collect(),
        Some(ListResult::Names(names)) => names,
        None => Vec::new(),
    };
    names
        .into_iter()
        .filter_map(|name| {
            let child = format!("{dir}/{name}");
            let fi = source.lookup(&format!("/{child}"), 0)?;
            Some((child, fi.mode))
        })
        .collect()
}

/// Remove the overlay directory `dir` and everything below it.
fn remove_tree(overlay: &WriteOverlay, dir: &str) -> Result<(), String> {
    for (child, mode) in children(overlay, dir) {
        if mode & S_IFMT == S_IFDIR {
            remove_tree(overlay, &child)?;
        } else {
            overlay
                .unlink(&format!("/{child}"))
                .map_err(|e| format!("{child}: {e}"))?;
        }
    }
    overlay
        .rmdir(&format!("/{dir}"))
        .map_err(|e| format!("{dir}: {e}"))
}

enum Replace {
    /// The deletions `(section index, path)` ran and the directory is gone.
    Removed(Vec<(usize, String)>),
    /// A covering deletion would fail; nothing was changed.
    Failed {
        message: String,
        /// Every covering deletion and its failed hunk indices, before restore.
        deletions: Vec<(usize, Vec<usize>)>,
    },
    /// Later sections do not delete everything below the directory.
    NotCovered,
}

/// Section `index` adds a file at `dir`, which is a directory in the merged
/// view. When later sections delete every non-directory below it, and no
/// other later section touches anything below it, apply those deletions now
/// and remove the emptied directory tree. Only this directory is pruned.
fn replace_directory(
    overlay: &WriteOverlay,
    lower: &dyn MountSource,
    patches: &[parse::FilePatch],
    index: usize,
    dir: &str,
    rejected: &BTreeSet<String>,
    limit: u64,
) -> Result<Replace, String> {
    let mut deletions = BTreeMap::new();
    for (j, later) in patches.iter().enumerate().skip(index + 1) {
        let below = later
            .old
            .iter()
            .chain(&later.new)
            .any(|p| p != dir && at_or_under(p, dir));
        if !below {
            continue;
        }
        match (&later.old, &later.new) {
            (Some(old), None) if later.deleted && !later.copy && old != dir => {
                if deletions.insert(old.clone(), j).is_some() {
                    return Ok(Replace::NotCovered);
                }
            }
            _ => return Ok(Replace::NotCovered),
        }
    }
    let mut files = Vec::new();
    let mut pending = vec![dir.to_string()];
    while let Some(d) = pending.pop() {
        // WriteOverlay::list can return an empty merged listing when the
        // lower directory exists but its listing failed. That is not proof
        // that the patch deletes all children: pruning it would hide data.
        let full = format!("/{d}");
        if lower.is_dir(&full) && lower.list(&full).is_none() {
            return Err(format!("{d}: cannot list lower directory for replacement"));
        }
        for (child, mode) in children(overlay, &d) {
            if mode & S_IFMT == S_IFDIR {
                pending.push(child);
            } else {
                files.push(child);
            }
        }
    }
    if files.len() != deletions.len() || files.iter().any(|f| !deletions.contains_key(f)) {
        return Ok(Replace::NotCovered);
    }
    if rejected.iter().any(|path| at_or_under(path, dir)) {
        return Ok(Replace::Failed {
            message: format!("{dir}: directory contains a rejected path"),
            deletions: Vec::new(),
        });
    }
    // Dry-run every deletion before changing anything.
    let mut checked = Vec::new();
    let mut failure = None;
    for (path, &j) in &deletions {
        let later = &patches[j];
        let Some((_, bytes)) = read_entry(overlay, path, limit)? else {
            return Ok(Replace::NotCovered);
        };
        let (content, failed) = apply_hunks(&bytes, &later.hunks, limit)?;
        if let Some(first) = failed.first() {
            failure.get_or_insert_with(|| {
                format!(
                    "{path}: hunk #{} failed (exact context not found)",
                    first + 1
                )
            });
        } else if !later.literal.as_deref().unwrap_or(&content).is_empty() {
            return Err(format!("{path}: deletion leaves content"));
        }
        checked.push((j, failed));
    }
    if let Some(message) = failure {
        return Ok(Replace::Failed {
            message,
            deletions: checked,
        });
    }
    for path in deletions.keys() {
        overlay
            .unlink(&format!("/{path}"))
            .map_err(|e| format!("{path}: {e}"))?;
    }
    remove_tree(overlay, dir)?;
    Ok(Replace::Removed(
        deletions.into_iter().map(|(path, j)| (j, path)).collect(),
    ))
}

fn read_entry(
    source: &dyn MountSource,
    path: &str,
    limit: u64,
) -> Result<Option<(FileInfo, Vec<u8>)>, String> {
    let Some(fi) = source.lookup(&format!("/{path}"), 0) else {
        return Ok(None);
    };
    let data = match fi.mode & S_IFMT {
        S_IFLNK => fi.linkname.as_bytes().to_vec(),
        S_IFREG => {
            if fi.size > limit {
                return Err(format!("{path}: preimage exceeds --max-patch-bytes"));
            }
            read_bounded(
                source
                    .open(&fi, libc::O_RDONLY)
                    .map_err(|e| format!("{path}: {e}"))?,
                limit,
            )
            .map_err(|e| format!("{path}: {e}"))?
        }
        _ => {
            return Err(format!(
                "{path}: patch preimage is not a regular file or symlink"
            ))
        }
    };
    Ok(Some((fi, data)))
}

fn write_entry(
    overlay: &WriteOverlay,
    path: &str,
    data: &[u8],
    mode: u32,
    time: f64,
) -> Result<(), String> {
    let full = format!("/{path}");
    // Materialize missing parents explicitly so their rows match mkdir in FUSE.
    for (i, _) in path.match_indices('/') {
        let parent = format!("/{}", &path[..i]);
        if overlay.lookup(&parent, 0).is_none() {
            overlay
                .mkdir(&parent, 0o755)
                .map_err(|e| format!("{path}: {e}"))?;
        }
    }
    if overlay
        .lookup(&full, 0)
        .is_some_and(|fi| fi.mode & S_IFMT == S_IFLNK)
        || mode & S_IFMT == S_IFLNK && overlay.lookup(&full, 0).is_some()
    {
        overlay.unlink(&full).map_err(|e| format!("{path}: {e}"))?;
    }
    if mode & S_IFMT == S_IFLNK {
        let target = std::str::from_utf8(data)
            .map_err(|_| format!("{path}: non-UTF-8 symlink target is unsupported (EILSEQ)"))?;
        if target.contains('\0') {
            return Err(format!("{path}: NUL in symlink target"));
        }
        overlay
            .create_symlink(&full, target)
            .map_err(|e| format!("{path}: {e}"))?;
    } else {
        let fd = overlay
            .create_file(&full, 0o600)
            .map_err(|e| format!("{path}: {e}"))?;
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0045-M01","item":"ratarmount::overlay_import::write_entry","disposition":"residual","reason":"overlay payload descriptor borrowed from create_file for an import write; reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let file = unsafe { fs::File::from_raw_fd(fd) };
        let result = overlay
            .truncate_file(&file, &full, 0)
            .and_then(|()| overlay.write_all_at(&file, &full, 0, data));
        overlay.finish_owned_write_fd(file);
        result.map_err(|e| format!("{path}: {e}"))?;
    }
    overlay
        .set_metadata(
            &full,
            &OverlayMetadata {
                mode: (mode & S_IFMT != S_IFLNK).then_some(mode & 0o7777),
                mtime: Some(time),
                ..Default::default()
            },
        )
        .map_err(|e| format!("{path}: {e}"))
}

fn restore(
    overlay: &WriteOverlay,
    lower: &dyn MountSource,
    path: &str,
    written: &BTreeSet<String>,
    limit: u64,
) -> Result<(), String> {
    let full = format!("/{path}");
    let original = lower.lookup(&full, 0);
    if let Some(fi) = original.filter(|fi| fi.mode & S_IFMT == S_IFDIR) {
        if overlay
            .lookup(&full, 0)
            .is_some_and(|fi| fi.mode & S_IFMT != S_IFDIR)
        {
            overlay.unlink(&full).map_err(|e| format!("{path}: {e}"))?;
        }
        overlay
            .mkdir(&full, 0o755)
            .map_err(|e| format!("{path}: {e}"))?;
        // Restore affected children, including implicit parents of written
        // paths. Unchanged lower files need no copying or preimage reads.
        let prefix = format!("{path}/");
        let mut affected: BTreeSet<_> = written
            .iter()
            .filter_map(|p| p.strip_prefix(&prefix))
            .map(|rest| format!("{prefix}{}", rest.split('/').next().unwrap()))
            .collect();
        // Replacing a directory prunes empty subdirectories too; these have
        // no file section and therefore are absent from `written`.
        for (child, mode) in children(lower, path) {
            if mode & S_IFMT == S_IFDIR && overlay.lookup(&format!("/{child}"), 0).is_none() {
                affected.insert(child);
            }
        }
        for child in affected {
            restore(overlay, lower, &child, written, limit)?;
        }
        return overlay
            .set_metadata(
                &full,
                &OverlayMetadata {
                    mode: Some(fi.mode & 0o7777),
                    mtime: Some(fi.mtime),
                    ..Default::default()
                },
            )
            .map_err(|e| format!("{path}: {e}"));
    }
    if overlay
        .lookup(&full, 0)
        .is_some_and(|fi| fi.mode & S_IFMT == S_IFDIR)
    {
        remove_tree(overlay, path)?;
    }
    if let Some((fi, data)) = read_entry(lower, path, limit)? {
        write_entry(overlay, path, &data, fi.mode, fi.mtime)
    } else {
        overlay
            .unlink(&format!("/{path}"))
            .map_err(|e| format!("{path}: {e}"))
    }
}

/// Exact matching with an offset search; no context lines are discarded.
fn apply_hunks(
    input: &[u8],
    hunks: &[parse::Hunk],
    limit: u64,
) -> Result<(Vec<u8>, Vec<usize>), String> {
    let mut lines: Vec<&[u8]> = input.split_inclusive(|b| *b == b'\n').collect();
    let mut failed = Vec::new();
    let mut floor = 0;
    let mut offset = 0i128;
    let mut length = input.len() as u64;
    for (index, hunk) in hunks.iter().enumerate() {
        let before: Vec<_> = hunk
            .lines
            .iter()
            .filter(|(tag, _)| *tag != b'+')
            .map(|(_, s)| s.as_slice())
            .collect();
        let after: Vec<_> = hunk
            .lines
            .iter()
            .filter(|(tag, _)| *tag != b'-')
            .map(|(_, s)| s.as_slice())
            .collect();
        let stated = hunk
            .old_start
            .saturating_sub(usize::from(hunk.old_count != 0));
        let expected = (stated as i128 + offset).clamp(0, lines.len() as i128) as usize;
        // Prefer the stated line, then search forward/backward by distance.
        let at = std::iter::once(Some(expected))
            .chain((1..=lines.len()).flat_map(|distance| {
                [
                    expected.checked_add(distance),
                    expected.checked_sub(distance),
                ]
            }))
            .flatten()
            .filter(|at| *at >= floor && *at <= lines.len())
            .find(|at| {
                if before.is_empty() && *at as i128 != stated as i128 + offset {
                    return false;
                }
                lines
                    .get(*at..at.saturating_add(before.len()))
                    .is_some_and(|slice| slice == before)
            });
        let Some(at) = at else {
            failed.push(index);
            continue;
        };
        let removed: u64 = before.iter().map(|s| s.len() as u64).sum();
        let added: u64 = after.iter().map(|s| s.len() as u64).sum();
        length = length.saturating_sub(removed).saturating_add(added);
        if length > limit {
            return Err("postimage exceeds --max-patch-bytes".into());
        }
        lines.splice(at..at + before.len(), after);
        floor = at + hunk.new_count;
        // Include both the actual location and cumulative insertions/deletions.
        offset = at as i128 - stated as i128 + hunk.new_count as i128 - hunk.old_count as i128;
    }
    Ok((lines.concat(), failed))
}
