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
use ratarmount_core::{FileInfo, MountSource, S_IFLNK, S_IFMT, S_IFREG};

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
        let (lowers, view) =
            super::MountLowerStack::open(classified.source(), None, lower, allow_unsealed_lower)?;
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
    #[cfg_attr(
        internal_read_inventory,
        expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0044-M01","item":"ratarmount::overlay_import::run","disposition":"out-of-family","category":"patch-or-bundle-input","reason":"patch input stream","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )
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
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0122-M01","item":"ratarmount::overlay_import::import","disposition":"output-owner","category":"overlay-import-directory","reason":"Claim the validated overlay import destination before opening its database.","creation":{"policy":"exclusive-directory","basis":"create_dir is called only for a missing destination; cleanup does not remove a directory whose claim/empty check failed."}}"###
            )
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
        let mut written = BTreeSet::new();
        let mut rejected = BTreeSet::new();
        let mut rejects: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for patch in patches {
            for path in patch.old.iter().chain(&patch.new) {
                check_parents(&overlay, stack.view.as_ref(), path)?;
            }
            // Type changes can be separate delete/add sections. Once any
            // section fails, keep that whole file at its original lower state.
            let already_rejected = patch
                .old
                .iter()
                .chain(&patch.new)
                .any(|p| rejected.contains(p));
            let original = match &patch.old {
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
                    restore(&overlay, stack.view.as_ref(), path, args.max_patch_bytes)?;
                    written.remove(path);
                    rejected.insert(path.clone());
                }
                let name = format!("{}.rej", patch.path());
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
            if patch.old.is_none() && overlay.lookup(&format!("/{}", patch.path()), 0).is_some() {
                return Err(format!("{}: added file already exists", patch.path()));
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

fn check_parents(
    overlay: &dyn MountSource,
    lower: &dyn MountSource,
    path: &str,
) -> Result<(), String> {
    for (i, _) in path.match_indices('/') {
        let parent = format!("/{}", &path[..i]);
        for source in [lower, overlay] {
            if let Some(fi) = source.lookup(&parent, 0) {
                if fi.mode & S_IFMT == S_IFLNK {
                    return Err(format!("{path}: symlink parent {parent} is refused"));
                }
                if fi.mode & S_IFMT != ratarmount_core::S_IFDIR {
                    return Err(format!("{path}: parent {parent} is not a directory"));
                }
            }
        }
    }
    Ok(())
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
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0045-M01","item":"ratarmount::overlay_import::write_entry","disposition":"residual","reason":"overlay payload descriptor borrowed from create_file for an import write; reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
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
    limit: u64,
) -> Result<(), String> {
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
