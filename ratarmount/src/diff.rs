//! Offline diff CLI. Change detection and canonical hashes live in compositing.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{ArgGroup, Parser};
use ratarmount_compositing::overlay_changes::{
    self as core, Algorithm, ChangeOptions, Entry, Normalize,
};
use ratarmount_compositing::{compose_stack, Immutability, OverlayMeta};
use ratarmount_core::{MountSource, S_IFDIR, S_IFMT};

mod live;
mod patch;
#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug, Parser)]
#[command(name = "ratarmount diff", about = "Compare an overlay with its composed lower view (no mount required)",
    long_about = "Compare an overlay with its composed lower view without mounting it. Render byte-preserving patches, path summaries, manifests, or canonical hashes against the base and optional lower layers.",
    after_help = "Example: ratarmount diff attempt base.tar.zst --git\n\nExit status:\n  0  No changes, or successful --hash/--manifest output.\n  1  Changes found.\n  2  Invalid input or operational error.\n  3  Size/file limit exceeded.",
    group(ArgGroup::new("mode").args(["patch", "git", "manifest", "hash", "stat", "name_only", "name_status"])))]
pub struct DiffArgs {
    pub directory: PathBuf,
    /// Index sidecar folders read when opening the base (as for a mount).
    #[arg(long, value_name = "FOLDERS")]
    pub index_folders: Option<String>,
    /// Archive, committed Git repository, folder or URL; defaults to meta.base_url.
    #[arg(value_name = "BASE")]
    pub base_source: Option<PathBuf>,
    #[arg(long, hide = true)]
    pub base: Option<PathBuf>,
    /// Unified patch (the default).
    #[arg(long)]
    pub patch: bool,
    /// Git-apply-compatible patch, including literal binary sections.
    #[arg(long)]
    pub git: bool,
    /// One JSON object per changed path.
    #[arg(long)]
    pub manifest: bool,
    /// Canonical content hash, independent of patch formatting.
    #[arg(long)]
    pub hash: bool,
    /// Print per-path line counts, totals and bytes written.
    #[arg(long)]
    pub stat: bool,
    #[arg(long)]
    pub name_only: bool,
    /// Print A/M/D/T (or written without a base) and paths.
    #[arg(long)]
    pub name_status: bool,
    /// Compare OTHER_DIR's tree to OVERLAY_DIR's tree on the same stack.
    #[arg(long, value_name = "OTHER_DIR")]
    pub between: Option<PathBuf>,
    /// Lower overlays, bottom to top; defaults to meta.lower_layers.
    #[arg(long, value_name = "DIR")]
    pub lower: Vec<PathBuf>,
    /// Hash/manifest normalization only; loose is for analysis, not grading.
    #[arg(long, default_value = "exact", value_parser = ["exact", "strict", "loose"])]
    pub normalize: String,
    /// Gitignore-style mount-relative exclusion; repeatable.
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,
    #[arg(long)]
    pub ignore_mode: bool,
    /// Hash algorithm: blake3 is several times faster without SHA CPU
    /// extensions and suits grading loops; keep sha256 for published digests.
    #[arg(long, default_value = "sha256", value_parser = ["sha256", "blake3"])]
    pub algo: String,
    /// Refuse unsealed top and lower overlays.
    #[arg(long)]
    pub strict: bool,
    /// Text above this size per side uses binary rendering (including Git literals).
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub max_diff_bytes: u64,
    /// Limit rendered patch bytes and per-payload input work; exceeded => exit 3.
    #[arg(long)]
    pub max_patch_bytes: Option<u64>,
    /// Limit changed paths / manifest rows; exceeded => exit 3.
    #[arg(long)]
    pub max_files: Option<usize>,
    /// Machine-readable --stat or --hash.
    #[arg(long)]
    pub json: bool,
    #[arg(short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Detect exact-content renames (never used for --hash/--manifest).
    #[arg(long)]
    pub detect_renames: bool,
    #[arg(short = 'U', long, default_value_t = 3)]
    pub context: usize,
    #[arg(long)]
    pub include_git_dir: bool,
    #[command(flatten)]
    pub identity: crate::overlay_cmd::BaseIdentityArgs,
}

impl Default for DiffArgs {
    fn default() -> Self {
        Self::parse_from(["ratarmount diff", "unused"])
    }
}

impl DiffArgs {
    fn is_patch(&self) -> bool {
        !(self.manifest || self.hash || self.stat || self.name_only || self.name_status)
    }
    fn options(&self) -> ChangeOptions {
        ChangeOptions {
            normalize: if !(self.hash || self.manifest) {
                Normalize::Exact
            } else {
                match self.normalize.as_str() {
                    "strict" => Normalize::Strict,
                    "loose" => Normalize::Loose,
                    _ => Normalize::Exact,
                }
            },
            algo: if self.algo == "blake3" {
                Algorithm::Blake3
            } else {
                Algorithm::Sha256
            },
            excludes: self.exclude.clone(),
            ignore_mode: self.ignore_mode,
            include_git_dir: self.include_git_dir,
            max_files: self.max_files,
            max_content_bytes: if self.is_patch() {
                self.max_patch_bytes
            } else {
                None
            },
        }
    }
}

// Rendering-only rename pairs. Canonical rows always remain delete + add.
#[derive(Clone, Debug)]
struct Change {
    from: String,
    to: String,
    old: Option<Entry>,
    new: Option<Entry>,
}
impl Change {
    fn status(&self) -> &'static str {
        match (&self.old, &self.new) {
            (None, _) => "A",
            (_, None) => "D",
            (Some(_), Some(_)) if self.from != self.to => "R100",
            (Some(a), Some(b)) if a.kind() != b.kind() => "T",
            _ => "M",
        }
    }
}

fn render_changes(changes: &[core::Change], args: &DiffArgs) -> io::Result<Vec<Change>> {
    let mut out = Vec::new();
    for change in changes {
        let path = std::str::from_utf8(&change.path)
            .map_err(io::Error::other)?
            .to_owned();
        out.push(Change {
            from: path.clone(),
            to: path,
            old: change.old.clone(),
            new: change.new.clone(),
        });
    }
    if args.detect_renames {
        detect_renames(&mut out);
    }
    Ok(out)
}

fn detect_renames(changes: &mut Vec<Change>) {
    let mut pairs = Vec::new();
    let mut used = BTreeSet::new();
    for (i, change) in changes.iter().enumerate().filter(|(_, c)| c.new.is_none()) {
        let Some(before) = &change.old else {
            continue;
        };
        if before.mode & S_IFMT == S_IFDIR {
            continue;
        }
        if let Some((j, _)) = changes.iter().enumerate().find(|(j, c)| {
            !used.contains(j)
                && c.old.is_none()
                && c.new
                    .as_ref()
                    .is_some_and(|after| before.kind() == after.kind() && before.hash == after.hash)
        }) {
            used.insert(j);
            pairs.push((i, j));
        }
    }
    for (i, j) in pairs {
        changes[i].to = changes[j].to.clone();
        changes[i].new = changes[j].new.take();
    }
    let mut index = 0;
    changes.retain(|_| {
        let keep = !used.contains(&index);
        index += 1;
        keep
    });
    changes.sort_by(|a, b| a.from.cmp(&b.from).then(a.to.cmp(&b.to)));
}

// Factory backends print cold-index progress to stdout. During the single-threaded
// CLI open, send it to stderr so stdout remains a patch. Restore on all errors.
pub(crate) struct ProgressToStderr(OwnedFd);

impl ProgressToStderr {
    pub(crate) fn new() -> io::Result<Self> {
        io::stdout().flush()?;
        let fd = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let saved = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        if unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(saved)
    }
}

impl Drop for ProgressToStderr {
    fn drop(&mut self) {
        let _ = io::stdout().flush();
        unsafe {
            libc::dup2(self.0.as_raw_fd(), libc::STDOUT_FILENO);
        }
    }
}

fn read_meta(dir: &Path, strict: bool) -> io::Result<Option<OverlayMeta>> {
    let meta = OverlayMeta::read(dir).map_err(io::Error::other)?;
    if strict && !meta.as_ref().is_some_and(OverlayMeta::layer_sealed) {
        return Err(io::Error::other(format!(
            "{}: unsealed overlay refused by --strict",
            dir.display()
        )));
    }
    match &meta {
        None => eprintln!("diff: {}: legacy overlay", dir.display()),
        Some(m) if m.legacy() => eprintln!("diff: {}: legacy overlay", dir.display()),
        Some(m) if !m.layer_sealed() => eprintln!(
            "diff: {}: unsealed overlay; stop writers before diff",
            dir.display()
        ),
        _ => {}
    }
    core::mentioned_paths(dir)?;
    Ok(meta)
}

struct Prepared {
    changes: Vec<core::Change>,
    options: ChangeOptions,
    meta: Option<OverlayMeta>,
    /// Set when `--force-base-mismatch` overrode a changed base:
    /// (recorded digest, digest of the base actually diffed).
    forced_base: Option<(Option<String>, String)>,
    /// A recorded row or an equal strong digest confirmed the base; false for
    /// a remote base with nothing cheap to compare (recorded identity unconfirmed).
    base_confirmed: bool,
}

fn prepare(
    args: &DiffArgs,
    context: &crate::base_identity::OverlayRunContext,
) -> io::Result<Prepared> {
    if args.json && !(args.hash || args.stat) {
        return Err(io::Error::other("--json requires --hash or --stat"));
    }
    let options = args.options();
    core::Excludes::new(&options)?;
    if options.normalize == Normalize::Loose {
        eprintln!("diff: warning: loose normalization is for analysis only, never grading");
    }
    let meta = read_meta(&args.directory, args.strict)?;
    let explicit_base = args.base_source.as_ref().or(args.base.as_ref());
    let recorded_base = meta
        .as_ref()
        .and_then(OverlayMeta::base_url)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let base = explicit_base.or(recorded_base.as_ref());
    if explicit_base.is_none() {
        if let Some(base) = base {
            eprintln!("diff: using base from overlay metadata: {}", base.display());
        }
    }
    let Some(_) = base else {
        if args.is_patch() || args.stat || args.between.is_some() || !args.lower.is_empty() {
            return Err(io::Error::other("BASE (or --base SOURCE / meta.base_url) is required for patches, --stat, --lower and --between"));
        }
        return Ok(Prepared {
            changes: core::change_set_without_base(&args.directory, &options)?,
            options,
            meta,
            forced_base: None,
            base_confirmed: false,
        });
    };
    let lower_dirs = if args.lower.is_empty() {
        meta.as_ref()
            .map(|m| {
                m.lower_layers()
                    .map(|ls| ls.into_iter().map(|l| l.path).collect())
            })
            .transpose()
            .map_err(io::Error::other)?
            .unwrap_or_default()
    } else {
        args.lower.clone()
    };
    let mut layers = Vec::new();
    for dir in lower_dirs {
        let m = read_meta(&dir, args.strict)?;
        let immutable = if m.as_ref().is_some_and(OverlayMeta::layer_sealed) {
            Immutability::Immutable
        } else {
            Immutability::Shared
        };
        layers.push((dir, immutable));
    }
    if let Some(other) = &args.between {
        let other_meta = read_meta(other, args.strict)?;
        let legacy = |m: &Option<OverlayMeta>| m.as_ref().is_none_or(OverlayMeta::legacy);
        if legacy(&meta) && legacy(&other_meta) {
            if explicit_base.is_none() || args.lower.is_empty() {
                return Err(io::Error::other("legacy --between requires an explicit BASE and --lower stack shared by both overlays"));
            }
            eprintln!("diff: legacy --between: using the explicitly supplied BASE and --lower stack for both overlays");
        } else {
            let stack = meta.as_ref().and_then(OverlayMeta::stack_digest);
            if stack.is_none() || stack != other_meta.as_ref().and_then(OverlayMeta::stack_digest) {
                return Err(io::Error::other(
                    "--between requires both overlays to record the same stack_digest",
                ));
            }
        }
    }
    // Open the base through the factory (a `.git` working tree is Git only
    // when the overlay recorded Git), keeping lazy lookup/open progress off
    // stdout as well as factory progress.
    let _progress = ProgressToStderr::new()?;
    let classified = crate::overlay_cmd::classify_base(explicit_base, meta.as_ref(), None, context)
        .map_err(io::Error::other)?;
    // Same cheap identity check as reopen and `--lower`: a base that is not the
    // one the overlay recorded must not be diffed silently.
    let gate =
        crate::overlay_cmd::gate_base(&args.directory, meta.as_ref(), &classified, &args.identity)
            .map_err(io::Error::other)?;
    let base_confirmed = gate.as_ref().is_some_and(|outcome| outcome.confirmed);
    let forced_base = gate.and_then(|outcome| {
        outcome.forced.map(|rows| {
            (
                outcome.recorded,
                rows.get("base_digest").cloned().unwrap_or_default(),
            )
        })
    });
    let source = classified.source();
    let stack = compose_stack(source, &layers)?;
    let changes = if let Some(other) = &args.between {
        core::between(&args.directory, other, stack, &options)?
    } else {
        core::change_set(&args.directory, stack, &options)?
    };
    Ok(Prepared {
        changes,
        options,
        meta,
        forced_base,
        base_confirmed,
    })
}

fn render(prepared: &Prepared, args: &DiffArgs, out: &mut dyn Write) -> io::Result<()> {
    if args.manifest {
        return core::write_manifest(&prepared.changes, out);
    }
    if args.hash {
        let hash = core::canonical_hash(&prepared.changes, &prepared.options)?;
        if args.json {
            let meta = prepared.meta.as_ref();
            // A pending archive base has no digest yet: report base and stack as
            // unknown (null), never a stack derived from the empty string.
            let forced = prepared.forced_base.as_ref();
            // A forced run reports the base actually diffed, never the stale
            // recorded value; an unforced one has just confirmed the recorded one.
            let base = match forced {
                Some((_, actual)) => Some(actual.as_str()),
                None => meta.and_then(OverlayMeta::known_base_digest),
            };
            let pending = meta.is_some_and(|m| m.base_digest_kind() == Some("pending"));
            let mut stack = meta.and_then(OverlayMeta::stack_digest).map(str::to_owned);
            if forced.is_some() {
                stack = None;
            }
            if stack.is_none() {
                if let Some(base) = base {
                    let lower = meta.unwrap().lower_layers().map_err(io::Error::other)?;
                    stack = Some(ratarmount_compositing::stack_digest(
                        base,
                        &lower
                            .iter()
                            .map(|l| l.layer_digest.as_str())
                            .collect::<Vec<_>>(),
                    ));
                }
            }
            serde_json::to_writer(
                &mut *out,
                &serde_json::json!({"patch":hash,"base":base,"base_forced":forced.is_some(),"base_identity":if forced.is_some() { "forced" } else if prepared.base_confirmed { "confirmed" } else { "unconfirmed" },"base_recorded":forced.and_then(|(recorded, _)| recorded.as_deref()),"stack":stack,"files":prepared.changes.len(),"normalize":prepared.options.normalize.as_str(),"excludes":args.exclude,"algo":prepared.options.algo.as_str(),"sealed":meta.is_some_and(OverlayMeta::layer_sealed),"base_pending":pending,"base_digest_state":meta.map_or("none", OverlayMeta::base_digest_state)}),
            )?;
            out.write_all(b"\n")?;
        } else {
            writeln!(out, "{hash}")?;
        }
        return Ok(());
    }
    if args.name_only
        || (args.name_status
            && prepared
                .changes
                .iter()
                .any(|c| c.status == core::Status::Written))
    {
        for change in &prepared.changes {
            if args.name_status {
                write!(out, "{}\t", change.status.letter())?;
            }
            writeln!(out, "{}", patch::quote_bytes(&change.path))?;
        }
        return Ok(());
    }
    patch::render(&render_changes(&prepared.changes, args)?, args, out)
}

struct LimitedWriter<'a> {
    inner: &'a mut dyn Write,
    left: u64,
}
impl Write for LimitedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.left {
            return Err(core::limit_error(
                "rendered patch exceeds --max-patch-bytes",
            ));
        }
        let n = self.inner.write(bytes)?;
        self.left -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn write_output(prepared: &Prepared, args: &DiffArgs, out: &mut dyn Write) -> io::Result<()> {
    if let Some(limit) = args.max_patch_bytes.filter(|_| args.is_patch()) {
        render(
            prepared,
            args,
            &mut LimitedWriter {
                inner: out,
                left: limit,
            },
        )
    } else {
        render(prepared, args, out)
    }
}

/// Keep the daemon's live inspection path: its writer holds the database lock,
/// so tombstones arrive through the inspection socket rather than a SQL read.
pub(crate) fn render_source(
    args: &DiffArgs,
    source: Arc<dyn MountSource>,
    deleted: Option<Vec<String>>,
) -> Result<Vec<u8>, String> {
    let result = || -> io::Result<Vec<u8>> {
        let options = args.options();
        let changes = match deleted {
            Some(deleted) => live::changes(args, source, deleted)?,
            None => core::change_set(&args.directory, source, &options)?,
        };
        let mut output = Vec::new();
        write_output(
            &Prepared {
                changes,
                options,
                meta: None,
                forced_base: None,
                base_confirmed: false,
            },
            args,
            &mut output,
        )?;
        Ok(output)
    };
    result().map_err(|e| e.to_string())
}

fn execute(args: &DiffArgs, context: &crate::base_identity::OverlayRunContext) -> io::Result<i32> {
    let prepared = prepare(args, context)?;
    // Withhold partial output on a limit/error. The spool holds rendered bytes,
    // not all source payloads, and is removed automatically on every error.
    let mut spool = tempfile::tempfile()?;
    write_output(&prepared, args, &mut spool)?;
    spool.rewind()?;
    if let Some(path) = &args.output {
        let mut out = fs::File::create(path)?;
        io::copy(&mut spool, &mut out)?;
        out.flush()?;
    } else {
        io::copy(&mut spool, &mut io::stdout().lock())?;
    }
    Ok(if args.hash || args.manifest {
        0
    } else {
        i32::from(!prepared.changes.is_empty())
    })
}

pub fn run(args: &DiffArgs, context: &crate::base_identity::OverlayRunContext) -> i32 {
    match execute(args, context) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("diff: {error}");
            if core::is_limit_error(&error) {
                3
            } else {
                2
            }
        }
    }
}
