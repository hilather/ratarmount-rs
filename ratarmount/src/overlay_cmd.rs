//! Offline overlay commands. Keep each verb's implementation independent.

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use ratarmount_compositing::{ClassifiedBase, OverlayMeta, OverlayStats};

use super::base_identity::{classify_offline, GitIntent, OverlayRunContext};

#[path = "overlay_upperdir.rs"]
mod upperdir;

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount overlay",
    about = "Inspect and manage write overlays offline"
)]
pub struct OverlayArgs {
    /// Index sidecar folders the verbs read when they open the base (as for a mount).
    ///
    /// A custom folder is where a cached digest of a local copy is found; the
    /// index is only ever read.
    #[arg(long, global = true, value_name = "FOLDERS")]
    pub index_folders: Option<String>,
    #[command(subcommand)]
    pub command: OverlayCommand,
}

#[derive(Debug, Subcommand)]
pub enum OverlayCommand {
    /// Show metadata, counts, and writability without modifying the overlay.
    ///
    /// Read creation metadata and overlay statistics without creating or repairing a database.
    #[command(
        after_help = "Example: ratarmount overlay info attempt --json\n\nExit status:\n  0  Metadata displayed.\n  1  Operational error.\n  2  Invalid arguments."
    )]
    Info(InfoArgs),
    /// Import a unified or Git patch into a new overlay.
    ///
    /// Apply a patch against a base and optional lower layers, then seal the result unless --no-seal is set.
    #[command(
        after_help = "Example: ratarmount overlay import attempt.patch replay base.tar.zst\n\nExit status:\n  0  Patch imported.\n  1  Hunks rejected with --reject.\n  2  Invalid input or operational error."
    )]
    Import(super::overlay_import::ImportArgs),
    /// Import a stopped kernel overlayfs upperdir.
    ///
    /// Translate whiteouts and opaque directories against the supplied lower stack, sealing the result unless --no-seal is set.
    #[command(
        after_help = "Example: ratarmount overlay import-upperdir upper replay base.tar.zst\n\nExit status:\n  0  Upperdir imported.\n  2  Invalid input or operational error."
    )]
    ImportUpperdir(upperdir::ImportUpperdirArgs),
    /// Seal exact changes and make the overlay read-only.
    ///
    /// Check consistency, record the exact change digest, and remove host write permissions; repeating seal returns the recorded digest.
    #[command(
        after_help = "Example: ratarmount overlay seal attempt base.tar.zst\n\nExit status:\n  0  Overlay sealed or already sealed.\n  2  Invalid input or operational error."
    )]
    Seal(SealCmd),
    /// Restore owner write permission and remove the seal.
    ///
    /// Require --i-know to discard the immutability guarantee, clear recorded seal hashes, and restore owner write access.
    #[command(
        after_help = "Example: ratarmount overlay unseal attempt --i-know\n\nExit status:\n  0  Overlay unsealed.\n  2  Invalid input (including missing --i-know) or operational error."
    )]
    Unseal {
        directory: PathBuf,
        #[arg(long)]
        i_know: bool,
    },
    /// Verify an overlay seal.
    ///
    /// Recompute exact changes against the base and lower layers and compare the digest, per-path hashes, and seal sentinel.
    #[command(
        after_help = "Example: ratarmount overlay verify attempt base.tar.zst --json\n\nExit status:\n  0  Seal matches.\n  1  Seal mismatch.\n  2  Invalid input, operational error, or overlay not sealed."
    )]
    Verify(VerifyArgs),
    /// Print the strong digest of a directory or archive base (experimental).
    ///
    /// Reads the whole base once and prints `sha256:<hex>`, for `--base-digest`. Opens no overlay, index or cache.
    #[command(
        after_help = "Example: ratarmount overlay digest-base base-dir --exclude-overlay base-dir/.ov --json\n\nExit status:\n  0  Digest printed.\n  1  Unreadable path, special file, or an un-excluded overlay inside the directory."
    )]
    DigestBase(DigestBaseArgs),
    /// Pack a sealed overlay as a portable seekable tar.zst bundle.
    ///
    /// Bundle the sealed overlay with a manifest against the lower view, optionally including its journal and indexes.
    #[command(
        after_help = "Example: ratarmount overlay pack attempt attempt.tar.zst\n\nExit status:\n  0  Bundle written.\n  2  Invalid input or operational error, including an unsealed overlay."
    )]
    Pack(PackArgs),
    /// Restore a sealed overlay from a bundle.
    ///
    /// Safely extract the overlay and check its seal; when the recorded stack is unavailable, check only the immutable database and sentinel.
    #[command(
        after_help = "Example: ratarmount overlay unpack attempt.tar.zst restored\n\nExit status:\n  0  Restored checks match.\n  1  Seal mismatch.\n  2  Invalid input or operational error."
    )]
    Unpack {
        bundle: PathBuf,
        directory: PathBuf,
        /// Refuse a bundle that extracts more than SIZE bytes (experimental; default 32G, or $RATARMOUNT_BUNDLE_MAX_BYTES).
        #[arg(long, value_name = "SIZE", value_parser = ratarmount_compositing::parse_overlay_size)]
        max_bytes: Option<u64>,
        /// Refuse a bundle with more than N entries (experimental; default 1000000, or $RATARMOUNT_BUNDLE_MAX_ENTRIES).
        #[arg(long, value_name = "N")]
        max_entries: Option<u64>,
    },
    /// Check overlay consistency.
    ///
    /// Inspect database rows and host entries after unmounting; --repair fixes recoverable inconsistencies and refuses sealed overlays.
    #[command(
        after_help = "Example: ratarmount overlay fsck attempt --repair --json\n\nExit status:\n  0  Clean or repaired.\n  1  Unrepaired inconsistencies.\n  2  Invalid input or operational error."
    )]
    Fsck {
        directory: PathBuf,
        #[arg(long)]
        repair: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
pub struct DigestBaseArgs {
    pub path: PathBuf,
    /// Leave an overlay, journal or lower layer that lives inside the directory out of the digest (repeatable).
    #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
    pub exclude_overlay: Vec<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PackArgs {
    #[command(flatten)]
    pub identity: BaseIdentityArgs,
    pub directory: PathBuf,
    pub bundle: PathBuf,
    #[arg(long)]
    pub include_journal: Option<PathBuf>,
    #[arg(long)]
    pub include_index: bool,
    #[arg(long, action = clap::ArgAction::Append)]
    pub lower: Vec<PathBuf>,
    pub base: Option<PathBuf>,
}

/// How `seal`, `pack` and `diff` treat a base that no longer matches the
/// identity the overlay recorded.
#[derive(Debug, Args, Default, Clone)]
pub struct BaseIdentityArgs {
    /// Proceed although the base differs from the one the overlay recorded (experimental).
    ///
    /// Seal and pack record the base actually used (its kind, place and the
    /// override time); diff reports it. With --base-digest that digest is
    /// recorded as strong; without one the base is recorded kind-only (`none`):
    /// later runs compare the kind, not the content. Without this flag a
    /// changed base (or one of another kind) is refused.
    #[arg(long)]
    pub force_base_mismatch: bool,
    /// Strong digest of the base (from `overlay digest-base`), confirming a copy without hashing (experimental).
    #[arg(long, value_name = "sha256:HEX", value_parser = parse_supplied_digest)]
    pub base_digest: Option<String>,
}

fn parse_supplied_digest(value: &str) -> Result<String, String> {
    match value.parse::<ratarmount_compositing::BaseDigestRequest>()? {
        ratarmount_compositing::BaseDigestRequest::Supplied(digest) => Ok(digest),
        _ => Err("expected sha256:<64 hex digits>".into()),
    }
}

#[derive(Debug, Args)]
pub struct SealCmd {
    #[command(flatten)]
    pub seal: SealArgs,
    #[command(flatten)]
    pub identity: BaseIdentityArgs,
}

#[derive(Debug, Args)]
pub struct SealArgs {
    pub directory: PathBuf,
    /// Base source (defaults to recorded base_url).
    pub base: Option<PathBuf>,
    /// Sealed lower layer, bottom to top (defaults to recorded lower_layers).
    #[arg(long, action = clap::ArgAction::Append)]
    pub lower: Vec<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub seal: SealArgs,
    /// Skip comparing the base with its recorded digest (experimental).
    ///
    /// By default verify also recomputes the base: a full read when the
    /// recorded digest is strong, a stat walk when it is a weak directory digest.
    #[arg(long)]
    pub no_base_check: bool,
}

#[derive(Debug, Args)]
pub struct InfoArgs {
    pub directory: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &OverlayArgs, context: &OverlayRunContext) -> Result<(String, i32), String> {
    match &args.command {
        OverlayCommand::Info(args) => info(args).map(|output| (output, 0)),
        OverlayCommand::Import(args) => super::overlay_import::run(args, context),
        OverlayCommand::ImportUpperdir(args) => Ok(bundle_exit(upperdir::run(args, context))),
        OverlayCommand::Seal(args) => seal(args, context),
        OverlayCommand::Unseal { directory, i_know } => unseal(directory, *i_know),
        OverlayCommand::Verify(args) => verify(args, context),
        OverlayCommand::DigestBase(args) => digest_base(args),
        OverlayCommand::Pack(args) => Ok(bundle_exit(pack(args, context))),
        OverlayCommand::Unpack {
            bundle,
            directory,
            max_bytes,
            max_entries,
        } => Ok(bundle_exit(unpack(
            bundle,
            directory,
            *max_bytes,
            *max_entries,
        ))),
        OverlayCommand::Fsck {
            directory,
            repair,
            json,
        } => fsck(directory, *repair, *json),
    }
}

fn digest_base(args: &DigestBaseArgs) -> Result<(String, i32), String> {
    let meta = std::fs::metadata(&args.path)
        .map_err(|e| format!("digest-base {}: {e}", args.path.display()))?;
    let (kind, digest, excluded) = if meta.is_dir() {
        let (base, excludes) =
            ratarmount_compositing::resolve_base_excludes(&args.path, &args.exclude_overlay)
                .map_err(|e| e.to_string())?;
        if !excludes.paths().is_empty() {
            let names: Vec<_> = excludes
                .paths()
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            eprintln!("excluding: {}", names.join(", "));
        }
        let digest = ratarmount_compositing::directory_digest_excluding(&base, &excludes)
            .map_err(|e| e.to_string())?;
        let excluded: Vec<String> = excludes
            .paths()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        ("directory", digest, excluded)
    } else {
        let mut file = std::fs::File::open(&args.path)
            .map_err(|e| format!("digest-base {}: {e}", args.path.display()))?;
        let hex = ratarmount_index::sha256_hex_stream(&mut file)
            .map_err(|e| format!("digest-base {}: {e}", args.path.display()))?;
        ("file", format!("sha256:{hex}"), Vec::new())
    };
    if args.json {
        let mut value = serde_json::json!({
            "path": args.path.display().to_string(),
            "kind": kind,
            "digest": digest,
        });
        if kind == "directory" {
            value["excluded"] = serde_json::json!(excluded);
        }
        Ok((value.to_string(), 0))
    } else {
        Ok((digest, 0))
    }
}

// The mount dispatch historically maps unknown offline errors to exit 1.
// Bundle verbs reserve that code for a digest mismatch.
fn bundle_exit(result: Result<(String, i32), String>) -> (String, i32) {
    result.unwrap_or_else(|error| {
        eprintln!("{error}");
        (String::new(), 2)
    })
}

pub fn unpack(
    bundle: &Path,
    directory: &Path,
    max_bytes: Option<u64>,
    max_entries: Option<u64>,
) -> Result<(String, i32), String> {
    let _progress = super::diff::ProgressToStderr::new().map_err(|e| e.to_string())?;
    let limits = super::overlay_pack::Limits::resolve(max_bytes, max_entries)
        .map_err(|e| format!("unpack {}: {e}", bundle.display()))?;
    let result = super::overlay_pack::unpack_with_limits(bundle, directory, limits)
        .map_err(|e| format!("unpack {}: {e}", bundle.display()))?;
    if !result.verified {
        eprintln!("content not verified; run `overlay verify DIR BASE` before using it as a lower");
    }
    let output = if result.ok {
        result.layer_digest
    } else {
        format!("{}\nseal mismatch", result.layer_digest)
    };
    Ok((output, i32::from(!result.ok)))
}

/// Open the base a verb is about through the factory and classify what it
/// served. `explicit` is the BASE named on the command line, else the one the
/// overlay recorded; `git` decides whether a plain working tree is Git (replay
/// the recorded kind unless the caller opens the base as the user would).
pub(super) fn classify_base(
    explicit: Option<&PathBuf>,
    meta: Option<&OverlayMeta>,
    git: Option<GitIntent>,
    context: &OverlayRunContext,
) -> Result<ClassifiedBase, String> {
    let recorded = meta
        .and_then(OverlayMeta::base_url)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let base = explicit.cloned().or(recorded).ok_or_else(|| {
        "no metadata base_url; pass BASE explicitly (including for legacy overlays)".to_owned()
    })?;
    classify_offline(
        &base,
        git.unwrap_or_else(|| GitIntent::replay(meta)),
        context,
    )
    .map_err(|e| {
        // A recorded remote URL is stored without credentials, so a
        // credentialed remote cannot be reopened from the overlay alone.
        if explicit.is_none() && ratarmount_remote::is_remote_url(&base.to_string_lossy()) {
            format!("{e}; recorded base URL is stored without credentials; pass BASE explicitly")
        } else {
            e
        }
    })
}

/// The lower layers to compose: `--lower`, else the recorded ones.
fn lower_paths(lower: &[PathBuf], meta: Option<&OverlayMeta>) -> Result<Vec<PathBuf>, String> {
    if !lower.is_empty() {
        return Ok(lower.to_vec());
    }
    Ok(meta
        .map(OverlayMeta::lower_layers)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default()
        .into_iter()
        .map(|l| l.path)
        .collect())
}

/// The classified base under its lower layers: what the layer's changes are
/// measured against. Offline: a bundle lower is verified against this base,
/// never trusted by a previous verification (no strong key here).
pub(super) fn lower_view(
    base: &ClassifiedBase,
    lower: &[PathBuf],
    meta: Option<&OverlayMeta>,
) -> Result<std::sync::Arc<dyn ratarmount_core::MountSource>, String> {
    let lowers = lower_paths(lower, meta)?;
    super::MountLowerStack::open(base.source(), None, &lowers, false).map(|(_, view)| view)
}

/// What the identity gate decided for `seal`, `pack` and `diff`.
pub(super) struct GateOutcome {
    /// The digest the overlay recorded, when it knows one.
    pub recorded: Option<String>,
    /// Set when `--force-base-mismatch` overrode a mismatch: the rows that
    /// describe the base actually used (`base_digest`, `stack_digest`, ...).
    pub forced: Option<std::collections::BTreeMap<String, String>>,
    /// True when a recorded row (stamp, manifest, tree) or an equal strong
    /// digest confirmed the base. False for a base with nothing cheap to
    /// compare (remote): the recorded identity is then unconfirmed.
    pub confirmed: bool,
    /// The base is at another place than the one the overlay recorded and
    /// nothing confirmed its content with a strong digest (the recorded one,
    /// supplied or cached): accepted only because the record cannot tell.
    pub unconfirmed_move: bool,
    /// The base is at another place than the recorded one.
    pub moved: bool,
}

/// Compare the classified base with the identity the overlay recorded, with
/// the check the `--lower` mount uses (metadata only, no hashing). The kind
/// the opener served is compared under every digest kind (a `none` overlay is
/// kind-only, not exempt); a base that moved between local and remote agrees
/// only for a strong record that a supplied `--base-digest` equals.
pub(super) fn gate_base(
    dir: &Path,
    meta: Option<&OverlayMeta>,
    base: &ClassifiedBase,
    identity: &BaseIdentityArgs,
) -> Result<Option<GateOutcome>, String> {
    use ratarmount_compositing::overlay_gate::{
        compare_base_identity, forced_base_record, BaseProbe,
    };
    let probe = BaseProbe {
        supplied: identity.base_digest.as_deref(),
        extra_excludes: &[],
    };
    let comparison = compare_base_identity(meta, base, &probe)?;
    let recorded = meta.and_then(|m| m.known_base_digest()).map(str::to_owned);
    let Some(current) = &comparison.mismatch else {
        let confirmed = comparison.compared
            || meta.is_some_and(|m| {
                m.base_digest_kind() == Some("strong")
                    && identity.base_digest.as_deref() == m.base_digest()
            });
        let moved = meta.is_some_and(|m| {
            ratarmount_compositing::overlay_gate::identity_rows(Some(m), base)
                .and_then(|rows| rows.get("base_location").cloned())
                .zip(m.get("base_location"))
                .is_some_and(|(now, then)| now != then)
        });
        let strong = meta.is_some_and(|m| {
            m.base_digest_kind() == Some("strong")
                && (identity.base_digest.as_deref() == m.base_digest()
                    || comparison.cached_digest.as_deref() == m.base_digest())
        });
        return Ok(Some(GateOutcome {
            recorded,
            forced: None,
            confirmed,
            unconfirmed_move: moved && !strong,
            moved,
        }));
    };
    let meta = meta.expect("a mismatch is measured against recorded metadata");
    if !identity.force_base_mismatch {
        let strong_hint = if meta.base_digest_kind() == Some("strong") {
            "; for a byte-identical copy pass its strong digest with --base-digest sha256:<hex> (see `overlay digest-base`), which confirms identity without hashing"
        } else {
            ""
        };
        return Err(format!(
            "base mismatch: {} is not the base overlay {} recorded (recorded {}; current {current}); identity could not be confirmed cheaply{strong_hint}; use --force-base-mismatch to proceed with the base as it is now",
            base.actual().base_url(),
            dir.display(),
            meta.base_digest().filter(|d| !d.is_empty()).unwrap_or("pending"),
        ));
    }
    if identity.base_digest.is_none() && meta.base_digest_kind() != Some("none") {
        eprintln!("warning: forcing a base change without --base-digest records the base as kind-only (`none`): later runs compare the kind, not the content, until you supply --base-digest");
    }
    let forced = forced_base_record(meta, base, &probe)?;
    Ok(Some(GateOutcome {
        recorded,
        forced: Some(forced),
        confirmed: false,
        unconfirmed_move: false,
        moved: true,
    }))
}

pub fn pack(args: &PackArgs, context: &OverlayRunContext) -> Result<(String, i32), String> {
    let meta = OverlayMeta::read(&args.directory).map_err(|e| e.to_string())?;
    if !meta.as_ref().is_some_and(OverlayMeta::layer_sealed) {
        return Err("overlay is not sealed".into());
    }
    let _progress = super::diff::ProgressToStderr::new().map_err(|e| e.to_string())?;
    let base = classify_base(args.base.as_ref(), meta.as_ref(), None, context)?;
    let outcome = gate_base(&args.directory, meta.as_ref(), &base, &args.identity)?;
    // The bundle carries the sealed record. A base at another place whose
    // content nothing confirmed would be measured for the manifest but never
    // be the base the seal describes: refuse it unless forced.
    if outcome
        .as_ref()
        .is_some_and(|o| o.unconfirmed_move && o.forced.is_none())
        && !args.identity.force_base_mismatch
    {
        return Err(format!(
            "base mismatch: {} is not the place overlay {} recorded and nothing confirms its content (pass the recorded strong digest with --base-digest, or use --force-base-mismatch to pack against the base as it is now)",
            base.actual().base_url(),
            args.directory.display()
        ));
    }
    let moved = outcome.as_ref().is_some_and(|o| o.moved);
    // `--force-base-mismatch` over an accepted but unconfirmed move bypassed the
    // refusal above with no rows, so the bundle kept naming the old place while
    // its manifest was measured on this one.
    let relocated = match (&outcome, meta.as_ref()) {
        (Some(o), Some(m)) if o.unconfirmed_move && o.forced.is_none() => {
            Some(ratarmount_compositing::overlay_gate::forced_relocation_record(m, &base)?)
        }
        _ => None,
    };
    let forced = outcome.and_then(|outcome| outcome.forced).or(relocated);
    let lower = lower_view(&base, &args.lower, meta.as_ref())?;
    let options = super::overlay_pack::PackOptions {
        include_journal: args.include_journal.clone(),
        include_index: args.include_index,
        base: base_archive(&base),
        base_rows: forced,
        check_change_set: moved,
    };
    super::overlay_pack::pack(&args.directory, &args.bundle, lower, &options)
        .map(|digest| (digest, 0))
        .map_err(|e| format!("pack: {e}"))
}

/// The local archive a classified base is, whose index sidecar a bundle may
/// carry.
fn base_archive(base: &ClassifiedBase) -> Option<PathBuf> {
    use ratarmount_compositing::overlay_identity::{BaseKind, BaseLocation};
    match (base.actual().kind(), base.actual().location()) {
        (BaseKind::Archive, Some(BaseLocation::Local(path))) => Some(path.clone()),
        _ => None,
    }
}

pub fn seal(cmd: &SealCmd, context: &OverlayRunContext) -> Result<(String, i32), String> {
    let args = &cmd.seal;
    // Idempotence does not require the base still to be available: an
    // overlay that is already sealed is finished from its own record. The
    // record is not a token, so it cannot start a seal.
    let outcome = if let Some(record) = ratarmount_compositing::SealedRecord::read(&args.directory)
        .map_err(|e| super::overlay_open_error(&args.directory, &e))?
    {
        let _progress = super::diff::ProgressToStderr::new().map_err(|e| e.to_string())?;
        ratarmount_compositing::overlay_seal::reseal(&record)
    } else {
        let meta = OverlayMeta::read(&args.directory)
            .map_err(|e| super::overlay_open_error(&args.directory, &e))?;
        let _progress = super::diff::ProgressToStderr::new().map_err(|e| e.to_string())?;
        let base = classify_base(args.base.as_ref(), meta.as_ref(), None, context)?;
        if let Some(forced) =
            gate_base(&args.directory, meta.as_ref(), &base, &cmd.identity)?.and_then(|o| o.forced)
        {
            ratarmount_compositing::overlay_gate::record_forced_base_rows(
                &args.directory,
                &base,
                &forced,
            )
            .map_err(|e| format!("seal {}: {e}", args.directory.display()))?;
        }
        let lower = lower_view(&base, &args.lower, meta.as_ref())?;
        ratarmount_compositing::overlay_seal::seal(&args.directory, &base, lower)
    }
    .map_err(|e| format!("seal {}: {e}", args.directory.display()))?;
    let output = if args.json {
        serde_json::json!({"layer_digest": outcome.layer_digest, "sealed_at": outcome.sealed_at})
            .to_string()
    } else {
        outcome.layer_digest
    };
    Ok((output, 0))
}

pub fn unseal(directory: &Path, i_know: bool) -> Result<(String, i32), String> {
    if !i_know {
        return Err("unseal removes the layer's immutability guarantee; pass --i-know to restore write access".into());
    }
    ratarmount_compositing::overlay_seal::unseal(directory)
        .map_err(|e| format!("unseal {}: {e}", directory.display()))?;
    Ok((format!("unsealed {}", directory.display()), 0))
}

pub fn verify(args: &VerifyArgs, context: &OverlayRunContext) -> Result<(String, i32), String> {
    use ratarmount_compositing::{BaseCheck, BaseStrength};
    let seal = &args.seal;
    let meta = OverlayMeta::read(&seal.directory)
        .map_err(|e| super::overlay_open_error(&seal.directory, &e))?;
    if !meta.as_ref().is_some_and(OverlayMeta::layer_sealed) {
        return Err("overlay is not sealed".into());
    }
    let _progress = super::diff::ProgressToStderr::new().map_err(|e| e.to_string())?;
    let base = classify_base(seal.base.as_ref(), meta.as_ref(), None, context)?;
    let report = ratarmount_compositing::overlay_seal::verify(
        &seal.directory,
        lower_view(&base, &seal.lower, meta.as_ref())?,
    )
    .map_err(|e| format!("verify {}: {e}", seal.directory.display()))?;
    let base_check = if args.no_base_check {
        BaseCheck::Skipped {
            reason: "--no-base-check".into(),
        }
    } else {
        ratarmount_compositing::overlay_gate::verify_base(&seal.directory, &base)
    };
    let base_mismatch = matches!(base_check, BaseCheck::Mismatch { .. });
    let code = i32::from(!report.ok || base_mismatch);
    let (base_ok, base_kind, base_current) = match &base_check {
        BaseCheck::Matches { current, strength } => {
            (Some(true), strength.as_str(), Some(current.as_str()))
        }
        BaseCheck::Mismatch {
            current, strength, ..
        } => (Some(false), strength.as_str(), Some(current.as_str())),
        BaseCheck::Skipped { .. } => (None, "skipped", None),
    };
    let output = if args.seal.json {
        serde_json::json!({"ok":report.ok,"recorded":report.recorded,"computed":report.computed,
            "sentinel_ok":report.sentinel_ok,"mismatched":report.mismatched,
            "base_ok":base_ok,"base_check":base_kind,"base_current":base_current})
        .to_string()
    } else if report.ok && !base_mismatch {
        report.computed
    } else {
        let mut lines = Vec::new();
        if !report.ok {
            let mut text = format!(
                "seal mismatch: recorded {}, computed {}",
                report.recorded, report.computed
            );
            if !report.sentinel_ok {
                text.push_str("\n.ratarmount-sealed: sentinel mismatch");
            }
            for path in report.mismatched {
                text.push_str(&format!("\n{path}"));
            }
            lines.push(text);
        }
        if let BaseCheck::Mismatch {
            recorded,
            current,
            strength,
        } = &base_check
        {
            let mut text = format!("base mismatch: recorded {recorded}, current {current}");
            if *strength == BaseStrength::Weak {
                text.push_str("\n(weak digest: size/mtime manifest)");
            }
            lines.push(text);
        }
        lines.join("\n")
    };
    Ok((output, code))
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
            meta.redacted_values()
                .into_iter()
                .map(|(k, v)| (k, v.into())),
        );
    }
    // A lazily hashed archive base has no digest yet (spec 1.2): say so rather
    // than print an empty string.
    if meta
        .as_ref()
        .is_some_and(|m| m.base_digest_kind() == Some("pending"))
    {
        fields.insert(
            "base_digest".into(),
            if args.json {
                serde_json::Value::Null
            } else {
                "pending (computing)".into()
            },
        );
    }
    fields.insert(
        "base_digest_state".into(),
        meta.as_ref()
            .map_or("none", OverlayMeta::base_digest_state)
            .into(),
    );
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
    use ratarmount_formats_git::{
        looks_like_git, parse_git_url, split_inline_reference, GitMountSource,
    };
    let [path] = paths else {
        return Ok(None);
    };
    // `git:///repo#rev` pins like `repo@rev`; HEAD when no fragment is given.
    let url = parse_git_url(&path.to_string_lossy()).map_err(|e| e.to_string())?;
    if url.is_some() {
        options.git = true;
    }
    let inline = match url {
        Some((repo, Some(rev))) => Some((repo, rev)),
        Some((repo, None)) => {
            *path = repo;
            None
        }
        None => split_inline_reference(path),
    };
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
    use ratarmount_compositing::FolderMountSource;
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
        let ov = crate::base_identity::fixtures::overlay_over(
            Arc::new(FolderMountSource::new(&source).unwrap()),
            &overlay,
            source.to_str().unwrap(),
            Vec::new(),
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
        // A directory base records the cheap weak manifest, never a content hash.
        assert_eq!(output["base_digest_kind"], "weak");
        assert!(output["base_weak_digest"]
            .as_str()
            .unwrap()
            .starts_with("weak:"));
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
            crate::base_identity::fixtures::new_overlay(
                Arc::new(FolderMountSource::new(&source).unwrap()),
                &overlay,
            )
            .unwrap(),
        );
        let output: serde_json::Value = serde_json::from_str(&info(&args).unwrap()).unwrap();
        assert_eq!(output["legacy"], true);
        assert_eq!(output["format_version"], "1");
        assert!(output.get("base_digest").is_none());
    }

    /// Regression: an archive base still being hashed must read as pending
    /// (JSON `null` + kind `pending`, text "pending (computing)"), not as an
    /// empty digest.
    #[test]
    fn regression_pending_overlay_info_reports_pending() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("a.tar");
        std::fs::write(&archive, b"abc").unwrap();
        let overlay = root.path().join("overlay");
        drop(
            crate::base_identity::fixtures::overlay_over(
                Arc::new(FolderMountSource::new(root.path()).unwrap()),
                &overlay,
                archive.to_str().unwrap(),
                Vec::new(),
            )
            .unwrap(),
        );
        let json: serde_json::Value = serde_json::from_str(
            &info(&InfoArgs {
                directory: overlay.clone(),
                json: true,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["base_digest"], serde_json::Value::Null);
        assert_eq!(json["base_digest_kind"], "pending");
        assert!(json.get("stack_digest").is_none());
        let text = info(&InfoArgs {
            directory: overlay,
            json: false,
        })
        .unwrap();
        assert!(
            text.contains("base_digest: pending (computing)\n"),
            "{text}"
        );
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

    fn strong_remote_meta(digest: &str) -> ratarmount_compositing::OverlayMeta {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
            .unwrap();
        for (key, value) in [
            ("format_version", "2"),
            ("base_kind", "archive"),
            ("base_location", "remote:http://127.0.0.1:1/base.tar"),
            ("base_url", "http://127.0.0.1:1/base.tar"),
            ("base_digest_kind", "strong"),
            ("base_digest", digest),
        ] {
            conn.execute("INSERT INTO meta VALUES (?1, ?2)", [key, value])
                .unwrap();
        }
        ratarmount_compositing::OverlayMeta::from_connection(&conn)
            .unwrap()
            .unwrap()
    }

    /// A token that says the opener served a remote HTTP archive at `url`.
    fn remote_archive(url: &str) -> ClassifiedBase {
        let empty = tempfile::tempdir().unwrap();
        ClassifiedBase::open(&mut crate::base_identity::fixtures::FixtureOpener {
            source: Arc::new(FolderMountSource::new(empty.path()).unwrap()),
            kind: ratarmount_compositing::ServedKind::Archive,
            inputs: vec![url.to_owned()],
            location: Some(ratarmount_compositing::ServedLocation::Remote(
                url.to_owned(),
            )),
        })
        .unwrap()
    }

    /// Regression (R4-S2): a remote base skipped the identity check, so a
    /// supplied `--base-digest` contradicting the recorded strong digest was
    /// ignored; with nothing cheap to compare the recorded identity is reported
    /// unconfirmed, and only an equal supplied digest confirms it (no hashing).
    #[test]
    fn regression_gate_base_remote_checks_supplied_digest() {
        let recorded = format!("sha256:{}", "a".repeat(64));
        let other = format!("sha256:{}", "b".repeat(64));
        let meta = strong_remote_meta(&recorded);
        let url = "http://127.0.0.1:1/base.tar";
        let base = remote_archive(url);
        let args = |digest: Option<&str>, force: bool| BaseIdentityArgs {
            force_base_mismatch: force,
            base_digest: digest.map(str::to_owned),
        };
        let err = gate_base(
            Path::new("o"),
            Some(&meta),
            &base,
            &args(Some(&other), false),
        )
        .err()
        .expect("contradicting digest must be refused");
        assert!(
            err.contains("--force-base-mismatch") && err.contains("recorded"),
            "{err}"
        );
        let nothing = gate_base(Path::new("o"), Some(&meta), &base, &args(None, false))
            .unwrap()
            .unwrap();
        assert!(!nothing.confirmed && nothing.forced.is_none());
        let equal = gate_base(
            Path::new("o"),
            Some(&meta),
            &base,
            &args(Some(&recorded), false),
        )
        .unwrap()
        .unwrap();
        assert!(equal.confirmed);
        let forced = gate_base(
            Path::new("o"),
            Some(&meta),
            &base,
            &args(Some(&other), true),
        )
        .unwrap()
        .unwrap();
        assert_eq!(forced.forced.unwrap()["base_digest"], other);
    }
}
