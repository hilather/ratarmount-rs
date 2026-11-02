//! Lower stacks of supervisor attempts (protocol version 2 `lowers`): the
//! validation before anything exists, the stack-consistency check, the
//! re-check once mounted and the `diff`-time check (plan R1b §5.2–§5.5).
//!
//! Lowers are read with `OverlayMeta::read_no_recovery`, which never rolls a
//! hot journal back, and with `bundle_meta`'s streamed scan, under one
//! decoded-byte budget per request. Nothing here takes a flock, opens a
//! write transaction or writes; SQLite's read transactions take only its
//! SHARED locks.

use super::protocol::{ApiError, Base};
use crate::overlay_pack::DecodeBudget;
use ratarmount_compositing::{redact_meta_values, Immutability, LowerLayerRecord, OverlayMeta};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

/// Most lowers one `new` may stack.
pub const MAX_LOWERS: usize = 32;

/// Most bytes the bundle lowers of one `new` may take on disk together,
/// refused from their sizes before any bundle is read. This bounds the I/O;
/// decompression, and so the stall, is bounded by [`MAX_BUNDLE_DECODED_BYTES`].
pub const MAX_BUNDLE_BYTES: u64 = 1 << 30;

/// Most bytes the bundle lowers of one `new` may decode to together. The
/// supervisor reads every bundle to its end (`meta.json` is the last member)
/// inside the serial serve loop, so this bounds how long one request stalls
/// every other client; a bundle that decodes past it is refused as soon as it
/// does. Larger layers are used as sealed directories.
pub const MAX_BUNDLE_DECODED_BYTES: u64 = 1 << 30;

/// Symbolic links one lower may pass through (Linux's `MAXSYMLINKS`).
const MAX_SYMLINKS: usize = 40;

/// Longest metadata key or value a message shows, and the longest re-check
/// message. A `failed` request record stores the message verbatim, and R1a's
/// `LINE_BOUND` assumes messages of a few KiB, like the 8 KiB `mount.log`
/// excerpt.
pub const SHOWN_BYTES: usize = 512;
pub const MESSAGE_BYTES: usize = 8 << 10;

/// `text` cut to at most `max` bytes at a character boundary, marked with `…`.
pub fn excerpt(text: &str, max: usize) -> std::borrow::Cow<'_, str> {
    if text.len() <= max {
        return text.into();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end]).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Directory,
    Bundle,
}

/// One validated lower, as the supervisor read it before spawning.
#[derive(Clone, Debug)]
pub struct Lower {
    pub kind: Kind,
    /// Canonical: the child's `--lower` argument.
    pub path: PathBuf,
    /// Every metadata row: a directory's `meta` table, a bundle's `meta.json`.
    pub meta: BTreeMap<String, String>,
}

impl Lower {
    fn get(&self, key: &str) -> &str {
        self.meta.get(key).map_or("", String::as_str)
    }

    pub fn layer_digest(&self) -> &str {
        self.get("layer_digest")
    }

    pub fn sealed_at(&self) -> &str {
        self.get("sealed_at")
    }

    /// The base identity it records: its kind and digest.
    fn base(&self) -> (&str, &str) {
        (self.get("base_digest_kind"), self.get("base_digest"))
    }

    /// The lowers it was written over; none when the row is absent (a layer
    /// sealed without the row was never mounted over lowers).
    fn prefix(&self) -> Result<Vec<LowerLayerRecord>, ApiError> {
        self.meta
            .get("lower_layers")
            .map_or(Ok(Vec::new()), |text| {
                // serde_json's message quotes an unexpected string whole.
                serde_json::from_str(text).map_err(|e| {
                    let message = format!(
                        "lower {}: invalid lower_layers row: {e}",
                        self.path.display()
                    );
                    invalid(excerpt(&message, MESSAGE_BYTES))
                })
            })
    }
}

/// The state root and, once it is known, the RAM root; and the retained
/// attempts whose `retained/ID/overlay` may be a lower (R1c-1 §5.7).
pub struct Roots<'a> {
    pub state: &'a Path,
    pub ram: Option<&'a Path>,
    /// The acknowledged retained attempts this daemon run serves.
    pub retained: Option<&'a BTreeSet<String>>,
}

impl Roots<'_> {
    fn all(&self) -> impl Iterator<Item = (&Path, &'static str)> {
        std::iter::once((self.state, "state directory"))
            .chain(self.ram.map(|ram| (ram, "RAM directory")))
    }
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new("invalid_request", message)
}

/// Validates `lowers` of a `new` on `base`, bottom first, before any
/// directory or child exists: the base, list, place and type rules, each
/// lower's metadata, then the stack (§5.2, §5.3). The bundles share
/// `decoded_budget` (the supervisor passes [`MAX_BUNDLE_DECODED_BYTES`]).
/// Every refusal is `invalid_request` naming the lower. The caller still
/// parses the spawn flags.
pub fn validate(
    base: &Base,
    lowers: &[String],
    roots: &Roots<'_>,
    decoded_budget: u64,
) -> Result<Vec<Lower>, ApiError> {
    check_base(base)?;
    if lowers.len() > MAX_LOWERS {
        return Err(invalid(format!(
            "at most {MAX_LOWERS} lowers are allowed, got {}",
            lowers.len()
        )));
    }
    let mut found = Vec::new();
    let mut bundle_bytes = 0u64;
    for lower in lowers {
        let (path, kind, size) = locate(lower, roots)?;
        if kind == Kind::Bundle {
            bundle_bytes = bundle_bytes.saturating_add(size);
            if bundle_bytes > MAX_BUNDLE_BYTES {
                return Err(invalid(format!(
                    "lower bundle {} brings the request's bundles to {bundle_bytes} bytes, over the {MAX_BUNDLE_BYTES}-byte cap; unpack large layers (`ratarmount overlay unpack`) and pass the sealed directories",
                    path.display()
                )));
            }
        }
        found.push((path, kind));
    }
    let budget = DecodeBudget::new(decoded_budget);
    let lowers = found
        .into_iter()
        .map(|(path, kind)| read(path, kind, &budget))
        .collect::<Result<Vec<_>, _>>()?;
    check_stack(&lowers)?;
    Ok(lowers)
}

/// Lowers are supported on the bases the sandbox mounts: one local path or a
/// local `git:///` URL, without binds or recursion.
fn check_base(base: &Base) -> Result<(), ApiError> {
    check_base_for(base, "lowers")
}

/// The base rule of lowers, finalize and retain (R1c-1 §5.5): one local path
/// or a local `git:///` URL, without binds or recursion. A refusal names the
/// `operation` (`lowers`, `finalize` or `retain`).
pub(crate) fn check_base_for(base: &Base, operation: &str) -> Result<(), ApiError> {
    let name = &base.name;
    let (subject, needs) = if operation == "lowers" {
        ("lowers are".to_owned(), "lowers need".to_owned())
    } else {
        (format!("{operation} is"), format!("{operation} needs"))
    };
    if !base.options.binds.is_empty() {
        return Err(invalid(format!(
            "{subject} not supported on base {name}, which has binds"
        )));
    }
    if base.options.recursive {
        return Err(invalid(format!(
            "{subject} not supported on base {name}, which is recursive"
        )));
    }
    let git = ratarmount_formats_git::parse_git_url(&base.source)
        .ok()
        .flatten()
        .is_some();
    if !git && !Path::new(&base.source).is_absolute() {
        return Err(invalid(format!(
            "{needs} a local base (an absolute path or a git:/// URL); base {name} is not one"
        )));
    }
    Ok(())
}

/// The exception R1b reserved for R1c (R1c-1 §5.7): exactly
/// `<state>/retained/<ID>/overlay` of an acknowledged retained attempt,
/// matched lexically before any lookup, with `retained/`, `retained/ID` and
/// `retained/ID/overlay` each a real directory, never a symlink. Every other
/// path under `retained/` is refused, naming the form to use.
fn retained_lower(lower: &str, roots: &Roots<'_>) -> Result<Option<PathBuf>, ApiError> {
    let dir = roots.state.join("retained");
    let Ok(rest) = Path::new(lower).strip_prefix(&dir) else {
        return Ok(None);
    };
    let refused = || {
        invalid(format!(
            "lower {lower} lies inside the supervisor's state directory; a retained attempt is used as a lower only by its overlay, {}",
            dir.join("ID").join("overlay").display()
        ))
    };
    let mut parts = rest.components();
    let (Some(Component::Normal(id)), Some(Component::Normal(overlay)), None) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(refused());
    };
    let expected = dir.join(id).join("overlay");
    if overlay != "overlay" || expected.as_os_str() != lower {
        return Err(refused());
    }
    let id = id.to_str().ok_or_else(refused)?;
    if !roots.retained.is_some_and(|retained| retained.contains(id)) {
        return Err(invalid(format!(
            "lower {lower}: attempt {id} is not a retained attempt this daemon serves (unknown, retained before a restart, or its commit not yet acknowledged)"
        )));
    }
    for path in [dir.clone(), dir.join(id), expected.clone()] {
        let real = fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir());
        if !real {
            return Err(invalid(format!(
                "lower {lower}: {} is not a real directory",
                path.display()
            )));
        }
    }
    Ok(Some(expected))
}

/// The list, place and type rules of one lower as sent: its canonical path,
/// kind and size.
fn locate(lower: &str, roots: &Roots<'_>) -> Result<(PathBuf, Kind, u64), ApiError> {
    if lower.is_empty() || lower.contains('\0') {
        return Err(invalid("lower paths must not be empty or contain NUL"));
    }
    if !Path::new(lower).is_absolute() {
        return Err(invalid(format!(
            "lower {lower} must be an absolute path; relative paths are refused"
        )));
    }
    if let Some(path) = retained_lower(lower, roots)? {
        return Ok((path, Kind::Directory, 0));
    }
    let path = resolve(lower, roots)?;
    if path.to_str().is_none() {
        return Err(invalid(format!(
            "lower {lower} must resolve to a UTF-8 path"
        )));
    }
    // `resolve` refused a path inside a root; this adds the roots' ancestors.
    for (root, what) in roots.all() {
        if path.starts_with(root) || root.starts_with(&path) {
            return Err(invalid(format!(
                "lower {lower} resolves to {}, inside or above the supervisor's {what}",
                path.display()
            )));
        }
    }
    // Before any open: opening a FIFO would block the serve loop.
    let entry = fs::symlink_metadata(&path).map_err(|e| invalid(format!("lower {lower}: {e}")))?;
    let kind = if entry.is_dir() {
        Kind::Directory
    } else if entry.is_file() {
        Kind::Bundle
    } else {
        return Err(invalid(format!(
            "lower {lower} is neither a sealed layer directory nor a bundle file"
        )));
    };
    // `components` drops a trailing `/` or `/.`, which `realpath` refuses
    // after a file.
    if kind == Kind::Bundle && (lower.ends_with('/') || lower.ends_with("/.")) {
        return Err(invalid(format!(
            "lower {lower}: {}",
            io::Error::from_raw_os_error(libc::ENOTDIR)
        )));
    }
    Ok((path, kind, entry.len()))
}

/// One step of a path being resolved.
enum Step {
    Up,
    Name(OsString),
}

/// Queues the steps of `path` so that its first step is popped first.
fn push_steps(pending: &mut Vec<Step>, path: &Path) {
    for component in path.components().rev() {
        match component {
            Component::Normal(name) => pending.push(Step::Name(name.to_owned())),
            Component::ParentDir => pending.push(Step::Up),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
}

/// The canonical path of the absolute `lower`, resolved like `realpath(3)`
/// one component at a time. Before any name is looked up, the path reached
/// so far plus that name must lie outside both roots (which are canonical:
/// `Supervisor::open` and `ram_root` resolve them). So no component of a
/// lower is ever looked up inside a root, and so never through an attempt's
/// FUSE mount: not as written (a path below a root is refused unresolved),
/// not when a later `..` would leave the root again, and not through a
/// symlink into a root.
fn resolve(lower: &str, roots: &Roots<'_>) -> Result<PathBuf, ApiError> {
    let failed = |e: io::Error| invalid(format!("lower {lower}: {e}"));
    let mut resolved = PathBuf::from("/");
    let mut pending = Vec::new();
    push_steps(&mut pending, Path::new(lower));
    let mut links = 0;
    while let Some(step) = pending.pop() {
        let name = match step {
            // `resolved` holds no symlink, so this is its real parent.
            Step::Up => {
                resolved.pop();
                continue;
            }
            Step::Name(name) => name,
        };
        let next = resolved.join(name);
        if let Some((_, what)) = roots.all().find(|(root, _)| next.starts_with(root)) {
            return Err(invalid(if links == 0 {
                format!("lower {lower} lies inside the supervisor's {what}")
            } else {
                format!(
                    "lower {lower} resolves to {}, inside the supervisor's {what}",
                    next.display()
                )
            }));
        }
        let entry = fs::symlink_metadata(&next).map_err(failed)?;
        if entry.file_type().is_symlink() {
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(failed(io::Error::from_raw_os_error(libc::ELOOP)));
            }
            let target = fs::read_link(&next).map_err(failed)?;
            if target.is_absolute() {
                resolved = PathBuf::from("/");
            }
            push_steps(&mut pending, &target);
        } else if !entry.is_dir() && !pending.is_empty() {
            return Err(failed(io::Error::from_raw_os_error(libc::ENOTDIR)));
        } else {
            resolved = next;
        }
    }
    Ok(resolved)
}

/// A lower's whole metadata. A directory must be a sealed layer with a valid
/// digest; a bundle passes `bundle_meta`'s structural checks (the child
/// verifies its content against the view beneath it), drawing its decoded
/// bytes from the request's `budget`.
fn read(path: PathBuf, kind: Kind, budget: &Rc<DecodeBudget>) -> Result<Lower, ApiError> {
    let refuse = |why: String| invalid(format!("lower {}: {why}", path.display()));
    let meta = match kind {
        Kind::Directory => {
            let meta = OverlayMeta::read_no_recovery(&path)
                .map_err(|e| refuse(format!("not a readable sealed layer: {e}")))?
                .ok_or_else(|| refuse("has no overlay metadata".into()))?;
            if !meta.layer_sealed() {
                return Err(refuse(
                    "is not sealed; seal it with `ratarmount overlay seal`".into(),
                ));
            }
            crate::overlay_pack::valid_digest(meta.get("layer_digest").unwrap_or(""))
                .map_err(|e| refuse(e.to_string()))?;
            meta.values().clone()
        }
        Kind::Bundle => {
            let limits = crate::overlay_pack::Limits::resolve(None, None)
                .map_err(|e| refuse(e.to_string()))?;
            crate::overlay_pack::bundle_meta_within(&path, limits, budget).map_err(|e| {
                if budget.exceeded() {
                    invalid(format!(
                        "lower bundle {} decodes past the {}-byte budget that the bundle lowers of one request share; unpack large layers (`ratarmount overlay unpack`) and pass the sealed directories",
                        path.display(),
                        budget.total()
                    ))
                } else {
                    refuse(format!("not a sealed layer bundle: {e}"))
                }
            })?
        }
    };
    Ok(Lower { kind, path, meta })
}

fn digests<'a>(digests: impl Iterator<Item = &'a str>) -> String {
    format!("[{}]", digests.collect::<Vec<_>>().join(", "))
}

/// Whether `digest` is a base digest of `kind` as seal records it: `sha256:`
/// and 64 lowercase hex digits for `strong` (an archive digest, or a supplied
/// `--base-digest`, which is stored lowercased), `git-tree:` and a 40- or
/// 64-digit tree id for `git-tree`.
fn base_digest_of_kind(kind: &str, digest: &str) -> bool {
    let hex = |text: &str, lengths: &[usize]| {
        lengths.contains(&text.len())
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    match kind {
        "strong" => digest
            .strip_prefix("sha256:")
            .is_some_and(|h| hex(h, &[64])),
        "git-tree" => digest
            .strip_prefix("git-tree:")
            .is_some_and(|h| hex(h, &[40, 64])),
        _ => false,
    }
}

/// Each lower's recorded prefix is exactly the requested lowers beneath it,
/// by layer digest; no lower records a forced marker; every lower records
/// the same comparable base identity (strong or Git tree, with a well-formed
/// digest).
fn check_stack(lowers: &[Lower]) -> Result<(), ApiError> {
    for (i, lower) in lowers.iter().enumerate() {
        let name = lower.path.display();
        for marker in ["stack_mismatch_forced_at", "base_mismatch_forced_at"] {
            if lower.meta.contains_key(marker) {
                return Err(invalid(format!(
                    "lower {name} records {marker}: its rows do not describe what it was written over"
                )));
            }
        }
        let kind = lower.get("base_digest_kind");
        if !matches!(kind, "strong" | "git-tree") {
            return Err(invalid(format!(
                "lower {name} records base identity kind {}; lowers need a strong or git-tree identity, which layers record over an archive or a Git base, or over a directory base created with --base-digest sha256:… (`ratarmount overlay digest-base` prints it)",
                if kind.is_empty() { "(none)".into() } else { excerpt(kind, SHOWN_BYTES) }
            )));
        }
        // Two missing digests would compare equal below.
        let digest = lower.get("base_digest");
        if !base_digest_of_kind(kind, digest) {
            return Err(invalid(format!(
                "lower {name} records base identity kind {kind} with {}; every lower must record a base digest the others can be compared with",
                if digest.is_empty() {
                    "no base digest".to_owned()
                } else {
                    format!("the malformed base digest {:?}", excerpt(digest, SHOWN_BYTES))
                }
            )));
        }
        let recorded = lower.prefix()?;
        let beneath = &lowers[..i];
        if recorded.len() != i
            || recorded
                .iter()
                .zip(beneath)
                .any(|(record, below)| record.layer_digest != below.layer_digest())
        {
            // The recorded prefix is not bounded: neither its length nor
            // its digests.
            let message = format!(
                "lower {name} (position {i}) was sealed over the lowers {} but the request puts {} beneath it; list the layers it was sealed over first, bottom first",
                digests(recorded.iter().map(|r| r.layer_digest.as_str())),
                digests(beneath.iter().map(Lower::layer_digest))
            );
            return Err(invalid(excerpt(&message, MESSAGE_BYTES)));
        }
    }
    if let Some((bottom, above)) = lowers.split_first() {
        if let Some(other) = above.iter().find(|lower| lower.base() != bottom.base()) {
            return Err(invalid(format!(
                "lower {} records base {} ({}) but lower {} records base {} ({}); every lower must record the same base",
                other.path.display(),
                other.get("base_digest"),
                other.get("base_digest_kind"),
                bottom.path.display(),
                bottom.get("base_digest"),
                bottom.get("base_digest_kind")
            )));
        }
    }
    Ok(())
}

/// After readiness (Keystone #3): the layers a child reports, and the
/// metadata of what it composed, read again now, must equal what was
/// validated. A difference is `lower_changed`; a failed read `mount_failed`.
/// Messages are cut to [`MESSAGE_BYTES`].
pub fn recheck(
    attempt: &str,
    validated: &[Lower],
    records: &[LowerLayerRecord],
) -> Result<(), ApiError> {
    let changed = |message: String| {
        let message = format!("attempt {attempt}: {message}");
        ApiError::new("lower_changed", excerpt(&message, MESSAGE_BYTES))
    };
    let short = |text: &str| excerpt(text, SHOWN_BYTES).into_owned();
    if records.len() != validated.len() {
        return Err(changed(format!(
            "it mounted {} lowers, but {} were validated",
            records.len(),
            validated.len()
        )));
    }
    for (i, (lower, record)) in validated.iter().zip(records).enumerate() {
        // A bundle's record names the cache directory the child resolved.
        // That path is trusted rather than compared: the child is our own
        // process, and the digest, `sealed_at` and metadata comparison below
        // still have to match what was validated, read from that directory.
        let same_path = lower.kind == Kind::Bundle || record.path == lower.path;
        if !same_path
            || record.layer_digest != lower.layer_digest()
            || record.sealed_at != lower.sealed_at()
        {
            return Err(changed(format!(
                "lower {i} ({}) was validated as layer_digest {} sealed_at {}, but the mount took {} with layer_digest {} sealed_at {}",
                lower.path.display(),
                short(lower.layer_digest()),
                short(lower.sealed_at()),
                short(&record.path.to_string_lossy()),
                short(&record.layer_digest),
                short(&record.sealed_at)
            )));
        }
        let now = OverlayMeta::read_no_recovery(&record.path)
            .map_err(|e| {
                let message = format!(
                    "attempt {attempt}: cannot read lower {i} ({}) again: {e}",
                    record.path.display()
                );
                ApiError::new("mount_failed", excerpt(&message, MESSAGE_BYTES))
            })?
            .map(|meta| meta.values().clone())
            .unwrap_or_default();
        if now != lower.meta {
            // Values are shown redacted: a layer an older build wrote may
            // still hold a credentialed `base_url` (`redact_meta_values` also
            // drops the `base_index_path` that embeds it).
            let (was, is) = (redact_meta_values(&lower.meta), redact_meta_values(&now));
            let differing: Vec<String> = lower
                .meta
                .keys()
                .chain(now.keys())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .filter(|key| lower.meta.get(*key) != now.get(*key))
                .map(|key| {
                    format!(
                        "{}: {} -> {}",
                        short(key),
                        shown(&lower.meta, &was, key),
                        shown(&now, &is, key)
                    )
                })
                .collect();
            return Err(changed(format!(
                "the metadata of lower {i} ({}) changed after validation: {}",
                record.path.display(),
                differing.join("; ")
            )));
        }
    }
    Ok(())
}

/// `key`'s value in the metadata map `raw` for a message, taken from
/// `redacted`, the `redact_meta_values` of `raw`, and cut to [`SHOWN_BYTES`].
fn shown(raw: &BTreeMap<String, String>, redacted: &BTreeMap<String, String>, key: &str) -> String {
    match (raw.get(key), redacted.get(key)) {
        (None, _) => "(absent)".to_owned(),
        (Some(_), None) => "(redacted)".to_owned(),
        (Some(_), Some(value)) => format!("{:?}", excerpt(value, SHOWN_BYTES)),
    }
}

/// The layers a verified attempt composed, for its `diff`: each must still be
/// sealed with the digest and seal time the attempt recorded. Never recovers
/// a hot journal, and never re-verifies a bundle (its cache directory is used,
/// as the CLI `diff` uses a top's recorded paths).
pub fn recorded_layers(
    records: &[LowerLayerRecord],
) -> Result<Vec<(PathBuf, Immutability)>, String> {
    records
        .iter()
        .map(|record| {
            let meta = OverlayMeta::read_no_recovery(&record.path)
                .map_err(|e| format!("lower {}: {e}", record.path.display()))?;
            let unchanged = meta.as_ref().is_some_and(|meta| {
                meta.layer_sealed()
                    && meta.get("layer_digest") == Some(record.layer_digest.as_str())
                    && meta.get("sealed_at") == Some(record.sealed_at.as_str())
            });
            if !unchanged {
                return Err(format!(
                    "lower {} is no longer sealed as layer_digest {} at {}, as the attempt mounted it; destroy the attempt",
                    record.path.display(),
                    record.layer_digest,
                    record.sealed_at
                ));
            }
            Ok((record.path.clone(), Immutability::Immutable))
        })
        .collect()
}
