//! Sealed and unsealed lower stacks composed onto a base.
//!
//! Bundle cache lookup and the mount path's base-identity check stay with the
//! caller. This module hashes the marker key and opens each layer; it does not
//! import the binary's bundle cache.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ratarmount_core::MountSource;
use sha2::{Digest, Sha256};

use crate::{
    compose_stack, open_overlay_db, stack_digest, DbName, Immutability, LowerLayerRecord,
    OverlayError, OverlayMeta, HIDDEN_DB,
};

/// Resolves a bundle file to a layer directory.
///
/// Arguments are the bundle path, the composed view beneath it, the marker key
/// this module already computed (`None` when a previous verification must not
/// be trusted), and the caller's cache directory (`None` means the resolver
/// applies its own default).
pub type BundleResolver =
    dyn Fn(&Path, Arc<dyn MountSource>, Option<&str>, Option<&Path>) -> std::io::Result<PathBuf>;

/// The whole error string when reading a layer's metadata fails.
pub type MetaErrorFormatter = dyn Fn(&Path, &OverlayError) -> String;

/// Mount-path identity of the bottom lower. `Err` is returned unchanged.
///
/// The lifetime is the callback's borrows. The mount path closes over a local
/// identity, so this is not `'static`.
pub type BottomIdentity<'a> = dyn Fn(&Path, Option<&OverlayMeta>) -> Result<String, String> + 'a;

/// Binary services the opener cannot own.
pub struct LowerStackServices<'a> {
    pub resolve_bundle: &'a BundleResolver,
    pub format_meta_error: &'a MetaErrorFormatter,
}

/// One `--lower` stack, bottom-up, and the identity recorded for its bottom layer.
pub struct MountLowerStack {
    pub layers: Vec<(PathBuf, Immutability)>,
    pub records: Vec<LowerLayerRecord>,
    /// Identity of the base this stack is mounted on. The mount callback's
    /// value when the opener enforced one (empty when unknown), otherwise the
    /// digest recorded by the bottom lower. `None` means that lower recorded
    /// no digest; `Some("")` means it recorded an empty one.
    pub base_digest: Option<String>,
}

enum Bottom<'a> {
    Recorded,
    Enforce(&'a BottomIdentity<'a>),
}

impl MountLowerStack {
    /// Open the same sealed lower stack used by the mount CLI for offline consumers.
    pub fn compose(
        base: Arc<dyn MountSource>,
        paths: &[PathBuf],
        services: &LowerStackServices<'_>,
    ) -> std::io::Result<Arc<dyn MountSource>> {
        Self::open(base, None, paths, false, services)
            .map(|(_, view)| view)
            .map_err(std::io::Error::other)
    }

    /// Open the lower stack on top of an existing `base`, bottom-up. A bundle
    /// is verified against the view beneath it (base plus the lowers below)
    /// before it is cached, so the base must exist first. `base_key` is the
    /// base's strong digest when the caller already has one without reading
    /// content (a supplied `--base-digest`, or a cached archive digest); only
    /// then, and only above sealed immutable lowers, may a previous
    /// verification be trusted instead of repeated.
    ///
    /// The bottom layer's `base_digest` is the digest that layer recorded.
    pub fn open(
        base: Arc<dyn MountSource>,
        base_key: Option<&str>,
        paths: &[PathBuf],
        allow_unsealed: bool,
        services: &LowerStackServices<'_>,
    ) -> Result<(Self, Arc<dyn MountSource>), String> {
        Self::open_in(base, base_key, paths, allow_unsealed, None, services)
    }

    /// [`Self::open`] with an explicit bundle cache directory (tests).
    pub fn open_in(
        base: Arc<dyn MountSource>,
        base_key: Option<&str>,
        paths: &[PathBuf],
        allow_unsealed: bool,
        cache: Option<&Path>,
        services: &LowerStackServices<'_>,
    ) -> Result<(Self, Arc<dyn MountSource>), String> {
        Self::open_inner(
            base,
            base_key,
            paths,
            allow_unsealed,
            cache,
            Bottom::Recorded,
            services,
        )
    }

    /// [`Self::open_in`] that asks `bottom_identity` for the bottom layer's
    /// base identity. A successful answer is stored as `Some`, including `""`.
    /// The callback's `Err` is returned unchanged.
    pub fn open_with(
        base: Arc<dyn MountSource>,
        base_key: Option<&str>,
        paths: &[PathBuf],
        allow_unsealed: bool,
        cache: Option<&Path>,
        bottom_identity: &BottomIdentity<'_>,
        services: &LowerStackServices<'_>,
    ) -> Result<(Self, Arc<dyn MountSource>), String> {
        Self::open_inner(
            base,
            base_key,
            paths,
            allow_unsealed,
            cache,
            Bottom::Enforce(bottom_identity),
            services,
        )
    }

    fn open_inner(
        base: Arc<dyn MountSource>,
        base_key: Option<&str>,
        paths: &[PathBuf],
        allow_unsealed: bool,
        cache: Option<&Path>,
        identity: Bottom<'_>,
        services: &LowerStackServices<'_>,
    ) -> Result<(Self, Arc<dyn MountSource>), String> {
        let mut stack = Self {
            layers: Vec::new(),
            records: Vec::new(),
            base_digest: None,
        };
        let mut view = base;
        for path in paths {
            let cached;
            let path = if path.is_file() {
                let marker_key = base_key
                    .filter(|_| {
                        stack.layers.iter().zip(&stack.records).all(|((_, im), r)| {
                            *im == Immutability::Immutable && !r.layer_digest.is_empty()
                        })
                    })
                    .map(|key| {
                        let mut hasher = Sha256::new();
                        hasher.update(key.as_bytes());
                        for record in &stack.records {
                            hasher.update([0]);
                            hasher.update(record.layer_digest.as_bytes());
                        }
                        format!("{:x}", hasher.finalize())
                    });
                cached =
                    (services.resolve_bundle)(path, view.clone(), marker_key.as_deref(), cache)
                        .map_err(|e| format!("lower bundle {}: {e}", path.display()))?;
                &cached
            } else {
                path
            };
            let path = path
                .canonicalize()
                .map_err(|e| format!("lower {}: {e}", path.display()))?;
            let meta =
                OverlayMeta::read(&path).map_err(|e| (services.format_meta_error)(&path, &e))?;
            let sealed = meta.as_ref().is_some_and(OverlayMeta::layer_sealed);
            if !sealed && !allow_unsealed {
                return Err(format!(
                    "lower {} is unsealed; pass --allow-unsealed-lower to use it",
                    path.display()
                ));
            }
            if stack.records.is_empty() {
                stack.base_digest = match identity {
                    Bottom::Recorded => meta
                        .as_ref()
                        .and_then(OverlayMeta::base_digest)
                        .map(str::to_owned),
                    Bottom::Enforce(bottom_identity) => {
                        Some(bottom_identity(&path, meta.as_ref())?)
                    }
                };
            }
            stack.records.push(LowerLayerRecord {
                path: path.clone(),
                layer_digest: meta
                    .as_ref()
                    .and_then(|m| m.get("layer_digest"))
                    .unwrap_or("")
                    .into(),
                sealed_at: meta
                    .as_ref()
                    .and_then(|m| m.get("sealed_at"))
                    .unwrap_or("")
                    .into(),
            });
            let immutability = if sealed {
                Immutability::Immutable
            } else {
                Immutability::Shared
            };
            view = compose_stack(view, &[(path.clone(), immutability)])
                .map_err(|e| format!("error opening lower stack: {e}"))?;
            stack.layers.push((path, immutability));
        }
        Ok((stack, view))
    }

    /// Identity a read-only composed mount (no `-w` top) serves through the
    /// root `user.ratarmount.*` status xattrs. Empty without `--lower`.
    pub fn read_only_metadata(&self) -> std::collections::BTreeMap<String, String> {
        let mut metadata = std::collections::BTreeMap::new();
        if self.records.is_empty() {
            return metadata;
        }
        let base = self.base_digest.clone().unwrap_or_default();
        let digests: Vec<&str> = self
            .records
            .iter()
            .map(|r| r.layer_digest.as_str())
            .collect();
        // No stack identity without a known base (e.g. an uncached archive).
        metadata.insert(
            "stack_digest".into(),
            if base.is_empty() {
                String::new()
            } else {
                stack_digest(&base, &digests)
            },
        );
        // An empty base here is an archive that was never hashed.
        metadata.insert(
            "base_digest_state".into(),
            if base.is_empty() {
                "pending"
            } else {
                "present"
            }
            .into(),
        );
        metadata.insert("base_digest".into(), base);
        metadata.insert(
            "lower_layers".into(),
            serde_json::to_string(&self.records).expect("lower records"),
        );
        // The composed view cannot change only when every layer is sealed.
        if self.records.iter().all(|r| !r.sealed_at.is_empty()) {
            let top = self.records.last().expect("non-empty");
            metadata.insert("sealed_at".into(), top.sealed_at.clone());
        }
        metadata
    }

    pub fn check_top(&self, dir: &Path, force: bool) -> Result<(), String> {
        // A missing, unreadable, corrupt or locked database is left to
        // `WriteOverlay::new`, whose errors name the file and the way out
        // (#89); it also refuses a sealed top inside its open transaction.
        if std::fs::symlink_metadata(dir.join(HIDDEN_DB)).is_err() {
            return Ok(());
        }
        let Ok(meta) = OverlayMeta::read(dir) else {
            return Ok(());
        };
        if meta.as_ref().is_some_and(OverlayMeta::layer_sealed) {
            return Err(format!(
                "overlay {} is sealed; mount it with --lower, or `overlay unseal`",
                dir.display()
            ));
        }
        let recorded = meta
            .as_ref()
            .map(OverlayMeta::lower_layers)
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let same = recorded.len() == self.records.len()
            && recorded.iter().zip(&self.records).all(|(a, b)| {
                std::path::absolute(&a.path).is_ok_and(|path| path == b.path)
                    && a.layer_digest == b.layer_digest
            });
        if same {
            return Ok(());
        }
        if !force {
            return Err(format!("overlay {} stack mismatch: recorded lower_layers {}; given --lower {}; pass --force-stack-mismatch to override",
                dir.display(), serde_json::to_string(&recorded).expect("lower records"),
                serde_json::to_string(&self.records).expect("lower records")));
        }
        let mut conn = open_overlay_db(
            &dir.join(HIDDEN_DB),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            DbName::Path,
        )
        .map_err(|e| e.to_string())?;
        conn.busy_timeout(Duration::ZERO)
            .map_err(|e| e.to_string())?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
            .map_err(|e| e.to_string())?;
        if OverlayMeta::from_connection(&tx)
            .map_err(|e| e.to_string())?
            .as_ref()
            .is_some_and(OverlayMeta::layer_sealed)
        {
            return Err("overlay is sealed; mount it with --lower, or `overlay unseal`".into());
        }
        tx.execute_batch(crate::overlay_meta::META_SCHEMA)
            .map_err(|e| e.to_string())?;
        let timestamp: String = tx
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now')", [], |row| {
                row.get(0)
            })
            .map_err(|e| e.to_string())?;
        OverlayMeta::set(&tx, "stack_mismatch_forced_at", &timestamp).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
}
