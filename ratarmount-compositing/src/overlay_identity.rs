//! What a base IS, as reported by the code that opened it.
//!
//! **Experimental.** The kind and location of an overlay's base are the ones
//! the opener actually served, never a guess made later from a path or a URL.
//! An [`OpenBase`] implementation (the binary's factory wrapper is the only
//! production one) reports an [`Opened`]; [`ClassifiedBase::open`] turns that
//! into the token every creator and gate takes. The token cannot be built
//! anywhere else (its fields are `pub(crate)`), so a caller that skips the
//! classifier does not compile; the `compile_fail` doctests below pin that.
//!
//! Accepted limit: [`Opened`] has public fields, so a crate can write a
//! dishonest [`OpenBase`]. The token proves "an opener was consulted and
//! reported this", not "the factory served it".

use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::MountSource;

use crate::overlay_meta::OverlayMeta;
use crate::write_overlay::Result;
use crate::BaseDigestRequest;
use crate::LowerLayerRecord;

/// **Experimental.** The kind of source an opener served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServedKind {
    /// A Git tree (the tree id after any subtree selection).
    Git { tree: String },
    /// A directory-like source: local folder, remote folder, torrent, image.
    Folder,
    /// A single archive file or stream (plain, compressed, split, nested).
    Archive,
}

/// **Experimental.** Where the served source came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServedLocation {
    /// The path the opener opened (never the typed URI). Only for a plain
    /// path or a `file://` URL; a fetched copy is [`Self::Remote`].
    Local(PathBuf),
    /// The raw typed remote input (redacted when the token is minted).
    Remote(String),
}

/// **Experimental.** Which index the opener selected for the first source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexProvenance {
    None,
    Local(PathBuf),
    /// A sidecar fetched from `from` (raw URL, redacted at mint).
    Discovered {
        path: PathBuf,
        from: String,
    },
}

/// **Experimental.** What [`OpenBase::open_base`] reports.
pub struct Opened {
    pub source: Arc<dyn MountSource>,
    pub kind: ServedKind,
    /// Typed inputs, the pre-pin selector first.
    pub inputs: Vec<String>,
    /// `None` only for a declared corpus source, which has no location.
    pub location: Option<ServedLocation>,
    pub index: IndexProvenance,
    /// Read-only peek target for a cached digest when the index itself stays
    /// in memory (offline verbs).
    pub sidecar_candidate: Option<PathBuf>,
    /// The first source was fetched to a temporary local copy.
    pub fetched: bool,
    /// Keeps fetched temporary files alive for as long as the token lives.
    pub keep_alive: Box<dyn Any + Send + Sync>,
}

/// **Experimental.** The opener a token is minted from.
pub trait OpenBase {
    fn open_base(&mut self) -> std::result::Result<Opened, String>;
}

/// **Experimental.** The kind recorded in the `base_kind` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseKind {
    Git,
    Dir,
    Archive,
}

impl BaseKind {
    pub const ALL: [BaseKind; 3] = [BaseKind::Git, BaseKind::Dir, BaseKind::Archive];

    /// The value stored in the `base_kind` row.
    pub fn as_str(self) -> &'static str {
        match self {
            BaseKind::Git => "git",
            BaseKind::Dir => "directory",
            BaseKind::Archive => "archive",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == text)
    }
}

/// **Experimental.** Where a base is, in the form that is stored and compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseLocation {
    Local(PathBuf),
    /// Redacted typed URL.
    Remote(String),
}

/// **Experimental.** What the opener served, canonicalized and redacted.
#[derive(Clone)]
pub struct ActualBase {
    pub(crate) kind: BaseKind,
    pub(crate) location: Option<BaseLocation>,
    pub(crate) base_url: String,
    pub(crate) credentialed: bool,
    pub(crate) git_tree: Option<String>,
    pub(crate) remote_token: Option<String>,
    pub(crate) index_for_peek: Option<PathBuf>,
}

impl std::fmt::Debug for ActualBase {
    // `index_for_peek` is left out: it may be derived from a credentialed URL.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActualBase")
            .field("kind", &self.kind)
            .field("location", &self.location)
            .field("base_url", &self.base_url)
            .field("credentialed", &self.credentialed)
            .field("git_tree", &self.git_tree)
            .finish_non_exhaustive()
    }
}

impl ActualBase {
    pub fn kind(&self) -> BaseKind {
        self.kind
    }
    pub fn location(&self) -> Option<&BaseLocation> {
        self.location.as_ref()
    }
    /// The redacted first typed input (the pre-pin selector).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    /// A credential was present in the typed input or the index URL.
    pub fn credentialed(&self) -> bool {
        self.credentialed
    }
    pub fn git_tree(&self) -> Option<&str> {
        self.git_tree.as_deref()
    }
    pub fn remote_token(&self) -> Option<&str> {
        self.remote_token.as_deref()
    }
    pub fn index_for_peek(&self) -> Option<&Path> {
        self.index_for_peek.as_deref()
    }
}

pub(crate) struct Inner {
    source: Arc<dyn MountSource>,
    actual: ActualBase,
    _keep_alive: Box<dyn Any + Send + Sync>,
}

/// **Experimental.** Proof that a base was opened and classified.
///
/// Every overlay creator and gate takes `&ClassifiedBase`. It cannot be
/// built outside this crate except through [`ClassifiedBase::open`]:
///
/// ```compile_fail
/// # use ratarmount_compositing::*;
/// # use ratarmount_core::MountSource;
/// # use std::sync::Arc;
/// # struct Fixture;
/// # impl OpenBase for Fixture {
/// #     fn open_base(&mut self) -> Result<Opened, String> {
/// #         let dir = std::env::temp_dir();
/// #         let source: Arc<dyn MountSource> =
/// #             Arc::new(FolderMountSource::new(&dir).map_err(|e| e.to_string())?);
/// #         Ok(Opened {
/// #             source,
/// #             kind: ServedKind::Folder,
/// #             inputs: vec![],
/// #             location: Some(ServedLocation::Local(dir)),
/// #             index: IndexProvenance::None,
/// #             sidecar_candidate: None,
/// #             fetched: false,
/// #             keep_alive: Box::new(()),
/// #         })
/// #     }
/// # }
/// // compile_fail: struct literal
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let _ = ClassifiedBase { inner: cb.inner.clone() };
/// # Ok::<(), String>(())
/// ```
///
/// ```no_run
/// # use ratarmount_compositing::*;
/// # use ratarmount_core::MountSource;
/// # use std::sync::Arc;
/// # struct Fixture;
/// # impl OpenBase for Fixture {
/// #     fn open_base(&mut self) -> Result<Opened, String> {
/// #         let dir = std::env::temp_dir();
/// #         let source: Arc<dyn MountSource> =
/// #             Arc::new(FolderMountSource::new(&dir).map_err(|e| e.to_string())?);
/// #         Ok(Opened {
/// #             source,
/// #             kind: ServedKind::Folder,
/// #             inputs: vec![],
/// #             location: Some(ServedLocation::Local(dir)),
/// #             index: IndexProvenance::None,
/// #             sidecar_candidate: None,
/// #             fetched: false,
/// #             keep_alive: Box::new(()),
/// #         })
/// #     }
/// # }
/// // control: struct literal
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let _ = cb.actual().kind();
/// # Ok::<(), String>(())
/// ```
///
/// ```compile_fail
/// # use ratarmount_compositing::*;
/// # use ratarmount_core::MountSource;
/// # use std::sync::Arc;
/// # struct Fixture;
/// # impl OpenBase for Fixture {
/// #     fn open_base(&mut self) -> Result<Opened, String> {
/// #         let dir = std::env::temp_dir();
/// #         let source: Arc<dyn MountSource> =
/// #             Arc::new(FolderMountSource::new(&dir).map_err(|e| e.to_string())?);
/// #         Ok(Opened {
/// #             source,
/// #             kind: ServedKind::Folder,
/// #             inputs: vec![],
/// #             location: Some(ServedLocation::Local(dir)),
/// #             index: IndexProvenance::None,
/// #             sidecar_candidate: None,
/// #             fetched: false,
/// #             keep_alive: Box::new(()),
/// #         })
/// #     }
/// # }
/// // compile_fail: mint
/// let opened = Fixture.open_base()?;
/// let _ = ClassifiedBase::mint(opened);
/// # Ok::<(), String>(())
/// ```
///
/// ```no_run
/// # use ratarmount_compositing::*;
/// # use ratarmount_core::MountSource;
/// # use std::sync::Arc;
/// # struct Fixture;
/// # impl OpenBase for Fixture {
/// #     fn open_base(&mut self) -> Result<Opened, String> {
/// #         let dir = std::env::temp_dir();
/// #         let source: Arc<dyn MountSource> =
/// #             Arc::new(FolderMountSource::new(&dir).map_err(|e| e.to_string())?);
/// #         Ok(Opened {
/// #             source,
/// #             kind: ServedKind::Folder,
/// #             inputs: vec![],
/// #             location: Some(ServedLocation::Local(dir)),
/// #             index: IndexProvenance::None,
/// #             sidecar_candidate: None,
/// #             fetched: false,
/// #             keep_alive: Box::new(()),
/// #         })
/// #     }
/// # }
/// // control: mint
/// let opened = Fixture.open_base()?;
/// let _ = opened.kind.clone();
/// let _ = ClassifiedBase::open(&mut Fixture)?;
/// # Ok::<(), String>(())
/// ```
///
/// ```compile_fail
/// # use ratarmount_compositing::*;
/// # use ratarmount_core::MountSource;
/// # use std::sync::Arc;
/// # struct Fixture;
/// # impl OpenBase for Fixture {
/// #     fn open_base(&mut self) -> Result<Opened, String> {
/// #         let dir = std::env::temp_dir();
/// #         let source: Arc<dyn MountSource> =
/// #             Arc::new(FolderMountSource::new(&dir).map_err(|e| e.to_string())?);
/// #         Ok(Opened {
/// #             source,
/// #             kind: ServedKind::Folder,
/// #             inputs: vec![],
/// #             location: Some(ServedLocation::Local(dir)),
/// #             index: IndexProvenance::None,
/// #             sidecar_candidate: None,
/// #             fetched: false,
/// #             keep_alive: Box::new(()),
/// #         })
/// #     }
/// # }
/// // compile_fail: ActualBase literal
/// let _ = ActualBase {
///     kind: ratarmount_compositing::overlay_identity::BaseKind::Dir,
///     location: None,
///     base_url: String::new(),
///     credentialed: false,
///     git_tree: None,
///     remote_token: None,
///     index_for_peek: None,
/// };
/// ```
///
/// ```no_run
/// # use ratarmount_compositing::*;
/// # use ratarmount_core::MountSource;
/// # use std::sync::Arc;
/// # struct Fixture;
/// # impl OpenBase for Fixture {
/// #     fn open_base(&mut self) -> Result<Opened, String> {
/// #         let dir = std::env::temp_dir();
/// #         let source: Arc<dyn MountSource> =
/// #             Arc::new(FolderMountSource::new(&dir).map_err(|e| e.to_string())?);
/// #         Ok(Opened {
/// #             source,
/// #             kind: ServedKind::Folder,
/// #             inputs: vec![],
/// #             location: Some(ServedLocation::Local(dir)),
/// #             index: IndexProvenance::None,
/// #             sidecar_candidate: None,
/// #             fetched: false,
/// #             keep_alive: Box::new(()),
/// #         })
/// #     }
/// # }
/// // control: ActualBase literal
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let _ = (cb.actual().kind(), cb.actual().base_url());
/// # Ok::<(), String>(())
/// ```
#[derive(Clone)]
pub struct ClassifiedBase {
    pub(crate) inner: Arc<Inner>,
}

const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<ClassifiedBase>();
        assert_send_sync::<ActualBase>();
        assert_send_sync::<SealedRecord>();
    }
    let _ = check;
};

fn canonical_or_same(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

impl ClassifiedBase {
    /// Open through `opener` and classify what it reports.
    pub fn open(opener: &mut dyn OpenBase) -> std::result::Result<Self, String> {
        Self::mint(opener.open_base()?)
    }

    /// Canonicalize, redact and mint. Not public: only [`Self::open`] reaches
    /// it, and only through the trait.
    pub(crate) fn mint(opened: Opened) -> std::result::Result<Self, String> {
        let Opened {
            source,
            kind,
            inputs,
            location,
            index,
            sidecar_candidate,
            fetched: _,
            keep_alive,
        } = opened;
        let raw_first = inputs.first().map(String::as_str).unwrap_or("");
        let index_from = match &index {
            IndexProvenance::Discovered { from, .. } => Some(from.as_str()),
            _ => None,
        };
        let redacted = |raw: &str| ratarmount_core::redact_base_url(raw);
        let credentialed = redacted(raw_first) != raw_first
            || index_from.is_some_and(|from| redacted(from) != from);
        let (base_kind, git_tree) = match kind {
            ServedKind::Git { tree } => (BaseKind::Git, Some(tree)),
            ServedKind::Folder => (BaseKind::Dir, None),
            ServedKind::Archive => (BaseKind::Archive, None),
        };
        let location = location.map(|location| match location {
            ServedLocation::Local(path) => BaseLocation::Local(canonical_or_same(&path)),
            ServedLocation::Remote(raw) => BaseLocation::Remote(redacted(&raw)),
        });
        let remote_token = (inputs.len() > 1).then(|| {
            let items: Vec<String> = inputs.iter().map(|raw| redacted(raw)).collect();
            serde_json::to_string(&items).expect("input paths serialize")
        });
        let index_for_peek = match (&base_kind, &location) {
            (BaseKind::Archive, Some(BaseLocation::Local(_))) if !credentialed => match index {
                IndexProvenance::Local(path) | IndexProvenance::Discovered { path, .. } => {
                    Some(path)
                }
                IndexProvenance::None => sidecar_candidate,
            },
            _ => None,
        };
        let actual = ActualBase {
            kind: base_kind,
            location,
            base_url: redacted(raw_first),
            credentialed,
            git_tree,
            remote_token,
            index_for_peek,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                source,
                actual,
                _keep_alive: keep_alive,
            }),
        })
    }

    /// The source as it was opened (stale after a live commit replaces it).
    pub fn source(&self) -> Arc<dyn MountSource> {
        self.inner.source.clone()
    }

    pub fn actual(&self) -> &ActualBase {
        &self.inner.actual
    }

    /// The same token pointed at the archive a commit just wrote.
    #[allow(dead_code)]
    pub(crate) fn repointed(&self, archive: &Path) -> Self {
        let mut actual = self.inner.actual.clone();
        actual.kind = BaseKind::Archive;
        actual.location = Some(BaseLocation::Local(canonical_or_same(archive)));
        actual.git_tree = None;
        Self {
            inner: Arc::new(Inner {
                source: self.inner.source.clone(),
                actual,
                // The temporary files, if any, stay with the old token's Arc.
                _keep_alive: Box::new(self.inner.clone()),
            }),
        }
    }

    /// In-crate tests: a token over `source` that claims `kind` at `location`.
    #[cfg(test)]
    pub(crate) fn for_tests(
        source: Arc<dyn MountSource>,
        kind: ServedKind,
        location: Option<ServedLocation>,
    ) -> Self {
        Self::mint(Opened {
            source,
            kind,
            inputs: Vec::new(),
            location,
            index: IndexProvenance::None,
            sidecar_candidate: None,
            fetched: false,
            keep_alive: Box::new(()),
        })
        .expect("test token")
    }
}

/// **Experimental.** A sealed overlay's own record. It is read from the
/// overlay, authorizes no create and no fresh seal, and nothing converts it
/// into a [`ClassifiedBase`].
///
/// ```compile_fail
/// # use ratarmount_compositing::*;
/// # use ratarmount_core::MountSource;
/// # use std::sync::Arc;
/// # struct Fixture;
/// # impl OpenBase for Fixture {
/// #     fn open_base(&mut self) -> Result<Opened, String> {
/// #         let dir = std::env::temp_dir();
/// #         let source: Arc<dyn MountSource> =
/// #             Arc::new(FolderMountSource::new(&dir).map_err(|e| e.to_string())?);
/// #         Ok(Opened {
/// #             source,
/// #             kind: ServedKind::Folder,
/// #             inputs: vec![],
/// #             location: Some(ServedLocation::Local(dir)),
/// #             index: IndexProvenance::None,
/// #             sidecar_candidate: None,
/// #             fetched: false,
/// #             keep_alive: Box::new(()),
/// #         })
/// #     }
/// # }
/// // compile_fail: SealedRecord literal
/// let record = SealedRecord::read(std::path::Path::new("/nonexistent"))?.unwrap();
/// let _ = SealedRecord {
///     dir: record.dir().to_path_buf(),
///     layer_digest: String::new(),
///     sealed_at: String::new(),
///     meta: record.meta().clone(),
/// };
/// # Ok::<(), ratarmount_compositing::OverlayError>(())
/// ```
///
/// ```no_run
/// # use ratarmount_compositing::*;
/// # use ratarmount_core::MountSource;
/// # use std::sync::Arc;
/// # struct Fixture;
/// # impl OpenBase for Fixture {
/// #     fn open_base(&mut self) -> Result<Opened, String> {
/// #         let dir = std::env::temp_dir();
/// #         let source: Arc<dyn MountSource> =
/// #             Arc::new(FolderMountSource::new(&dir).map_err(|e| e.to_string())?);
/// #         Ok(Opened {
/// #             source,
/// #             kind: ServedKind::Folder,
/// #             inputs: vec![],
/// #             location: Some(ServedLocation::Local(dir)),
/// #             index: IndexProvenance::None,
/// #             sidecar_candidate: None,
/// #             fetched: false,
/// #             keep_alive: Box::new(()),
/// #         })
/// #     }
/// # }
/// // control: SealedRecord literal
/// let record = SealedRecord::read(std::path::Path::new("/nonexistent"))?;
/// let _ = record.map(|r| r.layer_digest().to_owned());
/// # Ok::<(), ratarmount_compositing::OverlayError>(())
/// ```
#[derive(Clone, Debug)]
pub struct SealedRecord {
    pub(crate) dir: PathBuf,
    pub(crate) layer_digest: String,
    pub(crate) sealed_at: String,
    pub(crate) meta: OverlayMeta,
}

impl SealedRecord {
    /// `Some` only when the overlay's metadata says it is sealed.
    pub fn read(dir: impl AsRef<Path>) -> Result<Option<Self>> {
        let dir = dir.as_ref();
        let Some(meta) = OverlayMeta::read(dir)? else {
            return Ok(None);
        };
        if !meta.layer_sealed() {
            return Ok(None);
        }
        Ok(Some(Self {
            dir: dir.to_path_buf(),
            layer_digest: meta.get("layer_digest").unwrap_or("").to_owned(),
            sealed_at: meta.get("sealed_at").unwrap_or("").to_owned(),
            meta,
        }))
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn layer_digest(&self) -> &str {
        &self.layer_digest
    }
    pub fn sealed_at(&self) -> &str {
        &self.sealed_at
    }
    pub fn meta(&self) -> &OverlayMeta {
        &self.meta
    }
}

/// **Experimental.** Everything a creator or gate takes besides the token.
/// Identity-free: nothing here names the base.
#[derive(Clone, Debug, Default)]
pub struct CreateOptions {
    pub base_digest: BaseDigestRequest,
    pub force_base_mismatch: bool,
    pub lower_layers: Vec<LowerLayerRecord>,
    /// Paths of the caller (journal file, `--lower` layer directories) that
    /// may lie inside a directory base and must stay out of its digest.
    pub weak_exclude: Vec<PathBuf>,
    /// The index sidecar may be updated (a cached digest written back).
    pub index_writable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FolderMountSource;

    fn folder(root: &Path) -> Arc<dyn MountSource> {
        Arc::new(FolderMountSource::new(root).unwrap())
    }

    fn opened(root: &Path, kind: ServedKind, inputs: &[&str]) -> Opened {
        Opened {
            source: folder(root),
            kind,
            inputs: inputs.iter().map(|s| (*s).to_owned()).collect(),
            location: None,
            index: IndexProvenance::None,
            sidecar_candidate: None,
            fetched: false,
            keep_alive: Box::new(()),
        }
    }

    /// The token records what the opener reported, redacted and canonical.
    #[test]
    fn mint_maps_kind_redacts_and_canonicalizes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for (kind, want, tree) in [
            (ServedKind::Folder, BaseKind::Dir, None),
            (ServedKind::Archive, BaseKind::Archive, None),
            (
                ServedKind::Git { tree: "abc".into() },
                BaseKind::Git,
                Some("abc"),
            ),
        ] {
            let mut o = opened(&root, kind, &["https://u:s3cr3t@h.example/b.tar?sig=1"]);
            o.location = Some(ServedLocation::Remote(
                "https://u:s3cr3t@h.example/b.tar?sig=1".into(),
            ));
            let cb = ClassifiedBase::mint(o).unwrap();
            let actual = cb.actual();
            assert_eq!(actual.kind(), want);
            assert_eq!(actual.git_tree(), tree);
            assert!(actual.credentialed());
            assert_eq!(actual.base_url(), "https://h.example/b.tar");
            assert_eq!(
                actual.location(),
                Some(&BaseLocation::Remote("https://h.example/b.tar".into()))
            );
            assert!(!format!("{actual:?}").contains("s3cr3t"));
        }
        // A local location is canonical (a symlinked temp dir resolves).
        let mut o = opened(&root, ServedKind::Folder, &[]);
        o.location = Some(ServedLocation::Local(root.join(".")));
        let cb = ClassifiedBase::mint(o).unwrap();
        assert_eq!(cb.actual().location(), Some(&BaseLocation::Local(root)));
        assert!(!cb.actual().credentialed());
    }

    /// A composite carries a redacted token; a credentialed index URL marks
    /// the base credentialed and is never a peek target.
    #[test]
    fn mint_composite_token_and_credentialed_index() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut o = opened(
            &root,
            ServedKind::Archive,
            &["a.tar", "https://u:s3cr3t@h.example/b.tar"],
        );
        o.location = Some(ServedLocation::Local(root.clone()));
        o.index = IndexProvenance::Discovered {
            path: root.join("x.sqlite"),
            from: "https://h.example/x?token=abc#frag".into(),
        };
        let cb = ClassifiedBase::mint(o).unwrap();
        let token = cb.actual().remote_token().unwrap();
        assert!(!token.contains("s3cr3t"), "{token}");
        assert!(cb.actual().credentialed());
        assert_eq!(cb.actual().index_for_peek(), None);
        // Without a credential the discovered index is the peek target; an
        // in-memory open falls back to the sidecar candidate.
        let mut o = opened(&root, ServedKind::Archive, &["a.tar"]);
        o.location = Some(ServedLocation::Local(root.clone()));
        o.index = IndexProvenance::Local(root.join("x.sqlite"));
        o.sidecar_candidate = Some(root.join("a.tar.index.sqlite"));
        let cb = ClassifiedBase::mint(o).unwrap();
        assert_eq!(
            cb.actual().index_for_peek(),
            Some(root.join("x.sqlite").as_path())
        );
        let mut o = opened(&root, ServedKind::Archive, &["a.tar"]);
        o.location = Some(ServedLocation::Local(root.clone()));
        o.sidecar_candidate = Some(root.join("a.tar.index.sqlite"));
        let cb = ClassifiedBase::mint(o).unwrap();
        assert_eq!(
            cb.actual().index_for_peek(),
            Some(root.join("a.tar.index.sqlite").as_path())
        );
        // Never for a directory or a remote location.
        let mut o = opened(&root, ServedKind::Folder, &["d"]);
        o.location = Some(ServedLocation::Local(root.clone()));
        o.sidecar_candidate = Some(root.join("a.tar.index.sqlite"));
        assert_eq!(
            ClassifiedBase::mint(o).unwrap().actual().index_for_peek(),
            None
        );
    }

    /// `repointed` moves the token to the committed archive and keeps the
    /// source; `for_tests` builds the same token a test needs.
    #[test]
    fn repointed_targets_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let archive = root.join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let cb = ClassifiedBase::for_tests(folder(&root), ServedKind::Folder, None);
        assert_eq!(cb.actual().kind(), BaseKind::Dir);
        let moved = cb.repointed(&archive);
        assert_eq!(moved.actual().kind(), BaseKind::Archive);
        assert_eq!(
            moved.actual().location(),
            Some(&BaseLocation::Local(archive))
        );
        assert_eq!(moved.actual().git_tree(), None);
        assert!(Arc::ptr_eq(&cb.source(), &moved.source()));
    }
}
