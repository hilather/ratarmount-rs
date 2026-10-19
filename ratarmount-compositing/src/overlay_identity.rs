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

use crate::overlay_meta::{OverlayCreateInfo, OverlayMeta};
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

impl BaseLocation {
    /// The value stored in the `base_location` row.
    pub(crate) fn row(&self) -> String {
        match self {
            BaseLocation::Local(path) => format!("local:{}", path.display()),
            BaseLocation::Remote(url) => format!("remote:{url}"),
        }
    }

    /// Inverse of [`Self::row`]; `None` for an absent or unknown form.
    pub(crate) fn from_row(row: &str) -> Option<Self> {
        if let Some(path) = row.strip_prefix("local:") {
            Some(BaseLocation::Local(PathBuf::from(path)))
        } else {
            row.strip_prefix("remote:")
                .map(|url| BaseLocation::Remote(url.to_owned()))
        }
    }
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
    /// The index the opener selected (never a credentialed one).
    pub(crate) index_path: Option<PathBuf>,
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

    /// The creation input the overlay database is initialized from. The only
    /// way to build an [`OverlayCreateInfo`]: nothing here names a base the
    /// opener did not report.
    pub(crate) fn create_info(&self, options: &CreateOptions) -> OverlayCreateInfo {
        let composite = self.remote_token.is_some();
        let local_path = match (&self.location, self.kind) {
            // A composite has no single content identity, and a remote or Git
            // base is identified by other means.
            (Some(BaseLocation::Local(path)), BaseKind::Archive | BaseKind::Dir) if !composite => {
                Some(path.clone())
            }
            _ => None,
        };
        OverlayCreateInfo {
            base_url: self.base_url.clone(),
            base_digest: options.base_digest.clone(),
            lower_layers: options.lower_layers.clone(),
            force_base_mismatch: options.force_base_mismatch,
            local_path,
            classified: true,
            index_path: self
                .index_path
                .clone()
                .filter(|_| options.index_writable && !self.credentialed),
            git_tree: self.git_tree.clone(),
            remote_token: self
                .remote_token
                .clone()
                .or_else(|| options.remote_token.clone()),
            weak_exclude: options.weak_exclude.clone(),
        }
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
///     index_path: None,
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
///
/// A sealed overlay's own record cannot start a seal (it is not a token), but
/// the token can:
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
/// // compile_fail: seal(&sealed_record)
/// let record = SealedRecord::read("/nonexistent")?.unwrap();
/// let _ = overlay_seal::seal("/nonexistent".as_ref(), &record, Arc::new(FolderMountSource::new("/tmp").unwrap()));
/// # Ok::<(), OverlayError>(())
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
/// // control: seal(&classified)
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let _ = overlay_seal::seal("/nonexistent".as_ref(), &cb, cb.source());
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
/// // compile_fail: reseal(&classified)
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let _ = overlay_seal::reseal(&cb);
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
/// // control: reseal(&sealed_record)
/// let record = SealedRecord::read("/nonexistent")?.unwrap();
/// let _ = overlay_seal::reseal(&record);
/// # Ok::<(), OverlayError>(())
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
/// // compile_fail: check_commit_base (pub(crate))
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let conn = rusqlite::Connection::open_in_memory().unwrap();
/// let _ = overlay_gate::check_commit_base(&conn, &cb, "/tmp".as_ref());
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
/// // control: commit through the public WriteOverlay entry
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let overlay = WriteOverlay::open(&cb, cb.source(), "/nonexistent", &CreateOptions::default()).unwrap();
/// let _ = overlay.commit_atomic("/tmp/a.tar".as_ref());
/// # Ok::<(), String>(())
/// ```
///
/// The deleted token-free entries stay deleted, and their replacements take the
/// token:
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
/// // compile_fail: WriteOverlay::new (deleted)
/// let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new("/tmp").unwrap());
/// let _ = WriteOverlay::new(source, "/nonexistent");
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
/// // control: WriteOverlay::open
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let _ = WriteOverlay::open(
///     &cb,
///     cb.source(),
///     "/nonexistent",
///     &CreateOptions {
///         base_digest: BaseDigestRequest::None,
///         force_base_mismatch: false,
///         lower_layers: vec![],
///         weak_exclude: vec![],
///         index_writable: false,
///         remote_token: None,
///     },
/// );
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
/// // compile_fail: record_base_rows_offline (pub(crate))
/// let rows = std::collections::BTreeMap::new();
/// let _ = overlay_meta::record_base_rows_offline("/nonexistent".as_ref(), &rows);
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
/// // control: record_forced_base_rows
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let rows = std::collections::BTreeMap::new();
/// let _ = record_forced_base_rows("/nonexistent".as_ref(), &cb, &rows);
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
/// // compile_fail: commit_overlay without a token
/// let _ = commit_overlay("/nonexistent", "/tmp/a.tar", &CommitOverlayOptions::default());
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
/// // control: commit_overlay over a classified base, and the raw directory entry
/// let cb = ClassifiedBase::open(&mut Fixture)?;
/// let opts = CommitOverlayOptions::default();
/// let _ = commit_overlay("/nonexistent", "/tmp/a.tar", &cb, &opts);
/// let _ = commit_overlay_raw_dir("/nonexistent", "/tmp/a.tar", &opts);
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
/// // compile_fail: OverlayCreateInfo is not public
/// let _ = OverlayCreateInfo::default();
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
/// // control: CreateOptions is the public, identity-free input
/// let _ = CreateOptions::default();
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
        let index_path = match &index {
            IndexProvenance::Local(path) | IndexProvenance::Discovered { path, .. }
                if !credentialed =>
            {
                Some(path.clone())
            }
            _ => None,
        };
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
            index_path,
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
    /// Cheap remote identity (ETag, or Content-Length + Last-Modified) the
    /// caller read when it created a single remote base; a composite's token
    /// comes from the opener's inputs.
    pub remote_token: Option<String>,
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

    /// Regression: the default index name embeds the whole URL, so an index
    /// selected for a credentialed input is never recorded as `base_index_path`
    /// (the old check compared a URL with itself and was always false). It is
    /// also never a peek target. Without a credential it is recorded when the
    /// caller may write the index.
    #[test]
    fn regression_credentialed_url_index_path_not_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let options = CreateOptions {
            index_writable: true,
            ..Default::default()
        };
        for (typed, credentialed) in [
            ("https://u:s3cr3t@h.example/a.tar", true),
            ("https://h.example/a.tar?sig=abc", true),
            ("https://h.example/a.tar", false),
        ] {
            let mut o = opened(&root, ServedKind::Archive, &[typed]);
            o.location = Some(ServedLocation::Remote(typed.into()));
            o.index = IndexProvenance::Local(root.join("idx.sqlite"));
            let cb = ClassifiedBase::mint(o).unwrap();
            assert_eq!(cb.actual().credentialed(), credentialed, "{typed}");
            let info = cb.actual().create_info(&options);
            assert_eq!(
                info.index_path.is_some(),
                !credentialed,
                "{typed}: index_path {:?}",
                info.index_path
            );
        }
        // A caller that may not write the index records none either.
        let mut o = opened(&root, ServedKind::Archive, &["a.tar"]);
        o.location = Some(ServedLocation::Local(root.clone()));
        o.index = IndexProvenance::Local(root.join("idx.sqlite"));
        let cb = ClassifiedBase::mint(o).unwrap();
        assert!(cb
            .actual()
            .create_info(&CreateOptions::default())
            .index_path
            .is_none());
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
