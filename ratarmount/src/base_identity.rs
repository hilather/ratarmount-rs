//! The one production `OpenBase`: the session factory.
//!
//! Compositing defines the token ([`ClassifiedBase`]) and the trait; it cannot
//! call the factory (session depends on compositing). The binary supplies the
//! only production implementation, so every base a mount or a verb creates an
//! overlay over, or compares an overlay with, comes from what the factory
//! actually served, not from a path or URL guess.

use std::path::{Path, PathBuf};

use ratarmount_compositing::overlay_gate::Recorded;
use ratarmount_compositing::overlay_identity::BaseKind;
use ratarmount_compositing::{ClassifiedBase, OpenBase, Opened, OverlayMeta};
use ratarmount_core::OpenOptions;
use ratarmount_session::factory::{self, CompositingOptions, SourceBindings};

/// Opens a base through the factory and reports what it served.
///
/// One-shot: `open_base` consumes the compositing options and bindings.
pub struct FactoryOpener<'a> {
    /// The inputs as the user typed them (selectors included), captured
    /// BEFORE any Git pinning rewrites `paths[0]`.
    typed: Vec<String>,
    /// The positional paths handed to the factory (empty for a corpus or a
    /// rolling series, which arrive as declared sources).
    paths: Vec<PathBuf>,
    options: &'a mut OpenOptions,
    recreate: bool,
    comp: Option<CompositingOptions>,
    bindings: Option<SourceBindings>,
    /// Resolve a moving Git reference once before the factory opens it.
    pin_git: bool,
}

impl<'a> FactoryOpener<'a> {
    pub fn new(
        typed: Vec<String>,
        paths: Vec<PathBuf>,
        options: &'a mut OpenOptions,
        recreate: bool,
        comp: CompositingOptions,
        bindings: SourceBindings,
        pin_git: bool,
    ) -> Self {
        Self {
            typed,
            paths,
            options,
            recreate,
            comp: Some(comp),
            bindings: Some(bindings),
            pin_git,
        }
    }
}

impl OpenBase for FactoryOpener<'_> {
    fn open_base(&mut self) -> Result<Opened, String> {
        let (Some(comp), Some(bindings)) = (self.comp.take(), self.bindings.take()) else {
            return Err("the base was already opened".into());
        };
        if self.pin_git {
            // The tree id is read off the served source; pinning only makes a
            // moving reference resolve once.
            crate::overlay_cmd::pin_git_base(&mut self.paths, self.options)
                .map_err(|error| format!("resolving overlay base: {error}"))?;
        }
        let mut bundle = factory::build_mount_source_with_bindings(
            &self.paths,
            self.options,
            self.recreate,
            comp,
            bindings,
        )?;
        let served = bundle
            .served
            .take()
            .ok_or_else(|| "the factory opened no base".to_owned())?;
        Ok(Opened {
            source: bundle.source.clone(),
            kind: served.kind,
            inputs: std::mem::take(&mut self.typed),
            location: served.location,
            index: served.index,
            sidecar_candidate: served.sidecar_candidate,
            fetched: served.fetched,
            keep_alive: bundle.into_keep_alive(),
        })
    }
}

/// What the parent invocation says about how verbs should open a base: the
/// custom `--index-folders` an offline `seal`, `pack`, `diff`, `verify`,
/// import or `sandbox run` finish must honour, so the sidecar a mount used is
/// the one they read (and peek at, for a cached digest).
#[derive(Clone, Debug, Default)]
pub struct OverlayRunContext {
    pub index_folders: Vec<PathBuf>,
}

/// Whether a plain local path is Git. A path the user typed as `git://`,
/// `repo@rev` or a bare repository is always Git (the factory sees that);
/// this decides only the ambiguous case of a working tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitIntent {
    /// A working tree with a `.git` entry is mounted as Git (the import verbs
    /// open the base the way the user would mount it).
    Auto,
    /// Replay what the overlay recorded: Git only when it recorded Git.
    Replay(Option<BaseKind>),
}

impl GitIntent {
    /// Replay the kind an overlay recorded (none for an unrecorded one).
    pub fn replay(meta: Option<&OverlayMeta>) -> Self {
        Self::Replay(match Recorded::from_meta(meta) {
            Recorded::Kind { kind, .. } => Some(kind),
            Recorded::Unrecorded | Recorded::Nothing | Recorded::Unknown => None,
        })
    }
}

/// Open and classify a base for an offline verb: through the factory, with an
/// in-memory index, no index writes and the invocation's index folders.
pub fn classify_offline(
    base: &Path,
    git: GitIntent,
    context: &OverlayRunContext,
) -> Result<ClassifiedBase, String> {
    classify_offline_in_memory(base, git, context)
}

/// Classify the archive an offline `--commit-overlay` is about to rewrite.
///
/// Unlike [`classify_offline`] this never opens the archive: no index is built
/// or loaded (a large archive's index build was the whole cost), no sidecar is
/// read or written and no commit journal is recovered (the identity gate must
/// judge the file BEFORE recovery touches it). What the commit gate compares is
/// the kind, the place and the file's stamp; the kind and place come from the
/// factory's own dispatch questions ([`factory::served_without_indexing`]), so
/// a local `.torrent` or a `file://` URL is classified as a mount classifies
/// it. The token's source is an [`ratarmount_compositing::UnopenedSource`]:
/// the commit path reads only the identity.
pub fn classify_offline_commit(
    base: &Path,
    context: &OverlayRunContext,
) -> Result<ClassifiedBase, String> {
    let mut opener = CommitOpener {
        base,
        index_folders: &context.index_folders,
    };
    ClassifiedBase::open(&mut opener)
}

struct CommitOpener<'a> {
    base: &'a Path,
    index_folders: &'a [PathBuf],
}

impl OpenBase for CommitOpener<'_> {
    fn open_base(&mut self) -> Result<Opened, String> {
        let served = factory::served_without_indexing(self.base, self.index_folders)?;
        // Nothing is opened: `commit_overlay` takes the token's identity only.
        Ok(Opened {
            source: std::sync::Arc::new(ratarmount_compositing::UnopenedSource),
            kind: served.kind,
            inputs: vec![self.base.to_string_lossy().into_owned()],
            location: served.location,
            index: served.index,
            sidecar_candidate: served.sidecar_candidate,
            fetched: false,
            keep_alive: Box::new(()),
        })
    }
}

fn classify_offline_in_memory(
    base: &Path,
    git: GitIntent,
    context: &OverlayRunContext,
) -> Result<ClassifiedBase, String> {
    let git_tree = match git {
        GitIntent::Auto => base.join(".git").exists(),
        GitIntent::Replay(kind) => {
            kind == Some(BaseKind::Git) && ratarmount_formats_git::looks_like_git(base)
        }
    };
    let mut options = OpenOptions {
        write_index: false,
        index_in_memory: true,
        index_folders: context.index_folders.clone(),
        git: git_tree,
        ..Default::default()
    };
    let mut opener = FactoryOpener::new(
        vec![base.to_string_lossy().into_owned()],
        vec![base.to_path_buf()],
        &mut options,
        false,
        Default::default(),
        Default::default(),
        git == GitIntent::Auto,
    );
    ClassifiedBase::open(&mut opener)
}

/// The source a mount serves, plus what keeps it alive (downloaded bodies).
/// When the mount has an overlay or lower, the token owns the keep-alive too.
pub struct MountedSource {
    pub source: std::sync::Arc<dyn ratarmount_core::MountSource>,
    pub _keep_alive: Box<dyn std::any::Any + Send + Sync>,
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::path::Path;
    use std::sync::Arc;

    use ratarmount_compositing::{
        ClassifiedBase, IndexProvenance, OpenBase, Opened, ServedKind, ServedLocation,
    };
    use ratarmount_core::{MountSource, OpenOptions};

    /// Classify `path` through the real factory with index-free defaults.
    pub(crate) fn classify(path: &Path) -> ClassifiedBase {
        classify_with(path, OpenOptions::default())
    }

    pub(crate) fn classify_with(path: &Path, mut options: OpenOptions) -> ClassifiedBase {
        options.index_in_memory = true;
        let mut opener = super::FactoryOpener::new(
            vec![path.to_string_lossy().into_owned()],
            vec![path.to_path_buf()],
            &mut options,
            false,
            Default::default(),
            Default::default(),
            false,
        );
        ClassifiedBase::open(&mut opener).expect("classify through the factory")
    }

    /// A drop-in for `WriteOverlay::new(base, dir)` in tests: opens the
    /// overlay over a token that reports `base` as a local folder.
    pub(crate) fn new_overlay(
        base: Arc<dyn MountSource>,
        dir: impl AsRef<Path>,
    ) -> Result<ratarmount_compositing::WriteOverlay, ratarmount_compositing::OverlayError> {
        let token = ClassifiedBase::open(&mut FixtureOpener {
            source: base.clone(),
            kind: ServedKind::Folder,
            inputs: Vec::new(),
            location: None,
        })
        .map_err(ratarmount_compositing::OverlayError::Msg)?;
        ratarmount_compositing::WriteOverlay::open(
            &token,
            base,
            dir,
            &ratarmount_compositing::CreateOptions {
                base_digest: ratarmount_compositing::BaseDigestRequest::None,
                ..Default::default()
            },
        )
    }

    /// A drop-in for the old untokened `overlay_seal::seal(dir, view)`.
    pub(crate) fn seal(
        dir: &Path,
        view: Arc<dyn MountSource>,
    ) -> std::io::Result<ratarmount_compositing::overlay_seal::SealOutcome> {
        let token = ClassifiedBase::open(&mut FixtureOpener {
            source: view.clone(),
            kind: ServedKind::Folder,
            inputs: Vec::new(),
            location: None,
        })
        .map_err(std::io::Error::other)?;
        ratarmount_compositing::overlay_seal::seal(dir, &token, view)
    }

    /// A drop-in for the old `WriteOverlay::new_with_create_info(source, dir,
    /// &info)` in tests: the token reports `base_url` as the typed input
    /// (a directory is a local folder, a file a local archive, anything else a
    /// remote archive) and the overlay records the given lower layers.
    pub(crate) fn overlay_over(
        source: Arc<dyn MountSource>,
        dir: impl AsRef<Path>,
        base_url: &str,
        lower_layers: Vec<ratarmount_compositing::LowerLayerRecord>,
    ) -> Result<ratarmount_compositing::WriteOverlay, ratarmount_compositing::OverlayError> {
        overlay_over_with(
            source,
            dir,
            base_url,
            lower_layers,
            ratarmount_compositing::BaseDigestRequest::Compute,
        )
    }

    /// [`overlay_over`] with an explicit digest request.
    pub(crate) fn overlay_over_with(
        source: Arc<dyn MountSource>,
        dir: impl AsRef<Path>,
        base_url: &str,
        lower_layers: Vec<ratarmount_compositing::LowerLayerRecord>,
        base_digest: ratarmount_compositing::BaseDigestRequest,
    ) -> Result<ratarmount_compositing::WriteOverlay, ratarmount_compositing::OverlayError> {
        let path = Path::new(base_url);
        let (kind, location) = if path.is_dir() {
            (
                ServedKind::Folder,
                ServedLocation::Local(path.to_path_buf()),
            )
        } else if path.is_file() {
            (
                ServedKind::Archive,
                ServedLocation::Local(path.to_path_buf()),
            )
        } else {
            (
                ServedKind::Archive,
                ServedLocation::Remote(base_url.to_owned()),
            )
        };
        let token = ClassifiedBase::open(&mut FixtureOpener {
            source: source.clone(),
            kind,
            inputs: vec![base_url.to_owned()],
            location: Some(location),
        })
        .map_err(ratarmount_compositing::OverlayError::Msg)?;
        ratarmount_compositing::WriteOverlay::open(
            &token,
            source,
            dir,
            &ratarmount_compositing::CreateOptions {
                lower_layers,
                base_digest,
                ..Default::default()
            },
        )
    }

    /// An opener that reports exactly what a test says it served (no
    /// factory): for inputs that cannot be opened offline, such as a remote
    /// URL with a credential.
    pub(crate) struct FixtureOpener {
        pub source: Arc<dyn MountSource>,
        pub kind: ServedKind,
        pub inputs: Vec<String>,
        pub location: Option<ServedLocation>,
    }

    impl OpenBase for FixtureOpener {
        fn open_base(&mut self) -> Result<Opened, String> {
            Ok(Opened {
                source: self.source.clone(),
                kind: self.kind.clone(),
                inputs: self.inputs.clone(),
                location: self.location.clone(),
                index: IndexProvenance::None,
                sidecar_candidate: None,
                fetched: false,
                keep_alive: Box::new(()),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: classification is the factory open a verb already needs and
    /// nothing else: no directory walk, no digest, and (for an archive) no
    /// hashing or stamp comparison. A big directory and a plain archive are
    /// classified without any content work.
    #[test]
    fn regression_classifier_does_no_content_work() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let folder = root.join("folder");
        std::fs::create_dir(&folder).unwrap();
        for i in 0..50 {
            std::fs::write(folder.join(format!("f{i}")), vec![b'x'; 1024]).unwrap();
        }
        let archive = root.join("a.tar");
        let members = [ratarmount_formats_tar::UstarMember {
            path: "f",
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        }];
        let mut file = std::fs::File::create(&archive).unwrap();
        ratarmount_formats_tar::write_ustar_members(&mut file, &members).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut file).unwrap();
        drop(file);
        let walks = ratarmount_compositing::directory_weak_walks_this_thread();
        let digests = ratarmount_compositing::directory_digest_calls_this_thread();
        for base in [&folder, &archive] {
            classify_offline(base, GitIntent::Replay(None), &OverlayRunContext::default()).unwrap();
        }
        assert_eq!(
            ratarmount_compositing::directory_weak_walks_this_thread(),
            walks
        );
        assert_eq!(
            ratarmount_compositing::directory_digest_calls_this_thread(),
            digests
        );
        // No sidecar was created next to the archive, either.
        assert!(!root.join("a.tar.index.sqlite").exists());
    }

    /// Regression (R6-G4, offline-commit cost): offline `--commit-overlay`
    /// classified the archive with an in-memory index (R6 review), then by
    /// loading its sidecar (R6-F7), so a multi-GB archive paid an index
    /// build or load just to learn it is an archive. The commit's classifier
    /// opens nothing: the token's source holds no member of the archive, no
    /// file appears beside it and its sidecar is untouched; the sidecar is
    /// still the peek target for a cached digest.
    #[test]
    fn regression_offline_commit_classification_builds_no_index() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let archive = root.join("a.tar");
        let members = [ratarmount_formats_tar::UstarMember {
            path: "f",
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        }];
        let mut file = std::fs::File::create(&archive).unwrap();
        ratarmount_formats_tar::write_ustar_members(&mut file, &members).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut file).unwrap();
        drop(file);
        let sidecar = root.join("a.tar.index.sqlite");
        drop(
            ratarmount_formats_tar::SqliteIndexedTar::create_index(
                &archive,
                &archive,
                Some(&sidecar),
                &ratarmount_core::OpenOptions::default(),
                "test",
                &mut None,
            )
            .unwrap(),
        );
        let names = |dir: &Path| {
            let mut all: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            all.sort();
            all
        };
        let (listing, before) = (names(&root), std::fs::read(&sidecar).unwrap());
        let context = OverlayRunContext::default();
        let token = classify_offline_commit(&archive, &context).unwrap();
        assert_eq!(token.actual().kind(), BaseKind::Archive);
        assert!(
            token.source().lookup("/f", 0).is_none(),
            "no index of the archive may be built or loaded"
        );
        assert_eq!(token.actual().index_for_peek(), Some(sidecar.as_path()));
        assert_eq!(names(&root), listing, "nothing created beside the archive");
        assert!(
            std::fs::read(&sidecar).unwrap() == before,
            "sidecar written"
        );
        // The other offline verbs keep the factory's in-memory open.
        let fresh = classify_offline(&archive, GitIntent::Replay(None), &context).unwrap();
        assert!(fresh.source().lookup("/f", 0).is_some());
    }
}
