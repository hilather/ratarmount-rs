//! The one production `OpenBase`: the session factory.
//!
//! Compositing defines the token ([`ClassifiedBase`]) and the trait; it cannot
//! call the factory (session depends on compositing). The binary supplies the
//! only production implementation, so every base a mount or a verb creates an
//! overlay over, or compares an overlay with, comes from what the factory
//! actually served, not from a path or URL guess.

use std::path::PathBuf;

use ratarmount_compositing::{OpenBase, Opened};
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
