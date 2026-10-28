use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

pub(super) struct ByteFile {
    file: File,
}

impl ByteFile {
    pub(super) fn open(path: &Path, writable: bool) -> io::Result<Self> {
        debug_assert!(!writable);
        super::seams::set_path(path);
        super::seams::fire(super::Seam::BeforeOpen)?;
        #[cfg(any(test, feature = "test-hooks"))]
        super::XOPEN_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0453-I01","disposition":"managed-read","reason":"non-Unix backend of ManagedReadCursor (an ordinary private file)","regression":"regression_internal_cursor_clones_have_independent_offsets","managed_backend":true,"item":"<ratarmount_index::managed_read::imp::ByteFile>::open","native_observed":false,"creation":{"policy":"none","basis":"The non-Unix managed backend opens an existing private input file and validates regular-file type."},"category":"managed-reader-backend"}"###
        )]
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(super::not_regular_file(path));
        }
        super::seams::fire(super::Seam::AfterOpen)?;
        Ok(Self { file })
    }

    pub(super) fn len(&mut self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    pub(super) fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)
    }

    pub(super) fn sync(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }

    pub(super) fn has_moved(&mut self) -> io::Result<bool> {
        Ok(false)
    }
}
