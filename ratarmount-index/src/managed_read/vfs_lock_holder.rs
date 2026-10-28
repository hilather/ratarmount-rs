use super::{imp, VfsLockHolder};
use std::{io, path::Path};

impl VfsLockHolder {
    pub fn shared(path: &Path) -> io::Result<Self> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0076-M01","item":"<ratarmount_index::managed_read::VfsLockHolder>::shared","disposition":"managed-read","category":"feature-test-hook","reason":"Construct the test-hook shared-lock holder using the managed ByteFile reader.","creation":{"policy":"none","basis":"The helper opens existing content and then takes the SQLite shared lock; it does not create an input."}}"###
        )]
        let mut file = imp::ByteFile::open(path)?;
        file.lock_shared()?;
        Ok(Self { file })
    }
}

impl Drop for VfsLockHolder {
    fn drop(&mut self) {
        self.file.unlock();
    }
}
