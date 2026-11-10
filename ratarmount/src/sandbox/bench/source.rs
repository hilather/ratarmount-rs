//! Task archives are fresh source trees, never overlay/layer bundles.
use super::io::{self as owned, invalid};
use rustix::fd::OwnedFd;
use rustix::fs::{fchmod, futimens, symlinkat, utimensat, AtFlags, Mode, Timespec, Timestamps};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Seek};

const MAX_ENTRIES: usize = 100_000;
const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub(super) fn verify_artifact(file: &mut File, digest: &str, disk_bytes: u64) -> io::Result<()> {
    if file.metadata()?.len() > disk_bytes.min(MAX_BYTES) {
        return Err(invalid("artifact byte bound exceeded"));
    }
    file.rewind()?;
    let mut input = Hashed::new(file, disk_bytes.min(MAX_BYTES));
    io::copy(&mut input, &mut io::sink())?;
    if input.digest() != digest {
        return Err(invalid("artifact sha256 mismatch"));
    }
    input.reader.rewind()
}
struct Hashed<R> {
    reader: R,
    hash: Sha256,
    remaining: u64,
}
impl<R> Hashed<R> {
    fn new(reader: R, remaining: u64) -> Self {
        Self {
            reader,
            hash: Sha256::new(),
            remaining,
        }
    }
    fn digest(&self) -> String {
        format!("sha256:{:x}", self.hash.clone().finalize())
    }
}
impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let limit = buffer.len().min(self.remaining.saturating_add(1) as usize);
        let count = self.reader.read(&mut buffer[..limit])?;
        if count as u64 > self.remaining {
            return Err(invalid("archive byte bound exceeded"));
        }
        self.remaining -= count as u64;
        self.hash.update(&buffer[..count]);
        Ok(count)
    }
}
fn path(bytes: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("non-UTF-8 archive path"))?;
    let text = text.trim_end_matches('/');
    if text.len() > 4096 || text.split('/').count() > 128 || text.contains(['\0', '\\']) {
        return Err(invalid("unsafe archive path"));
    }
    for part in text.split('/') {
        owned::component(part)?;
    }
    Ok(text.to_owned())
}
fn link_target(parent: &str, bytes: &[u8]) -> io::Result<String> {
    let target = std::str::from_utf8(bytes).map_err(|_| invalid("non-UTF-8 symlink"))?;
    if target.is_empty()
        || target.starts_with('/')
        || target.len() > 4096
        || target.contains(['\0', '\\'])
    {
        return Err(invalid("unsafe symlink target"));
    }
    let mut depth = if parent.is_empty() {
        0
    } else {
        parent.split('/').count()
    };
    for part in target.split('/') {
        match part {
            ".." => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid("symlink escapes tree"))?
            }
            "" | "." => {}
            _ => depth += 1,
        }
    }
    Ok(target.into())
}
pub(super) struct Tree {
    root: OwnedFd,
    directories: BTreeMap<String, (OwnedFd, u32, u64)>,
}
impl Tree {
    fn directory(&mut self, name: &str) -> io::Result<&OwnedFd> {
        let mut parent = String::new();
        for part in name.split('/').filter(|p| !p.is_empty()) {
            let child = if parent.is_empty() {
                part.into()
            } else {
                format!("{parent}/{part}")
            };
            if !self.directories.contains_key(&child) {
                let fd = if parent.is_empty() {
                    &self.root
                } else {
                    &self.directories[&parent].0
                };
                let child_fd = owned::create_directory(fd, part)?;
                self.directories.insert(child.clone(), (child_fd, 0o755, 0));
            }
            parent = child;
        }
        Ok(if name.is_empty() {
            &self.root
        } else {
            &self.directories[name].0
        })
    }
    pub fn make_removable(&self) -> io::Result<()> {
        fchmod(&self.root, Mode::from_raw_mode(0o700))?;
        for (fd, _, _) in self.directories.values() {
            fchmod(fd, Mode::from_raw_mode(0o700))?;
        }
        Ok(())
    }
}
// No automatic deletion: the caller must first establish that the runtime stopped.
pub(super) fn extract(
    file: &mut File,
    root: OwnedFd,
    digest: &str,
    max_bytes: u64,
) -> io::Result<Tree> {
    file.rewind()?;
    let size = file.metadata()?.len();
    let mut decoder = zstd::stream::read::Decoder::new(&mut *file)?.single_frame();
    decoder.window_log_max(27)?;
    let mut tree = Tree {
        root,
        directories: BTreeMap::new(),
    };
    let extracted = (|| {
        extract_tar(
            &mut tree,
            Hashed::new(&mut decoder, max_bytes.min(MAX_BYTES)),
            digest,
            MAX_ENTRIES,
        )?;
        let mut buffered = decoder.finish();
        let remaining = buffered.buffer().len() as u64;
        if buffered.get_mut().stream_position()? - remaining != size {
            return Err(invalid("artifact must contain exactly one zstd frame"));
        }
        Ok(())
    })();
    if extracted.is_err() {
        tree.make_removable()?;
    }
    extracted?;
    Ok(tree)
}
fn extract_tar<R: Read>(
    tree: &mut Tree,
    input: Hashed<R>,
    digest: &str,
    max_entries: usize,
) -> io::Result<()> {
    let mut archive = tar::Archive::new(input);
    let mut seen = BTreeSet::new();
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        if seen.len() >= max_entries {
            return Err(invalid("archive entry bound exceeded"));
        }
        let name = path(&entry.path_bytes())?;
        if !seen.insert(name.clone()) {
            return Err(invalid("duplicate archive path"));
        }
        let mode = entry.header().mode()?;
        if mode & !0o777 != 0 {
            return Err(invalid("unsupported archive mode bits"));
        }
        let mtime = entry.header().mtime()?;
        let kind = entry.header().entry_type();
        let (parent, leaf) = name.rsplit_once('/').unwrap_or(("", &name));
        if kind.is_dir() {
            tree.directory(&name)?;
            let metadata = tree.directories.get_mut(&name).unwrap();
            metadata.1 = mode;
            metadata.2 = mtime;
        } else if kind.is_file() {
            let parent = tree.directory(parent)?;
            let mut output = owned::create_tree_file(parent, leaf)?;
            let expected = entry.size();
            if expected > MAX_BYTES {
                return Err(invalid("archive member byte bound exceeded"));
            }
            if io::copy(&mut entry, &mut output)? != expected {
                return Err(invalid("truncated archive member"));
            }
            fchmod(&output, Mode::from_raw_mode(mode))?;
            futimens(&output, &times(mtime)?)?;
        } else if kind.is_symlink() {
            let bytes = entry
                .link_name_bytes()
                .ok_or_else(|| invalid("missing symlink target"))?;
            let target = link_target(parent, &bytes)?;
            let parent = tree.directory(parent)?;
            symlinkat(target.as_str(), parent, leaf)?;
            utimensat(parent, leaf, &times(mtime)?, AtFlags::SYMLINK_NOFOLLOW)?;
        } else {
            return Err(invalid("unsupported special archive entry"));
        }
    }
    let mut input = archive.into_inner();
    io::copy(&mut input, &mut io::sink())?; // Hash the complete tar stream, including padding.
    if input.digest() != digest {
        return Err(invalid("tar-stream sha256 mismatch"));
    }
    // Held descriptors let restrictive parent modes be applied after all descendants.
    for (fd, mode, mtime) in tree.directories.values().rev() {
        fchmod(fd, Mode::from_raw_mode(*mode))?;
        futimens(fd, &times(*mtime)?)?;
    }
    Ok(())
}

fn times(mtime: u64) -> io::Result<Timestamps> {
    let time = Timespec {
        tv_sec: mtime
            .try_into()
            .map_err(|_| invalid("archive mtime out of range"))?,
        tv_nsec: 0,
    };
    Ok(Timestamps {
        last_access: time,
        last_modification: time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn tar(entries: &[(&str, u8, u32, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, mode, data) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_mode(*mode);
            header.set_mtime(123456);
            header.set_entry_type(tar::EntryType::new(*kind));
            header.set_size(if *kind == b'0' { data.len() as u64 } else { 0 });
            if *kind == b'2' {
                header.set_link_name(data).unwrap();
            }
            // Write raw paths so negative tests are not refused by the fixture builder.
            header.as_mut_bytes()[..100].fill(0);
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            builder
                .append(&header, if *kind == b'0' { data.as_bytes() } else { b"" })
                .unwrap();
        }
        builder.into_inner().unwrap()
    }
    fn unpack(bytes: &[u8], digest: &str, max: u64, entries: usize) -> io::Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let mut tree = Tree {
            root: owned::open_directory(dir.path())?,
            directories: BTreeMap::new(),
        };
        let result = extract_tar(&mut tree, Hashed::new(bytes, max), digest, entries);
        tree.make_removable()?;
        result
    }
    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }
    // Regression: artifact digest mismatches reached extraction or runtime setup.
    #[test]
    fn regression_bench_manifest_artifact_sha_mismatch() {
        let mut file = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut file, b"artifact").unwrap();
        assert!(verify_artifact(&mut file, &digest(b"other"), 100)
            .unwrap_err()
            .to_string()
            .contains("artifact sha256 mismatch"));
        assert!(verify_artifact(&mut file, &digest(b"artifact"), 7).is_err());
        verify_artifact(&mut file, &digest(b"artifact"), 100).unwrap();
    }
    // Regression: unsafe, duplicate, special entries or symlink parents escaped extraction.
    #[test]
    fn regression_bench_native_archive_paths_confined() {
        for entries in [
            vec![("../escape", b'0', 0o644, "x")],
            vec![("/absolute", b'0', 0o644, "x")],
            vec![("a//b", b'0', 0o644, "x")],
            vec![("a/./b", b'0', 0o644, "x")],
            vec![("a", b'0', 0o644, "x"), ("a", b'0', 0o644, "y")],
            vec![
                ("dir", b'5', 0o755, ""),
                ("a", b'2', 0o777, "dir"),
                ("a/file", b'0', 0o644, "x"),
            ],
            vec![("a", b'2', 0o777, "../escape")],
            vec![("a", b'2', 0o777, "/absolute")],
            vec![("a", b'1', 0o644, "")],
            vec![("a", b'6', 0o644, "")],
            vec![("a", b'0', 0o4755, "x")],
        ] {
            let bytes = tar(&entries);
            assert!(
                unpack(&bytes, &digest(&bytes), 100_000, 10).is_err(),
                "{entries:?}"
            );
        }
        let bytes = tar(&[("a", b'0', 0o755, "data")]);
        assert!(unpack(&bytes, &digest(&bytes), 10, 10).is_err());
        assert!(unpack(&bytes, &digest(&bytes), 100_000, 0).is_err());
    }
    // Regression: valid compressed bytes with a different tar identity were executed.
    #[test]
    fn regression_bench_native_source_digest_mismatch() {
        let bytes = tar(&[("a", b'0', 0o644, "data")]);
        assert!(unpack(&bytes, &digest(b"wrong"), 100_000, 10)
            .unwrap_err()
            .to_string()
            .contains("tar-stream sha256 mismatch"));
    }
    // Regression: restrictive directory modes blocked descendants or private roots were widened.
    #[test]
    fn regression_bench_native_directory_modes_applied_after_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let parent = owned::open_directory(dir.path()).unwrap();
        let private = owned::create_directory(&parent, "private").unwrap();
        let root = owned::create_directory(&private, "tree").unwrap();
        let mut tree = Tree {
            root,
            directories: BTreeMap::new(),
        };
        let bytes = tar(&[
            ("d", b'5', 0o500, ""),
            ("d/sub", b'5', 0o555, ""),
            ("d/sub/tool", b'0', 0o751, "data"),
            ("d/link", b'2', 0o777, "sub/tool"),
        ]);
        extract_tar(
            &mut tree,
            Hashed::new(bytes.as_slice(), 100_000),
            &digest(&bytes),
            10,
        )
        .unwrap();
        let base = dir.path().join("private");
        for (name, mode) in [
            ("", 0o700),
            ("tree", 0o700),
            ("tree/d", 0o500),
            ("tree/d/sub", 0o555),
            ("tree/d/sub/tool", 0o751),
        ] {
            assert_eq!(
                std::fs::metadata(base.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
        }
        assert_eq!(std::fs::read(base.join("tree/d/link")).unwrap(), b"data");
        assert_eq!(
            std::fs::metadata(base.join("tree/d")).unwrap().mtime(),
            123456
        );
        assert_eq!(
            std::fs::symlink_metadata(base.join("tree/d/link"))
                .unwrap()
                .mtime(),
            123456
        );
        tree.make_removable().unwrap();
        // Regression: a trailing frame failure left restrictive directories impossible to remove.
        let mut compressed = zstd::encode_all(bytes.as_slice(), 1).unwrap();
        compressed.extend(zstd::encode_all(&b""[..], 1).unwrap());
        let artifact = dir.path().join("source.zst");
        std::fs::write(&artifact, compressed).unwrap();
        let mut file = File::open(&artifact).unwrap();
        let root = owned::create_directory(&private, "failed").unwrap();
        assert!(extract(&mut file, root, &digest(&bytes), 100_000)
            .err()
            .unwrap()
            .to_string()
            .contains("exactly one zstd frame"));
        let failed = base.join("failed");
        for name in ["d", "d/sub"] {
            assert_eq!(
                std::fs::metadata(failed.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(failed).unwrap();
    }
}
