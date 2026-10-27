#![allow(
    clippy::disallowed_methods,
    reason = "Metadata regression directly exercises the restricted splice publisher"
)]

use super::*;

struct MetadataFaultGuard;

impl Drop for MetadataFaultGuard {
    fn drop(&mut self) {
        crate::commit_journal::fault::clear();
    }
}

/// Regression: any non-root owner error must still permit group restoration
/// and mode-preserving replacement; root ownership errors stop publication.
#[test]
fn regression_235_archive_owner_errors_and_group_restoration() {
    use std::cell::Cell;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::rc::Rc;

    fn splice(path: &Path, source: &std::fs::Metadata) -> crate::Result<crate::SpliceStats> {
        crate::splice_zstd_last_frames_replace(
            path,
            0,
            |input, _, output| {
                io::copy(input, output)?;
                output.write_all(b"changed")
            },
            source,
        )
    }

    let root = unsafe { libc::geteuid() } == 0;
    if root {
        // The checkout can live below a root-only home directory, so the
        // dropped-privilege child needs its executable outside that tree.
        let child_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(child_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let executable = child_dir.path().join("metadata-test");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut child = std::process::Command::new(&executable);
        child.current_dir(child_dir.path());
        child.args([
            "--exact",
            "fastcopy::metadata_tests::regression_235_archive_owner_errors_and_group_restoration",
            "--nocapture",
        ]);
        // Run the ignored-ownership-error case without privilege even when
        // the surrounding suite is root, with a transferable extra group.
        unsafe {
            child.pre_exec(|| {
                let groups: [libc::gid_t; 2] = [65534, 65533];
                if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0
                    || libc::setgid(65534) != 0
                    || libc::setuid(65534) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        assert!(child.status().unwrap().success());
    } else {
        let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        assert!(n >= 0);
        let mut groups = vec![0 as libc::gid_t; n as usize];
        assert_eq!(unsafe { libc::getgroups(n, groups.as_mut_ptr()) }, n);
        let primary = unsafe { libc::getegid() };
        let extra = groups.into_iter().find(|&group| group != primary);
        if extra.is_none() {
            eprintln!("skip: supplementary-group transfer needs a second permitted group");
        }
        for mode in [0o644, 0o640] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive.zst");
            let original = zstd::stream::encode_all(&b"original"[..], 1).unwrap();
            std::fs::write(&path, original).unwrap();
            let file = File::open(&path).unwrap();
            if let Some(group) = extra {
                if unsafe { libc::fchown(file.as_raw_fd(), !0, group) } != 0 {
                    eprintln!(
                        "skip: supplementary-group transfer to gid {group}: {}",
                        io::Error::last_os_error()
                    );
                }
            }
            file.set_permissions(std::fs::Permissions::from_mode(mode))
                .unwrap();
            let source = file.metadata().unwrap();
            let owner_calls = Rc::new(Cell::new(0));
            let group_calls = Rc::new(Cell::new(0));
            let owner_seen = owner_calls.clone();
            let group_seen = group_calls.clone();
            let _fault = MetadataFaultGuard;
            crate::commit_journal::fault::install(move |step| {
                if step == "archive metadata owner" {
                    owner_seen.set(owner_seen.get() + 1);
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                if step == "archive metadata group" {
                    group_seen.set(group_seen.get() + 1);
                }
                Ok(())
            });
            splice(&path, &source).unwrap();
            assert_eq!(owner_calls.get(), 1, "injected EIO must be consumed");
            assert_eq!(
                group_calls.get(),
                1,
                "group must be attempted independently"
            );
            let after = std::fs::metadata(&path).unwrap();
            assert_ne!((after.dev(), after.ino()), (source.dev(), source.ino()));
            assert_eq!(after.mode() & 0o777, mode);
            assert_eq!((after.uid(), after.gid()), (source.uid(), source.gid()));
            assert_eq!(
                zstd::stream::decode_all(File::open(&path).unwrap()).unwrap(),
                b"originalchanged"
            );
        }
    }

    if !root {
        eprintln!("skip: root ownership-preservation/fatal-error cases need euid 0");
        return;
    }
    for failure in [
        None,
        Some("archive metadata owner"),
        Some("archive metadata group"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.zst");
        let original = zstd::stream::encode_all(&b"original"[..], 1).unwrap();
        std::fs::write(&path, &original).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 65534, 65534) }, 0);
        file.set_permissions(std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let source = file.metadata().unwrap();
        let consumed = Rc::new(Cell::new(false));
        let seen = consumed.clone();
        let _fault = MetadataFaultGuard;
        crate::commit_journal::fault::install(move |step| {
            if Some(step) == failure && !seen.replace(true) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        });
        let result = splice(&path, &source);
        let after = std::fs::metadata(&path).unwrap();
        if failure.is_some() {
            assert!(consumed.get());
            assert!(matches!(
                result,
                Err(crate::CompressError::ArchiveMetadata(ref error))
                    if error.raw_os_error() == Some(libc::EIO)
            ));
            assert_eq!((after.dev(), after.ino()), (source.dev(), source.ino()));
            assert_eq!(std::fs::read(&path).unwrap(), original);
        } else {
            result.unwrap();
            assert_ne!((after.dev(), after.ino()), (source.dev(), source.ino()));
            assert_eq!(
                zstd::stream::decode_all(File::open(&path).unwrap()).unwrap(),
                b"originalchanged"
            );
        }
        assert_eq!(after.mode() & 0o777, 0o640);
        assert_eq!((after.uid(), after.gid()), (65534, 65534));
    }
}
