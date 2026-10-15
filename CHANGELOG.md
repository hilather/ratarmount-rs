# Changelog

## Unreleased

- FUSE `-w`: a file that is unlinked or replaced while the kernel still holds it keeps returning its old bytes and attributes (`nlink` 0) until the last reference is dropped. A write handle opened before that keeps writing the orphan (discarded at commit). A new write open or an fh-less setattr on that nodeid returns `EACCES`.
- FUSE now returns the real errno (ENOTDIR, EISDIR, EXDEV, ELOOP, ENOTEMPTY, ENOSPC, EMFILE, ENFILE, …) instead of EIO for unmapped I/O errors.
- FUSE foreground (`-f`): an `ECONNABORTED` from the session read at unmount is now a clean exit (exit 0), like `ENODEV`, and is logged at info; it used to exit 1 when `FORGET`s raced the unmount.
