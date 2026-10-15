# Changelog

## Unreleased

- FUSE now returns the real errno (ENOTDIR, EISDIR, EXDEV, ELOOP, ENOTEMPTY, ENOSPC, EMFILE, ENFILE, …) instead of EIO for unmapped I/O errors.
