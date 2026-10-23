# overlay-v0.1.35

A write overlay created by a REAL `ratarmount 0.1.35` binary (the released tag,
built from `v0.1.35`), not a synthetic database:

- `base.tar`: one ustar member `a.txt`.
- `overlay/`: the overlay directory of `ratarmount -f -w overlay base.tar mnt`
  after `created.txt` was written through the mount and the mount was unmounted.
  It has the `files`, `overlay_metadata` and `xattrs` tables and **no `meta`
  table** (released builds recorded no base identity).

Regenerate with `test-harness/make-overlay-v0.1.35.sh PATH-TO-0.1.35-BINARY`
(needs FUSE). `ratarmount/tests/overlay_v035.rs` reads it: a released overlay
must keep remounting without `--force-base-mismatch`, and the first `-w` open
records its kind, place and URL.
