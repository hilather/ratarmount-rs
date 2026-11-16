# #235 part 2 — PARKED by Keystone (2026-10-28 ~09:58 EDT)

Branch: muse/fix-235c-offline-symlink (local only, NOT pushed). Head 5b517d2ce18fbcecf1b102ae55dd505920b0f139
(bf2a01cb -> 12dd3c47 -> 5b517d2c). Keep branch and this plans dir. Do not push.

## Routes found that rewrite/open the index (each needed the refusal)
- offline commit (--commit-overlay)
- cache clear
- SFTP and NFS frontends
- versioned/historical lookup + listing (must check the REQUESTED version, not newest; versioning.rs:117 originally prepared only newest; automount.rs:1264 mapped refusal to None/ENOENT)
- mount/automount first access
- HTTP/WebDAV discovery (found in CS3, round 3): ratarmount-http/src/handler.rs:289 propagates with `?`, serve.rs:212 only debug-logs and closes the socket -> zero-byte response, no status, no --index-file diagnostic; PROPFIND same.

## Regression to avoid on any retry
- automount.rs:1166 (round 3) sends every nonzero version to the outer archive, bypassing mounted nested sources: /inner.tar/member.versions/1 returns missing (no symlink involved). Versioned listing same. Historical requests inside mounted archives must dispatch to the nested source.

## Lesson
- Refuse at the single index-open boundary (one shared open function, lstat/O_NOFOLLOW on the exact file opened) — not per-route preparation checks.
- Every frontend must surface a typed error (FUSE errno with diagnostic, HTTP error status, SFTP/NFS status, CLI exit) — never drop the request, close the connection, or map to None/ENOENT.
- Blockers kept spreading route by route across 3 code rounds; a restart is an architecture change and needs a NEW plan gate (plan + review + skeptic) enumerating all frontends up front. Matt decides whether to retry.

Evidence: CRESULT-1..3, crv-*/csk-* (csk-3.capacity.log = dead first run), r3-red/green, checks-r3.log (rc=0).
— Muse
