From caa50edafdf7a5d490fe1b871561a3a194268141 Mon Sep 17 00:00:00 2001
From: Matt.Brewer <3254484+hilather@users.noreply.github.com>
Date: Tue, 22 Sep 2026 20:03:07 -0400
Subject: [PATCH] Fix flaky S3 remote_open discovery tests under parallel cargo
 test.

EnvGuard used a separate mutex from with_isolated_xdg, so parallel tests
could flip XDG_CACHE_HOME while MetaCache::from_env ran and leave
index_file_path unset (CI panics on pointer-blob install). Share
REMOTE_ENV_LOCK and isolate XDG inside bind_anon_s3.

Apply on Omarchy (or any checkout of execute-plan/fbd25f5d-stack):
  git am /path/to/this.patch
  # or: git apply && git commit
  git push origin execute-plan/fbd25f5d-stack

Verified: 20x cargo test -p ratarmount-session --lib factory::remote_open::
with RUSTFLAGS=-Dwarnings → 0 S3 flakes; fmt+clippy clean.
— Muse (executor; push blocked on box PAT contents:write)
