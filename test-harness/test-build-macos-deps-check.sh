#!/usr/bin/env bash
# Regression for packaging/build-macos-deps.sh `check` (#248 code sweep 2):
# the minos probe must consume all of `otool -l` so a valid dylib never fails
# with SIGPIPE (141) under pipefail. Runs on Linux with a fake otool whose
# output keeps going well past the pipe buffer after the minos line.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
P="$t/prefix"; mkdir -p "$P/lib/pkgconfig" "$t/bin"
touch "$P/lib/pkgconfig/libarchive.pc"
for l in libarchive.13 liblzma.5 liblz4.1 libzstd.1; do : > "$P/lib/$l.dylib"; done
printf '#define HAVE_LZMA_H 1\n#define HAVE_LZ4_H 1\n#define HAVE_ZSTD_H 1\n#define HAVE_EXPAT_H 1\n' > "$P/libarchive-config.h"
cat > "$t/bin/otool" <<FAKE
#!/usr/bin/env bash
if [[ \$1 == -L ]]; then
  echo "\$2:"
  for l in liblzma.5 liblz4.1 libzstd.1; do echo "	$P/lib/\$l.dylib (compat)"; done
  echo "	/usr/lib/libSystem.B.dylib (compat)"
else
  printf 'Load command 0\n      cmd LC_BUILD_VERSION\n    minos %s\n' "\${FAKE_MINOS:-14.0}"
  yes '  sectname __filler' | head -n 200000
fi
FAKE
chmod +x "$t/bin/otool"
export PATH="$t/bin:$PATH" MACOSX_DEPLOYMENT_TARGET=14.0
for i in 1 2 3; do
  "$root/packaging/build-macos-deps.sh" check "$P" >/dev/null || { echo "FAIL: valid prefix rejected (run $i, rc=$?)" >&2; exit 1; }
done
if FAKE_MINOS=15.0 "$root/packaging/build-macos-deps.sh" check "$P" >/dev/null 2>&1; then
  echo "FAIL: minos 15.0 accepted" >&2; exit 1
fi
echo "ok: build-macos-deps check survives long otool output and still rejects minos 15.0"
