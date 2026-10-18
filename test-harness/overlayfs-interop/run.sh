#!/usr/bin/env bash
# Called inside unshare -Urm by ratarmount/tests/overlayfs_interop.rs.
# The read-only FUSE lower mount is created outside the namespace by that test.
set -euo pipefail
binary=$1
root=$2
helpers=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir "$root/tmpfs" "$root/merged"
cleanup() {
    umount "$root/merged" 2>/dev/null || true
    umount "$root/tmpfs" 2>/dev/null || true
}
trap cleanup EXIT
if ! mount -t tmpfs -o size=64m,mode=755 tmpfs "$root/tmpfs"; then
    echo 'skip: tmpfs mount unavailable in user namespace' >&2
    exit 77
fi
mkdir -m 755 "$root/tmpfs/up" "$root/tmpfs/work"
options="lowerdir=$root/lower-mnt,upperdir=$root/tmpfs/up,workdir=$root/tmpfs/work,userxattr,index=off,xino=off,redirect_dir=off,metacopy=off"
if ! mount -t overlay overlay -o "$options" "$root/merged"; then
    echo "skip: overlayfs rejected FUSE lowerdir; options=$options; kernel=$(uname -r)" >&2
    exit 77
fi
python3 "$helpers/trees.py" snapshot "$root/lower-mnt" "$root/before.json"
(
    cd "$root/merged"
    make
    rm remove-me
    rm -rf opaque
    mkdir -p opaque/sub
    printf 'new opaque payload\n' > opaque/sub/new
    rm -rf to-file
    printf 'directory became a file\n' > to-file
    rm to-dir
    mkdir to-dir
    printf 'file became a directory\n' > to-dir/new
    ln -s input link
    chmod 751 build/result
    test ! -e opaque/sub/old
    test ! -e remove-me
    test "$(cat build/result)" = prepared
)
python3 "$helpers/trees.py" snapshot "$root/merged" "$root/after.json"
umount "$root/merged"
# Import native device/xattr whiteouts, then a portable copy that replaces
# device 0:0 with .wh. markers (mknod is often forbidden in a user namespace).
"$binary" overlay import-upperdir --lower "$root/prepared" "$root/tmpfs/up" "$root/imported-native" "$root/base"
python3 "$helpers/trees.py" copy "$root/tmpfs/up" "$root/copied-upper"
"$binary" overlay import-upperdir --lower "$root/prepared" "$root/copied-upper" "$root/imported-copy" "$root/base"
for name in imported-native imported-copy; do
    "$binary" diff --manifest "$root/$name" > "$root/$name.jsonl"
done
echo "overlayfs FUSE lowerdir build/test succeeded; kernel=$(uname -r); $options"
