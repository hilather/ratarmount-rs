#!/usr/bin/env bash
# Regression (#183): recipes must wait for overlay locks and on-exit commits.
# Run both complete recipes against a real binary and FUSE.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export RATARMOUNT_BIN=${1:-"$root/target/debug/ratarmount"}
if [[ ! -e /dev/fuse ]] || ! command -v fusermount3 >/dev/null; then
    echo 'skip: daemon recipe regressions require /dev/fuse and fusermount3'
    exit 0
fi
for recipe in checkpoint-archives swe-bench-sandbox; do
    bash "$root/docs/recipes/scripts/$recipe.sh"
    echo "regression_183_recipe_$recipe: ok"
done
