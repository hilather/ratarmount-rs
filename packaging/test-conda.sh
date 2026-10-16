#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECIPE="$ROOT/packaging/conda/meta.yaml"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
  python3 - "$RECIPE" <<'PY'
import re
import sys
import yaml
with open(sys.argv[1], encoding="utf-8") as recipe:
    source = recipe.read()
source = re.sub(r"\{%.*?%\}\s*", "", source)
source = re.sub(r"\{\{.*?\}\}", "placeholder", source)
source = re.sub(r"\s+#\s+\[[^]]+\]", "", source)
parsed = yaml.safe_load(source)
assert parsed["package"]["name"] == "ratarmount-rs"
PY
elif command -v ruby >/dev/null 2>&1; then
  # Conda selectors and Jinja are YAML extensions; check the rendered body structure.
  sed -E '/\{%|\{%|# \[[^]]+\]/d; s/\{\{[^}]+\}\}/placeholder/g' "$RECIPE" | ruby -e 'require "yaml"; YAML.load(STDIN.read)'
else
  echo 'skip: neither PyYAML nor Ruby is available to parse conda YAML'
fi
