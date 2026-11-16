"""Reviewed Cargo dependency/feature provenance for compiled API witnesses.

Only standard Cargo metadata and lockfile records are used. This is neither a
Rust source resolver nor operation/flag/symbol policy. Unrelated lock entries do
not affect the review record.
"""
import hashlib
import json
from pathlib import Path
import tomllib

API_DEPENDENCIES = frozenset({"libc", "rustix", "tempfile", "nix", "tokio", "git2", "lopdf"})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def records(lock):
    return sorted(
        ({key: package[key] for key in ("name", "version", "source", "checksum") if key in package}
         for package in lock["package"] if package["name"] in API_DEPENDENCIES),
        key=lambda package: (package["name"], package["version"], package.get("source", "")),
    )


def collect(metadata, lock, fixture_locks, *, root):
    declarations = {}
    for package in metadata["packages"]:
        if package["id"] not in metadata["workspace_members"]:
            continue
        selected = [dependency for dependency in package["dependencies"]
                    if dependency["name"] in API_DEPENDENCIES and dependency.get("kind") is None]
        if not selected:
            continue
        dependencies = [{key: dependency.get(key) for key in ("name", "rename", "req", "source", "registry", "features", "uses_default_features", "optional", "target")}
                        for dependency in selected]
        for dependency in dependencies:
            dependency["features"] = sorted(dependency["features"])
        declarations[package["name"]] = {
            "dependencies": sorted(dependencies, key=canonical),
            "features": {name: sorted(values) for name, values in package["features"].items()},
        }
    root_records = records(lock)
    if {row["name"] for row in root_records} != API_DEPENDENCIES:
        raise ValueError("configured API dependency disappeared from the workspace lockfile")
    fixtures = {name: records(value) for name, value in fixture_locks.items()}
    for name, values in fixtures.items():
        for value in values:
            if value not in root_records:
                raise ValueError(f"{name} API witness dependency differs from the workspace lockfile: {value['name']} {value['version']}")
    return {
        "schema": 1,
        "dependencies": root_records,
        "root_declarations_sha256": hashlib.sha256(canonical(declarations).encode()).hexdigest(),
        "fixture_dependencies": fixtures,
    }


def current(metadata, *, root, here):
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    fixtures = {name: tomllib.loads((here / name / "Cargo.lock").read_text()) for name in ("public", "aliases", "journal")}
    return collect(metadata, lock, fixtures, root=root)


def validate(metadata, *, root, here):
    approved = json.loads((here / "dependency-provenance.json").read_text())
    actual = current(metadata, root=root, here=here)
    if actual != approved.get("provenance"):
        raise RuntimeError("API witness dependencies/features changed; review current Cargo provenance and renew applicable availability witnesses")
    if not approved.get("reviewer") or not approved.get("basis"):
        raise RuntimeError("API witness dependency provenance requires review metadata")


def main():
    import argparse
    import os
    import subprocess
    here = Path(__file__).resolve().parent
    root = here.parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", action="store_true", help="print current review data without updating approval")
    args = parser.parse_args()
    result = subprocess.run(["flock", "/tmp/muse-cargo.lock", "cargo", "+1.98.0", "metadata", "--manifest-path", str(root / "Cargo.toml"), "--no-deps", "--format-version=1"], env={**os.environ, "CARGO_BUILD_JOBS": "2"}, capture_output=True, text=True, check=True)
    metadata = json.loads(result.stdout)
    if args.candidate:
        print(json.dumps(current(metadata, root=root, here=here), indent=2, sort_keys=True))
    else:
        validate(metadata, root=root, here=here)
        print("Reviewed API dependency/feature provenance matches.")


if __name__ == "__main__":
    main()
