#!/usr/bin/env python3
"""Compiled N1 API witnesses; Clippy resolves all referenced definitions.

This test reads compiler diagnostics only to assert each fixture's exact expected
lint. It is not an operation collector and is never a manifest identity source.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib

HERE = Path(__file__).resolve().parent
CONFIG = HERE.parent / "clippy.toml"


def diagnostics(output):
    rows = []
    finished = None
    for line in output.splitlines():
        row = json.loads(line)
        if row.get("reason") == "compiler-message":
            rows.append(row["message"])
        elif row.get("reason") == "build-finished":
            finished = row.get("success")
    if finished is None:
        raise RuntimeError("Cargo omitted build-finished")
    return rows, finished


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--driver", type=Path, default=Path.home() / ".cargo/internal-read-clippy/target/debug/clippy-driver")
    args = parser.parse_args()
    driver = args.driver.resolve()
    if not driver.is_file():
        raise RuntimeError("build the pinned policy driver with compiler/build.py before running API witnesses")
    availability = json.loads((HERE / "availability.json").read_text())
    config = tomllib.loads(CONFIG.read_text())
    paths = {entry["path"] for entry in config["disallowed-methods"]}
    if paths != {entry["path"] for entry in availability}:
        raise RuntimeError("configured API set changed; review and renew witnesses")
    if len(paths) != len(availability):
        raise RuntimeError("duplicate API availability row")
    spec = importlib.util.spec_from_file_location("witness_provenance", HERE / "provenance.py")
    provenance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provenance)
    root = HERE.parents[2]
    metadata = subprocess.run(["flock", "/tmp/muse-cargo.lock", "cargo", "+1.98.0", "metadata", "--manifest-path", str(root / "Cargo.toml"), "--no-deps", "--format-version=1"], env={**os.environ, "CARGO_BUILD_JOBS": "2"}, capture_output=True, text=True, check=True)
    provenance.validate(json.loads(metadata.stdout), root=root, here=HERE)
    output = args.output or Path(tempfile.mkdtemp(prefix="internal-read-witnesses-"))
    output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["CARGO_BUILD_JOBS"] = "2"
    env["CLIPPY_CONF_DIR"] = str(CONFIG.parent)
    env.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    env.setdefault("CARGO_INCREMENTAL", "0")
    env.setdefault("CARGO_TARGET_DIR", str(output / "target"))
    sysroot = Path(subprocess.check_output(["rustc", "+1.98.0", "--print", "sysroot"], text=True).strip())
    env["LD_LIBRARY_PATH"] = str(sysroot / "lib") + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    manifest = HERE / "public" / "Cargo.toml"
    common = ["--manifest-path", str(manifest), "--locked", "--lib", "--message-format=json"]
    if args.offline:
        common.append("--offline")
    summary = {}
    for label, command, expected in [
        ("check", ["check", *common], 0),
        ("clippy", ["check", *common], 101),
    ]:
        effective = env.copy()
        if label == "clippy":
            effective["RUSTC_WORKSPACE_WRAPPER"] = str(driver)
            effective["CLIPPY_ARGS"] = "__CLIPPY_HACKERY__".join(["-D", "warnings", "-D", "clippy::disallowed_methods", "-D", "clippy::disallowed_types"])
        run = subprocess.run(["flock", "/tmp/muse-cargo.lock", "cargo", "+1.98.0", *command], env=effective, text=True, capture_output=True)
        (output / f"{label}.jsonl").write_text(run.stdout)
        (output / f"{label}.stderr").write_text(run.stderr)
        messages, finished = diagnostics(run.stdout)
        if run.returncode != expected or finished is not (expected == 0):
            raise RuntimeError(f"{label}: unexpected exit {run.returncode}; see {output}")
        summary[label] = {"exit": run.returncode, "build_finished": finished}
        if label == "clippy":
            methods = [m for m in messages if (m.get("code") or {}).get("code") == "clippy::disallowed_methods"]
            for row in availability:
                if row["availability"] != "native-external":
                    continue
                expected_message = f"use of a disallowed method `{row['path']}`"
                matching = [m for m in methods if m["message"] == expected_message]
                if len(matching) != 1:
                    raise RuntimeError(f"expected one exact own-method diagnostic for {row['path']}, got {len(matching)}")
            types = [m for m in messages if (m.get("code") or {}).get("code") == "clippy::disallowed_types"]
            for entry in config["disallowed-types"]:
                expected_message = f"use of a disallowed type `{entry['path']}`"
                if not any(m["message"] == expected_message for m in types):
                    raise RuntimeError(f"missing own-type diagnostic for {entry['path']}")
            unexpected = [m for m in messages if m["level"] == "error" and (m.get("code") or {}).get("code") not in {"clippy::disallowed_methods", "clippy::disallowed_types"}]
            if unexpected:
                raise RuntimeError(f"unrelated compiler errors: {unexpected}")
            summary["native_external_paths"] = sum(r["availability"] == "native-external" for r in availability)
            summary["method_diagnostics"] = len(methods)
            summary["type_paths"] = len(config["disallowed-types"])
    # The existing journal policy is independent of inventory classification,
    # but its configured definitions must remain valid too. Compile references
    # to all eleven actual repository APIs, including helpers with no native use.
    journal_manifest = HERE / "journal" / "Cargo.toml"
    ordinary = tomllib.loads((HERE.parents[2] / "clippy.toml").read_text())
    journal_paths = {entry["path"] for entry in ordinary["disallowed-methods"]}
    for label in ["journal-check", "journal-clippy"]:
        effective = env.copy()
        if label == "journal-clippy":
            effective["RUSTC_WORKSPACE_WRAPPER"] = str(driver)
            effective["CLIPPY_ARGS"] = "__CLIPPY_HACKERY__".join(["-D", "warnings", "-D", "clippy::disallowed_methods"])
        command = ["flock", "/tmp/muse-cargo.lock", "cargo", "+1.98.0", "check", "--manifest-path", str(journal_manifest), "--locked", "--lib", "--message-format=json", *(["--offline"] if args.offline else [])]
        run = subprocess.run(command, env=effective, text=True, capture_output=True)
        (output / f"{label}.jsonl").write_text(run.stdout)
        (output / f"{label}.stderr").write_text(run.stderr)
        messages, finished = diagnostics(run.stdout)
        expected = 0 if label == "journal-check" else 101
        if run.returncode != expected or finished is not (expected == 0):
            raise RuntimeError(f"{label}: unexpected exit {run.returncode}; see {output}")
        if label == "journal-clippy":
            methods = [message for message in messages if (message.get("code") or {}).get("code") == "clippy::disallowed_methods"]
            assert len(methods) == len(journal_paths)
            for path in journal_paths:
                matching = [message for message in methods if message["message"] == f"use of a disallowed method `{path}`"]
                if len(matching) != 1:
                    raise RuntimeError(f"expected own journal diagnostic for {path}, got {len(matching)}")
            summary["journal_paths"] = len(journal_paths)
    # Clippy's map keys are DefIds: the two spellings alias the same definition.
    # Isolate each spelling in config so neither can hide an invalid sibling.
    alias_manifest = HERE / "aliases" / "Cargo.toml"
    for label, module in [("public-alias", "db_inodes"), ("private-alias", "db_inodes::unix")]:
        directory = output / label
        directory.mkdir(exist_ok=True)
        alias_paths = [f"ratarmount_core::{module}::{name}" for name in ["open_admitted", "openat_admitted"]]
        config_text = "disallowed-methods = [\n" + "".join(
            f'    {{ path = "{path}", reason = "compiled alias witness" }},\n' for path in alias_paths
        ) + "]\n"
        (directory / "clippy.toml").write_text(config_text)
        alias_env = env.copy()
        alias_env["CLIPPY_CONF_DIR"] = str(directory)
        alias_env["RUSTC_WORKSPACE_WRAPPER"] = str(driver)
        alias_env["CLIPPY_ARGS"] = "__CLIPPY_HACKERY__".join(["-D", "warnings", "-D", "clippy::disallowed_methods"])
        alias_env["CARGO_TARGET_DIR"] = str(Path(env["CARGO_TARGET_DIR"]) / label)
        run = subprocess.run(
            ["flock", "/tmp/muse-cargo.lock", "cargo", "+1.98.0", "check", "--manifest-path", str(alias_manifest), "--locked", "--lib", "--message-format=json", *(["--offline"] if args.offline else [])],
            env=alias_env, text=True, capture_output=True,
        )
        (directory / "clippy.jsonl").write_text(run.stdout)
        (directory / "clippy.stderr").write_text(run.stderr)
        messages, finished = diagnostics(run.stdout)
        if run.returncode != 101 or finished is not False:
            raise RuntimeError(f"{label}: expected Clippy refusal, got {run.returncode}; see {directory}")
        for path in alias_paths:
            matching = [m for m in messages if (m.get("code") or {}).get("code") == "clippy::disallowed_methods" and m["message"] == f"use of a disallowed method `{path}`"]
            if len(matching) != 1:
                raise RuntimeError(f"expected one own alias diagnostic for {path}, got {len(matching)}")
        summary[label] = {"exit": run.returncode, "method_paths": alias_paths}
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
