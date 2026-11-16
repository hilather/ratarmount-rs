#!/usr/bin/env python3
"""Native stock-Clippy coverage; Cargo selects production and Clippy resolves APIs.

The Linux patched driver and manifest diff remain the approval authority. This
runner never parses Rust or interprets imports, methods, flags or symbols.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location("native_policy", HERE / "policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def cargo(arguments, *, cwd=ROOT, env=None, **kwargs):
    effective = os.environ.copy() if env is None else env.copy()
    effective["CARGO_BUILD_JOBS"] = "2"
    # Local Linux uses the shared repository lock. Native CI workers have one
    # sequential runner, and neither macOS nor native MSVC provides flock.
    command = ["cargo", *arguments]
    if sys.platform.startswith("linux"):
        command = ["flock", "/tmp/muse-cargo.lock", *command]
    return subprocess.run(command, cwd=cwd, env=effective, **kwargs)


def compiler_command(arguments, settings):
    clippy = Path(arguments[0]).name.startswith("clippy-driver")
    rustc = arguments[1] if clippy else arguments[0]
    rustargs = arguments[2:] if clippy else arguments[1:]
    sources = [str(Path(arg).resolve()) for arg in rustargs if arg.endswith(".rs")]
    crates = policy.rust_argument(rustargs, "--crate-name")
    kinds = sorted(kind for value in policy.rust_argument(rustargs, "--crate-type")
                   for kind in value.split(","))
    selected = any(sources == [row["source"]] and crates == [row["crate"]]
                   and kinds == row["crate_types"] for row in settings["targets"])
    # cargo-hack checks each selected package itself. A package which happens
    # to be another run's dependency must remain ordinary rustc in this run.
    selected = clippy and selected and "--test" not in rustargs
    env = os.environ.copy()
    if selected:
        env["CLIPPY_CONF_DIR"] = str(HERE)
        flags = ["--cfg", "internal_read_inventory", "--check-cfg=cfg(internal_read_inventory)",
                 "-D", "warnings", "-D", "clippy::disallowed_methods",
                 "-F", "unused_macros", "-D", "unfulfilled_lint_expectations"]
        return [arguments[0], *arguments[1:], *flags], env, True
    env.pop("CLIPPY_ARGS", None)
    env.pop("CLIPPY_CONF_DIR", None)
    return [rustc, *rustargs], env, False


def wrap(arguments):
    settings = json.loads(Path(os.environ["INTERNAL_READ_NATIVE_SETTINGS"]).read_text())
    command, env, _ = compiler_command(arguments, settings)
    # Windows does not support replacing the process with execvpe as Unix does.
    return subprocess.run(command, env=env, close_fds=(os.name == "nt")).returncode


def wrapper_env(directory, metadata, packages):
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / ("native-wrapper.exe" if os.name == "nt" else "native-wrapper")
    subprocess.run(["rustc", str(HERE / "native-wrapper.rs"), "-o", str(binary)], check=True)
    selected = []
    for package in packages:
        selected.extend(policy.targets(metadata, ["-p", package, "--lib", "--bins"]))
    settings = directory / "settings.json"
    settings.write_text(json.dumps({"targets": selected}))
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER=str(binary), INTERNAL_READ_NATIVE_SETTINGS=str(settings),
               INTERNAL_READ_NATIVE_PYTHON=sys.executable, INTERNAL_READ_NATIVE_SCRIPT=str(HERE / "native.py"))
    return env


def native_host():
    if os.environ.get("CARGO_BUILD_TARGET"):
        raise SystemExit("native policy does not accept CARGO_BUILD_TARGET")
    version = subprocess.check_output(["rustc", "-Vv"], text=True)
    host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    if sys.platform == "win32" and not host.endswith("-pc-windows-msvc"):
        raise SystemExit(f"native Windows policy requires MSVC, got {host}")
    if sys.platform == "darwin" and not host.endswith("-apple-darwin"):
        raise SystemExit(f"native macOS policy requires an Apple host, got {host}")
    return host


def hack_arguments(package, exclusions, methods_level):
    command = ["hack", "clippy", "-p", package, "--all-targets", "--each-feature"]
    if exclusions:
        command.extend(["--exclude-features", ",".join(exclusions)])
    command.extend(["--", "-D", "warnings", methods_level, "clippy::disallowed_methods", "-D", "clippy::disallowed_types",
                    "-D", "clippy::disallowed_macros", "-F", "unused_macros"])
    return command


def package_exclusions(metadata, package, exclusions):
    features = next(row["features"] for row in metadata["packages"] if row["name"] == package)
    return sorted(set(exclusions).intersection(features))


def diagnostics(output):
    codes = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("reason") == "compiler-message":
            code = row["message"].get("code")
            if code:
                codes.append(code["code"])
    return codes


def fixtures(output):
    output.mkdir(parents=True, exist_ok=True)
    results = []
    cases = [("positive", [], None),
             ("windows-read", [], "clippy::disallowed_methods" if sys.platform == "win32" else None),
             ("feature-read", ["--all-features"], None),
             ("feature-read", ["--no-default-features"], "clippy::disallowed_methods"),
             ("approved-read", [], None),
             ("unfulfilled-expect", [], "unfulfilled_lint_expectations")]
    for index, (name, features, expected_code) in enumerate(cases):
        directory = output / str(index)
        directory.mkdir(exist_ok=True)
        (directory / "src").mkdir(exist_ok=True)
        (directory / "src/lib.rs").write_text((HERE / f"fixtures/native/{name}.rs").read_text())
        (directory / "Cargo.toml").write_text(
            '[package]\nname="native-control"\nversion="0.0.0"\nedition="2021"\n'
            '[workspace]\n[features]\ndefault=["backend"]\nbackend=[]\n'
            '[dependencies]\nfixture-helper={path="helper"}\n'
            '[lints.rust]\nunexpected_cfgs={level="deny",check-cfg=["cfg(internal_read_inventory)"]}\n')
        (directory / "build.rs").write_text('fn main() { let _ = std::fs::read("build-fixture"); }\n')
        helper = directory / "helper"
        helper.mkdir(exist_ok=True)
        (helper / "Cargo.toml").write_text('[package]\nname="fixture-helper"\nversion="0.0.0"\nedition="2021"\n[lib]\npath="lib.rs"\n')
        (helper / "lib.rs").write_text('pub fn fixture_dependency() { let _ = std::fs::read("dependency-fixture"); }\n')
        metadata = cargo(["metadata", "--format-version=1", "--no-deps"], cwd=directory,
                         check=True, capture_output=True, text=True)
        env = wrapper_env(directory, json.loads(metadata.stdout), ["native-control"])
        env["CARGO_TARGET_DIR"] = str(directory / "target")
        result = cargo(["clippy", "--all-targets", "--message-format=json", *features, "--",
                        "-D", "warnings", "-D", "clippy::disallowed_methods", "-F", "unused_macros"],
                       cwd=directory, env=env, capture_output=True, text=True)
        (directory / "stdout.jsonl").write_text(result.stdout)
        (directory / "stderr.txt").write_text(result.stderr)
        codes = diagnostics(result.stdout)
        if ((expected_code and (result.returncode == 0 or expected_code not in codes))
                or (expected_code is None and result.returncode != 0)):
            raise SystemExit(f"native {name} {features}: expected diagnostic={expected_code}; "
                             f"exit={result.returncode}, diagnostics={codes}; {directory}")
        results.append({"fixture": name, "features": features, "methods_level": "-D",
                        "expected_diagnostic": expected_code,
                        "exit": result.returncode, "diagnostics": codes})
    # Regression: a package first compiled as an ordinary dependency must be
    # linted when it becomes the selected primary package in the same cache.
    directory = output / "0"
    metadata = cargo(["metadata", "--format-version=1", "--no-deps"], cwd=directory,
                     check=True, capture_output=True, text=True)
    env = wrapper_env(directory, json.loads(metadata.stdout), ["fixture-helper"])
    env["CARGO_TARGET_DIR"] = str(directory / "target")
    cargo(["clean", "-p", "fixture-helper"], cwd=directory, env=env, check=True, capture_output=True)
    result = cargo(["clippy", "-p", "fixture-helper", "--all-targets", "--message-format=json", "--",
                    "-D", "warnings", "-D", "clippy::disallowed_methods", "-F", "unused_macros"], cwd=directory,
                   env=env, capture_output=True, text=True)
    (output / "cache-primary.stdout.jsonl").write_text(result.stdout)
    (output / "cache-primary.stderr.txt").write_text(result.stderr)
    codes = diagnostics(result.stdout)
    if result.returncode == 0 or "clippy::disallowed_methods" not in codes:
        raise SystemExit(f"cached dependency was not linted as primary: exit={result.returncode}, diagnostics={codes}")
    results.append({"fixture": "cached-dependency-to-primary", "exit": result.returncode,
                    "expected_diagnostic": "clippy::disallowed_methods", "diagnostics": codes})
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--wrap":
        return wrap(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "target/internal-read-native-controls")
    parser.add_argument("--methods-level", choices=["-D"], default="-D")
    args = parser.parse_args()
    if args.fixtures:
        native_host()
        fixtures(args.output.resolve())
        return 0
    if sys.platform not in ("darwin", "win32"):
        raise SystemExit("native matrix runs on macOS or Windows; use --fixtures for Linux controls")
    host = native_host()
    platform = "windows" if sys.platform == "win32" else "macos"
    matrix = json.loads((HERE / "native.json").read_text())[platform]
    restricted = json.loads((HERE / "policy.json").read_text())["restricted_packages"]
    packages = restricted if matrix["packages"] == "restricted_packages" else matrix["packages"]
    result = cargo(["metadata", "--format-version=1", "--no-deps"], check=True,
                   capture_output=True, text=True)
    metadata = json.loads(result.stdout)
    with tempfile.TemporaryDirectory(prefix="internal-read-native-") as scratch:
        cache_key = hashlib.sha256(b"".join((HERE / path).read_bytes() for path in
            ("native.py", "native-wrapper.rs", "native.json", "policy.py", "policy.json", "clippy.toml"))
            + host.encode() + args.methods_level.encode()).hexdigest()[:16]
        for package in packages:
            env = wrapper_env(Path(scratch) / package, metadata, [package])
            env["CARGO_TARGET_DIR"] = str(ROOT / "target/internal-read-native" / cache_key)
            # Clear only this package's generated artifacts before it becomes
            # primary. Earlier ordinary dependency builds must not satisfy its
            # Clippy gate. Shared dependencies stay cached across all 40 sweeps.
            cargo(["clean", "-p", package], env=env, check=True)
            exclusions = package_exclusions(metadata, package, matrix["excluded_features"])
            cargo(hack_arguments(package, exclusions, args.methods_level),
                  env=env, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
