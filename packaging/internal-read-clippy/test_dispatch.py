#!/usr/bin/env python3
"""Compiled dispatcher/cache regressions using Cargo's selected production tuples."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, default=Path.home() / ".cargo/internal-read-clippy/target/debug/clippy-driver")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    actual_driver = args.driver.resolve()
    if not actual_driver.is_file():
        raise RuntimeError("build the pinned Clippy driver first")
    results = []
    with tempfile.TemporaryDirectory(prefix="internal-read-dispatch-") as temporary:
        root = Path(temporary)
        tools = root / "packaging/internal-read-clippy"
        tools.mkdir(parents=True)
        for name in ["policy.py", "dispatch.py", "diagnostics.py"]:
            shutil.copy2(HERE / name, tools / name)
        (tools / "dispatch.py").chmod(0o755)
        config = json.loads((HERE / "policy.json").read_text())
        config.update(restricted_packages=[], classified_packages=["dispatch-fixture"], include_exceptions=[])
        (tools / "policy.json").write_text(json.dumps(config))
        profiles = [["fixture", ["--workspace", "--lib", "--bins", "--all-features"]]]
        (tools / "profiles.json").write_text(json.dumps(profiles))
        (tools / "clippy.toml").write_text('disallowed-methods=[{path="std::fs::read",reason="inventory-op:fixture"}]\n')
        (root / "clippy.toml").write_text("disallowed-methods=[]\n")
        (root / "Cargo.toml").write_text('''[package]
name = "dispatch-fixture"
version = "0.0.0"
edition = "2021"
build = "vendor/owned.rs"
[lib]
path = "vendor/owned.rs"
[[bin]]
name = "custom-driver"
path = "generated/driver.rs"
[features]
extra = []
[dependencies]
unselected-dependency = { path = "dependency" }
[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(internal_read_inventory)'] }
[workspace]
exclude = ["dependency"]
''')
        (root / "vendor").mkdir()
        (root / "generated").mkdir()
        (root / "tests").mkdir()
        (root / "examples").mkdir()
        (root / "dependency/src").mkdir(parents=True)
        (root / "dependency/Cargo.toml").write_text('[package]\nname="unselected-dependency"\nversion="0.0.0"\nedition="2021"\n[workspace]\n')
        (root / "dependency/src/lib.rs").write_text('pub fn raw_dependency_read(){ let _ = std::fs::read("unmarked dependency input"); }\n')
        def mark(identifier, item):
            review = {"id": identifier, "item": item, "disposition": "support", "category": "fixture", "reason": "Compile the selected input reader", "creation": {"policy": "none", "basis": "Existing fixture input only"}}
            return '#[expect(clippy::disallowed_methods, reason = r#"internal-read:v1 ' + json.dumps(review) + '"#)]\n'
        (root / "vendor/owned.rs").write_text('''#![forbid(unused_macros)]
#![cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))]
#[path = "../tests/production.rs"] pub mod production;
pub fn load() {
''' + mark("IR-DISPATCH-ROOT", "dispatch_fixture::load") + '''let _ = std::fs::read("input");
}
pub fn main() { ::std::println!("cargo::rerun-if-changed=vendor/owned.rs"); }
#[cfg(test)] mod tests {
    #[test] fn test_only_read() { let _ = std::fs::read("unmarked unit-test input"); }
}
''')
        (root / "tests/production.rs").write_text('pub fn load() {\n' + mark("IR-DISPATCH-MODULE", "dispatch_fixture::production::load") + 'let _ = std::fs::read("input");\n}\n')
        (root / "generated/driver.rs").write_text('#![forbid(unused_macros)]\nfn main() { dispatch_fixture::load(); }\n')
        (root / "tests/test_only.rs").write_text('#[test] fn test_only_read(){ let _=std::fs::read("unmarked integration-test input"); }\n')
        (root / "examples/read.rs").write_text('fn main(){ let _=std::fs::read("unmarked example input"); }\n')
        # The fixture attestation binds the actual already-built binary. It is
        # only a cache identity input for this controlled runner regression.
        driver = root / "compiler-cache/target/debug/clippy-driver"
        driver.parent.mkdir(parents=True)
        try:
            os.link(actual_driver, driver)
        except OSError:
            shutil.copy2(actual_driver, driver)
        pin = json.loads((HERE / "compiler/toolchain.json").read_text())
        import hashlib
        (driver.parents[2] / "build.json").write_text(json.dumps({"schema": 1, "patch_digest": hashlib.sha256(driver.read_bytes()).hexdigest(), "source_digest": pin["source"]["sha256"], "component_digest": pin["rustc_dev"]["sha256"], "compiler_revision": pin["revision"]}))
        spec = importlib.util.spec_from_file_location("fixture_policy", tools / "policy.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        # The production matrix validator intentionally requires this repo's
        # 48 packages / 40 restricted packages. This one-package compiler
        # fixture substitutes only that repo-specific census, leaving the real
        # dispatcher, runner, report validation and manifest logic unchanged.
        def fixture_matrix(metadata):
            members = {p["name"] for p in metadata["packages"] if p["id"] in metadata["workspace_members"]}
            assert members == {"dispatch-fixture"}, members
        policy.validate_config = fixture_matrix
        candidate = args.output.resolve() / "candidate.json"
        attestation = args.output.resolve() / "run.json"
        parameters = argparse.Namespace(driver=driver, target_dir=root / "cache", candidate=candidate, attestation=attestation, manifest=root / "approved.json", collect=True)
        base_env = os.environ.copy()
        for key in list(os.environ):
            if key.startswith(("INTERNAL_READ_", "CLIPPY_")) or key in {"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR", "CARGO_ENCODED_RUSTFLAGS"}:
                os.environ.pop(key, None)
        os.environ.update(CARGO_BUILD_JOBS="2", RUSTFLAGS="-Dwarnings")
        try:
            policy.cargo(["+1.98.0", "generate-lockfile", "--offline"], cwd=root, capture_output=True, text=True)
            def run(label, *, fresh):
                try:
                    policy.run(parameters)
                except Exception:
                    for path in (root / "cache").rglob("cargo.stderr"):
                        shutil.copyfile(path, args.output / f"{label}-{path.parent.parent.name}-error.stderr")
                    for path in (root / "cache").rglob("reports/*.jsonl"):
                        destination = args.output / f"{label}-error-reports-{path.parent.parent.name}"
                        destination.mkdir(exist_ok=True)
                        shutil.copyfile(path, destination / path.name)
                    raise
                audit = json.loads(attestation.read_text())
                cache = Path(parameters.target_dir).resolve() / audit["cache_key"]
                for mode in ["strict", "collection"]:
                    messages = policy.json_lines(cache / mode / "fixture/cargo.jsonl")
                    artifacts = [row for row in messages if row.get("reason") == "compiler-artifact" and row["target"]["src_path"] in {str(root / "vendor/owned.rs"), str(root / "generated/driver.rs")} and row["target"]["kind"] != ["custom-build"]]
                    assert len(artifacts) == 2, (label, mode, artifacts)
                    assert all(row["fresh"] is fresh for row in artifacts), (label, mode, artifacts)
                    report_files = list((cache / mode / "reports").glob("*.jsonl"))
                    assert len(report_files) == 2, (label, mode, report_files)
                    for path in report_files:
                        policy.validate_report(path)
                manifest = json.loads(candidate.read_text())
                assert len(manifest["entries"]) == 2, manifest
                assert {row["item"] for row in manifest["entries"]} == {"dispatch_fixture::load", "dispatch_fixture::production::load"}
                results.append({"case": label, "cache_key": audit["cache_key"], "production_targets": 2, "manifest_entries": 2, "fresh": fresh})
                shutil.copyfile(candidate, args.output / f"{label}-manifest.json")
                return cache
            first = run("initial-strict-collection", fresh=False)
            warm = run("warm-strict-collection", fresh=True)
            assert first == warm
            # Unit/integration/example targets and dependency implementations do
            # not acquire obligations, including --test of the exact lib root.
            dispatch = first / "strict/fixture/dispatch.json"
            settings = json.loads(dispatch.read_text())
            env = os.environ.copy()
            env.update(CARGO_TARGET_DIR=str(first / "strict/target"), CARGO_PROFILE_DEV_DEBUG="0", CARGO_INCREMENTAL="0", RUSTC_WRAPPER=str(tools / "dispatch.py"), INTERNAL_READ_DISPATCH=str(dispatch), CLIPPY_CONF_DIR=settings["config_dir"])
            checked = policy.cargo(["+1.98.0", "check", "--all-targets", "--all-features", "--message-format=json"], cwd=root, env=env, capture_output=True, text=True)
            (args.output / "all-targets.jsonl").write_text(checked.stdout)
            (args.output / "all-targets.stderr").write_text(checked.stderr)
            # cargo check and cargo clippy may use different artifact suffixes;
            # every retained version still belongs to one selected root key.
            reports = list(Path(settings["reports"]).glob("*.jsonl"))
            assert len(reports) >= 2
            for report in reports:
                assert any(report.name.startswith(row["key"] + "-") for row in settings["targets"]), report
                policy.validate_report(report)
            results.append({"case": "nonproduction-and-shared-source-tests", "exit": checked.returncode})
            # Regression: removing the documented root forbid cannot disable
            # the mandatory unused-macro lint injected by the CI dispatcher.
            source = root / "vendor/owned.rs"
            original = source.read_text()
            source.write_text(original.replace('#![forbid(unused_macros)]\n', '')
                              + '\nmacro_rules! dormant_unexported { () => {}; }\n')
            rejected = subprocess.run(
                ["flock", "/tmp/muse-cargo.lock", "cargo", "+1.98.0", "clippy",
                 "--lib", "--message-format=json"], cwd=root, env=env,
                capture_output=True, text=True)
            codes = {((row.get("message") or {}).get("code") or {}).get("code")
                     for line in rejected.stdout.splitlines()
                     if (row := json.loads(line)).get("reason") == "compiler-message"}
            assert rejected.returncode and "unused_macros" in codes, (rejected.stdout, rejected.stderr)
            (args.output / "missing-root-unused-macro.jsonl").write_text(rejected.stdout)
            source.write_text(original.replace('#![forbid(unused_macros)]\n',
                                               '#![allow(unused_macros)]\n')
                              + '\nmacro_rules! dormant_unexported { () => {}; }\n')
            lowered = subprocess.run(
                ["flock", "/tmp/muse-cargo.lock", "cargo", "+1.98.0", "clippy",
                 "--lib", "--message-format=json"], cwd=root, env=env,
                capture_output=True, text=True)
            lowered_codes = {((row.get("message") or {}).get("code") or {}).get("code")
                             for line in lowered.stdout.splitlines()
                             if (row := json.loads(line)).get("reason") == "compiler-message"}
            assert lowered.returncode and "E0453" in lowered_codes, (lowered.stdout, lowered.stderr)
            assert "unused_macros" in lowered.stdout, lowered.stdout
            (args.output / "lowered-unused-macro.jsonl").write_text(lowered.stdout)
            source.write_text(original)
            results.append({"case": "missing-root-unused-macro", "rejected": True,
                            "diagnostic": "unused_macros", "lowering_diagnostic": "E0453"})
            # A new config or dispatcher revision gets a distinct cache, so
            # Cargo cannot replay artifacts compiled with the previous policy.
            with (tools / "clippy.toml").open("a") as output:
                output.write("# Reviewed policy configuration revision\n")
            changed_config = run("config-change", fresh=False)
            assert changed_config != first
            with (tools / "dispatch.py").open("a") as output:
                output.write("\n# Reviewed dispatcher revision\n")
            changed_wrapper = run("wrapper-change", fresh=False)
            assert changed_wrapper not in {first, changed_config}
            # Losing reports under a still-fresh Cargo cache must fail closed.
            report = next((changed_wrapper / "strict/reports").glob("*.jsonl"))
            report.unlink()
            try:
                policy.run(parameters)
            except (policy.PolicyError, OSError):
                pass
            else:
                raise AssertionError("fresh Cargo artifact accepted without its compiler report")
            results.append({"case": "missing-warm-report", "rejected": True})
        finally:
            os.environ.clear()
            os.environ.update(base_env)
    (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} compiled dispatcher/cache regressions passed")


if __name__ == "__main__":
    main()
