#!/usr/bin/env python3
"""Compiled regression: every policy diagnostic must join one lookup event."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("internal_read_diagnostics", HERE / "diagnostics.py")
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, default=Path.home() / ".cargo/internal-read-clippy/target/debug/clippy-driver")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="internal-read-diagnostics-") as temporary:
        root = Path(temporary)
        (root / "Cargo.toml").write_text('[package]\nname="diagnostic-fixture"\nversion="0.0.0"\nedition="2021"\n[lib]\npath="lib.rs"\n[workspace]\n')
        review = {"id": "IR-DIAGNOSTIC", "item": "diagnostic_fixture::load", "disposition": "support", "category": "fixture", "reason": "Read the fixture input", "creation": {"policy": "none", "basis": "Existing input only"}}
        (root / "lib.rs").write_text('''#![forbid(unused_macros)]
pub fn journal() {}
pub fn load() {
    #[expect(clippy::disallowed_methods, reason="Reviewed journal delegation")]
    let () = journal();
    #[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason=r#"internal-read:v1 ''' + json.dumps(review) + '''"#))]
    let _ = std::fs::read("input");
}
''')
        (root / "clippy.toml").write_text('disallowed-methods=[{path="std::fs::read",reason="inventory-op:fixture"},{path="diagnostic_fixture::journal",reason="independent journal restriction"}]\n')
        config = json.loads((HERE / "policy.json").read_text())
        config.update(restricted_packages=[], classified_packages=["diagnostic-fixture"], include_exceptions=[])
        (root / "policy.json").write_text(json.dumps(config))
        sysroot = Path(subprocess.check_output(["rustc", "+1.98.0", "--print", "sysroot"], text=True).strip())
        env = {key: value for key, value in os.environ.items() if not key.startswith(("CLIPPY_", "INTERNAL_READ_")) and key not in {"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_ENCODED_RUSTFLAGS"}}
        report = args.output.resolve() / "compiler.jsonl"
        env.update(CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(root / "target"), CARGO_PROFILE_DEV_DEBUG="0", CARGO_INCREMENTAL="0", RUSTC_WORKSPACE_WRAPPER=str(args.driver.resolve()), CLIPPY_CONF_DIR=str(root), CLIPPY_ARGS="__CLIPPY_HACKERY__".join(["--force-warn=clippy::disallowed_methods", "--cfg=internal_read_inventory", "--check-cfg=cfg(internal_read_inventory)", "-Dwarnings", "-Dunfulfilled_lint_expectations"]), INTERNAL_READ_REPORT=str(report), INTERNAL_READ_CONFIG=str(root / "policy.json"), INTERNAL_READ_ROOT=str(root), LD_LIBRARY_PATH=str(sysroot / "lib") + os.pathsep + env.get("LD_LIBRARY_PATH", ""))
        done = subprocess.run(["flock", "/tmp/muse-cargo.lock", "cargo", "+1.98.0", "check", "--manifest-path", str(root / "Cargo.toml"), "--lib", "--message-format=json", "--offline"], cwd=root, env=env, text=True, capture_output=True)
        (args.output / "cargo.jsonl").write_text(done.stdout)
        (args.output / "cargo.stderr").write_text(done.stderr)
        assert done.returncode == 0, done.stderr
        messages = [json.loads(line) for line in done.stdout.splitlines()]
        rows = [json.loads(line) for line in report.read_text().splitlines()]
        target = {"source": str(root / "lib.rs"), "crate": "diagnostic_fixture", "crate_types": ["lib"]}
        joined = diagnostics.validate_diagnostics(messages, target, rows, root=root)
        assert joined == {"operations": 2, "diagnostics": 2}, joined
        results.append({"case": "compiled-complete", **joined})
        operations = [index for index, row in enumerate(rows) if row.get("kind") == "operation"]
        compiler_messages = [index for index, row in enumerate(messages) if row.get("reason") == "compiler-message" and (row.get("message", {}).get("code") or {}).get("code") == "clippy::disallowed_methods"]
        def reject(name, mutated_messages, mutated_rows):
            try:
                diagnostics.validate_diagnostics(mutated_messages, target, mutated_rows, root=root)
            except diagnostics.DiagnosticsError as error:
                results.append({"case": name, "rejected": True, "detail": str(error)})
            else:
                raise AssertionError(f"{name}: malformed diagnostic/event join passed")
        reject("missing-lookup-with-complete-phases", messages, [row for index, row in enumerate(rows) if index != operations[0]])
        reject("duplicate-lookup-ambiguous", messages, [*rows, copy.deepcopy(rows[operations[0]])])
        reject("missing-diagnostic", [row for index, row in enumerate(messages) if index != compiler_messages[0]], rows)
        reject("duplicate-diagnostic", [*messages, copy.deepcopy(messages[compiler_messages[0]])], rows)
        malformed = copy.deepcopy(messages)
        malformed[compiler_messages[0]]["message"]["spans"] = []
        reject("missing-primary-span", malformed, rows)
        malformed = copy.deepcopy(messages)
        malformed[compiler_messages[0]]["message"]["spans"] *= 2
        reject("ambiguous-primary-span", malformed, rows)
        malformed = copy.deepcopy(messages)
        malformed[compiler_messages[0]]["message"]["children"] = []
        reject("missing-configured-reason-note", malformed, rows)
        malformed_rows = copy.deepcopy(rows)
        malformed_rows[operations[0]]["span"]["line"] = "1"
        reject("malformed-event-coordinate", messages, malformed_rows)
        # Diagnostic prose is deliberately irrelevant to resolved identity.
        unrelated = copy.deepcopy(messages)
        for index in compiler_messages:
            unrelated[index]["message"]["message"] = "opaque diagnostic prose"
        diagnostics.validate_diagnostics(unrelated, target, rows, root=root)
        rebound = copy.deepcopy(rows)
        rebound[operations[0]]["resolved"] = "changed::defining_identity"
        diagnostics.validate_diagnostics(messages, target, rebound, root=root)
        results.append({"case": "no-identity-from-diagnostic-prose", "accepted": True})
        external = copy.deepcopy(messages[compiler_messages[0]])
        external["target"].update(src_path=str(root / "dependency/lib.rs"), name="dependency")
        diagnostics.validate_diagnostics([*messages, external], target, rows, root=root)
        results.append({"case": "unselected-dependency-diagnostic", "accepted": True})
    (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} compiled diagnostic/event regressions passed")


if __name__ == "__main__":
    main()
