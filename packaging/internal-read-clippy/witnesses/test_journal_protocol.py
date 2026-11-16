#!/usr/bin/env python3
"""Regression: journal expectations never approve inventory operations."""
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
spec = importlib.util.spec_from_file_location("inventory_policy", HERE.parent / "policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, default=Path.home() / ".cargo/internal-read-clippy/target/debug/clippy-driver")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    sysroot = Path(subprocess.check_output(["rustc", "+1.98.0", "--print", "sysroot"], text=True).strip())
    metadata = {"id": "IR-JOURNAL-FIXTURE", "item": "control::run", "disposition": "support", "category": "fixture", "reason": "Read the fixture's input", "creation": {"policy": "none", "basis": "Existing input only"}}
    inventory = "#[expect(clippy::disallowed_methods, reason = r#\"internal-read:v1 " + json.dumps(metadata) + "\"#)]"
    journal = '#[expect(clippy::disallowed_methods, reason = "journal-policy: reviewed internal call")]'
    variants = {
        "separate": journal + '\nlet () = journal();\n' + inventory + '\nlet _ = std::fs::read("input");',
        "unmarked-journal": 'journal();',
        "stale-journal": journal + '\nlet () = ();',
        "stacked-same-leaf": journal + '\n' + inventory + '\nlet () = journal();',
        "stacked-mixed": journal + '\n' + inventory + '\nlet _ = (journal(), std::fs::read("input"));',
        "journal-hides-inventory": journal + '\nlet _ = (journal(), std::fs::read("input"));',
        "inactive-unmanifested": '#[cfg(windows)]\n#[expect(clippy::disallowed_methods, reason="review journal operation")]\nlet _ = std::fs::read("input");',
        "inactive-reviewed": '#[cfg(windows)]\n' + journal + '\nlet () = journal();',
    }
    results = []
    with tempfile.TemporaryDirectory(prefix="internal-read-journal-") as temporary:
        root = Path(temporary)
        config = json.loads((HERE.parent / "policy.json").read_text())
        config.update(restricted_packages=[], include_exceptions=[], allowed_extern_module="other::ffi")
        config_path = root / "policy.json"
        config_path.write_text(json.dumps(config))
        journal_reason = tomllib.loads((policy.ROOT / "clippy.toml").read_text())["disallowed-methods"][0]["reason"]
        (root / "clippy.toml").write_text('disallowed-methods=[{path="control::journal",reason=' + json.dumps(journal_reason) + '},{path="std::fs::read",reason="inventory-op:fs::read"}]\n')
        # Fixture exemptions are explicit, reviewed inputs, never inferred from
        # the expectation's prose or automatically accepted from compiler events.
        exemption = {"journal_exemption": True, "item": "control::run",
                     "reason": "journal-policy: reviewed internal call",
                     "lint": "clippy::disallowed_methods", "resolved": "control::journal",
                     "configured_path": "control::journal", "rule_reason": journal_reason}
        policy.ROOT = root
        env = os.environ.copy()
        env.update(INTERNAL_READ_ROOT=str(root), INTERNAL_READ_CONFIG=str(config_path), CLIPPY_CONF_DIR=str(root), LD_LIBRARY_PATH=str(sysroot / "lib") + os.pathsep + env.get("LD_LIBRARY_PATH", ""))
        for name, body in variants.items():
            source = root / "lib.rs"
            source.write_text('#![forbid(unused_macros)]\npub fn journal() {}\npub fn run() {\n' + body + '\n}\n')
            for mode in ["strict", "collection"]:
                report = args.output / f"{name}-{mode}.jsonl"
                env["INTERNAL_READ_REPORT"] = str(report.resolve())
                flags = ["-Dwarnings", "-Dunfulfilled_lint_expectations", "--cfg", "internal_read_inventory", "--check-cfg=cfg(internal_read_inventory)"]
                flags += ["--force-warn=clippy::disallowed_methods"] if mode == "collection" else ["-Dclippy::disallowed_methods"]
                run = subprocess.run([str(args.driver.resolve()), str(source), "--crate-name", "control", "--crate-type=lib", "--edition=2021", "--emit=metadata", "--out-dir", str(root), *flags], env=env, capture_output=True, text=True)
                (args.output / f"{name}-{mode}.stderr").write_text(run.stderr)
                rejected = bool(run.returncode)
                manifest_rejected = None
                if mode == "strict":
                    expected = name in {"unmarked-journal", "stale-journal", "stacked-same-leaf", "stacked-mixed"}
                    assert rejected == expected, (name, mode, run.stderr)
                elif not rejected:
                    try:
                        manifest = policy.manifest([("all-features", report)], {}, [exemption])
                    except policy.PolicyError:
                        manifest_rejected = True
                    else:
                        manifest_rejected = False
                        expected_entries = 2 if name == "separate" else 1
                        assert len(manifest["entries"]) == expected_entries, (name, manifest)
                        if name == "inactive-reviewed":
                            assert manifest["entries"][0]["native_observed"] is False
                    assert manifest_rejected == (name not in {"separate", "inactive-reviewed"}), (name, mode)
                    if name == "separate":
                        try:
                            policy.manifest([("all-features", report)], {})
                        except policy.PolicyError:
                            pass
                        else:
                            raise AssertionError("journal reason approved itself without the explicit manifest flag")
                results.append({"fixture": name, "mode": mode, "exit": run.returncode, "manifest_rejected": manifest_rejected})
    (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} journal protocol regressions passed")


if __name__ == "__main__":
    main()
