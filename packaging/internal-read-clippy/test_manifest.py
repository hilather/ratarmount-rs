#!/usr/bin/env python3
"""Compile real Clippy events, then exercise the actual manifest generator."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("internal_read_policy", HERE / "policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="internal-read-manifest-") as temporary:
        root = Path(temporary)
        config = json.loads((HERE / "policy.json").read_text())
        config["restricted_packages"] = []
        config["include_exceptions"] = []
        (root / "policy.json").write_text(json.dumps(config))
        conf = root / "conf"
        conf.mkdir()
        (conf / "clippy.toml").write_text('disallowed-methods=[{path="control::acquire",reason="inventory-op:fixture"}]\n')
        sysroot = subprocess.check_output(["rustc", "+1.98.0", "--print", "sysroot"], text=True).strip()
        env = os.environ.copy()
        env.update(INTERNAL_READ_ROOT=str(root), INTERNAL_READ_CONFIG=str(root / "policy.json"),
                   LD_LIBRARY_PATH=str(Path(sysroot) / "lib"), CLIPPY_CONF_DIR=str(conf), RUSTC_BOOTSTRAP="1")
        review = {"id": "IR-REBIND", "item": "control::load", "disposition": "out-of-family",
                  "category": "fixture", "reason": "Exercise a resolved reexport identity",
                  "creation": {"policy": "none", "basis": "Compile-only fixture"}}
        reason = "internal-read:v1 " + json.dumps(review, separators=(",", ":"))
        mark = '#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason = r#"' + reason + '"#))]\n'
        prefix = '''#![forbid(unused_macros)]
pub mod a { pub fn open() -> u8 { 1 } }
pub mod b { pub fn open() -> u8 { 2 } }
'''

        def compile_case(name, source, *, reject=False, collection=True):
            src = root / "lib.rs"
            src.write_text(source)
            report = args.output / (name + ".jsonl")
            env["INTERNAL_READ_REPORT"] = str(report.resolve())
            command = [str(args.driver.resolve()), str(src), "--crate-name", "control", "--crate-type=lib",
                       "--edition=2024", "--emit=metadata", "--out-dir", str(root), "--cfg", "internal_read_inventory",
                       "--check-cfg=cfg(internal_read_inventory)", "-Dwarnings", "-Dunfulfilled_lint_expectations",
                       "--force-warn" if collection else "-D", "clippy::disallowed_methods"]
            completed = subprocess.run(command, env=env, capture_output=True, text=True)
            (args.output / (name + ".stderr")).write_text(completed.stderr)
            if bool(completed.returncode) != reject:
                raise AssertionError(f"{name}: unexpected exit {completed.returncode}:\n{completed.stderr}")
            results.append({"case": name, "exit": completed.returncode})
            return report

        def generate(name, source):
            report = compile_case(name, source)
            manifest = policy.manifest([("all-features", report)], {})
            (args.output / (name + ".manifest.json")).write_text(policy.canonical(manifest))
            return manifest

        source = prefix + 'pub use a::open as acquire;\npub fn load() {\n' + mark + 'let _ = acquire();\n}\n'
        first = generate("original", source)
        rebound = generate("rebound", source.replace("pub use a::open", "pub use b::open"))
        assert first["entries"][0]["configured_path"] == rebound["entries"][0]["configured_path"]
        assert first["entries"][0]["reason"] == rebound["entries"][0]["reason"]
        assert first["entries"][0]["leaf_digest"] == rebound["entries"][0]["leaf_digest"]
        assert first["entries"][0]["resolved"] == "control::a::open"
        assert rebound["entries"][0]["resolved"] == "control::b::open"
        assert first != rebound
        shifted = generate("line-shift", "\n// unrelated source movement\n\n" + source)
        assert first == shifted
        inserted = generate("impl-insertion", source.replace("pub fn load()", "pub struct Unrelated;\nimpl Unrelated { pub fn x() {} }\npub fn load()"))
        assert first == inserted
        # Strict mode independently rejects stale/unmarked expectations.
        compile_case("strict-marked", source, collection=False)
        compile_case("strict-unmarked", source.replace(mark, ""), collection=False, reject=True)
        compile_case("strict-stale", source.replace("let _ = acquire();", "let _ = ();"), collection=False, reject=True)
        # Rust can fulfill one expectation with two calls; the manifest cannot.
        doubled = source.replace("let _ = acquire();", "let _ = (acquire(), acquire());")
        path = compile_case("two-operations", doubled)
        try:
            policy.manifest([("all-features", path)], {})
        except policy.PolicyError:
            pass
        else:
            raise AssertionError("two operations shared one approval")
        unowned = source.replace(mark, "#[allow(clippy::disallowed_methods)]\n")
        path = compile_case("source-allow", unowned)
        try:
            policy.manifest([("all-features", path)], {})
        except policy.PolicyError:
            pass
        else:
            raise AssertionError("source allow authorized an unmarked lookup")
    (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} compiled manifest regressions passed")


if __name__ == "__main__":
    main()
