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
        mark = '#[expect(clippy::disallowed_methods, reason = r#"' + reason + '"#)]\n'
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
        # Regression: a fulfilled, well-formed expectation still needs review
        # in the approved manifest; removing its source must also fail the diff.
        approved = args.output / "approved.json"
        approved.write_text(policy.canonical(first))
        unmanifested_source = source.replace("IR-REBIND", "IR-UNMANIFESTED")
        unmanifested_report = compile_case("unmanifested-expect", unmanifested_source, collection=False)
        unmanifested = policy.manifest([("all-features", unmanifested_report)], {})
        for name, candidate in [
            ("unmanifested-expect", unmanifested),
            ("manifest-without-source-expect", generate("removed-expect", prefix)),
        ]:
            try:
                policy.check_diff(candidate, approved)
            except policy.PolicyError as error:
                assert "internal-read manifest changed; review the candidate" == str(error)
                results.append({"case": name + "-diff", "refusal": str(error)})
            else:
                raise AssertionError(name + ": missing bidirectional approval refusal")
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
        unrelated = generate("unrelated-expect", prefix + '#[expect(dead_code, reason="review")] fn unused() {}\n')
        assert unrelated["entries"] == [], unrelated
        ordinary = compile_case("active-ordinary-expect", source.replace(mark,
            '#[expect(clippy::disallowed_methods, reason="ordinary review")]\n'), collection=False)
        active_rows = [r for r in policy.json_lines(ordinary)
                       if r.get("kind") == "expectation" and r.get("active") is True]
        assert any(r.get("reason") == "ordinary review" and r.get("lint") == "clippy::disallowed_methods"
                   for r in active_rows), active_rows
        try:
            policy.manifest([("all-features", ordinary)], {})
        except policy.PolicyError as error:
            assert "literal internal-read:v1 reason" in str(error), str(error)
            results.append({"case": "active-ordinary-expect-unmanifested", "refusal": str(error)})
        else:
            raise AssertionError("ordinary reason authorized an unmanifested active expectation")
        # Regression: a later fulfilled expect shadows the first HIR lint ID.
        # Source validation must still retain and reject the earlier approval.
        shadowed = compile_case("shadowed-ordinary-expect", source.replace(mark,
            '#[allow(unfulfilled_lint_expectations)]\n'
            '#[expect(clippy::disallowed_methods, reason="shadowed ordinary review")]\n' + mark),
            collection=False)
        try:
            policy.manifest([("all-features", shadowed)], {})
        except policy.PolicyError as error:
            assert "literal internal-read:v1 reason" in str(error), str(error)
            results.append({"case": "shadowed-ordinary-expect-unmanifested", "refusal": str(error)})
        else:
            raise AssertionError("shadowed unmanifested expectation was dropped")
        # Regression: inactive Windows expectations with ordinary reason text
        # disappeared from Linux approval checks. A reviewed file only exempts
        # its target predicates; it cannot exempt any expectation from review.
        config["restricted_packages"] = ["ratarmount-index"]
        config["reviewed_target_files"] = [{"file": "lib.rs", "reviewer": "compiled fixture",
                                            "reason": "Exercise inactive manifest validation"}]
        (root / "policy.json").write_text(json.dumps(config))
        env["CARGO_PKG_NAME"] = "ratarmount-index"
        for name, predicate, literal in [
            ("inactive-windows-ordinary-expect", "windows", "review journal operation"),
            ("inactive-false-ordinary-expect", "any()", "ordinary review"),
            ("inactive-release-ordinary-expect", "not(debug_assertions)", ""),
        ]:
            source = prefix + '#[cfg(' + predicate + ')] pub fn hidden() {\n' + \
                '#[expect(clippy::disallowed_methods, reason=' + json.dumps(literal) + ')]\n' + \
                'let _ = a::open();\n}\n'
            report = compile_case(name, source, collection=False)
            try:
                policy.manifest([("all-features", report)], {})
            except policy.PolicyError as error:
                assert "literal internal-read:v1 reason" in str(error), (name, str(error))
                results.append({"case": name + "-unmanifested", "refusal": str(error)})
            else:
                raise AssertionError(name + ": inactive unmanifested expectation was dropped")
    (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} compiled manifest regressions passed")


if __name__ == "__main__":
    main()
