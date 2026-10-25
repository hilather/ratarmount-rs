#!/usr/bin/env python3
"""Regression tests for fail-closed reports and stable approval identity."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("internal_read_policy", Path(__file__).with_name("policy.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
PolicyError, canonical, check_diff, manifest, targets = (
    policy.PolicyError, policy.canonical, policy.check_diff, policy.manifest, policy.targets)


class Contract(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.metadata = {
            "id": "IR-TEST", "item": "probe::acquire", "disposition": "out-of-family",
            "category": "fixture", "reason": "Read the regression fixture",
            "creation": {"policy": "none", "basis": "Existing fixture input"},
        }
        self.operation = {
            "schema": 1, "kind": "operation", "owner": "probe::acquire",
            "reason": "internal-read:v1 " + json.dumps(self.metadata),
            "lint": "clippy::disallowed_methods", "resolved": "std::fs::read",
            "configured_path": "probe::alias", "rule_reason": "inventory-op:fs::read",
            "leaf_digest": "a" * 64,
            "source_leaf_observed": True,
            "source_leaf_span": {"file": "src/a.rs", "lo": 5, "hi": 25},
            "span": {"file": "src/a.rs", "lo": 10, "hi": 20},
        }
        self.complete = {
            "schema": 1, "kind": "complete", "success": True, "syntax_complete": True,
            "expanded_complete": True, "hir_complete": True,
        }

    def report(self, rows, filename="report.jsonl"):
        path = self.root / filename
        rows = [{"schema": 1, "kind": "syntax_loaded", "scope": "crate"},
                {"schema": 1, "kind": "expansion_complete", "records": 0, "matched": 0},
                {"schema": 1, "kind": "hir_complete"}, *rows]
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return path

    def generate(self, row=None):
        return manifest([("all-features", self.report([row or self.operation, self.complete]))], {})

    def test_regression_rebinding_configured_reexport_diffs_actual_definition(self):
        first = self.generate()
        rebound = dict(self.operation, resolved="another::open")
        second = self.generate(rebound)
        self.assertEqual(first["entries"][0]["reason"], second["entries"][0]["reason"])
        self.assertNotEqual(first, second)
        approved = self.root / "manifest.json"
        approved.write_text(canonical(first))
        with self.assertRaisesRegex(PolicyError, "manifest changed"):
            check_diff(second, approved)

    def test_regression_line_shift_and_scratch_path_do_not_change_manifest(self):
        first = self.generate()
        shifted = dict(self.operation, span={"file": "src/b.rs", "lo": 100, "hi": 110},
                       source_leaf_span={"file": "src/b.rs", "lo": 95, "hi": 115})
        self.assertEqual(first, self.generate(shifted))

    def test_regression_second_operation_cannot_share_one_approval(self):
        path = self.report([self.operation, self.operation, self.complete])
        with self.assertRaisesRegex(PolicyError, "multiple operations"):
            manifest([("default", path)], {})

    def test_regression_missing_actual_lookup_cannot_use_stock_diagnostics(self):
        for missing in ("resolved", "configured_path", "rule_reason"):
            row = self.operation.copy()
            del row[missing]
            with self.assertRaises(PolicyError):
                self.generate(row)

    def test_regression_generated_or_outside_primary_cannot_approve_itself(self):
        for row in (dict(self.operation, source_leaf_observed=False),
                    dict(self.operation, span={"file": "/out/generated.rs", "lo": 10, "hi": 20}),
                    dict(self.operation, span={"file": "out/generated.rs", "lo": 10, "hi": 20}),
                    dict(self.operation, span={"file": "src/a.rs", "lo": 1, "hi": 50})):
            with self.assertRaisesRegex(PolicyError, "(unowned|not contained)"):
                self.generate(row)

    def test_regression_source_allow_does_not_approve_unmarked_lookup(self):
        row = self.operation.copy()
        del row["reason"]
        with self.assertRaisesRegex(PolicyError, "literal"):
            self.generate(row)

    def test_regression_journal_reason_cannot_approve_inventory_operation(self):
        row = dict(self.operation, reason="Journal authorization")
        with self.assertRaisesRegex(PolicyError, "literal"):
            self.generate(row)

    def test_regression_compiler_owner_must_match_literal_owner(self):
        with self.assertRaisesRegex(PolicyError, "declared owner"):
            self.generate(dict(self.operation, owner="probe::different"))

    def test_regression_broad_owner_and_unknown_namespace_fail(self):
        with self.assertRaisesRegex(PolicyError, "broad"):
            self.generate(dict(self.operation, broad=True))
        with self.assertRaisesRegex(PolicyError, "namespace"):
            self.generate(dict(self.operation, rule_reason="unknown-policy"))

    def test_regression_stale_active_metadata_without_event_fails(self):
        row = dict(self.operation, kind="expectation", active=True)
        with self.assertRaisesRegex(PolicyError, "no inventory lookup"):
            self.generate(row)

    def test_regression_malformed_partial_and_missing_reports_fail(self):
        path = self.root / "bad.jsonl"
        for contents in ("", "{}", "{broken}\n", json.dumps(self.operation) + "\n"):
            path.write_text(contents)
            with self.assertRaises(PolicyError):
                manifest([("default", path)], {})

    def test_regression_duplicate_ids_and_conflicting_profile_events_fail(self):
        other = copy.deepcopy(self.operation)
        review = dict(self.metadata, reason="Different reviewed purpose")
        other["reason"] = "internal-read:v1 " + json.dumps(review)
        path = self.report([self.operation, other, self.complete])
        with self.assertRaisesRegex(PolicyError, "duplicate expectation id"):
            manifest([("default", path)], {})
        first = self.report([self.operation, self.complete], "one.jsonl")
        other = dict(self.operation, resolved="rebound::open")
        second = self.report([other, self.complete], "two.jsonl")
        with self.assertRaisesRegex(PolicyError, "conflicting compiler"):
            manifest([("default", first), ("all-features", second)], {})

    def test_regression_custom_bin_and_proc_macro_are_production(self):
        metadata = {"workspace_members": ["p"], "packages": [{
            "id": "p", "name": "custom", "targets": [
                {"name": "driver", "src_path": "/tmp/custom.rs", "kind": ["bin"], "crate_types": ["bin"]},
                {"name": "derive", "src_path": "/tmp/derive.rs", "kind": ["proc-macro"], "crate_types": ["proc-macro"]},
                {"name": "builder", "src_path": "/tmp/build.rs", "kind": ["custom-build"], "crate_types": ["bin"]},
                {"name": "example", "src_path": "/tmp/example.rs", "kind": ["example"], "crate_types": ["bin"]},
            ]}]}
        rows = targets(metadata, ["--workspace", "--lib", "--bins"])
        self.assertEqual({r["crate"] for r in rows}, {"derive", "driver"})


if __name__ == "__main__":
    unittest.main()
