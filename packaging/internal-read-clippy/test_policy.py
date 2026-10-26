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
            "leaf_digest": policy.digest(b"let _ = std::fs::read(input);"),
            "source_leaf_observed": True,
            "source_leaf_span": {"file": "src/a.rs", "lo": 5, "hi": 25},
            "span": {"file": "src/a.rs", "lo": 10, "hi": 20},
        }
        rule = policy.tomllib.loads((policy.ROOT / "clippy.toml").read_text())["disallowed-methods"][0]
        self.journal = dict(self.operation, reason="A reviewed journal call",
                            configured_path=rule["path"], resolved=rule["path"],
                            rule_reason=rule["reason"])
        self.exemption = {"journal_exemption": True, "item": self.journal["owner"],
                          **{key: self.journal[key] for key in
                             ("reason", "lint", "resolved", "configured_path", "rule_reason")}}
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

    def test_regression_journal_needs_explicit_flag_and_exact_lookup(self):
        path = self.report([self.journal, self.complete])
        with self.assertRaisesRegex(PolicyError, "explicit journal exemption"):
            manifest([("default", path)], {})
        for flag in (False, None):
            approval = dict(self.exemption, journal_exemption=flag)
            with self.assertRaisesRegex(PolicyError, "explicit manifest flag"):
                manifest([("default", path)], {}, [approval])
        approved = manifest([("default", path)], {}, [self.exemption])
        entry = approved["entries"][0]
        self.assertTrue(entry["journal_exemption"])
        self.assertEqual(entry["multiplicity"], 1)
        for field in ("resolved", "configured_path", "rule_reason", "lint"):
            row = dict(self.journal, **{field: "changed"})
            path = self.report([row, self.complete])
            with self.assertRaisesRegex(PolicyError, "(lookup differs|lint differs)"):
                manifest([("default", path)], {}, [self.exemption])

    def test_regression_journal_flag_cannot_approve_inventory_or_unknown_rules(self):
        row = dict(self.operation, reason=self.journal["reason"])
        path = self.report([row, self.complete])
        with self.assertRaisesRegex(PolicyError, "cannot approve an inventory rule"):
            manifest([("default", path)], {}, [self.exemption])
        for changed in (dict(rule_reason="unknown-policy"),
                        dict(configured_path="std::fs::read"),
                        dict(rule_reason="inventory-op:fs::read")):
            approval = dict(self.exemption, **changed)
            with self.assertRaisesRegex(PolicyError, "independent root Clippy rule"):
                manifest([("default", path)], {}, [approval])

    def test_regression_inactive_noninventory_reason_requires_manifest(self):
        row = {"schema": 1, "kind": "expectation", "native_active": False, "owner": self.journal["owner"],
               "lint": "clippy::disallowed_methods", "reason": self.journal["reason"],
               "leaf": {"tokens": "let _ = journal();"}}
        path = self.report([row, self.complete])
        with self.assertRaisesRegex(PolicyError, "literal internal-read:v1 reason"):
            manifest([("default", path)], {})
        entry = manifest([("default", path)], {}, [self.exemption])["entries"][0]
        self.assertTrue(entry["journal_exemption"])
        self.assertFalse(entry["native_observed"])
        ambiguous = dict(self.exemption, item="probe::other")
        with self.assertRaisesRegex(PolicyError, "duplicate expectation reason on different items"):
            manifest([("default", path)], {}, [self.exemption, ambiguous])

    def test_regression_active_shadowed_source_expectation_cannot_disappear(self):
        row = {"schema": 1, "kind": "expectation", "source": True, "owner": self.operation["owner"],
               "lint": "clippy::disallowed_methods", "reason": "unreviewed shadowed approval",
               "leaf": {"tokens": "let _ = std::fs::read(input);"}}
        path = self.report([row, self.complete])
        with self.assertRaisesRegex(PolicyError, "literal internal-read:v1 reason"):
            manifest([("default", path)], {})
        row = dict(row, reason=self.operation["reason"])
        path = self.report([row, self.operation, self.complete])
        entry = manifest([("default", path)], {})["entries"][0]
        self.assertTrue(entry["native_observed"])
        self.assertEqual(entry["multiplicity"], 1)
        path = self.report([row, row, self.complete])
        with self.assertRaisesRegex(PolicyError, "multiple operations/marks"):
            manifest([("default", path)], {})

    def test_regression_copied_journal_reason_keeps_inactive_item_owner(self):
        """Regression: an inactive journal-reason copy merged into the approved item."""
        copied = {"schema": 1, "kind": "expectation", "source": True,
                  "owner": "probe::hidden", "lint": self.journal["lint"],
                  "reason": self.journal["reason"],
                  "leaf": {"tokens": "let _ = std::fs::read(input);"}}
        owned = self.report([self.journal, self.complete], "owned.jsonl")
        hidden = self.report([copied, self.complete], "hidden.jsonl")
        for reports in ([("default", hidden)],
                        [("default", owned), ("all-features", hidden)],
                        [("default", hidden), ("all-features", owned)]):
            with self.assertRaisesRegex(PolicyError, "duplicate expectation reason on different items"):
                manifest(reports, {}, [self.exemption])
        for rows in ([self.journal, copied], [copied, self.journal]):
            with self.assertRaisesRegex(PolicyError, "duplicate expectation reason on different items"):
                manifest([("default", self.report([*rows, self.complete]))], {}, [self.exemption])

    def test_regression_source_native_merge_collisions_fail_in_both_orders(self):
        """Regression: native observations overwrote conflicting source leaves."""
        source = {"schema": 1, "kind": "expectation", "source": True,
                  "owner": self.operation["owner"], "lint": self.operation["lint"],
                  "reason": self.operation["reason"], "leaf": {"tokens": "different source leaf"}}
        for operation, exemptions in ((self.operation, []), (self.journal, [self.exemption])):
            source["reason"] = operation["reason"]
            op = self.report([operation, self.complete], "native.jsonl")
            mark = self.report([source, self.complete], "source.jsonl")
            for reports in ([("default", op), ("all-features", mark)],
                            [("default", mark), ("all-features", op)]):
                with self.assertRaisesRegex(PolicyError, "conflicting compiler observations"):
                    manifest(reports, {}, exemptions)
            for rows in ([operation, source], [source, operation]):
                with self.assertRaisesRegex(PolicyError, "conflicting compiler observations"):
                    manifest([("default", self.report([*rows, self.complete]))], {}, exemptions)

    def test_regression_source_native_lint_collisions_fail_in_both_orders(self):
        """Regression: source/native merges lost the source protected-lint identity."""
        source = {"schema": 1, "kind": "expectation", "source": True,
                  "owner": self.operation["owner"], "lint": "clippy::disallowed_types",
                  "reason": self.operation["reason"],
                  "leaf": {"tokens": "let _ = std::fs::read(input);"}}
        native = self.report([self.operation, self.complete], "native.jsonl")
        mark = self.report([source, self.complete], "source.jsonl")
        for reports in ([("default", native), ("all-features", mark)],
                        [("default", mark), ("all-features", native)]):
            with self.assertRaisesRegex(PolicyError, "conflicting compiler observations"):
                manifest(reports, {})
        for rows in ([self.operation, source], [source, self.operation]):
            with self.assertRaisesRegex(PolicyError, "conflicting compiler observations"):
                manifest([("default", self.report([*rows, self.complete]))], {})

    def test_regression_source_owner_cannot_come_from_reason_metadata(self):
        source = {"schema": 1, "kind": "expectation", "source": True,
                  "owner": "probe::hidden", "lint": self.operation["lint"],
                  "reason": self.operation["reason"], "leaf": {"tokens": "unused"}}
        with self.assertRaisesRegex(PolicyError, "declared owner differs"):
            manifest([("default", self.report([source, self.complete]))], {})
        del source["owner"]
        with self.assertRaisesRegex(PolicyError, "no compiler item owner"):
            manifest([("default", self.report([source, self.complete]))], {})

    def test_regression_unresolved_source_impl_owner_fails_closed(self):
        source = {"schema": 1, "kind": "expectation", "source": True,
                  "owner": "probe::<unresolved-impl>::acquire", "lint": self.operation["lint"],
                  "reason": self.operation["reason"], "leaf": {"tokens": "let _ = std::fs::read(input);"},
                  "owner_span": {"file": "src/a.rs", "lo": 1, "hi": 30}}
        with self.assertRaisesRegex(PolicyError, "requires a resolved compiler impl owner"):
            manifest([("default", self.report([source, self.complete]))], {})
        binding = {"schema": 1, "kind": "source_owner", "owner": self.operation["owner"],
                   "span": source["owner_span"]}
        candidate = manifest([("default", self.report([source, binding, self.operation, self.complete]))], {})
        self.assertEqual(candidate["entries"][0]["item"], self.operation["owner"])

    def test_regression_stale_and_broad_journal_expectations_fail(self):
        row = dict(self.journal, kind="expectation", active=True)
        path = self.report([row, self.complete])
        with self.assertRaisesRegex(PolicyError, "no inventory lookup"):
            manifest([("default", path)], {}, [self.exemption])
        row = dict(self.journal, broad=True)
        path = self.report([row, self.complete])
        with self.assertRaisesRegex(PolicyError, "broad inventory expectation"):
            manifest([("default", path)], {}, [self.exemption])

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
