#!/usr/bin/env python3
"""Regression: renew API witnesses on relevant Cargo drift only."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("witness_provenance", HERE / "provenance.py")
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.lock = {"package": [{"name": name, "version": "1.0.0", "source": "registry", "checksum": "reviewed"} for name in sorted(provenance.API_DEPENDENCIES)]}
        self.metadata = {"workspace_members": ["member"], "packages": [{"id": "member", "name": "member", "dependencies": [{"name": "tokio", "req": "1", "features": ["fs"], "uses_default_features": False, "optional": True, "kind": None}], "features": {"remote": ["dep:tokio", "tokio/net"]}}]}
        self.fixtures = {"public": copy.deepcopy(self.lock), "aliases": {"package": []}, "journal": {"package": []}}

    def result(self):
        return provenance.collect(self.metadata, self.lock, self.fixtures, root=Path("/fixture"))

    def test_regression_unrelated_lock_change_is_not_an_api_approval(self):
        before = self.result()
        self.lock["package"].append({"name": "unrelated", "version": "99.0.0"})
        self.assertEqual(before, self.result())

    def test_regression_relevant_root_version_and_fixture_mismatch_fail(self):
        self.lock["package"][0]["version"] = "2.0.0"
        with self.assertRaisesRegex(ValueError, "differs from the workspace"):
            self.result()

    def test_regression_dependency_features_and_feature_definitions_require_review(self):
        before = self.result()
        self.metadata["packages"][0]["dependencies"][0]["features"].append("process")
        self.assertNotEqual(before, self.result())
        self.metadata["packages"][0]["dependencies"][0]["features"].pop()
        self.metadata["packages"][0]["features"]["remote"].append("tokio/process")
        self.assertNotEqual(before, self.result())

    def test_regression_manifest_and_lock_order_do_not_change_provenance(self):
        before = self.result()
        self.lock["package"].reverse()
        self.fixtures["public"]["package"].reverse()
        self.metadata["packages"][0]["features"]["remote"].reverse()
        self.assertEqual(before, self.result())

    def test_regression_same_version_source_or_checksum_drift_requires_review(self):
        before = self.result()
        self.lock["package"][0]["checksum"] = "changed"
        with self.assertRaisesRegex(ValueError, "differs from the workspace"):
            self.result()
        self.fixtures["public"]["package"][0]["checksum"] = "changed"
        self.assertNotEqual(before, self.result())


if __name__ == "__main__":
    unittest.main()
