"""Opt-in producer compatibility test; KOVA_CHECKOUT is a local pinned checkout."""
import os
from pathlib import Path
import subprocess
import unittest

from tests import test_kova_evidence as fixtures


class KovaUpstreamContractTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("KOVA_CHECKOUT"), "set KOVA_CHECKOUT for upstream producer test")
    def test_real_kova_report_ledger_and_bundle_are_importable(self):
        fixture = fixtures.KovaEvidenceTest()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        result = subprocess.run([
            "node", str(fixtures.ROOT / "tests/kova_upstream_fixture.mjs"),
            str(Path(os.environ["KOVA_CHECKOUT"]).resolve()), str(fixture.root),
        ], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        imported = fixture.run_import()
        self.assertEqual(imported.returncode, 0, fixture.read_output())
        content = fixture.read_output()["evidence_content"]
        self.assertEqual(content["candidate_binding"]["scope"], "core_npm_artifact_only")
        self.assertEqual(content["post_activation_e2e"], "not_run")
        fixture.require_environment_gate()
        self.assertEqual(fixture.run_import().returncode, 2)
        self.assertEqual(fixture.read_output()["status"], "incomplete")
