import json
from pathlib import Path
import unittest

from tests.test_openclaw_benchmark import assert_schema_contract


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "references" / "shadow-runs-index.json"
SCHEMA_PATH = (
    ROOT / "schemas" / "openclaw.safe_update.shadow_runs_index.v1.schema.json"
)
DECISION_PATH = ROOT / "references" / "v1.3-decision.md"


class V13ExitGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
        self.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_index_is_schema_valid_and_evaluation_only(self) -> None:
        assert_schema_contract(self.index, self.schema)
        self.assertFalse(self.index["authoritative"])
        self.assertEqual(self.index["canonical_status_effect"], "none")
        self.assertFalse(self.index["selective_omission_enabled"])
        self.assertFalse(self.index["human_risk_acceptance_can_upgrade"])

    def test_positive_gate_is_not_claimed_without_field_evidence(self) -> None:
        observed = self.index["observed"]
        thresholds = self.index["thresholds"]
        self.assertGreaterEqual(
            observed["labeled_fixtures"], thresholds["labeled_fixtures"]
        )
        self.assertLess(
            observed["field_rehearsals"], thresholds["field_rehearsals"]
        )
        self.assertLess(
            observed["distinct_candidate_roots"],
            thresholds["distinct_candidate_roots"],
        )
        self.assertFalse(self.index["completion"]["positive_gate_met"])
        self.assertEqual(self.index["decision"], "retain_additive_baseline")

    def test_fixture_run_is_digest_bound_and_never_claims_candidate_parity(self) -> None:
        run = self.index["runs"][0]
        self.assertEqual(run["stratum"], "fixture")
        self.assertIsNone(run["candidate_root"])
        self.assertEqual(run["fixture_count"], 14)
        self.assertRegex(run["corpus_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(run["run_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(len(run["evidence_digests"]), 3)
        for evidence_digest in run["evidence_digests"]:
            self.assertRegex(evidence_digest, r"^sha256:[0-9a-f]{64}$")

    def test_decision_record_preserves_additive_baseline(self) -> None:
        text = DECISION_PATH.read_text(encoding="utf-8")
        self.assertIn("`retain_additive_baseline`", text)
        self.assertIn("0 of 5 required", text)
        self.assertIn("0 of 3 required", text)
        self.assertIn("future selective mode requires a separate RFC", text)
        self.assertIn("Do not\nenable evidence subtraction", text)
        self.assertNotIn("selective_omission_enabled: true", text)

    def test_any_recorded_false_green_would_force_retention(self) -> None:
        self.assertEqual(self.index["thresholds"]["unexplained_false_greens"], 0)
        self.assertEqual(self.index["observed"]["unexplained_false_greens"], 0)
        self.assertIn("unexplained_false_greens", self.schema["$defs"]["counts"]["properties"])
        self.assertEqual(self.index["decision"], "retain_additive_baseline")


if __name__ == "__main__":
    unittest.main()
