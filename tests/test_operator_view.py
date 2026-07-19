import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "openclaw_operator_view.py"
SAFE_UPDATE_PATH = ROOT / "scripts" / "openclaw_safe_update.py"


spec = importlib.util.spec_from_file_location("safe_update_for_view", SAFE_UPDATE_PATH)
assert spec and spec.loader
SAFE_UPDATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SAFE_UPDATE)


def digest(character: str) -> str:
    return "sha256:" + (character * 64)


def status(verdict: str) -> dict:
    failed = verdict == "blocked"
    failed_fields = {"installation_attestation", "conservative_gates"} if failed else set()
    evidence = {
        field: ("failed" if field in failed_fields else "success")
        for field in SAFE_UPDATE.EVIDENCE_STATUS_FIELDS
    }
    gate_status = "failed" if failed else "success"
    return SAFE_UPDATE.build_status(
        generated_at="2026-07-19T00:00:00+00:00",
        verdict=verdict,
        reason="fixture reason",
        reason_code=(
            "required_evidence_failed"
            if failed
            else "baseline_rehearsal_passed"
        ),
        evidence_status=evidence,
        gate_decision={
            "status": gate_status,
            "handling": "blocked" if failed else "baseline",
            "required_gates": ["rollback-evidence"] if failed else [],
            "decision_digest": digest("b"),
        },
        candidate_roots={
            "current": digest("c"),
            "target": None if failed else digest("d"),
        },
        evidence_bundle={
            "path": "evidence-bundle.json",
            "sha256": "e" * 64,
        },
        next_step=(
            "repair evidence and rerun"
            if failed
            else "prepare rollback-aware operator plan and stop before apply"
        ),
        next_step_code=(
            "repair_and_rerun" if failed else "prepare_operator_plan"
        ),
    )


class OperatorViewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.artifacts = Path(self.temporary.name) / "artifacts"
        self.artifacts.mkdir()

    def run_view(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--artifact-dir",
                str(self.artifacts),
                "--repository-url",
                "https://github.com/pdurlej/openclaw-skill-safe-update",
                "--run-url",
                "https://github.com/pdurlej/openclaw-skill-safe-update/actions/runs/1",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def run_view_with_index(self) -> subprocess.CompletedProcess[str]:
        index_path = ROOT / "references" / "shadow-runs-index.json"
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--artifact-dir",
                str(self.artifacts),
                "--repository-url",
                "https://github.com/pdurlej/openclaw-skill-safe-update",
                "--shadow-runs-index",
                str(index_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def write_status(self, verdict: str) -> None:
        (self.artifacts / "verdict.json").write_text(
            json.dumps(status(verdict)),
            encoding="utf-8",
        )

    def test_ready_preflight_view_is_explicitly_not_live_proof(self) -> None:
        self.write_status("ready_for_operator_plan")
        result = self.run_view()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("`ready_for_operator_plan`", result.stdout)
        self.assertIn("Post-activation E2E:** `not_run`", result.stdout)
        self.assertIn("Production apply allowed:** `false`", result.stdout)
        self.assertIn("does not prove live channels", result.stdout)
        self.assertIn("verdict.json` is the only status authority", result.stdout)

    def test_blocked_preflight_still_renders_evidence_and_gate(self) -> None:
        self.write_status("blocked")
        result = self.run_view()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("`blocked`", result.stdout)
        self.assertIn("`rollback-evidence`", result.stdout)
        self.assertIn("installation_attestation`: `failed`", result.stdout)
        self.assertIn("Workflow run and uploaded artifact", result.stdout)

    def test_shadow_observations_are_visible_but_non_authoritative(self) -> None:
        self.write_status("ready_for_operator_plan")
        shadow = {
            "schema": "openclaw.safe_update.impact_shadow.v1",
            "status": "success",
            "would_block": True,
            "would_add_checks": [{"id": "shadow:check"}],
            "would_flag_risks": [{"id": "shadow:risk:one"}],
            "unmapped_members": [{"member": "dist/example.js"}],
            "unmapped_packages": ["example"],
        }
        (self.artifacts / "impact-shadow.json").write_text(
            json.dumps(shadow),
            encoding="utf-8",
        )
        result = self.run_view()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Shadow observations (non-authoritative)", result.stdout)
        self.assertIn("Would block: `true`", result.stdout)
        self.assertIn("Risk: `shadow:risk:one`", result.stdout)
        self.assertIn("Canonical status:** `ready_for_operator_plan`", result.stdout)

    def test_missing_or_tampered_status_fails_closed(self) -> None:
        missing = self.run_view()
        self.assertEqual(missing.returncode, 2)
        self.write_status("ready_for_operator_plan")
        value = json.loads((self.artifacts / "verdict.json").read_text())
        value["production_apply_allowed"] = True
        (self.artifacts / "verdict.json").write_text(json.dumps(value))
        tampered = self.run_view()
        self.assertEqual(tampered.returncode, 2)

    def test_malformed_optional_shadow_does_not_hide_canonical_status(self) -> None:
        self.write_status("ready_for_operator_plan")
        (self.artifacts / "impact-shadow.json").write_text(
            '{"schema":"wrong"}',
            encoding="utf-8",
        )
        result = self.run_view()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("`invalid`; canonical status is unchanged", result.stdout)
        self.assertIn("Canonical status:** `ready_for_operator_plan`", result.stdout)

    def test_workflow_uploads_blocked_evidence_before_enforcing_status(self) -> None:
        workflow = (
            ROOT / "assets" / "github-workflows" / "openclaw-safe-update.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("artifacts/installation-contract.json", workflow)
        self.assertIn("artifacts/safe-update/operator-view.md", workflow)
        self.assertIn("artifacts/safe-update/analysis-cache.json", workflow)
        self.assertIn("artifacts/safe-update/impact-shadow.json", workflow)
        self.assertIn("artifacts/advisory-*.json", workflow)
        self.assertIn("artifacts/benchmark/*.json", workflow)
        self.assertIn("references/shadow-runs-index.json", workflow)
        self.assertIn("$GITHUB_STEP_SUMMARY", workflow)
        self.assertLess(
            workflow.index("Upload fail-closed evidence"),
            workflow.index("Enforce rehearsal verdict"),
        )
        for banned in (
            "openclaw update",
            "systemctl restart",
            "npm install -g",
            "pull_request_comment",
            "issues: write",
            "contents: write",
        ):
            self.assertNotIn(banned, workflow)

    def test_v13_progress_exposes_bounded_completion_without_enabling_selection(self) -> None:
        self.write_status("ready_for_operator_plan")
        result = self.run_view_with_index()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Exit decision: `retain_additive_baseline`", result.stdout)
        self.assertIn("Fixture threshold: `100%`", result.stdout)
        self.assertIn("Field rehearsal threshold: `0%`", result.stdout)
        self.assertIn("Candidate-root threshold: `0%`", result.stdout)
        self.assertIn("Selective omission enabled: `false`", result.stdout)


if __name__ == "__main__":
    unittest.main()
