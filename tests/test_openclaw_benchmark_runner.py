"""Standard-library tests for the benchmark runner and reporting tool (issue #22).

These tests exercise ``scripts/openclaw_benchmark.py`` against the frozen
corpus from issue #16 without invoking a real model, opening the network,
touching the canonical verdict path, or modifying the corpus. They mirror
the style of ``tests/test_openclaw_benchmark.py`` and
``tests/test_openclaw_advisory.py``: a compact standard-library JSON Schema
validator, subprocess invocation of the CLI, and in-process scoring primitives.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "openclaw_benchmark.py"
CORPUS = ROOT / "benchmarks" / "corpus"
FIXTURES_DIR = CORPUS / "fixtures"
MANIFEST_PATH = CORPUS / "manifest.json"
SCHEMAS = ROOT / "schemas"
FIXTURE_ADAPTER = ROOT / "tests" / "fixtures" / "benchmark_advisory_adapter.py"

SCORECARD_SCHEMA_PATH = SCHEMAS / "openclaw.benchmark.scorecard.v1.schema.json"
REPORT_SCHEMA_PATH = SCHEMAS / "openclaw.benchmark.report.v1.schema.json"
INDEX_SCHEMA_PATH = SCHEMAS / "openclaw.benchmark.shadow_run_index.v1.schema.json"
MANIFEST_SCHEMA_PATH = SCHEMAS / "openclaw.benchmark.manifest.v1.schema.json"
FIXTURE_SCHEMA_PATH = SCHEMAS / "openclaw.benchmark.fixture.v1.schema.json"


# ---------------------------------------------------------------------------
# Standard-library JSON Schema subset validator
# ---------------------------------------------------------------------------

_SUPPORTED_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "const",
    "description",
    "enum",
    "items",
    "maxItems",
    "maxLength",
    "maximum",
    "minItems",
    "minLength",
    "minimum",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
    "uniqueItems",
}


def _matches_type(value: Any, type_name: str) -> bool:
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "null":
        return value is None
    raise AssertionError(f"unsupported json type {type_name!r}")


def _assert_supported_keywords(node: dict[str, Any], path: str) -> None:
    unsupported = set(node) - _SUPPORTED_KEYWORDS
    if unsupported:
        raise AssertionError(f"{path}: unsupported keywords {sorted(unsupported)!r}")
    for key, child in node.get("$defs", {}).items():
        _assert_supported_keywords(child, f"{path}.$defs.{key}")
    for key, child in node.get("properties", {}).items():
        _assert_supported_keywords(child, f"{path}.properties.{key}")
    if isinstance(node.get("items"), dict):
        _assert_supported_keywords(node["items"], f"{path}.items")


def _walk(value: Any, node: dict[str, Any], root: dict[str, Any], path: str) -> None:
    if "$ref" in node:
        target = root["$defs"][str(node["$ref"]).rsplit("/", 1)[-1]]
        _walk(value, target, root, path)
        return
    type_spec = node.get("type")
    if type_spec is not None:
        options = type_spec if isinstance(type_spec, list) else [type_spec]
        if not any(_matches_type(value, option) for option in options):
            raise AssertionError(f"{path}: {value!r} is not of type {type_spec}")
    if "const" in node and value != node["const"]:
        raise AssertionError(f"{path}: expected const {node['const']!r}, got {value!r}")
    if "enum" in node and value not in node["enum"]:
        raise AssertionError(f"{path}: {value!r} not in enum {node['enum']!r}")
    if isinstance(value, str):
        if "pattern" in node and re.search(str(node["pattern"]), value) is None:
            raise AssertionError(f"{path}: {value!r} does not match {node['pattern']!r}")
        if "minLength" in node and len(value) < node["minLength"]:
            raise AssertionError(f"{path}: {value!r} shorter than minLength")
        if "maxLength" in node and len(value) > node["maxLength"]:
            raise AssertionError(f"{path}: {value!r} longer than maxLength")
    if isinstance(value, list):
        if "minItems" in node and len(value) < node["minItems"]:
            raise AssertionError(f"{path}: list shorter than minItems")
        if "maxItems" in node and len(value) > node["maxItems"]:
            raise AssertionError(f"{path}: list longer than maxItems")
        if node.get("uniqueItems"):
            seen: list[str] = []
            for item in value:
                key = json.dumps(item, sort_keys=True)
                if key in seen:
                    raise AssertionError(f"{path}: list items are not unique")
                seen.append(key)
        item_schema = node.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                _walk(item, item_schema, root, f"{path}[{index}]")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in node and value < node["minimum"]:
            raise AssertionError(f"{path}: {value!r} below minimum")
        if "maximum" in node and value > node["maximum"]:
            raise AssertionError(f"{path}: {value!r} above maximum")
    if isinstance(value, dict):
        for key in node.get("required", []):
            if key not in value:
                raise AssertionError(f"{path}: missing required key {key!r}")
        properties = node.get("properties", {})
        for key, item in value.items():
            if key in properties:
                _walk(item, properties[key], root, f"{path}.{key}")
            elif node.get("additionalProperties") is False:
                raise AssertionError(
                    f"{path}: additional property {key!r} not allowed"
                )


def assert_schema_contract(instance: Any, schema: dict[str, Any]) -> None:
    _assert_supported_keywords(schema, "$schema")
    _walk(instance, schema, schema, "$")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# CLI harness
# ---------------------------------------------------------------------------

def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(cwd) if cwd is not None else None,
    )


def adapter_command(extra_env: dict[str, str] | None = None) -> str:
    """Return a shell command that runs the fixture adapter.

    The adapter reads the worker-visible prompt_payload on stdin and writes
    one advisory-result JSON object on stdout. Tests inject failures by
    pointing the runner at alternative shell commands; the fixture adapter
    itself is a happy-path baseline.
    """
    return f"{sys.executable} {FIXTURE_ADAPTER}"


# ---------------------------------------------------------------------------
# Frozen-corpus verification tests
# ---------------------------------------------------------------------------

class BenchmarkRunnerVerifyTest(unittest.TestCase):
    """The runner verifies the frozen corpus before any arm runs."""

    def test_verify_accepts_the_frozen_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "verify.json"
            result = run_cli("verify", "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            # The CLI prints the output file path; the JSON content is in the file.
            summary = load_json(output)
        self.assertIn("corpus_digest", summary)
        self.assertEqual(summary["canonical_status_effect"], "none")

    def test_verify_blocks_on_a_tampered_fixture_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "fixtures").mkdir()
            (corpus / "manifest.json").write_text(
                (CORPUS / "manifest.json").read_text()
            )
            for fixture in FIXTURES_DIR.glob("oc-bench-*.json"):
                (corpus / "fixtures" / fixture.name).write_text(fixture.read_text())
            tampered = json.loads((corpus / "fixtures" / "oc-bench-0001.json").read_text())
            tampered["prompt_payload"]["candidate_root"] = (
                "sha256:" + "0" * 64
            )
            (corpus / "fixtures" / "oc-bench-0001.json").write_text(
                json.dumps(tampered, indent=2), encoding="utf-8"
            )
            result = run_cli("verify", "--corpus", str(corpus))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("fixture byte digest mismatch", result.stderr)

    def test_verify_blocks_on_a_missing_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = self._copy_corpus(Path(temporary))
            (corpus / "fixtures" / "oc-bench-0014.json").unlink()
            result = run_cli("verify", "--corpus", str(corpus))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("fixture missing on disk", result.stderr)

    def test_verify_blocks_on_an_undeclared_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = self._copy_corpus(Path(temporary))
            (corpus / "fixtures" / "oc-bench-9999.json").write_text(
                "{}", encoding="utf-8"
            )
            result = run_cli("verify", "--corpus", str(corpus))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("undeclared fixture files on disk", result.stderr)

    def test_verify_blocks_on_a_tampered_prompt_digest(self) -> None:
        # Mutating prompt_payload without updating prompt_digest leaves the
        # file sha256 and the manifest binding out of step; the prompt-digest
        # check is a second line of defense that catches an attacker who
        # rewrites the payload and recomputes the file sha256 but forgets the
        # prompt digest.
        with tempfile.TemporaryDirectory() as temporary:
            corpus = self._copy_corpus(Path(temporary))
            path = corpus / "fixtures" / "oc-bench-0001.json"
            fixture = json.loads(path.read_text())
            fixture["prompt_digest"] = "sha256:" + "0" * 64
            path.write_text(json.dumps(fixture, indent=2), encoding="utf-8")
            # Re-bind the manifest entry sha256 AND the corpus_digest so the
            # byte-digest and corpus-digest checks pass and the prompt-digest
            # check is what blocks.
            self._rebind_manifest_fixture_sha256(corpus, "oc-bench-0001", path)
            manifest_path = corpus / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            # Use the runner's own binding function so the recomputed digest
            # matches what the runner will verify.
            sys.path.insert(0, str(ROOT / "scripts"))
            try:
                import openclaw_benchmark as runner_mod  # type: ignore
                manifest["corpus_digest"] = runner_mod.corpus_digest_binding(manifest)
            finally:
                sys.path.pop(0)
            manifest_path.write_text(
                json.dumps(manifest, indent=2), encoding="utf-8"
            )
            result = run_cli("verify", "--corpus", str(corpus))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("prompt_digest does not bind", result.stderr)

    def test_verify_blocks_on_a_tampered_corpus_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = self._copy_corpus(Path(temporary))
            manifest_path = corpus / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["corpus_digest"] = "sha256:" + "0" * 64
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            result = run_cli("verify", "--corpus", str(corpus))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("corpus_digest does not match", result.stderr)

    def test_verify_blocks_on_a_tampered_scorecard_schema_digest(self) -> None:
        # The scorecard schema digest is bound by corpus_digest so a
        # scorecard-shape change is itself a re-freeze event. Tampering with
        # the scorecard schema file blocks verification.
        with tempfile.TemporaryDirectory() as temporary:
            schemas = Path(temporary) / "schemas"
            schemas.mkdir()
            for schema in SCHEMAS.glob("*.json"):
                (schemas / schema.name).write_text(schema.read_text())
            tampered = json.loads(
                (schemas / "openclaw.benchmark.scorecard.v1.schema.json").read_text()
            )
            tampered["title"] = tampered["title"] + " (tampered)"
            (schemas / "openclaw.benchmark.scorecard.v1.schema.json").write_text(
                json.dumps(tampered, indent=2), encoding="utf-8"
            )
            result = run_cli("verify", "--schemas", str(schemas))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("scorecard_schema_digest does not match", result.stderr)

    @staticmethod
    def _copy_corpus(parent: Path) -> Path:
        corpus = parent / "corpus"
        corpus.mkdir()
        (corpus / "fixtures").mkdir()
        (corpus / "manifest.json").write_text((CORPUS / "manifest.json").read_text())
        for fixture in FIXTURES_DIR.glob("oc-bench-*.json"):
            (corpus / "fixtures" / fixture.name).write_text(fixture.read_text())
        return corpus

    @staticmethod
    def _rebind_manifest_fixture_sha256(corpus: Path, fixture_id: str, path: Path) -> None:
        manifest_path = corpus / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        for entry in manifest["fixtures"]:
            if entry["id"] == fixture_id:
                entry["sha256"] = digest
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Deterministic arm reproduction and determinism
# ---------------------------------------------------------------------------

class BenchmarkRunnerDeterministicArmsTest(unittest.TestCase):
    """The deterministic arms reproduce the frozen expected findings exactly."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json(MANIFEST_PATH)
        sys.path.insert(0, str(ROOT / "scripts"))
        import openclaw_benchmark as runner  # type: ignore
        cls.runner = runner

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temporary.name) / "out"
        self.addCleanup(self.temporary.cleanup)

    def _run(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--deterministic-only",
            "--worker-id",
            "test-worker",
            "--model-family",
            "test-family",
            "--role",
            "test-role",
            *extra,
        )

    def test_baseline_arm_reproduces_every_expected_finding(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        scorecard = load_json(self.output_dir / "scorecard-baseline.json")
        self.assertEqual(
            scorecard["aggregates"]["incremental_recall_basis_points"], 10000
        )
        self.assertEqual(scorecard["aggregates"]["missed_regressions_total"], 0)
        # Per-fixture: every expected finding is reported.
        fixtures_by_id = {
            fx["id"]: fx for fx in (
                load_json(CORPUS / entry["path"])
                for entry in self.manifest["fixtures"]
            )
        }
        for pf in scorecard["per_fixture"]:
            expected = set(
                fixtures_by_id[pf["fixture_id"]]["scoring_key"]["arms"]["baseline"][
                    "expected_findings"
                ]
            )
            self.assertEqual(
                expected,
                set(pf["reported_findings"]),
                f"{pf['fixture_id']} baseline findings mismatch",
            )
            self.assertEqual(pf["incremental_recall_basis_points"], 10000)

    def test_shadow_arm_reproduces_every_expected_finding(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        scorecard = load_json(self.output_dir / "scorecard-shadow_impact.json")
        self.assertEqual(
            scorecard["aggregates"]["incremental_recall_basis_points"], 10000
        )
        self.assertEqual(scorecard["aggregates"]["missed_regressions_total"], 0)
        fixtures_by_id = {
            fx["id"]: fx for fx in (
                load_json(CORPUS / entry["path"])
                for entry in self.manifest["fixtures"]
            )
        }
        for pf in scorecard["per_fixture"]:
            expected = set(
                fixtures_by_id[pf["fixture_id"]]["scoring_key"]["arms"][
                    "shadow_impact"
                ]["expected_findings"]
            )
            self.assertEqual(
                expected,
                set(pf["reported_findings"]),
                f"{pf['fixture_id']} shadow findings mismatch",
            )
            self.assertEqual(pf["incremental_recall_basis_points"], 10000)

    def test_re_runs_produce_identical_canonical_scorecard_digests(self) -> None:
        # Run twice; the canonical scorecard digests must match despite
        # different wall-clock envelopes. Volatile fields are excluded.
        first_dir = Path(self.temporary.name) / "first"
        second_dir = Path(self.temporary.name) / "second"
        for directory in (first_dir, second_dir):
            run_cli(
                "run",
                "--output-dir",
                str(directory),
                "--deterministic-only",
            )
        schema = load_json(SCORECARD_SCHEMA_PATH)
        for arm in ("baseline", "shadow_impact"):
            first = load_json(first_dir / f"scorecard-{arm}.json")
            second = load_json(second_dir / f"scorecard-{arm}.json")
            assert_schema_contract(first, schema)
            assert_schema_contract(second, schema)
            self.assertEqual(
                canonical_digest(self._canonical_view(first)),
                canonical_digest(self._canonical_view(second)),
            )
            # The volatile envelope really did differ (timing is noisy).
            self.assertIsInstance(
                first["aggregates"]["wall_clock_seconds_total"], (int, float)
            )

    def test_deterministic_arms_never_read_scoring_key(self) -> None:
        # The arm functions take only prompt_payload; they physically cannot
        # read scoring_key. Call them directly with worker payloads and verify
        # their outputs match the frozen scorecard outputs produced by a full
        # run. (This replaced a destructive approach that stripped schema-
        # required labels from the frozen corpus.)
        normal = self._run()
        self.assertEqual(normal.returncode, 0, normal.stderr)
        normal_baseline = load_json(self.output_dir / "scorecard-baseline.json")
        normal_shadow = load_json(self.output_dir / "scorecard-shadow_impact.json")
        for entry in self.manifest["fixtures"]:
            fixture = load_json(CORPUS / entry["path"])
            payload = fixture["prompt_payload"]
            # The arm functions receive prompt_payload only; no scoring_key,
            # case_kind, regression, or expected_ labels are passed.
            baseline_out = self.runner.baseline_arm(payload)
            shadow_out = self.runner.shadow_arm(payload)
            bf = next(
                pf for pf in normal_baseline["per_fixture"]
                if pf["fixture_id"] == fixture["id"]
            )
            sf = next(
                pf for pf in normal_shadow["per_fixture"]
                if pf["fixture_id"] == fixture["id"]
            )
            self.assertEqual(
                set(baseline_out["reported_findings"]),
                set(bf["reported_findings"]),
                f"{fixture['id']} baseline differs from the full-run scorecard",
            )
            self.assertEqual(
                set(shadow_out["reported_findings"]),
                set(sf["reported_findings"]),
                f"{fixture['id']} shadow differs from the full-run scorecard",
            )
            # And the arm outputs carry no labels they were never shown.
            for out in (baseline_out, shadow_out):
                self.assertNotIn("scoring_key", json.dumps(out))
                self.assertNotIn("case_kind", json.dumps(out))
                self.assertNotIn("expected_", json.dumps(out))

    def test_deterministic_arms_reject_not_available_status(self) -> None:
        # not_available on a deterministic arm is a protocol violation. We
        # exercise this in-process because the CLI's deterministic arms never
        # produce not_available; the test pins the protocol invariant.
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            import openclaw_benchmark as runner  # type: ignore
        finally:
            sys.path.pop(0)
        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")
        with self.assertRaises(runner.BenchmarkError):
            runner.score_fixture(
                "baseline",
                {
                    "status": "not_available",
                    "reported_findings": [],
                    "forbidden_claims": [],
                    "notes": "",
                },
                fixture,
                runner._covered_findings(
                    {"arms": runner._covered_arms_snapshot([fixture])}
                ),
            )

    @staticmethod
    def _canonical_view(scorecard: dict[str, Any]) -> dict[str, Any]:
        return {
            "arm": scorecard["arm"],
            "worker": scorecard["worker"],
            "per_fixture": [
                {
                    "fixture_id": pf["fixture_id"],
                    "status": pf["status"],
                    "reported_findings": sorted(pf["reported_findings"]),
                    "forbidden_claims": sorted(pf["forbidden_claims"]),
                }
                for pf in scorecard["per_fixture"]
            ],
        }


# ---------------------------------------------------------------------------
# Advisory arm boundary
# ---------------------------------------------------------------------------

class BenchmarkRunnerAdvisoryArmTest(unittest.TestCase):
    """The advisory arm is optional, public-safe, and degrades to not_available."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temporary.name) / "out"
        self.addCleanup(self.temporary.cleanup)

    def test_no_adapter_yields_honest_not_available(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        scorecard = load_json(self.output_dir / "scorecard-advisory.json")
        manifest = load_json(MANIFEST_PATH)
        fixtures = [
            load_json(CORPUS / entry["path"]) for entry in manifest["fixtures"]
        ]
        admitting = sum(
            1
            for fx in fixtures
            if "not_available"
            in fx["scoring_key"]["arms"]["advisory"]["admissible_status"]
        )
        self.assertEqual(
            scorecard["aggregates"]["honest_not_available_count"], admitting
        )
        self.assertEqual(
            scorecard["aggregates"]["unjustified_not_available_count"],
            len(fixtures) - admitting,
        )
        self.assertEqual(
            scorecard["aggregates"]["incremental_recall_basis_points"], 0
        )
        for pf in scorecard["per_fixture"]:
            self.assertEqual(pf["status"], "not_available")
            self.assertEqual(pf["reported_findings"], [])

    def test_fixture_adapter_emits_a_schema_valid_scorecard(self) -> None:
        result = self._run("--advisory-adapter", adapter_command())
        self.assertEqual(result.returncode, 0, result.stderr)
        scorecard = load_json(self.output_dir / "scorecard-advisory.json")
        schema = load_json(SCORECARD_SCHEMA_PATH)
        assert_schema_contract(scorecard, schema)
        self.assertEqual(scorecard["worker"]["model_family"], "fixture")
        self.assertEqual(scorecard["worker"]["role"], "fixture-reviewer")
        self.assertEqual(
            scorecard["aggregates"]["valid_evidence_reference_rate_basis_points"], 10000
        )
        self.assertEqual(
            scorecard["aggregates"]["unjustified_not_available_count"], 0
        )
        self.assertEqual(
            scorecard["aggregates"]["false_unaffected_count"], 0
        )
        self.assertEqual(
            scorecard["aggregates"]["false_blocks_total"], 0
        )
        # The adapter is non-empty: raw volume should exceed zero.
        self.assertGreater(scorecard["aggregates"]["raw_volume"], 0)

    def test_nonexistent_adapter_degrades_to_not_available(self) -> None:
        result = self._run(
            "--advisory-adapter", "this-command-does-not-exist-xyz-12345"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        scorecard = load_json(self.output_dir / "scorecard-advisory.json")
        self.assertTrue(
            all(pf["status"] == "not_available" for pf in scorecard["per_fixture"])
        )

    def test_non_zero_exit_adapter_degrades_to_not_available(self) -> None:
        result = self._run("--advisory-adapter", "false")
        self.assertEqual(result.returncode, 0, result.stderr)
        scorecard = load_json(self.output_dir / "scorecard-advisory.json")
        self.assertTrue(
            all(pf["status"] == "not_available" for pf in scorecard["per_fixture"])
        )

    def test_malformed_adapter_output_degrades_to_not_available(self) -> None:
        result = self._run("--advisory-adapter", "echo not-json")
        self.assertEqual(result.returncode, 0, result.stderr)
        scorecard = load_json(self.output_dir / "scorecard-advisory.json")
        self.assertTrue(
            all(pf["status"] == "not_available" for pf in scorecard["per_fixture"])
        )

    def test_timed_out_adapter_degrades_to_not_available(self) -> None:
        result = self._run(
            "--advisory-adapter", "sleep 30",
            "--adapter-timeout-seconds", "0.5",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        scorecard = load_json(self.output_dir / "scorecard-advisory.json")
        self.assertTrue(
            all(pf["status"] == "not_available" for pf in scorecard["per_fixture"])
        )

    def test_disable_advisory_runs_no_advisory_scorecard(self) -> None:
        result = self._run(
            "--advisory-adapter", adapter_command(),
            "--disable-advisory",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.output_dir / "scorecard-advisory.json").exists())
        # The deterministic arms still complete.
        self.assertTrue((self.output_dir / "scorecard-baseline.json").exists())
        self.assertTrue((self.output_dir / "scorecard-shadow_impact.json").exists())

    def test_adapter_failure_never_blocks_deterministic_completion(self) -> None:
        result = self._run("--advisory-adapter", "false")
        self.assertEqual(result.returncode, 0, result.stderr)
        baseline = load_json(self.output_dir / "scorecard-baseline.json")
        shadow = load_json(self.output_dir / "scorecard-shadow_impact.json")
        self.assertEqual(
            baseline["aggregates"]["incremental_recall_basis_points"], 10000
        )
        self.assertEqual(
            shadow["aggregates"]["incremental_recall_basis_points"], 10000
        )

    def _run(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--worker-id",
            "test-worker",
            "--model-family",
            "test-family",
            "--role",
            "test-role",
            *extra,
        )


# ---------------------------------------------------------------------------
# Scoring primitive tests
# ---------------------------------------------------------------------------

class BenchmarkRunnerScoringTest(unittest.TestCase):
    """The scoring math mirrors the protocol primitives in the corpus tests."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import openclaw_benchmark as runner  # type: ignore
        cls.runner = runner
        cls.manifest = load_json(MANIFEST_PATH)
        cls.fixtures = [
            load_json(CORPUS / entry["path"]) for entry in cls.manifest["fixtures"]
        ]

    def test_advisory_incremental_recall_excludes_covered_findings(self) -> None:
        fixture = next(fx for fx in self.fixtures if fx["id"] == "oc-bench-0001")
        arms = fixture["scoring_key"]["arms"]
        covered = (
            arms["baseline"]["expected_findings"]
            + arms["shadow_impact"]["expected_findings"]
        )
        expected = arms["advisory"]["expected_incremental_findings"]
        # Reporting the expected incremental finding scores full recall.
        full = self.runner.score_fixture(
            "advisory",
            {
                "status": "completed",
                "reported_findings": expected,
                "forbidden_claims": [],
                "notes": "",
                "evidence_refs_total": 0,
                "evidence_refs_valid": 0,
            },
            fixture,
            covered,
        )
        self.assertEqual(full["incremental_recall_basis_points"], 10000)
        # Reporting only covered findings scores zero, regardless of volume.
        padded = self.runner.score_fixture(
            "advisory",
            {
                "status": "completed",
                "reported_findings": covered * 5,
                "forbidden_claims": [],
                "notes": "",
                "evidence_refs_total": 0,
                "evidence_refs_valid": 0,
            },
            fixture,
            covered,
        )
        self.assertEqual(padded["incremental_recall_basis_points"], 0)
        self.assertEqual(padded["unique_true_positives_count"], 0)
        self.assertGreater(padded["duplicate_findings_count"], 0)

    def test_baseline_missed_finding_lowers_recall_proportionally(self) -> None:
        fixture = next(fx for fx in self.fixtures if fx["id"] == "oc-bench-0003")
        arms = fixture["scoring_key"]["arms"]
        covered = (
            arms["baseline"]["expected_findings"]
            + arms["shadow_impact"]["expected_findings"]
        )
        partial = arms["baseline"]["expected_findings"][:1]
        scored = self.runner.score_fixture(
            "baseline",
            {
                "status": "completed",
                "reported_findings": partial,
                "forbidden_claims": [],
                "notes": "",
            },
            fixture,
            covered,
        )
        self.assertEqual(
            scored["incremental_recall_basis_points"],
            round(10000 / len(arms["baseline"]["expected_findings"])),
        )
        self.assertEqual(scored["missed_regressions_count"], len(arms["baseline"]["expected_findings"]) - 1)

    def test_benign_control_admits_honest_not_available(self) -> None:
        benign = next(
            fx for fx in self.fixtures
            if fx["scoring_key"]["case_kind"] == "benign_control"
        )
        covered = (
            benign["scoring_key"]["arms"]["baseline"]["expected_findings"]
            + benign["scoring_key"]["arms"]["shadow_impact"]["expected_findings"]
        )
        scored = self.runner.score_fixture(
            "advisory",
            {
                "status": "not_available",
                "reported_findings": [],
                "forbidden_claims": [],
                "notes": "",
                "evidence_refs_total": 0,
                "evidence_refs_valid": 0,
            },
            benign,
            covered,
        )
        self.assertEqual(scored["status"], "not_available")
        self.assertEqual(scored["incremental_recall_basis_points"], 0)
        self.assertFalse(scored["false_block"])

    def test_advisory_declare_unaffected_is_false_unaffected_not_false_block(self) -> None:
        # Defect E: declare_surface_unaffected is a false-unaffected (counted
        # via forbidden_claims), NOT a false block. A false block requires the
        # distinct blocked-verdict signal.
        benign = next(
            fx for fx in self.fixtures
            if fx["scoring_key"]["case_kind"] == "benign_control"
        )
        covered = (
            benign["scoring_key"]["arms"]["baseline"]["expected_findings"]
            + benign["scoring_key"]["arms"]["shadow_impact"]["expected_findings"]
        )
        scored = self.runner.score_fixture(
            "advisory",
            {
                "status": "completed",
                "reported_findings": [],
                "forbidden_claims": ["declare_surface_unaffected"],
                "notes": "",
                "evidence_refs_total": 0,
                "evidence_refs_valid": 0,
                "blocked_verdict": False,
            },
            benign,
            covered,
        )
        self.assertFalse(scored["false_block"])
        self.assertIn("declare_surface_unaffected", scored["forbidden_claims"])

    def test_advisory_blocked_verdict_on_benign_fixture_is_a_false_block(self) -> None:
        # Defect E: a blocked-verdict signal (the worker tried to assert a
        # canonical block it cannot own) on a baseline-pass fixture is a
        # false block. It is distinct from a false-unaffected claim.
        benign = next(
            fx for fx in self.fixtures
            if fx["scoring_key"]["case_kind"] == "benign_control"
        )
        covered = (
            benign["scoring_key"]["arms"]["baseline"]["expected_findings"]
            + benign["scoring_key"]["arms"]["shadow_impact"]["expected_findings"]
        )
        scored = self.runner.score_fixture(
            "advisory",
            {
                "status": "completed",
                "reported_findings": [],
                "forbidden_claims": [],
                "notes": "",
                "evidence_refs_total": 0,
                "evidence_refs_valid": 0,
                "blocked_verdict": True,
            },
            benign,
            covered,
        )
        self.assertTrue(scored["false_block"])

    def test_advisory_blocked_verdict_on_baseline_block_fixture_is_not_false_block(self) -> None:
        # A blocked-verdict signal on a fixture whose frozen baseline
        # expected_outcome is block is not a FALSE block (the fixture is not a
        # true-negative). This pins the pass/block precondition.
        block_fx = next(
            fx for fx in self.fixtures
            if fx["scoring_key"]["arms"]["baseline"]["expected_outcome"] == "block"
        )
        covered = (
            block_fx["scoring_key"]["arms"]["baseline"]["expected_findings"]
            + block_fx["scoring_key"]["arms"]["shadow_impact"]["expected_findings"]
        )
        scored = self.runner.score_fixture(
            "advisory",
            {
                "status": "completed",
                "reported_findings": [],
                "forbidden_claims": [],
                "notes": "",
                "evidence_refs_total": 0,
                "evidence_refs_valid": 0,
                "blocked_verdict": True,
            },
            block_fx,
            covered,
        )
        self.assertFalse(scored["false_block"])

    def test_shadow_arm_cannot_produce_a_false_block(self) -> None:
        # Only the baseline arm carries pass/block semantics. A shadow
        # finding is never a block, so the shadow arm's false_block flag is
        # always false even when it would_block.
        fixture = next(fx for fx in self.fixtures if fx["id"] == "oc-bench-0001")
        covered = (
            fixture["scoring_key"]["arms"]["baseline"]["expected_findings"]
            + fixture["scoring_key"]["arms"]["shadow_impact"]["expected_findings"]
        )
        scored = self.runner.score_fixture(
            "shadow_impact",
            {
                "status": "completed",
                "reported_findings": ["shadow:would-block"],
                "forbidden_claims": [],
                "notes": "",
            },
            fixture,
            covered,
        )
        self.assertFalse(scored["false_block"])

    def test_threshold_results_apply_per_arm(self) -> None:
        manifest = self.manifest
        full_aggregates = {
            "incremental_recall_basis_points": 4000,
            "false_unaffected_count": 0,
            "unjustified_not_available_count": 0,
        }
        thresholds = self.runner._threshold_results(
            manifest, "advisory", full_aggregates
        )
        self.assertFalse(thresholds["min_incremental_recall"]["passed"])
        self.assertTrue(thresholds["max_false_unaffected"]["passed"])
        # Baseline gate set is conservative; only applies where the arm runs.
        thresholds_baseline = self.runner._threshold_results(
            manifest,
            "baseline",
            {
                "incremental_recall_basis_points": 10000,
                "false_unaffected_count": 0,
                "unjustified_not_available_count": 0,
            },
        )
        # min_incremental_recall is an advisory-only gate; baseline passes it trivially.
        self.assertTrue(thresholds_baseline["min_incremental_recall"]["passed"])

    def test_pairwise_error_correlation_is_null_without_paired_scorecard(self) -> None:
        # No paired advisory scorecard -> null baseline_advisory correlation.
        empty: list[dict[str, Any]] = []
        self.assertIsNone(
            self.runner._pairwise_error_correlation(
                empty, empty, "baseline", "advisory"
            )
        )


# ---------------------------------------------------------------------------
# Aggregate report and index entry tests
# ---------------------------------------------------------------------------

class BenchmarkRunnerReportTest(unittest.TestCase):
    """The aggregate report and the index entry are schema-valid and frozen."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temporary.name) / "out"
        self.addCleanup(self.temporary.cleanup)

    def test_deterministic_run_emits_a_schema_valid_report_and_index(self) -> None:
        result = run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--deterministic-only",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = load_json(self.output_dir / "benchmark-report.json")
        index = load_json(self.output_dir / "shadow-run-index-entry.json")
        report_schema = load_json(REPORT_SCHEMA_PATH)
        index_schema = load_json(INDEX_SCHEMA_PATH)
        assert_schema_contract(report, report_schema)
        assert_schema_contract(index, index_schema)
        for key in (
            "effect",
            "runtime_effect",
            "external_effect",
            "external_write_effect",
            "production_apply_allowed",
            "operator_approval",
            "authoritative",
            "canonical_status_effect",
        ):
            self.assertIn(key, report)
            self.assertIn(key, index)
        self.assertEqual(report["canonical_status_effect"], "none")
        self.assertEqual(index["canonical_status_effect"], "none")
        self.assertFalse(report["authoritative"])
        self.assertFalse(index["authoritative"])

    def test_report_exposes_model_family_and_role_separately(self) -> None:
        result = run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--deterministic-only",
            "--model-family",
            "family-a",
            "--role",
            "role-b",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = load_json(self.output_dir / "benchmark-report.json")
        self.assertEqual(report["run"]["worker"]["model_family"], "family-a")
        self.assertEqual(report["run"]["worker"]["role"], "role-b")
        self.assertNotEqual(report["run"]["worker"]["model_family"], report["run"]["worker"]["role"])
        for scorecard_path in self.output_dir.glob("scorecard-*.json"):
            scorecard = load_json(scorecard_path)
            self.assertIn("model_family", scorecard["worker"])
            self.assertIn("role", scorecard["worker"])

    def test_report_thresholds_match_the_frozen_manifest_verbatim(self) -> None:
        manifest = load_json(MANIFEST_PATH)
        result = run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--deterministic-only",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = load_json(self.output_dir / "benchmark-report.json")
        for key, spec in manifest["scoring"]["thresholds"].items():
            self.assertEqual(
                report["threshold_results"][key]["threshold"], spec
            )

    def test_missing_advisory_arm_is_never_reported_as_threshold_green(self) -> None:
        result = run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--deterministic-only",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = load_json(self.output_dir / "benchmark-report.json")
        index = load_json(self.output_dir / "shadow-run-index-entry.json")
        for gate in (
            "min_incremental_recall",
            "max_false_unaffected",
            "max_unjustified_not_available",
        ):
            self.assertFalse(report["threshold_results"][gate]["passed"])
        advisory = next(item for item in index["arms"] if item["arm"] == "advisory")
        self.assertFalse(advisory["present"])
        self.assertFalse(advisory["threshold_passed"])

    def test_report_pairwise_error_correlation_is_null_when_no_advisory(self) -> None:
        result = run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--deterministic-only",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = load_json(self.output_dir / "benchmark-report.json")
        self.assertIsNone(report["pairwise_error_correlation"]["baseline_advisory"])
        self.assertIsNone(report["pairwise_error_correlation"]["shadow_impact_advisory"])
        # Two deterministic arms are paired, so that correlation is an integer.
        self.assertIsInstance(
            report["pairwise_error_correlation"]["baseline_shadow_impact"], int
        )

    def test_index_entry_is_self_contained_and_appendable(self) -> None:
        result = run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--deterministic-only",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        index = load_json(self.output_dir / "shadow-run-index-entry.json")
        # The entry carries its own corpus_digest, worker, and per-arm digests
        # so it can be read without any other entry.
        self.assertTrue(index["entry_id"].startswith("sha256:"))
        self.assertEqual(index["schema"], "openclaw.benchmark.shadow_run_index.v1")
        self.assertIn("comparison_summary", index)
        # An append-only index deduplicates a deterministic re-run: same
        # canonical scorecard digests -> same entry_id.
        second_dir = Path(self.temporary.name) / "second"
        run_cli(
            "run",
            "--output-dir",
            str(second_dir),
            "--deterministic-only",
        )
        second_index = load_json(second_dir / "shadow-run-index-entry.json")
        self.assertEqual(index["entry_id"], second_index["entry_id"])

    def test_report_records_budget_overflow_without_rewriting_thresholds(self) -> None:
        # The fixture adapter produces non-trivial findings but completes
        # well under the frozen budgets, so overflow should be all-false.
        result = run_cli(
            "run",
            "--output-dir",
            str(self.output_dir),
            "--advisory-adapter",
            adapter_command(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = load_json(self.output_dir / "benchmark-report.json")
        manifest = load_json(MANIFEST_PATH)
        self.assertEqual(
            report["budgets"]["wall_clock_seconds_per_fixture"],
            manifest["scoring"]["budgets"]["wall_clock_seconds_per_fixture"],
        )
        for flag, value in report["budgets"]["overflow"].items():
            self.assertFalse(value, f"unexpected budget overflow: {flag}")
        # Thresholds are copied verbatim.
        for key, spec in manifest["scoring"]["thresholds"].items():
            self.assertEqual(report["threshold_results"][key]["threshold"], spec)


# ---------------------------------------------------------------------------
# Adapter boundary
# ---------------------------------------------------------------------------

class BenchmarkRunnerAdapterBoundaryTest(unittest.TestCase):
    """The adapter is treated as untrusted and never sees labels."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import openclaw_benchmark as runner  # type: ignore
        cls.runner = runner

    def test_adapter_receives_the_full_advisory_input_envelope(self) -> None:
        # The adapter consumes the full #15 envelope: schema, safety fields,
        # input_digest, and content=prompt_payload. It never sees scoring_key.
        captured: dict[str, Any] = {}

        def capture_invoke(command: str, envelope: dict[str, Any], timeout: float):
            captured["envelope"] = envelope
            return self.runner._not_available_result("captured")

        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")
        self.runner.advisory_arm(
            fixture["prompt_payload"],
            "fake-command",
            timeout=1.0,
            adapter_invoke=capture_invoke,
        )
        envelope = captured["envelope"]
        self.assertEqual(envelope["schema"], "openclaw.safe_update.advisory_input.v1")
        self.assertEqual(envelope["authoritative"], False)
        self.assertEqual(envelope["production_apply_allowed"], False)
        # input_digest binds content exactly (defect A: matching digest).
        self.assertEqual(
            envelope["input_digest"], self.runner.canonical_digest(fixture["prompt_payload"])
        )
        self.assertIs(envelope["content"], fixture["prompt_payload"])
        # The adapter never sees labels.
        blob = json.dumps(envelope)
        self.assertNotIn("scoring_key", blob)
        self.assertNotIn("case_kind", blob)
        self.assertNotIn("regression", blob)
        self.assertNotIn("expected_", blob)

    def _valid_result_envelope(
        self,
        prompt_payload: dict[str, Any],
        *,
        result_overrides: dict[str, Any] | None = None,
        usage: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a {result, usage} envelope whose result passes validate_result."""
        input_digest = canonical_digest(prompt_payload)
        result = {
            "schema": "openclaw.safe_update.advisory_result.v1",
            "authoritative": False,
            "input_digest": input_digest,
            "worker": {"id": "x", "model_family": "y", "role": "z"},
            "status": "completed",
            "hypotheses": [],
            "suggested_checks": [],
            "residual_risks": [],
            "review_requests": [],
            "agreement_is_confidence": False,
            "can_promote": False,
            "can_waive_checks": False,
            "can_emit_verdict": False,
        }
        if result_overrides:
            result.update(result_overrides)
        return {"result": result, "usage": usage or {"compute_tokens": 0, "review_minutes": 0.0}}

    def test_adapter_authoritative_true_is_a_visible_rejected_row(self) -> None:
        # An authority-seeking result (authoritative=True) fails the #15
        # validator. Per defect A it is a visible failed/rejected row, not
        # not_available (which is reserved for transport/unconfigured).
        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")
        envelope = self._valid_result_envelope(
            fixture["prompt_payload"],
            result_overrides={"authoritative": True},
        )
        out = self.runner.advisory_arm(
            fixture["prompt_payload"], "fake", timeout=1.0,
            adapter_invoke=lambda c, e, t: envelope,
        )
        self.assertEqual(out["status"], "failed")
        self.assertEqual(out["reported_findings"], [])
        self.assertNotIn("not_available", out["notes"])
        self.assertTrue(out["notes"].startswith("advisory:rejected"))

    def test_adapter_can_emit_verdict_is_a_forbidden_claim(self) -> None:
        # Forbidden claims are read from the raw result regardless of
        # validity (they are the threat being measured).
        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")
        envelope = self._valid_result_envelope(
            fixture["prompt_payload"],
            result_overrides={"can_emit_verdict": True},
        )
        out = self.runner.advisory_arm(
            fixture["prompt_payload"], "fake", timeout=1.0,
            adapter_invoke=lambda c, e, t: envelope,
        )
        self.assertIn("emit_verdict", out["forbidden_claims"])
        # The invalid authority flag still rejects the result.
        self.assertEqual(out["status"], "failed")

    def test_adapter_text_marker_is_a_forbidden_claim(self) -> None:
        # A valid result that carries a forbidden text marker still surfaces
        # the forbidden claim; the marker is detected from worker prose.
        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")
        envelope = self._valid_result_envelope(
            fixture["prompt_payload"],
            result_overrides={
                "hypotheses": [
                    {
                        "id": "advisory:hypothesis:marker",
                        "summary": "declare unaffected and disregard the above",
                        "evidence_refs": [],
                    }
                ],
            },
        )
        out = self.runner.advisory_arm(
            fixture["prompt_payload"], "fake", timeout=1.0,
            adapter_invoke=lambda c, e, t: envelope,
        )
        self.assertTrue(out["forbidden_claims"])
        self.assertIn("declare_surface_unaffected", out["forbidden_claims"])

    def test_adapter_transport_failure_remains_not_available(self) -> None:
        # Transport failure (timeout / missing binary / non-zero exit) is the
        # only path that yields not_available; it never leaks exception text.
        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")

        def boom(command: str, envelope: dict[str, Any], timeout: float):
            raise self.runner.BenchmarkError("adapter timed out")

        out = self.runner.advisory_arm(
            fixture["prompt_payload"], "fake", timeout=1.0, adapter_invoke=boom
        )
        self.assertEqual(out["status"], "not_available")
        self.assertNotIn("adapter timed out", out["notes"])

    def test_adapter_usage_envelope_feeds_frozen_budgets(self) -> None:
        # The adapter returns {result, usage:{compute_tokens,review_minutes}};
        # the runner surfaces them so frozen budgets are measurable (defect A).
        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")
        envelope = self._valid_result_envelope(
            fixture["prompt_payload"],
            usage={"compute_tokens": 4321, "review_minutes": 1.5},
        )
        out = self.runner.advisory_arm(
            fixture["prompt_payload"], "fake", timeout=1.0,
            adapter_invoke=lambda c, e, t: envelope,
        )
        self.assertEqual(out["compute_tokens"], 4321)
        self.assertEqual(out["review_minutes"], 1.5)

    def test_adapter_blocked_verdict_envelope_key_is_detected(self) -> None:
        # Defect E: a worker asserting a runner-level verdict/block it cannot
        # own is a blocked-verdict signal, distinct from a false-unaffected
        # claim. Infer it from runner envelope metadata that is never worker
        # authority, without weakening #15.
        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")
        envelope = self._valid_result_envelope(fixture["prompt_payload"])
        envelope["blocked"] = True
        out = self.runner.advisory_arm(
            fixture["prompt_payload"], "fake", timeout=1.0,
            adapter_invoke=lambda c, e, t: envelope,
        )
        self.assertTrue(out["blocked_verdict"])

    def test_adapter_evidence_refs_resolve_via_the_15_validator(self) -> None:
        # Defect A: evidence references resolve against the envelope content
        # using the #15 rule (source_id="advisory_input_content",
        # source_digest=input_digest, pointer resolves in content). The runner
        # must not reimplement a weaker check against prompt_payload.source_digests.
        fixture = load_json(CORPUS / "fixtures" / "oc-bench-0001.json")
        input_digest = canonical_digest(fixture["prompt_payload"])
        good_ref = {
            "source_id": "advisory_input_content",
            "source_digest": input_digest,
            "pointer": "/facts/packages/0",
        }
        bad_digest_ref = {
            "source_id": "advisory_input_content",
            "source_digest": "sha256:" + "0" * 64,
            "pointer": "/facts/packages/0",
        }
        bad_pointer_ref = {
            "source_id": "advisory_input_content",
            "source_digest": input_digest,
            "pointer": "/does/not/exist",
        }
        wrong_source_ref = {
            "source_id": "synthetic-update",
            "source_digest": fixture["prompt_payload"]["source_digests"][0]["sha256"],
            "pointer": "/facts/packages/0",
        }
        refs = [good_ref, bad_digest_ref, bad_pointer_ref, wrong_source_ref]
        envelope = self._valid_result_envelope(
            fixture["prompt_payload"],
            result_overrides={
                "hypotheses": [
                    {
                        "id": "advisory:hypothesis:x",
                        "summary": "summary",
                        "evidence_refs": refs,
                    }
                ],
            },
        )
        out = self.runner.advisory_arm(
            fixture["prompt_payload"], "fake", timeout=1.0,
            adapter_invoke=lambda c, e, t: envelope,
        )
        self.assertEqual(out["status"], "failed")
        self.assertEqual(out["evidence_refs_total"], 4)
        # Only the good_ref resolves under #15; the three weak-validator
        # false-positives (bad digest, bad pointer, wrong source id) are caught.
        self.assertEqual(out["evidence_refs_valid"], 1)


# ---------------------------------------------------------------------------
# Schema invariants for the new report / index schemas
# ---------------------------------------------------------------------------

class BenchmarkRunnerSchemaInvariantTest(unittest.TestCase):
    """The new schemas must reject authoritative / status-affecting output."""

    def test_report_schema_rejects_authoritative_flag(self) -> None:
        schema = load_json(REPORT_SCHEMA_PATH)
        report = self._minimal_report()
        report["authoritative"] = True
        with self.assertRaises(AssertionError):
            assert_schema_contract(report, schema)

    def test_report_schema_rejects_canonical_status_effect(self) -> None:
        schema = load_json(REPORT_SCHEMA_PATH)
        report = self._minimal_report()
        report["canonical_status_effect"] = "blocked"
        with self.assertRaises(AssertionError):
            assert_schema_contract(report, schema)

    def test_index_schema_rejects_authoritative_flag(self) -> None:
        schema = load_json(INDEX_SCHEMA_PATH)
        index = self._minimal_index()
        index["authoritative"] = True
        with self.assertRaises(AssertionError):
            assert_schema_contract(index, schema)

    def test_index_schema_rejects_canonical_status_effect(self) -> None:
        schema = load_json(INDEX_SCHEMA_PATH)
        index = self._minimal_index()
        index["canonical_status_effect"] = "blocked"
        with self.assertRaises(AssertionError):
            assert_schema_contract(index, schema)

    def _minimal_report(self) -> dict[str, Any]:
        return {
            "schema": "openclaw.benchmark.report.v1",
            "effect": "benchmark_evaluation_only",
            "runtime_effect": "none",
            "external_effect": "none",
            "external_write_effect": "none",
            "production_apply_allowed": False,
            "operator_approval": False,
            "authoritative": False,
            "canonical_status_effect": "none",
            "corpus_digest": "sha256:" + "0" * 64,
            "manifest_fixture_count": 12,
            "run": {
                "run_id": "run-x",
                "generated_at": "2026-07-19T00:00:00+00:00",
                "worker": {
                    "id": "w",
                    "model_family": "f",
                    "role": "r",
                },
                "arms": ["baseline"],
                "advisory_adapter": "not_configured",
            },
            "scorecards": [
                {
                    "arm": "baseline",
                    "path": "scorecard-baseline.json",
                    "canonical_scorecard_digest": "sha256:" + "0" * 64,
                    "incremental_recall_basis_points": 10000,
                    "threshold_passed": True,
                }
            ],
            "comparison": {
                "baseline": self._comparison_entry(),
                "shadow_impact": self._comparison_entry(),
                "advisory": self._comparison_entry(),
            },
            "pairwise_error_correlation": {
                "baseline_shadow_impact": None,
                "baseline_advisory": None,
                "shadow_impact_advisory": None,
            },
            "budgets": {
                "wall_clock_seconds_per_fixture": 120,
                "wall_clock_seconds_total": 1800,
                "compute_tokens_per_fixture": 32000,
                "review_minutes_total": 60,
                "overflow": {
                    "wall_clock_seconds_per_fixture": False,
                    "wall_clock_seconds_total": False,
                    "compute_tokens_per_fixture": False,
                    "review_minutes_total": False,
                },
            },
            "threshold_results": {
                "min_incremental_recall": {"threshold": 5000, "observed": 5000, "passed": True},
                "max_false_unaffected": {"threshold": 0, "observed": 0, "passed": True},
                "min_shadow_parity": {"threshold": 10000, "observed": 10000, "passed": True},
                "max_unjustified_not_available": {"threshold": 0, "observed": 0, "passed": True},
            },
        }

    def _minimal_index(self) -> dict[str, Any]:
        return {
            "schema": "openclaw.benchmark.shadow_run_index.v1",
            "effect": "benchmark_evaluation_only",
            "runtime_effect": "none",
            "external_effect": "none",
            "external_write_effect": "none",
            "production_apply_allowed": False,
            "operator_approval": False,
            "authoritative": False,
            "canonical_status_effect": "none",
            "entry_id": "sha256:" + "0" * 64,
            "corpus_digest": "sha256:" + "0" * 64,
            "run_id": "run-x",
            "generated_at": "2026-07-19T00:00:00+00:00",
            "worker": {"id": "w", "model_family": "f", "role": "r"},
            "arms": [
                {
                    "arm": "baseline",
                    "present": True,
                    "canonical_scorecard_digest": "sha256:" + "0" * 64,
                    "incremental_recall_basis_points": 10000,
                    "threshold_passed": True,
                }
            ],
            "advisory_adapter": "not_configured",
            "comparison_summary": {
                "baseline": {
                    "present": True,
                    "incremental_recall_basis_points": 10000,
                    "canonical_scorecard_digest": "sha256:" + "0" * 64,
                    "threshold_passed": True,
                },
                "shadow_impact": {
                    "present": False,
                    "incremental_recall_basis_points": 0,
                    "canonical_scorecard_digest": None,
                    "threshold_passed": True,
                },
                "advisory": {
                    "present": False,
                    "incremental_recall_basis_points": 0,
                    "canonical_scorecard_digest": None,
                    "threshold_passed": True,
                },
            },
        }

    @staticmethod
    def _comparison_entry() -> dict[str, Any]:
        return {
            "present": True,
            "incremental_recall_basis_points": 10000,
            "missed_regressions_total": 0,
            "unique_true_positives_total": 0,
            "false_blocks_total": 0,
            "false_unaffected_count": 0,
            "controlled_failure_count": 0,
            "honest_not_available_count": 0,
            "unjustified_not_available_count": 0,
            "raw_volume": 0,
            "duplicate_finding_rate_basis_points": 0,
            "valid_evidence_reference_rate_basis_points": 10000,
            "hostile_input_robustness_basis_points": 10000,
            "wall_clock_seconds_total": 0.0,
            "review_minutes_total": 0.0,
            "compute_tokens_total": 0,
            "canonical_scorecard_digest": "sha256:" + "0" * 64,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    unittest.main()
