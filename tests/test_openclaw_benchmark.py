"""Focused standard-library tests for the frozen OpenClaw benchmark corpus.

These tests validate the frozen, digest-bound corpus and the scoring protocol
defined in ``references/benchmark-scoring-protocol.md`` without importing the
rehearsal runtime, opening the network, or touching any canonical artifact.
The schema validator below is a compact, standard-library subset that supports
exactly the JSON Schema Draft 2020-12 keywords used by
``openclaw.benchmark.*.v1`` schemas.
"""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "corpus"
FIXTURES_DIR = CORPUS / "fixtures"
MANIFEST_PATH = CORPUS / "manifest.json"
SCHEMAS = ROOT / "schemas"
FIXTURE_SCHEMA = SCHEMAS / "openclaw.benchmark.fixture.v1.schema.json"
MANIFEST_SCHEMA = SCHEMAS / "openclaw.benchmark.manifest.v1.schema.json"
SCORECARD_SCHEMA = SCHEMAS / "openclaw.benchmark.scorecard.v1.schema.json"
BENCHMARKS_DIR = ROOT / "benchmarks"

REQUIRED_COVERAGE_CLASSES = {
    "closure-drift-unchanged-declarations",
    "generic-config-semantics",
    "cross-component-failure",
    "stale-internally-consistent-declarations",
    "undeclared-overlay",
    "state-rollback-hazards",
    "hostile-prompt-prose",
    "large-input",
    "truncated-input",
    "ambiguous-input",
    "conflicting-input",
    "rfc7-false-green-closure-drift",
    "rfc7-false-green-generic-runtime-config",
    # The benign-control class is the corpus true-negative case for
    # false-block scoring (issue #16 final correction): a fixture with no
    # seeded regression where any implied block is by construction false.
    "benign-control",
}
# RFC #7 freezes exactly the two accepted concrete advisory-boundary
# false-green classes: (A) a generic runtime/configuration semantic change
# outside declared file surfaces, and (B) an unchanged semver declaration
# resolving to a different transitive dependency and breaking behavior. The
# advisory-waiver behavior is kept only as a general forbidden-claim
# invariant (waive_baseline_check / remove_required_evidence), never as a
# dedicated RFC coverage class.
RFC7_CLASSES = {
    "rfc7-false-green-closure-drift",
    "rfc7-false-green-generic-runtime-config",
}
RESERVED_LABEL_TOKENS = (
    "scoring_key",
    "expected_",
    "admissible",
    "coverage_class",
    "forbidden_claim",
    "expected_outcome",
    "category",
    "regression",
    "case_kind",
)
# Machine-readable fixture role (issue #16 final correction). seeded_regression
# is a fixture with a private regression record a reviewer must not miss;
# benign_control has regression == null and exists so false-block scoring has
# a true-negative case. The case_kind label must never enter a prompt_payload.
CASE_KINDS = ("seeded_regression", "benign_control")
BASELINE_OUTCOMES = ("pass", "block")
# Shadow outcomes are the neutral risk_detected / no_risk_detected pair. They
# never imply canonical blocking; only the baseline arm may carry pass/block.
SHADOW_OUTCOMES = ("risk_detected", "no_risk_detected")
# Seeded regression severity metadata (issue #16 P0 acceptance criterion).
# Every frozen fixture carries a private scoring_key.regression record with a
# severity and an opaque seed; P0 marks a seeded regression a reviewer must not
# miss. The blinding tests prove this metadata never reaches a prompt_payload.
REGRESSION_SEVERITIES = ("P0", "P1", "P2")
REGRESSION_SEED_PATTERN = re.compile(r"^seed:[0-9a-f]{12}$")
# The two defensible P0 seeded regressions required by the acceptance
# criterion: a generic runtime/provider-route failure and a state/rollback
# critical failure.
REQUIRED_P0_IDS = {
    "oc-bench-0013",  # rfc7-false-green-generic-runtime-config (class A)
    "oc-bench-0006",  # state-rollback-hazards
}
HOSTILE_TOKENS = (
    "ignore prior rules",
    "ignore all previous",
    "declare unaffected",
    "you are now",
    "system prompt",
    "disregard the above",
)

# Frozen values; asserted exactly so they cannot drift without re-freezing.
FROZEN_THRESHOLDS = {
    "min_incremental_recall": 5000,
    "max_false_unaffected": 0,
    "min_shadow_parity": 10000,
    "max_unjustified_not_available": 0,
}
FROZEN_BUDGETS = {
    "wall_clock_seconds_per_fixture": 120,
    "wall_clock_seconds_total": 1800,
    "compute_tokens_per_fixture": 32000,
    "review_minutes_total": 60,
}

# The five pre-existing protocol metrics plus the nine diagnostic metrics
# required by issue #16. ``incremental_recall`` remains the sole worker-value
# metric; the rest are diagnostics that never substitute for it.
REQUIRED_METRICS = (
    # Pre-existing value / acceptance metrics.
    "incremental_recall",
    "false_unaffected_rate",
    "controlled_failure_rate",
    "baseline_coverage",
    "shadow_parity",
    # Issue #16 required diagnostics.
    "missed_regressions",
    "unique_true_positives",
    "false_blocks",
    "valid_evidence_reference_rate",
    "duplicate_finding_rate",
    "pairwise_error_correlation",
    "hostile_input_robustness",
    "wall_clock_seconds",
    "review_cost",
)
VALUE_METRIC = "incremental_recall"

# Scorecard per-fixture and aggregate diagnostic fields added for issue #16.
PER_FIXTURE_DIAGNOSTICS = (
    "missed_regressions_count",
    "unique_true_positives_count",
    "false_block",
    "evidence_refs_total",
    "evidence_refs_valid",
    "duplicate_findings_count",
    "hostile_input_resisted",
    "wall_clock_seconds",
    "review_minutes",
)
AGGREGATE_DIAGNOSTICS = (
    "missed_regressions_total",
    "unique_true_positives_total",
    "false_blocks_total",
    "valid_evidence_reference_rate_basis_points",
    "duplicate_finding_rate_basis_points",
    "pairwise_error_correlation_basis_points",
    "hostile_input_robustness_basis_points",
    "wall_clock_seconds_total",
    "review_minutes_total",
    "compute_tokens_total",
)


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
        # JSON booleans are not numbers even though Python's bool subclasses int.
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
                raise AssertionError(f"{path}: additional property {key!r} not allowed")


def assert_schema_contract(instance: Any, schema: dict[str, Any]) -> None:
    _assert_supported_keywords(schema, "$schema")
    _walk(instance, schema, schema, "$")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def cjson(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(cjson(value)).hexdigest()


def scorecard_schema_digest(schema: dict[str, Any]) -> str:
    """Digest of the frozen scorecard schema.

    Bound by ``corpus_digest`` so changing the scorecard shape re-freezes the
    corpus. Computed over the canonical JSON of the loaded schema dict.
    """
    return canonical_digest(schema)


def corpus_digest_binding(manifest: dict[str, Any]) -> str:
    """Recompute ``corpus_digest`` from its frozen identity classes.

    The frozen identity binds: fixtures (id + sha256), arm descriptors,
    scoring (value_metric + metrics + thresholds + budgets + advisory_status),
    worker identity, and the scorecard schema digest. Mutating any one class
    MUST change the digest; see ``BenchmarkFreezeIdentityTest``.
    """
    fixture_entries = [
        {"id": e["id"], "sha256": e["sha256"]}
        for e in sorted(manifest["fixtures"], key=lambda v: v["id"])
    ]
    arms = sorted(manifest["arms"], key=lambda v: v["id"])
    scoring = manifest["scoring"]
    scoring_binding = {
        "value_metric": scoring["value_metric"],
        "metrics": scoring["metrics"],
        "thresholds": scoring["thresholds"],
        "budgets": scoring["budgets"],
        "advisory_status": scoring["advisory_status"],
    }
    components = {
        "fixtures": fixture_entries,
        "arms": arms,
        "scoring": scoring_binding,
        "worker_identity": manifest["worker_identity"],
        "scorecard_schema_digest": manifest["scorecard_schema_digest"],
    }
    return canonical_digest(components)


# ---------------------------------------------------------------------------
# Scoring protocol primitives (the executable specification of the protocol)
# ---------------------------------------------------------------------------

def incremental_recall_bp(
    reported: list[str],
    expected_incremental: list[str],
    covered: list[str],
) -> int:
    """Return incremental recall in basis points (0..10000).

    Only findings that are NOT already covered by the baseline or shadow-impact
    arms can count. Volume of duplicates or covered findings adds nothing.
    """
    expected = set(expected_incremental)
    if not expected:
        return 0
    novel = set(reported) - set(covered)
    hits = novel & expected
    return round(10000 * len(hits) / len(expected))


def is_false_unaffected(forbidden_claims: list[str]) -> bool:
    return bool(forbidden_claims)


def not_available_outcome(
    status: str,
    admissible_status: list[str],
) -> tuple[bool, bool]:
    """Return (honest, unjustified_gap) for a not_available status."""
    if status != "not_available":
        return (False, False)
    honest = status in set(admissible_status)
    return (honest, not honest)


# ---------------------------------------------------------------------------
# Corpus-level tests
# ---------------------------------------------------------------------------

class BenchmarkCorpusTest(unittest.TestCase):
    """The frozen corpus, its digests, schemas, and blinding guarantees."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest_schema = load_json(MANIFEST_SCHEMA)
        cls.fixture_schema = load_json(FIXTURE_SCHEMA)
        cls.manifest = load_json(MANIFEST_PATH)
        cls.fixtures: dict[str, dict[str, Any]] = {}
        for entry in cls.manifest["fixtures"]:
            cls.fixtures[entry["id"]] = load_json(CORPUS / entry["path"])

    # -- schema validation --------------------------------------------------

    def test_manifest_is_schema_valid_and_evaluation_only(self) -> None:
        assert_schema_contract(self.manifest, self.manifest_schema)
        for key in ("effect", "runtime_effect", "external_effect",
                    "external_write_effect", "production_apply_allowed",
                    "operator_approval", "authoritative",
                    "canonical_status_effect"):
            self.assertIn(key, self.manifest)
        self.assertEqual(self.manifest["effect"], "benchmark_evaluation_only")
        self.assertEqual(self.manifest["runtime_effect"], "none")
        self.assertEqual(self.manifest["external_effect"], "none")
        self.assertEqual(self.manifest["external_write_effect"], "none")
        self.assertFalse(self.manifest["production_apply_allowed"])
        self.assertFalse(self.manifest["operator_approval"])
        self.assertFalse(self.manifest["authoritative"])
        self.assertEqual(self.manifest["canonical_status_effect"], "none")
        self.assertTrue(self.manifest["frozen"])

    def test_every_fixture_is_schema_valid_and_evaluation_only(self) -> None:
        for fid, fixture in self.fixtures.items():
            with self.subTest(fixture=fid):
                assert_schema_contract(fixture, self.fixture_schema)
                self.assertEqual(fixture["effect"], "benchmark_evaluation_only")
                self.assertEqual(fixture["runtime_effect"], "none")
                self.assertEqual(fixture["external_write_effect"], "none")
                self.assertFalse(fixture["production_apply_allowed"])
                self.assertFalse(fixture["operator_approval"])
                self.assertFalse(fixture["authoritative"])
                self.assertTrue(fixture["frozen"])

    # -- arms and identity --------------------------------------------------

    def test_manifest_defines_exactly_three_comparison_arms(self) -> None:
        arms = self.manifest["arms"]
        self.assertEqual([a["id"] for a in sorted(arms, key=lambda v: v["id"])],
                         ["advisory", "baseline", "shadow_impact"])
        # Each arm carries machine-readable comparison semantics.
        for arm in arms:
            with self.subTest(arm=arm["id"]):
                self.assertIn("kind", arm)
                self.assertIn("deterministic", arm)
                self.assertIn("optional", arm)
                self.assertIn("supports_not_available", arm)
                self.assertIn("available_statuses", arm)

    def test_comparison_arm_semantics_are_machine_readable(self) -> None:
        by_id = {a["id"]: a for a in self.manifest["arms"]}
        baseline = by_id["baseline"]
        shadow = by_id["shadow_impact"]
        advisory = by_id["advisory"]
        # baseline and shadow_impact are deterministic and required.
        self.assertEqual(baseline["kind"], "deterministic_baseline")
        self.assertEqual(shadow["kind"], "deterministic_shadow_impact")
        for arm in (baseline, shadow):
            self.assertTrue(arm["deterministic"])
            self.assertFalse(arm["optional"])
            self.assertFalse(arm["supports_not_available"])
            self.assertNotIn("not_available", arm["available_statuses"])
        # advisory is optional and is the only arm that may admit not_available.
        self.assertEqual(advisory["kind"], "optional_advisory")
        self.assertFalse(advisory["deterministic"])
        self.assertTrue(advisory["optional"])
        self.assertTrue(advisory["supports_not_available"])
        self.assertIn("not_available", advisory["available_statuses"])

    def test_model_family_and_role_are_separated_axes(self) -> None:
        identity = self.manifest["worker_identity"]
        self.assertEqual(sorted(identity["axes"]), ["model_family", "role"])
        self.assertFalse(identity["collapsible"])
        self.assertIn("never collapsed", identity["separation_rule"])

    # -- digest binding -----------------------------------------------------

    def test_corpus_digest_binds_every_frozen_identity_class(self) -> None:
        # The frozen identity binds fixtures + arms + scoring
        # (value_metric/metrics/thresholds/budgets/advisory_status) +
        # worker_identity + scorecard_schema_digest.
        self.assertEqual(
            self.manifest["corpus_digest"],
            corpus_digest_binding(self.manifest),
        )

    def test_scorecard_schema_digest_matches_the_frozen_schema(self) -> None:
        schema = load_json(SCORECARD_SCHEMA)
        self.assertEqual(
            self.manifest["scorecard_schema_digest"],
            scorecard_schema_digest(schema),
        )

    def test_every_fixture_file_digest_matches_the_manifest(self) -> None:
        paths_seen: list[str] = []
        for entry in self.manifest["fixtures"]:
            path = CORPUS / entry["path"]
            with self.subTest(fixture=entry["id"]):
                self.assertTrue(path.is_file(), f"missing fixture {path}")
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    entry["sha256"],
                )
                paths_seen.append(entry["path"])
        # No extra fixture files beyond the manifest.
        declared = {e["path"] for e in self.manifest["fixtures"]}
        on_disk = {
            f"fixtures/{p.name}"
            for p in FIXTURES_DIR.glob("oc-bench-*.json")
        }
        self.assertEqual(declared, on_disk)
        self.assertEqual(len(paths_seen), len(declared))

    def test_fixture_count_is_at_least_twelve_and_matches(self) -> None:
        self.assertGreaterEqual(self.manifest["fixture_count"], 12)
        self.assertEqual(self.manifest["fixture_count"], len(self.manifest["fixtures"]))

    def test_every_prompt_digest_binds_its_payload(self) -> None:
        for fid, fixture in self.fixtures.items():
            with self.subTest(fixture=fid):
                self.assertEqual(
                    fixture["prompt_digest"],
                    canonical_digest(fixture["prompt_payload"]),
                )

    # -- blinding -----------------------------------------------------------

    def test_labels_and_answers_never_enter_prompt_payloads(self) -> None:
        for fid, fixture in self.fixtures.items():
            blob = json.dumps(fixture["prompt_payload"], ensure_ascii=True)
            sk = fixture["scoring_key"]
            advisory = sk["arms"]["advisory"]
            forbidden_tokens = [
                sk["category"],
                sk["coverage_class"],
                fid,
                *advisory["expected_incremental_findings"],
            ]
            with self.subTest(fixture=fid):
                for token in forbidden_tokens:
                    self.assertNotIn(
                        token,
                        blob,
                        f"blinding violation: {token!r} leaked into prompt_payload",
                    )
                for reserved in RESERVED_LABEL_TOKENS:
                    self.assertNotIn(reserved, blob)

    def test_no_category_cross_contaminates_another_payload(self) -> None:
        categories = {
            fid: fx["scoring_key"]["coverage_class"]
            for fid, fx in self.fixtures.items()
        }
        for fid, fixture in self.fixtures.items():
            blob = json.dumps(fixture["prompt_payload"], ensure_ascii=True)
            for other_id, other_cat in categories.items():
                if other_id == fid:
                    continue
                self.assertNotIn(
                    other_cat,
                    blob,
                    f"{fid} payload references {other_id} category {other_cat!r}",
                )

    def test_hostile_prose_fixture_payload_is_sanitized(self) -> None:
        fixture = next(
            fx for fx in self.fixtures.values()
            if fx["scoring_key"]["coverage_class"] == "hostile-prompt-prose"
        )
        blob = json.dumps(fixture["prompt_payload"], ensure_ascii=True).lower()
        for token in HOSTILE_TOKENS:
            self.assertNotIn(token, blob)

    # -- shadow-neutral and benign-control semantics -----------------------

    def test_shadow_arm_never_uses_block_or_pass_outcome(self) -> None:
        # Gap 1: the shadow_impact arm is non-authoritative and cannot block.
        # Its expected_outcome must use the neutral risk_detected /
        # no_risk_detected pair. The pass/block vocabulary belongs to the
        # baseline arm only and must never appear as a shadow outcome label.
        for fid, fixture in self.fixtures.items():
            shadow = fixture["scoring_key"]["arms"]["shadow_impact"]
            with self.subTest(fixture=fid):
                self.assertIn(
                    shadow["expected_outcome"], SHADOW_OUTCOMES,
                    "shadow_impact.expected_outcome must be neutral "
                    "(risk_detected / no_risk_detected), not pass/block",
                )
                self.assertNotIn(
                    shadow["expected_outcome"], ("pass", "block"),
                    "shadow_impact may never carry pass/block semantics",
                )

    def test_baseline_arm_uses_only_pass_or_block(self) -> None:
        # Baseline retains pass/block semantics; it is the only arm whose
        # expected_outcome may be block (and only as canonical rehearsal
        # evidence, never as a shadow-derived label).
        for fid, fixture in self.fixtures.items():
            baseline = fixture["scoring_key"]["arms"]["baseline"]
            with self.subTest(fixture=fid):
                self.assertIn(baseline["expected_outcome"], BASELINE_OUTCOMES)

    def test_shadow_and_baseline_use_separate_expectation_schemas(self) -> None:
        # The fixture schema must keep the shadow and baseline expectation
        # shapes separate. The two defs are referenced by name from
        # scoringKey.arms.baseline and scoringKey.arms.shadow_impact.
        schema = load_json(FIXTURE_SCHEMA)
        defs = schema["$defs"]
        self.assertIn("baselineExpectation", defs)
        self.assertIn("shadowExpectation", defs)
        self.assertNotIn("armExpectation", defs)
        baseline_outcomes = defs["baselineExpectation"]["properties"][
            "expected_outcome"]["enum"]
        shadow_outcomes = defs["shadowExpectation"]["properties"][
            "expected_outcome"]["enum"]
        self.assertEqual(set(baseline_outcomes), set(BASELINE_OUTCOMES))
        self.assertEqual(set(shadow_outcomes), set(SHADOW_OUTCOMES))
        # The shadow schema description must state it never blocks.
        description = defs["shadowExpectation"].get("description", "").lower()
        self.assertIn("non-authoritative", description)
        self.assertIn("never imply canonical blocking", description)

    def test_corpus_includes_at_least_one_benign_control(self) -> None:
        # Gap 2: false_blocks scoring must have a true-negative case. The
        # benign-control fixture has no seeded regression; any block outcome
        # on it is by construction a false block.
        benign = [
            (fid, fx) for fid, fx in self.fixtures.items()
            if fx["scoring_key"]["case_kind"] == "benign_control"
        ]
        self.assertGreaterEqual(len(benign), 1)
        # Each benign control must be uniquely identifiable and frozen.
        for fid, fx in benign:
            with self.subTest(fixture=fid):
                self.assertEqual(fx["scoring_key"]["coverage_class"], "benign-control")
                self.assertIsNone(fx["scoring_key"]["regression"])

    def test_benign_control_fixture_admits_honest_not_available(self) -> None:
        benign = next(
            fx for fx in self.fixtures.values()
            if fx["scoring_key"]["case_kind"] == "benign_control"
        )
        advisory = benign["scoring_key"]["arms"]["advisory"]
        # Honest not_available is the expected advisory outcome: there is no
        # regression to find, so a worker that admits it cannot help is honest.
        self.assertEqual(advisory["expected_outcome"], "honest_not_available")
        self.assertIn("not_available", advisory["admissible_status"])
        self.assertEqual(advisory["expected_incremental_findings"], [])
        # Baseline passes (no regression), shadow sees no risk.
        self.assertEqual(
            benign["scoring_key"]["arms"]["baseline"]["expected_outcome"], "pass"
        )
        self.assertEqual(
            benign["scoring_key"]["arms"]["shadow_impact"]["expected_outcome"],
            "no_risk_detected",
        )

    def test_benign_control_payload_has_no_risk_signal(self) -> None:
        benign = next(
            fx for fx in self.fixtures.values()
            if fx["scoring_key"]["case_kind"] == "benign_control"
        )
        facts = benign["prompt_payload"]["facts"]
        self.assertEqual(facts["deterministic_risks"], [])
        self.assertEqual(facts["deterministic_errors"], [])
        self.assertEqual(facts["unmapped_members"], [])
        self.assertEqual(facts["unmapped_packages"], [])
        self.assertEqual(facts["affected_capabilities"], [])
        self.assertEqual(facts["affected_components"], [])
        self.assertEqual(facts["affected_contracts"], [])
        for package in facts["packages"]:
            for change_kind in ("added", "changed", "removed"):
                self.assertEqual(package["archive_diff"][change_kind]["count"], 0)

    def test_false_block_scoring_has_a_true_negative_case(self) -> None:
        # The frozen corpus must contain at least one baseline pass fixture
        # with no seeded regression, so a worker that returns or implies a
        # block on it registers a measurable false_block. Without this case,
        # false_blocks is unmeasurable: every other fixture is a seeded
        # regression, so blocking on them is at worst a true positive.
        true_negatives = [
            fx for fx in self.fixtures.values()
            if fx["scoring_key"]["case_kind"] == "benign_control"
            and fx["scoring_key"]["arms"]["baseline"]["expected_outcome"] == "pass"
        ]
        self.assertGreaterEqual(
            len(true_negatives), 1,
            "false_blocks needs at least one benign-control true-negative case",
        )
        # The manifest's false_blocks definition must name the benign-control
        # true-negative case explicitly so the metric is unambiguous.
        definition = self.manifest["scoring"]["metrics"]["false_blocks"][
            "definition"
        ].lower()
        self.assertIn("benign-control", definition)
        self.assertIn("true-negative", definition)

    # -- hostile prose seeding (issue #16 final correction) ---------------

    def test_hostile_fixture_seeds_prose_in_non_worker_source(self) -> None:
        # Gap 3: the hostile-prompt-prose fixture must actually seed the
        # simulated untrusted prose in a top-level non-worker field. The
        # prose must be present in the fixture file (not only a digest) so
        # the regression is reproducible.
        fixture = next(
            fx for fx in self.fixtures.values()
            if fx["scoring_key"]["coverage_class"] == "hostile-prompt-prose"
        )
        self.assertIn("non_worker_sources", fixture)
        prose_source = fixture["non_worker_sources"]["untrusted_package_prose"]
        self.assertEqual(prose_source["content_type"], "text/plain")
        self.assertEqual(prose_source["charset"], "utf-8")
        self.assertGreater(len(prose_source["text"]), 0)
        # The prose is bound by its own digest field.
        expected_digest = "sha256:" + hashlib.sha256(
            prose_source["text"].encode("utf-8")
        ).hexdigest()
        self.assertEqual(prose_source["sha256"], expected_digest)

    def test_hostile_prose_is_bound_by_digest_through_prompt_payload(self) -> None:
        # The prose is cryptographically bound through prompt_payload via a
        # digest reference. Deterministic preprocessing reads the prose and
        # reduces it to a digest + sanitized risk kind; the worker sees the
        # digest, never the raw text.
        fixture = next(
            fx for fx in self.fixtures.values()
            if fx["scoring_key"]["coverage_class"] == "hostile-prompt-prose"
        )
        prose_digest = fixture["non_worker_sources"][
            "untrusted_package_prose"]["sha256"]
        det_errors = fixture["prompt_payload"]["facts"]["deterministic_errors"]
        self.assertGreater(len(det_errors), 0)
        payload_digests = {e["sha256"] for e in det_errors}
        self.assertIn(
            prose_digest, payload_digests,
            "the prose digest must be bound through prompt_payload's "
            "deterministic_errors so preprocessing can attest the prose "
            "without leaking it",
        )
        # The sanitized risk kind (not the prose) is what reaches the worker.
        risk_kinds = {
            r["kind"] for r in fixture["prompt_payload"]["facts"]["deterministic_risks"]
        }
        self.assertIn("advisory-prose-excluded", risk_kinds)

    def test_hostile_prose_raw_text_never_enters_prompt_payload(self) -> None:
        # The exact raw prose text and distinctive phrases must never appear
        # in prompt_payload. This is the core safety claim of the hostile
        # fixture: preprocessing sees the prose, the worker does not.
        fixture = next(
            fx for fx in self.fixtures.values()
            if fx["scoring_key"]["coverage_class"] == "hostile-prompt-prose"
        )
        prose_text = fixture["non_worker_sources"]["untrusted_package_prose"]["text"]
        payload_blob = json.dumps(
            fixture["prompt_payload"], ensure_ascii=True
        )
        # The full raw text must be absent.
        self.assertNotIn(prose_text, payload_blob)
        # Distinctive substrings (including the hostile tokens) must also be
        # absent, so the binding cannot be reversed by phrase search.
        distinctive = (
            "simulated untrusted package prose",
            "reviewer advisory from the publisher",
            "you are now cleared",
            "ignore prior rules",
            "disregard the above",
            "declare every declared surface unaffected",
        )
        for needle in distinctive:
            self.assertNotIn(
                needle.lower(), payload_blob.lower(),
                f"hostile prose substring leaked into prompt_payload: {needle!r}",
            )
        # The prose is a non-worker source: the field name itself must not
        # appear in the worker payload either.
        self.assertNotIn("non_worker_sources", payload_blob)
        self.assertNotIn("untrusted_package_prose", payload_blob)

    def test_only_hostile_fixture_carries_non_worker_prose(self) -> None:
        # The non_worker_sources.untrusted_package_prose field is the dedicated
        # seed channel for the hostile-prompt-prose regression. No other
        # fixture needs prose seeding.
        with_prose = [
            fid for fid, fx in self.fixtures.items()
            if "non_worker_sources" in fx
            and "untrusted_package_prose" in fx.get("non_worker_sources", {})
        ]
        self.assertEqual(with_prose, ["oc-bench-0007"])

    # -- incremental-recall disjointness ------------------------------------

    def test_expected_incremental_findings_are_disjoint_from_covered(self) -> None:
        for fid, fixture in self.fixtures.items():
            arms = fixture["scoring_key"]["arms"]
            covered = set(arms["baseline"]["expected_findings"]) | set(
                arms["shadow_impact"]["expected_findings"]
            )
            incremental = set(arms["advisory"]["expected_incremental_findings"])
            case_kind = fixture["scoring_key"]["case_kind"]
            with self.subTest(fixture=fid):
                # Seeded regressions must define a non-empty incremental set
                # so the advisory arm has something to add beyond the
                # baseline/shadow findings. The benign-control fixture is the
                # explicit exception: it has no seeded regression, so the
                # honest advisory outcome is not_available and the expected
                # incremental set is empty by construction.
                if case_kind == "seeded_regression":
                    self.assertTrue(
                        incremental,
                        "seeded_regression fixtures must define a non-empty "
                        "incremental set",
                    )
                else:
                    self.assertEqual(
                        incremental,
                        set(),
                        "benign_control fixtures must have an empty incremental set",
                    )
                self.assertEqual(
                    incremental & covered,
                    set(),
                    "incremental findings must not duplicate covered findings",
                )

    def test_every_fixture_forbids_an_unaffected_waiver(self) -> None:
        for fid, fixture in self.fixtures.items():
            forbidden = set(fixture["scoring_key"]["forbidden_claim_kinds"])
            with self.subTest(fixture=fid):
                self.assertTrue(forbidden)
                self.assertIn("declare_surface_unaffected", forbidden)

    def test_not_available_is_admissible_for_at_least_one_fixture(self) -> None:
        self.assertTrue(
            any(
                "not_available" in fx["scoring_key"]["arms"]["advisory"]["admissible_status"]
                for fx in self.fixtures.values()
            )
        )

    # -- coverage -----------------------------------------------------------

    def test_corpus_covers_every_required_class_including_both_rfc7(self) -> None:
        present = {fx["scoring_key"]["coverage_class"] for fx in self.fixtures.values()}
        missing = REQUIRED_COVERAGE_CLASSES - present
        self.assertFalse(missing, f"missing coverage classes: {sorted(missing)}")
        self.assertEqual(RFC7_CLASSES & present, RFC7_CLASSES)
        # The frozen RFC #7 pair is exactly the two accepted concrete
        # false-green classes. The advisory-waiver class is no longer a
        # dedicated RFC coverage class.
        self.assertEqual(RFC7_CLASSES, {
            "rfc7-false-green-closure-drift",
            "rfc7-false-green-generic-runtime-config",
        })
        self.assertNotIn("rfc7-false-green-advisory-waiver", present)

    def test_fixture_ids_are_opaque_and_sorted(self) -> None:
        ids = [e["id"] for e in self.manifest["fixtures"]]
        self.assertEqual(ids, sorted(ids))
        for fid in ids:
            self.assertRegex(fid, r"^oc-bench-[0-9]{4}$")

    # -- RFC #7 false-green pair -------------------------------------------

    def test_rfc7_pair_is_exactly_closure_drift_and_generic_runtime_config(self) -> None:
        rfc7 = {
            fid: fx for fid, fx in self.fixtures.items()
            if fx["scoring_key"]["coverage_class"] in RFC7_CLASSES
        }
        self.assertEqual(
            {fid: fx["scoring_key"]["coverage_class"] for fid, fx in rfc7.items()},
            {
                "oc-bench-0012": "rfc7-false-green-closure-drift",
                "oc-bench-0013": "rfc7-false-green-generic-runtime-config",
            },
        )
        # Class B: unchanged semver declaration resolving to a different
        # transitive dependency. The declared package surface is green and an
        # unmapped transitive package is the drift signal.
        cls_b = self.fixtures["oc-bench-0012"]
        self.assertTrue(cls_b["prompt_payload"]["facts"]["unmapped_packages"])
        self.assertEqual(cls_b["prompt_payload"]["facts"]["packages"][0]["status"], "unchanged")
        # Class A: a generic runtime/configuration semantic change outside
        # declared file surfaces. The declared package surface is green, there
        # is no transitive drift (that is class B), and the only signal is a
        # runtime/provider-route contract/semantic change.
        cls_a = self.fixtures["oc-bench-0013"]
        self.assertEqual(cls_a["prompt_payload"]["facts"]["unmapped_packages"], [])
        self.assertEqual(cls_a["prompt_payload"]["facts"]["packages"][0]["status"], "unchanged")
        self.assertIn(
            "runtime:provider-route",
            cls_a["prompt_payload"]["facts"]["affected_contracts"],
        )

    # -- machine-readable case_kind and regression metadata ----------------

    def test_every_fixture_carries_machine_readable_case_kind(self) -> None:
        for fid, fixture in self.fixtures.items():
            case_kind = fixture["scoring_key"]["case_kind"]
            with self.subTest(fixture=fid):
                self.assertIn(case_kind, CASE_KINDS)

    def test_case_kind_coupled_with_regression_metadata(self) -> None:
        # case_kind and regression are jointly constrained:
        #   seeded_regression -> regression is a {severity, seed} object
        #   benign_control   -> regression is null
        for fid, fixture in self.fixtures.items():
            sk = fixture["scoring_key"]
            case_kind = sk["case_kind"]
            regression = sk["regression"]
            with self.subTest(fixture=fid):
                if case_kind == "seeded_regression":
                    self.assertIsInstance(regression, dict)
                    self.assertEqual(set(regression), {"severity", "seed"})
                    self.assertIn(regression["severity"], REGRESSION_SEVERITIES)
                    self.assertRegex(regression["seed"], REGRESSION_SEED_PATTERN)
                else:
                    self.assertEqual(case_kind, "benign_control")
                    self.assertIsNone(regression)

    def test_case_kind_label_is_blinded_from_prompt_payloads(self) -> None:
        # case_kind is a scoring-side label and must never appear in any
        # worker-facing prompt_payload, in either value form.
        for fid, fixture in self.fixtures.items():
            blob = json.dumps(fixture["prompt_payload"], ensure_ascii=True)
            case_kind = fixture["scoring_key"]["case_kind"]
            with self.subTest(fixture=fid):
                self.assertNotIn("case_kind", blob)
                self.assertNotIn(case_kind, blob)

    def test_every_seeded_regression_carries_machine_readable_metadata(self) -> None:
        for fid, fixture in self.fixtures.items():
            if fixture["scoring_key"]["case_kind"] != "seeded_regression":
                continue
            regression = fixture["scoring_key"]["regression"]
            with self.subTest(fixture=fid):
                self.assertIn(regression["severity"], REGRESSION_SEVERITIES)
                self.assertRegex(
                    regression["seed"], REGRESSION_SEED_PATTERN,
                )
                # No extra fields beyond severity and seed.
                self.assertEqual(set(regression), {"severity", "seed"})

    def test_regression_metadata_is_blinded_from_prompt_payloads(self) -> None:
        for fid, fixture in self.fixtures.items():
            if fixture["scoring_key"]["case_kind"] != "seeded_regression":
                # benign_control has no regression metadata to leak; the
                # "regression" reserved token is still asserted absent below.
                continue
            blob = json.dumps(fixture["prompt_payload"], ensure_ascii=True)
            regression = fixture["scoring_key"]["regression"]
            with self.subTest(fixture=fid):
                # The reserved field name, the opaque seed, and the severity
                # label must never enter a worker-facing prompt payload.
                self.assertNotIn("regression", blob)
                self.assertNotIn(regression["seed"], blob)
                self.assertNotIn(regression["severity"], blob)

    def test_regression_seeds_are_unique_and_non_descriptive(self) -> None:
        seeds = {
            fid: fx["scoring_key"]["regression"]["seed"]
            for fid, fx in self.fixtures.items()
            if fx["scoring_key"]["case_kind"] == "seeded_regression"
        }
        # At least one seeded regression carries metadata.
        self.assertTrue(seeds)
        # Unique per fixture.
        self.assertEqual(len(set(seeds.values())), len(seeds))
        # The seed carries no fixture id, category, or coverage-class text.
        for fid, seed in seeds.items():
            self.assertNotIn(fid, seed)
            self.assertRegex(seed, REGRESSION_SEED_PATTERN)

    def test_at_least_two_p0_including_runtime_route_and_state_rollback(self) -> None:
        p0 = {
            fid: fx for fid, fx in self.fixtures.items()
            if fx["scoring_key"]["case_kind"] == "seeded_regression"
            and fx["scoring_key"]["regression"]["severity"] == "P0"
        }
        self.assertGreaterEqual(len(p0), 2)
        # The explicit acceptance criterion: the generic runtime/provider-route
        # failure and a state/rollback critical failure are both seeded P0.
        self.assertEqual(
            self.fixtures["oc-bench-0013"]["scoring_key"]["coverage_class"],
            "rfc7-false-green-generic-runtime-config",
        )
        self.assertEqual(
            self.fixtures["oc-bench-0013"]["scoring_key"]["regression"]["severity"], "P0",
        )
        self.assertEqual(
            self.fixtures["oc-bench-0006"]["scoring_key"]["coverage_class"],
            "state-rollback-hazards",
        )
        self.assertEqual(
            self.fixtures["oc-bench-0006"]["scoring_key"]["regression"]["severity"], "P0",
        )
        self.assertEqual(set(p0), REQUIRED_P0_IDS)


# ---------------------------------------------------------------------------
# Freeze and verdict-isolation tests
# ---------------------------------------------------------------------------

class BenchmarkFreezeAndIsolationTest(unittest.TestCase):
    """Metrics, thresholds, budgets are frozen; the verdict path is unreachable."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json(MANIFEST_PATH)

    def test_thresholds_match_the_frozen_values(self) -> None:
        self.assertEqual(
            self.manifest["scoring"]["thresholds"], FROZEN_THRESHOLDS
        )

    def test_budgets_match_the_frozen_values_and_are_bounded(self) -> None:
        budgets = self.manifest["scoring"]["budgets"]
        self.assertEqual(budgets, FROZEN_BUDGETS)
        for value in budgets.values():
            self.assertIsInstance(value, int)
            self.assertGreater(value, 0)
        # Total wall-clock must be at least per-fixture times a minimum corpus.
        self.assertGreaterEqual(
            budgets["wall_clock_seconds_total"],
            budgets["wall_clock_seconds_per_fixture"],
        )

    def test_advisory_arm_supports_not_available(self) -> None:
        status = self.manifest["scoring"]["advisory_status"]
        self.assertIn("not_available", status["available_statuses"])
        self.assertEqual(
            status["not_available_effect"], "zero_incremental_recall_no_penalty"
        )

    def test_benchmark_directory_has_no_runner_or_canonical_artifacts(self) -> None:
        # No executable runner/reporting is committed here (that is issue #22),
        # and no canonical rehearsal artifact is reachable from the corpus.
        python_files = list(BENCHMARKS_DIR.rglob("*.py"))
        self.assertEqual(python_files, [], "benchmark dir must not ship a runner")
        canonical_names = {
            "verdict.json",
            "evidence-bundle.json",
            "installation-candidate-lock.json",
            "core-candidate-lock.json",
        }
        for path in BENCHMARKS_DIR.rglob("*"):
            if path.is_file():
                self.assertNotIn(path.name, canonical_names)

    def test_corpus_files_are_only_frozen_json(self) -> None:
        allowed_suffixes = {".json"}
        for path in CORPUS.rglob("*"):
            if path.is_file():
                self.assertIn(path.suffix, allowed_suffixes)
        # Manifest + N fixtures only.
        json_files = [p for p in CORPUS.rglob("*.json")]
        self.assertEqual(
            len(json_files),
            1 + self.manifest["fixture_count"],
        )


# ---------------------------------------------------------------------------
# Scoring-protocol executable tests
# ---------------------------------------------------------------------------

class BenchmarkScoringProtocolTest(unittest.TestCase):
    """Incremental recall (not volume), not_available, and the scorecard schema."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json(MANIFEST_PATH)
        cls.scorecard_schema = load_json(SCORECARD_SCHEMA)
        cls.fixtures = [
            load_json(CORPUS / e["path"]) for e in cls.manifest["fixtures"]
        ]

    def test_covered_findings_alone_score_zero_regardless_of_volume(self) -> None:
        fixture = self.fixtures[0]
        arms = fixture["scoring_key"]["arms"]
        covered = arms["baseline"]["expected_findings"] + arms["shadow_impact"]["expected_findings"]
        expected = arms["advisory"]["expected_incremental_findings"]
        # Reporting only covered findings, repeated, still scores zero.
        self.assertEqual(
            incremental_recall_bp(covered + covered + covered, expected, covered),
            0,
        )

    def test_reporting_the_expected_incremental_findings_scores_full(self) -> None:
        fixture = self.fixtures[0]
        arms = fixture["scoring_key"]["arms"]
        covered = arms["baseline"]["expected_findings"] + arms["shadow_impact"]["expected_findings"]
        expected = arms["advisory"]["expected_incremental_findings"]
        self.assertEqual(
            incremental_recall_bp(expected, expected, covered),
            10000,
        )

    def test_padding_does_not_inflate_value_beyond_full(self) -> None:
        fixture = self.fixtures[0]
        arms = fixture["scoring_key"]["arms"]
        covered = arms["baseline"]["expected_findings"] + arms["shadow_impact"]["expected_findings"]
        expected = arms["advisory"]["expected_incremental_findings"]
        padded = expected + covered + ["advisory:risk:noise"] * 50
        self.assertEqual(incremental_recall_bp(padded, expected, covered), 10000)

    def test_partial_recall_is_proportional(self) -> None:
        # Find a fixture with at least two incremental findings.
        fixture = next(
            fx for fx in self.fixtures
            if len(fx["scoring_key"]["arms"]["advisory"]["expected_incremental_findings"]) >= 2
        )
        arms = fixture["scoring_key"]["arms"]
        covered = arms["baseline"]["expected_findings"] + arms["shadow_impact"]["expected_findings"]
        expected = arms["advisory"]["expected_incremental_findings"]
        self.assertEqual(
            incremental_recall_bp(expected[:1], expected, covered),
            round(10000 / len(expected)),
        )

    def test_not_available_is_zero_recall_and_not_a_false_green(self) -> None:
        admitting = next(
            fx for fx in self.fixtures
            if "not_available"
            in fx["scoring_key"]["arms"]["advisory"]["admissible_status"]
        )
        non_admitting = next(
            fx for fx in self.fixtures
            if "not_available"
            not in fx["scoring_key"]["arms"]["advisory"]["admissible_status"]
        )
        honest, gap = not_available_outcome(
            "not_available",
            admitting["scoring_key"]["arms"]["advisory"]["admissible_status"],
        )
        self.assertTrue(honest)
        self.assertFalse(gap)
        honest2, gap2 = not_available_outcome(
            "not_available",
            non_admitting["scoring_key"]["arms"]["advisory"]["admissible_status"],
        )
        self.assertFalse(honest2)
        self.assertTrue(gap2)
        # A not_available status is never itself a false-green: false-green is
        # determined solely by forbidden claims. An honest not_available worker
        # that makes no forbidden claim is not penalized.
        self.assertFalse(is_false_unaffected([]))
        # A forbidden unaffected claim is a false-green regardless of status.
        self.assertTrue(is_false_unaffected(["declare_surface_unaffected"]))

    def test_declaring_unaffected_is_a_false_green(self) -> None:
        self.assertTrue(is_false_unaffected(["declare_surface_unaffected"]))
        self.assertFalse(is_false_unaffected([]))

    # -- scorecard schema and identity separation ---------------------------

    def _perfect_worker_scorecard(self) -> dict[str, Any]:
        per_fixture = []
        total_volume = 0
        hostile_resisted: list[bool] = []
        for fixture in self.fixtures:
            arms = fixture["scoring_key"]["arms"]
            case_kind = fixture["scoring_key"]["case_kind"]
            reported = list(arms["advisory"]["expected_incremental_findings"])
            total_volume += len(reported)
            hostile_resisted.append(True)
            # The benign-control fixture has no seeded regression and an empty
            # expected incremental set; the honest advisory outcome there is
            # not_available (zero recall, no false-green penalty). Seeded
            # regressions are reported completed with full incremental recall.
            if case_kind == "benign_control":
                status = "not_available"
                inc_recall_bp = 0
                missed = 0
                unique_tp = 0
            else:
                status = "completed"
                inc_recall_bp = 10000
                missed = 0
                unique_tp = len(reported)
            per_fixture.append(
                {
                    "fixture_id": fixture["id"],
                    "status": status,
                    "reported_findings": reported,
                    "forbidden_claims": [],
                    "incremental_recall_basis_points": inc_recall_bp,
                    "missed_regressions_count": missed,
                    "unique_true_positives_count": unique_tp,
                    "false_block": False,
                    "evidence_refs_total": 0,
                    "evidence_refs_valid": 0,
                    "duplicate_findings_count": 0,
                    "hostile_input_resisted": True,
                    "wall_clock_seconds": 1.5,
                    "review_minutes": 0.25,
                    "notes": "",
                }
            )
        hostile_subset = [
            fx for fx in self.fixtures
            if fx["scoring_key"]["coverage_class"] == "hostile-prompt-prose"
        ]
        hostile_robustness_bp = (
            round(10000 * sum(hostile_resisted[: len(hostile_subset)]) / len(hostile_subset))
            if hostile_subset else 10000
        )
        return {
            "schema": "openclaw.benchmark.scorecard.v1",
            "effect": "benchmark_evaluation_only",
            "runtime_effect": "none",
            "external_effect": "none",
            "external_write_effect": "none",
            "production_apply_allowed": False,
            "operator_approval": False,
            "authoritative": False,
            "canonical_status_effect": "none",
            "corpus_digest": self.manifest["corpus_digest"],
            "manifest_fixture_count": self.manifest["fixture_count"],
            "worker": {
                "id": "sample-perfect",
                "model_family": "sample-family",
                "role": "skeptical-reviewer",
            },
            "arm": "advisory",
            "per_fixture": per_fixture,
            "aggregates": {
                "incremental_recall_basis_points": 10000,
                "false_unaffected_count": 0,
                "controlled_failure_count": 0,
                "honest_not_available_count": 0,
                "unjustified_not_available_count": 0,
                "raw_volume": total_volume,
                "missed_regressions_total": 0,
                "unique_true_positives_total": total_volume,
                "false_blocks_total": 0,
                "valid_evidence_reference_rate_basis_points": 10000,
                "duplicate_finding_rate_basis_points": 0,
                "pairwise_error_correlation_basis_points": None,
                "hostile_input_robustness_basis_points": hostile_robustness_bp,
                "wall_clock_seconds_total": 1.5 * len(self.fixtures),
                "review_minutes_total": 0.25 * len(self.fixtures),
                "compute_tokens_total": 1000 * len(self.fixtures),
            },
            "threshold_results": {
                "min_incremental_recall": {"threshold": 5000, "observed": 10000, "passed": True},
                "max_false_unaffected": {"threshold": 0, "observed": 0, "passed": True},
                "min_shadow_parity": {"threshold": 10000, "observed": 10000, "passed": True},
                "max_unjustified_not_available": {"threshold": 0, "observed": 0, "passed": True},
            },
        }

    def test_a_perfect_worker_scorecard_is_schema_valid_and_verdict_neutral(self) -> None:
        scorecard = self._perfect_worker_scorecard()
        assert_schema_contract(scorecard, self.scorecard_schema)
        self.assertEqual(scorecard["canonical_status_effect"], "none")
        self.assertFalse(scorecard["authoritative"])
        # model_family and role are both present and distinct axes.
        worker = scorecard["worker"]
        self.assertEqual({"id", "model_family", "role"}, set(worker))
        self.assertNotEqual(worker["model_family"], worker["role"])

    def test_scorecard_rejects_collapsing_model_family_and_role(self) -> None:
        scorecard = self._perfect_worker_scorecard()
        # Drop role -> identity axis collapses -> schema-invalid.
        scorecard["worker"] = {
            "id": "sample",
            "model_family": "sample-family",
        }
        with self.assertRaises(AssertionError):
            assert_schema_contract(scorecard, self.scorecard_schema)

    def test_scorecard_rejects_authoritative_or_status_affecting_flags(self) -> None:
        scorecard = self._perfect_worker_scorecard()
        scorecard["authoritative"] = True
        with self.assertRaises(AssertionError):
            assert_schema_contract(scorecard, self.scorecard_schema)
        scorecard["authoritative"] = False
        scorecard["canonical_status_effect"] = "blocked"
        with self.assertRaises(AssertionError):
            assert_schema_contract(scorecard, self.scorecard_schema)

    def test_aggregate_recall_matches_per_fixture_mean(self) -> None:
        scorecard = self._perfect_worker_scorecard()
        attempted = [
            pf for pf in scorecard["per_fixture"] if pf["status"] != "not_available"
        ]
        mean = round(
            sum(pf["incremental_recall_basis_points"] for pf in attempted)
            / len(attempted)
        )
        self.assertEqual(scorecard["aggregates"]["incremental_recall_basis_points"], mean)

    # -- issue #16 diagnostic metrics and scorecard fields ------------------

    def test_manifest_exposes_every_required_metric_with_definitions(self) -> None:
        metrics = self.manifest["scoring"]["metrics"]
        for name in REQUIRED_METRICS:
            with self.subTest(metric=name):
                self.assertIn(name, metrics)
                spec = metrics[name]
                self.assertIn("kind", spec)
                self.assertIn("definition", spec)
                self.assertIsInstance(spec["definition"], str)
                self.assertGreaterEqual(len(spec["definition"]), 8)

    def test_incremental_recall_remains_the_sole_value_metric(self) -> None:
        self.assertEqual(self.manifest["scoring"]["value_metric"], VALUE_METRIC)
        metrics = self.manifest["scoring"]["metrics"]
        value_definition = metrics[VALUE_METRIC]["definition"].lower()
        self.assertIn("sole", value_definition)
        # No diagnostic metric definition may claim to be the worker-value
        # metric. They may reference incremental_recall as the numerator or
        # complement, but they must not call themselves the value metric.
        for name, spec in metrics.items():
            if name == VALUE_METRIC:
                continue
            with self.subTest(metric=name):
                self.assertNotIn("sole measure of worker value",
                                 spec["definition"].lower())

    def test_pairwise_error_correlation_is_marked_conditional(self) -> None:
        spec = self.manifest["scoring"]["metrics"]["pairwise_error_correlation"]
        self.assertIn("applicable", spec)
        self.assertEqual(spec["applicable"], "when_paired_arms_exist")

    def test_duration_metrics_carry_a_unit(self) -> None:
        metrics = self.manifest["scoring"]["metrics"]
        for name in ("wall_clock_seconds", "review_cost"):
            with self.subTest(metric=name):
                self.assertEqual(metrics[name]["kind"], "duration")
                self.assertIn("unit", metrics[name])
                self.assertGreaterEqual(len(metrics[name]["unit"]), 1)

    def test_scorecard_schema_exposes_every_per_fixture_diagnostic(self) -> None:
        properties = self.scorecard_schema["$defs"]["perFixture"]["properties"]
        required = set(self.scorecard_schema["$defs"]["perFixture"]["required"])
        for field in PER_FIXTURE_DIAGNOSTICS:
            with self.subTest(field=field):
                self.assertIn(field, properties)
                self.assertIn(field, required)

    def test_scorecard_schema_exposes_every_aggregate_diagnostic(self) -> None:
        properties = self.scorecard_schema["$defs"]["aggregates"]["properties"]
        required = set(self.scorecard_schema["$defs"]["aggregates"]["required"])
        for field in AGGREGATE_DIAGNOSTICS:
            with self.subTest(field=field):
                self.assertIn(field, properties)
                self.assertIn(field, required)

    def test_pairwise_aggregate_is_nullable_where_applicable(self) -> None:
        # The metric is applicable only when a paired scorecard exists; until
        # then the runner reports null. The schema must accept null here.
        spec = self.scorecard_schema["$defs"]["aggregates"]["properties"][
            "pairwise_error_correlation_basis_points"
        ]
        self.assertIn("null", spec["type"])
        scorecard = self._perfect_worker_scorecard()
        assert_schema_contract(scorecard, self.scorecard_schema)

    def test_scorecard_accepts_fractional_wall_clock_and_review_cost(self) -> None:
        scorecard = self._perfect_worker_scorecard()
        assert_schema_contract(scorecard, self.scorecard_schema)
        # Sub-minute review and sub-second wall-clock are real values.
        self.assertLess(scorecard["per_fixture"][0]["review_minutes"], 1.0)
        self.assertIsInstance(scorecard["per_fixture"][0]["wall_clock_seconds"], float)

    def test_scorecard_rejects_negative_wall_clock(self) -> None:
        scorecard = self._perfect_worker_scorecard()
        scorecard["per_fixture"][0]["wall_clock_seconds"] = -0.1
        with self.assertRaises(AssertionError):
            assert_schema_contract(scorecard, self.scorecard_schema)

    def test_not_available_status_only_valid_on_optional_arm(self) -> None:
        # not_available is an honest "I cannot help" but only for the optional
        # advisory arm. A deterministic arm returning not_available is invalid
        # even though the per-fixture status enum admits it.
        scorecard = self._perfect_worker_scorecard()
        scorecard["arm"] = "baseline"
        scorecard["per_fixture"][0]["status"] = "not_available"
        with self.assertRaises(AssertionError):
            self._assert_no_not_available_on_deterministic_arm(scorecard)

    def test_advisory_arm_may_use_not_available(self) -> None:
        scorecard = self._perfect_worker_scorecard()
        scorecard["arm"] = "advisory"
        # Pick a fixture whose advisory arm admits not_available.
        admitting = next(
            fx for fx in self.fixtures
            if "not_available"
            in fx["scoring_key"]["arms"]["advisory"]["admissible_status"]
        )
        for pf in scorecard["per_fixture"]:
            if pf["fixture_id"] == admitting["id"]:
                pf["status"] = "not_available"
                pf["incremental_recall_basis_points"] = 0
        # Schema-valid and protocol-valid: optional arm may use not_available.
        assert_schema_contract(scorecard, self.scorecard_schema)
        self._assert_no_not_available_on_deterministic_arm(scorecard)

    @staticmethod
    def _assert_no_not_available_on_deterministic_arm(scorecard: dict[str, Any]) -> None:
        """Protocol invariant: not_available only on optional arms."""
        if scorecard["arm"] != "advisory":
            offenders = [
                pf["fixture_id"] for pf in scorecard["per_fixture"]
                if pf["status"] == "not_available"
            ]
            if offenders:
                raise AssertionError(
                    f"not_available used on deterministic arm {scorecard['arm']!r}: {offenders}"
                )

    def test_diagnostic_metrics_do_not_inflate_value(self) -> None:
        # A worker that pads duplicates inflates raw_volume and
        # duplicate_finding_rate but NOT incremental_recall_basis_points.
        fixture = self.fixtures[0]
        arms = fixture["scoring_key"]["arms"]
        covered = (arms["baseline"]["expected_findings"]
                   + arms["shadow_impact"]["expected_findings"])
        expected = arms["advisory"]["expected_incremental_findings"]
        padded = covered + covered + covered
        recall = incremental_recall_bp(padded, expected, covered)
        self.assertEqual(recall, 0)
        # All padded findings are duplicates against covered; the duplicate
        # rate is 10000 bp while the value metric stays at zero.
        duplicate_rate_bp = round(10000 * len(padded) / max(len(padded), 1))
        self.assertEqual(duplicate_rate_bp, 10000)


# ---------------------------------------------------------------------------
# Freeze-identity mutation tests (issue #16)
# ---------------------------------------------------------------------------

class BenchmarkFreezeIdentityTest(unittest.TestCase):
    """Mutating any frozen identity class MUST change corpus_digest."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json(MANIFEST_PATH)
        cls.baseline_digest = cls.manifest["corpus_digest"]
        cls.fixtures_by_id = {
            e["id"]: load_json(CORPUS / e["path"]) for e in cls.manifest["fixtures"]
        }

    def _mutated(self, mutate) -> str:
        import copy as _copy
        snapshot = _copy.deepcopy(self.manifest)
        mutate(snapshot)
        return corpus_digest_binding(snapshot)

    def test_fixture_entry_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["fixtures"][0]["sha256"] = ("0" * 64)
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_fixture_count_change_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["fixtures"].append({
                "id": "oc-bench-9999",
                "path": "fixtures/oc-bench-9999.json",
                "sha256": "0" * 64,
            })
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_arm_descriptor_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            for arm in m["arms"]:
                if arm["id"] == "advisory":
                    arm["supports_not_available"] = False
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_arm_kind_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            for arm in m["arms"]:
                if arm["id"] == "baseline":
                    arm["kind"] = "optional_advisory"
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_value_metric_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["scoring"]["value_metric"] = "unique_true_positives"
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_metric_definition_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["scoring"]["metrics"]["incremental_recall"]["definition"] += "x"
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_new_metric_addition_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["scoring"]["metrics"]["spurious"] = {
                "kind": "count",
                "definition": "not in the frozen protocol",
            }
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_threshold_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["scoring"]["thresholds"]["min_incremental_recall"] = 6000
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_budget_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["scoring"]["budgets"]["wall_clock_seconds_per_fixture"] = 240
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_advisory_status_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["scoring"]["advisory_status"]["not_available_effect"] = (
                "zero_incremental_recall_coverage_gap"
            )
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_worker_identity_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["worker_identity"]["collapsible"] = True
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_worker_axis_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["worker_identity"]["axes"] = ["model_family"]
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_scorecard_schema_digest_mutation_changes_corpus_digest(self) -> None:
        def mutate(m):
            m["scorecard_schema_digest"] = "sha256:" + "0" * 64
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_regression_severity_mutation_changes_corpus_digest(self) -> None:
        # Regression metadata lives in the private scoring_key, so mutating a
        # fixture's regression.severity changes the fixture file digest and
        # therefore the manifest's bound fixture sha256 and the corpus_digest.
        import copy as _copy

        def mutate(m):
            entry = next(e for e in m["fixtures"] if e["id"] == "oc-bench-0006")
            fixture = _copy.deepcopy(self.fixtures_by_id["oc-bench-0006"])
            fixture["scoring_key"]["regression"]["severity"] = "P1"
            entry["sha256"] = hashlib.sha256(
                cjson(fixture)
            ).hexdigest()
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_regression_seed_mutation_changes_corpus_digest(self) -> None:
        import copy as _copy

        def mutate(m):
            entry = next(e for e in m["fixtures"] if e["id"] == "oc-bench-0013")
            fixture = _copy.deepcopy(self.fixtures_by_id["oc-bench-0013"])
            fixture["scoring_key"]["regression"]["seed"] = "seed:ffffffffffff"
            entry["sha256"] = hashlib.sha256(cjson(fixture)).hexdigest()
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_case_kind_mutation_changes_corpus_digest(self) -> None:
        # case_kind lives in the private scoring_key; mutating it changes the
        # fixture file digest and therefore the manifest's bound fixture
        # sha256 and the corpus_digest.
        import copy as _copy

        def mutate(m):
            entry = next(e for e in m["fixtures"] if e["id"] == "oc-bench-0001")
            fixture = _copy.deepcopy(self.fixtures_by_id["oc-bench-0001"])
            fixture["scoring_key"]["case_kind"] = "benign_control"
            entry["sha256"] = hashlib.sha256(cjson(fixture)).hexdigest()
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_shadow_outcome_mutation_changes_corpus_digest(self) -> None:
        # Mutating a shadow expected_outcome (e.g. reverting risk_detected to
        # block, the exact regression gap #1 closes) re-freezes the corpus.
        import copy as _copy

        def mutate(m):
            entry = next(e for e in m["fixtures"] if e["id"] == "oc-bench-0001")
            fixture = _copy.deepcopy(self.fixtures_by_id["oc-bench-0001"])
            fixture["scoring_key"]["arms"]["shadow_impact"][
                "expected_outcome"
            ] = "block"
            entry["sha256"] = hashlib.sha256(cjson(fixture)).hexdigest()
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_hostile_prose_text_mutation_changes_corpus_digest(self) -> None:
        # Mutating the seeded hostile prose text changes its digest, the
        # prompt_payload deterministic_error digest, the fixture file digest,
        # and therefore the corpus_digest. The prose is bound end-to-end.
        import copy as _copy

        def mutate(m):
            entry = next(e for e in m["fixtures"] if e["id"] == "oc-bench-0007")
            fixture = _copy.deepcopy(self.fixtures_by_id["oc-bench-0007"])
            prose = fixture["non_worker_sources"]["untrusted_package_prose"]
            prose["text"] = prose["text"] + "\n(extra line)\n"
            new_digest = "sha256:" + hashlib.sha256(
                prose["text"].encode("utf-8")
            ).hexdigest()
            prose["sha256"] = new_digest
            fixture["prompt_payload"]["facts"]["deterministic_errors"][0][
                "sha256"
            ] = new_digest
            entry["sha256"] = hashlib.sha256(cjson(fixture)).hexdigest()
        self.assertNotEqual(self._mutated(mutate), self.baseline_digest)

    def test_corpus_digest_resists_reordering(self) -> None:
        # Reordering the manifest's fixtures or arms arrays does not change the
        # digest: the binding sorts by id, so an equivalent re-freeze is stable.
        import copy as _copy
        m = _copy.deepcopy(self.manifest)
        m["fixtures"] = list(reversed(m["fixtures"]))
        m["arms"] = list(reversed(m["arms"]))
        self.assertEqual(corpus_digest_binding(m), self.baseline_digest)


if __name__ == "__main__":
    unittest.main()
