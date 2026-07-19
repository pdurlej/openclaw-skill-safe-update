import json
from pathlib import Path
import unittest

from tests.test_openclaw_benchmark import assert_schema_contract


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
DOC_PATH = ROOT / "references" / "phase-handoffs.md"
DIGEST = "sha256:" + ("a" * 64)
OTHER_DIGEST = "sha256:" + ("b" * 64)
GATE_IDS = {
    "lifecycle-download-evidence",
    "state-migration-rehearsal",
    "rollback-evidence",
    "plugin-sdk-contract",
    "launcher-service-contract",
    "permissions-contract",
    "protocol-contract",
    "channel-crypto-contract",
    "environment-matched-rehearsal",
}


SCHEMA_PATHS = {
    "preflight": SCHEMA_DIR / "openclaw.safe_update.preflight_handoff.v1.schema.json",
    "migration": SCHEMA_DIR / "openclaw.safe_update.migration_handoff.v1.schema.json",
    "activation": SCHEMA_DIR / "openclaw.safe_update.activation_handoff.v1.schema.json",
    "forward": SCHEMA_DIR / "openclaw.safe_update.forward_reconcile_handoff.v1.schema.json",
}


def load_schema(name: str) -> dict:
    return json.loads(SCHEMA_PATHS[name].read_text(encoding="utf-8"))


def base_handoff(schema: str) -> dict:
    return {
        "schema": schema,
        "effect": "read_only_phase_handoff",
        "runtime_effect": "none",
        "external_effect": "none",
        "external_write_effect": "none",
        "production_apply_allowed": False,
        "operator_approval": False,
        "authoritative": False,
        "candidate_root": DIGEST,
        "source_status_digest": OTHER_DIGEST,
        "producer": "producer",
        "consumer": "consumer",
        "handoff_status": "ready",
    }


def phase_examples() -> dict[str, dict]:
    preflight = base_handoff("openclaw.safe_update.preflight_handoff.v1")
    preflight.update(
        required_gate_ids=[],
        preflight_status="ready_for_operator_plan",
        decision_digest=DIGEST,
        live_e2e="not_run",
    )
    migration = base_handoff("openclaw.safe_update.migration_handoff.v1")
    migration.update(
        state_migration_gate="state-migration-rehearsal",
        disposable_environment_digest=DIGEST,
        state_snapshot_digest=DIGEST,
        migration_evidence_digest=DIGEST,
        restore_evidence_digest=DIGEST,
    )
    activation = base_handoff("openclaw.safe_update.activation_handoff.v1")
    activation.update(
        activation_approval="external_explicit_required",
        activation_boundary_digest=DIGEST,
        point_of_no_return="before_activation",
        rollback_boundary="known",
        rollback_gate="rollback-evidence",
        rollback_evidence_digest=DIGEST,
        forward_recovery_rule_digest=None,
        e2e_plan_digest=DIGEST,
        live_e2e="not_run",
    )
    forward = base_handoff(
        "openclaw.safe_update.forward_reconcile_handoff.v1"
    )
    forward.update(
        operational_approval="external_explicit_required",
        activation_receipt_digest=DIGEST,
        post_activation_e2e="failed",
        post_activation_e2e_digest=DIGEST,
        forward_recovery_rule_digest=DIGEST,
        rollback_or_containment_rule_digest=DIGEST,
    )
    return {
        "preflight": preflight,
        "migration": migration,
        "activation": activation,
        "forward": forward,
    }


class PhaseHandoffContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.schemas = {name: load_schema(name) for name in SCHEMA_PATHS}
        self.examples = phase_examples()

    def test_examples_are_schema_valid(self) -> None:
        for name, example in self.examples.items():
            assert_schema_contract(example, self.schemas[name])

    def test_schemas_are_strict_and_read_only(self) -> None:
        for schema in self.schemas.values():
            self.assertFalse(schema["additionalProperties"])
            properties = schema["properties"]
            self.assertEqual(properties["runtime_effect"]["const"], "none")
            self.assertEqual(properties["external_effect"]["const"], "none")
            self.assertEqual(properties["external_write_effect"]["const"], "none")
            self.assertFalse(properties["production_apply_allowed"]["const"])
            self.assertFalse(properties["operator_approval"]["const"])
            self.assertFalse(properties["authoritative"]["const"])

    def test_preflight_remains_preflight_only(self) -> None:
        preflight = self.examples["preflight"]
        self.assertEqual(
            preflight["preflight_status"], "ready_for_operator_plan"
        )
        self.assertEqual(preflight["live_e2e"], "not_run")
        self.assertFalse(preflight["production_apply_allowed"])
        self.assertFalse(preflight["operator_approval"])

    def test_migration_handoff_binds_snapshot_migrate_and_restore_evidence(self) -> None:
        migration = self.examples["migration"]
        for field in (
            "disposable_environment_digest",
            "state_snapshot_digest",
            "migration_evidence_digest",
            "restore_evidence_digest",
        ):
            self.assertRegex(migration[field], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            migration["state_migration_gate"], "state-migration-rehearsal"
        )

    def test_unknown_rollback_boundary_is_a_stable_blocker(self) -> None:
        activation = self.examples["activation"]
        activation["handoff_status"] = "blocked"
        activation["point_of_no_return"] = "unknown"
        activation["rollback_boundary"] = "unknown"
        activation["rollback_evidence_digest"] = None
        self.assertEqual(activation["handoff_status"], "blocked")
        self.assertEqual(activation["rollback_gate"], "rollback-evidence")
        self.assertIsNone(activation["rollback_evidence_digest"])
        assert_schema_contract(activation, self.schemas["activation"])

    def test_forward_reconcile_has_separate_approval_and_containment(self) -> None:
        forward = self.examples["forward"]
        self.assertEqual(
            forward["operational_approval"], "external_explicit_required"
        )
        self.assertRegex(
            forward["rollback_or_containment_rule_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertFalse(forward["operator_approval"])

    def test_gate_ids_match_the_policy_owned_set(self) -> None:
        self.assertEqual(
            set(self.schemas["preflight"]["$defs"]["gateId"]["enum"]),
            GATE_IDS,
        )

    def test_contract_contains_no_live_command_surface(self) -> None:
        text = DOC_PATH.read_text(encoding="utf-8") + "".join(
            path.read_text(encoding="utf-8") for path in SCHEMA_PATHS.values()
        )
        for banned in (
            "openclaw update",
            "systemctl restart",
            "runtime-deps repair",
            "npm install -g",
        ):
            self.assertNotIn(banned, text)

    def test_unknown_fields_and_authority_escalation_are_not_schema_members(self) -> None:
        example = dict(self.examples["activation"])
        example["apply_command"] = "forbidden"
        with self.assertRaises(AssertionError):
            assert_schema_contract(example, self.schemas["activation"])
        self.assertFalse(example["operator_approval"])


if __name__ == "__main__":
    unittest.main()
