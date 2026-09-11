from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tests.test_openclaw_benchmark import assert_schema_contract


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "openclaw_safe_update.py"
POLICY_EXAMPLE = ROOT / "examples" / "kova-evidence-policy.example.json"
EVIDENCE_SCHEMA = (
    ROOT / "schemas" / "openclaw.safe_update.kova_evidence.v1.schema.json"
)

SCRIPT_SPEC = importlib.util.spec_from_file_location("openclaw_safe_update_kova", SCRIPT)
assert SCRIPT_SPEC is not None and SCRIPT_SPEC.loader is not None
SAFE_UPDATE = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(SAFE_UPDATE)


REQUIRED_SCENARIOS = (
    "upgrade-existing-user",
    "release-runtime-startup",
    "official-plugin-install",
    "plugin-lifecycle",
    "mcp-runtime-start-stop",
    "mcp-tool-call",
)
NPM_INTEGRITY = "sha512-" + __import__("base64").b64encode(b"b" * 64).decode("ascii")
REQUIRED_EVIDENCE = {
    item["id"]: item["required_evidence"]
    for item in json.loads(POLICY_EXAMPLE.read_text(encoding="utf-8"))["scenarios"]
}


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def add_tar_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.mode = 0o644
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))


class KovaEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy = self.root / "policy.json"
        self.policy.write_bytes(POLICY_EXAMPLE.read_bytes())
        self.candidate_lock = self.root / "installation-candidate-lock.json"
        self.output = self.root / "kova-evidence.json"
        self.verdict = self.root / "verdict.json"
        self.verdict.write_bytes(b'{"sentinel":"unchanged"}\n')
        self.identity = {
            "schemaVersion": "kova.target.identity.v1",
            "requestedSelector": "npm:1.1.0",
            "resolvedVersion": "1.1.0",
            "npmIntegrity": NPM_INTEGRITY,
            "gitSha": None,
            "buildDigest": None,
        }
        self._write_candidate_lock()
        self.receipt = self._write_kova_run()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_candidate_lock(self, artifact_identity: str = "openclaw@1.1.0") -> None:
        target_content = {
            "schema": "openclaw.safe_update.installation_candidate.v1",
            "lane": "target",
            "core_root": "sha256:" + "1" * 64,
            "installation_contract_digest": "sha256:" + "2" * 64,
            "composition_policy_version": "1",
            "analyzer_version": "1.0.0",
            "environment": {
                "node_version": "22.14.0",
                "npm_version": "11.4.2",
                "os": "linux",
                "arch": "x64",
                "libc": "glibc",
            },
            "components": [
                {
                    "id": "core.openclaw",
                    "roles": ["core"],
                    "application_phases": ["core"],
                    "artifacts": [
                        {
                            "kind": "npm_package",
                            "ref": "openclaw",
                            "identity": artifact_identity,
                            "integrity": self.identity["npmIntegrity"],
                        }
                    ],
                    "contracts": [],
                    "depends_on": [],
                    "supports": ["openclaw.core"],
                    "governance_digest": "sha256:" + "3" * 64,
                }
            ],
        }
        target = {
            **target_content,
            "root": SAFE_UPDATE.canonical_digest(target_content),
        }
        document = {
            "schema": "openclaw.safe_update.installation_candidate_lock.v1",
            "generated_at": "2026-08-23T00:00:00+00:00",
            "effect": "read_only_openclaw_update_rehearsal",
            "runtime_effect": "none",
            "external_effect": "npm_registry_read_only",
            "external_write_effect": "none",
            "production_apply_allowed": False,
            "operator_approval": False,
            "status": "success",
            "current_root": "sha256:" + "4" * 64,
            "target_root": target["root"],
            "current": None,
            "target": target,
            "errors": [],
        }
        self.candidate_lock.write_bytes(json_bytes(document))

    def _record(self, scenario: str, status: str = "PASS") -> dict[str, object]:
        ledger_status = "passed" if status == "PASS" else "failed"
        entries = [
            {
                "id": item["id"],
                "category": item["category"],
                "required": True,
                "status": ledger_status,
            }
            for item in REQUIRED_EVIDENCE[scenario]
        ]
        by_category: dict[str, int] = {}
        for item in entries:
            by_category[item["category"]] = by_category.get(item["category"], 0) + 1
        return {
            "scenario": scenario,
            "status": status,
            "privateLog": "PRIVATE-CONVERSATION-MUST-NOT-LEAK",
            "evidenceLedger": {
                "schemaVersion": "kova.evidenceLedger.v1",
                "completeness": "complete" if status == "PASS" else "failed",
                "summary": {
                    "total": len(entries),
                    "required": len(entries),
                    "requiredMissing": 0,
                    "requiredFailed": 0 if status == "PASS" else len(entries),
                    "byStatus": {ledger_status: len(entries)},
                    "byCategory": by_category,
                },
                "entries": entries,
            },
        }

    def _write_kova_run(
        self,
        *,
        statuses: dict[str, str] | None = None,
        omit_scenario: str | None = None,
        identity: dict[str, object] | None | bool = True,
        receipt_schema: str = "kova.matrix.run.receipt.v1",
        report_schema: str = "kova.report.v1",
        publication_omission: bool = False,
        corrupt_indexed_member: bool = False,
        empty_ledgers: bool = False,
        malformed_ledger: bool = False,
        contradictory_ledger_summary: bool = False,
        arbitrary_evidence: bool = False,
        platform: dict[str, str] | None | bool = True,
    ) -> Path:
        records = [
            self._record(scenario, (statuses or {}).get(scenario, "PASS"))
            for scenario in REQUIRED_SCENARIOS
            if scenario != omit_scenario
        ]
        if empty_ledgers:
            for record in records:
                record["evidenceLedger"]["entries"] = []
                record["evidenceLedger"]["summary"] = {
                    "total": 0,
                    "required": 0,
                    "requiredMissing": 0,
                    "requiredFailed": 0,
                    "byStatus": {},
                    "byCategory": {},
                }
        if malformed_ledger:
            records[0]["evidenceLedger"]["entries"] = [None]
        if contradictory_ledger_summary:
            for record in records:
                record["evidenceLedger"]["summary"]["requiredMissing"] = 1
                record["evidenceLedger"]["summary"]["requiredFailed"] = 1
        if arbitrary_evidence:
            for record in records:
                record["evidenceLedger"] = {
                    "schemaVersion": "kova.evidenceLedger.v1",
                    "completeness": "complete",
                    "summary": {
                        "total": 1,
                        "required": 1,
                        "requiredMissing": 0,
                        "requiredFailed": 0,
                        "byStatus": {"passed": 1},
                        "byCategory": {"x": 1},
                    },
                    "entries": [
                        {"id": "x", "category": "x", "required": True, "status": "passed"}
                    ],
                }
        counts: dict[str, int] = {}
        for record in records:
            status = str(record["status"])
            counts[status] = counts.get(status, 0) + 1
        summary = {"total": len(records), "statuses": counts}
        target_identity = self.identity if identity is True else identity
        if target_identity is not None:
            for record in records:
                record["targetIdentity"] = target_identity
        report: dict[str, object] = {
            "schemaVersion": report_schema,
            "generatedAt": "2026-08-23T00:00:00.000Z",
            "runId": "kova-20260823-000000-public",
            "mode": "execution",
            "target": "npm:1.1.0",
            "gate": None,
            "summary": summary,
            "records": records,
        }
        if platform is True:
            report["platform"] = {
                "os": "linux",
                "arch": "x64",
                "libc": "glibc",
                "node": "v22.14.0",
                "npm": "11.4.2",
            }
        elif isinstance(platform, dict):
            report["platform"] = platform
        if target_identity is not None:
            report["targetIdentity"] = target_identity
        report_path = self.root / "kova-run.json"
        report_payload = json_bytes(report)
        report_path.write_bytes(report_payload)
        summary_payload = json_bytes(summary)
        manifest_payload = json_bytes(
            {
                "schemaVersion": "kova.bundle.manifest.v1",
                "runId": report["runId"],
                "publicationOmissions": {
                    "fileCount": 1 if publication_omission else 0,
                    "totalBytes": 5 if publication_omission else 0,
                },
            }
        )
        files = {
            "report.json": report_payload,
            "kova-run.summary.json": summary_payload,
            "manifest.json": manifest_payload,
        }
        bundle_root = "kova-run-bundle"
        entries = [
            {
                "path": name,
                "archivePath": name,
                "bytes": len(payload),
                "sha256": sha256(payload),
            }
            for name, payload in sorted(files.items())
        ]
        omission_entries = (
            [
                {
                    "path": "artifacts/node-profiles/node-trace-private.json",
                    "bytes": 5,
                    "sha256": "a" * 64,
                    "reason": "publication-limit",
                }
            ]
            if publication_omission
            else []
        )
        artifact_index = {
            "schemaVersion": "kova.artifact.index.v1",
            "generatedAt": "2026-08-23T00:00:00.000Z",
            "bundleRoot": bundle_root,
            "fileCount": len(entries),
            "totalBytes": sum(item["bytes"] for item in entries),
            "publicationOmissions": {
                "fileCount": len(omission_entries),
                "totalBytes": sum(item["bytes"] for item in omission_entries),
                "entries": omission_entries,
            },
            "entries": entries,
        }
        bundle_path = self.root / "kova-run-bundle.tar.gz"
        with tarfile.open(bundle_path, "w:gz") as archive:
            for name, payload in sorted(files.items()):
                if corrupt_indexed_member and name == "manifest.json":
                    payload = payload + b"tampered"
                add_tar_bytes(archive, f"{bundle_root}/{name}", payload)
            add_tar_bytes(
                archive,
                f"{bundle_root}/artifact-index.json",
                json_bytes(artifact_index),
            )
        checksum_path = self.root / "kova-run-bundle.tar.gz.sha256"
        checksum_path.write_text(
            f"{sha256(bundle_path.read_bytes())}  {bundle_path.name}\n",
            encoding="ascii",
        )
        receipt: dict[str, object] = {
            "schemaVersion": receipt_schema,
            "generatedAt": "2026-08-23T00:00:01.000Z",
            "mode": "execution",
            "runId": report["runId"],
            "jsonPath": str(report_path),
            "bundlePath": str(bundle_path),
            "checksumPath": str(checksum_path),
            "gate": None,
            "summary": summary,
        }
        if target_identity is not None:
            receipt["targetIdentity"] = target_identity
        receipt_path = self.root / "kova-receipt.json"
        receipt_path.write_bytes(json_bytes(receipt))
        return receipt_path

    def run_import(self, output: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "kova-evidence",
                "--receipt",
                str(self.receipt),
                "--candidate-lock",
                str(self.candidate_lock),
                "--policy",
                str(self.policy),
                "--output",
                str(output or self.output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def read_output(self, output: Path | None = None) -> dict[str, object]:
        return json.loads((output or self.output).read_text(encoding="utf-8"))

    def test_exact_all_pass_bundle_is_accepted_and_schema_valid(self) -> None:
        before = self.verdict.read_bytes()

        result = self.run_import()

        self.assertEqual(result.returncode, 0, result.stderr)
        document = self.read_output()
        self.assertEqual(document["status"], "accepted")
        self.assertEqual(document["evidence_content"]["candidate_binding"]["status"], "exact")
        self.assertEqual(
            [item["id"] for item in document["evidence_content"]["eligible_gates"]],
            [
                "launcher-service-contract",
                "plugin-sdk-contract",
                "protocol-contract",
                "state-migration-rehearsal",
            ],
        )
        schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
        assert_schema_contract(document, schema)
        self.assertEqual(self.verdict.read_bytes(), before)
        self.assertNotIn(str(self.root), json.dumps(document))
        self.assertNotIn("PRIVATE-CONVERSATION", json.dumps(document))

    def test_current_kova_without_exact_identity_is_incomplete(self) -> None:
        self.receipt = self._write_kova_run(identity=None)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertEqual(document["evidence_content"]["candidate_binding"]["status"], "missing")
        self.assertEqual(document["evidence_content"]["eligible_gates"], [])

    def test_version_only_identity_is_diagnostic_not_gate_evidence(self) -> None:
        identity = copy.deepcopy(self.identity)
        identity["npmIntegrity"] = None
        self.receipt = self._write_kova_run(identity=identity)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertEqual(document["evidence_content"]["candidate_binding"]["status"], "version_only")

    def test_missing_environment_identity_is_incomplete(self) -> None:
        self.require_environment_gate()
        self.receipt = self._write_kova_run(platform=None)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertIn(
            "target-environment-incomplete",
            document["evidence_content"]["error_codes"],
        )

    def test_different_harness_platform_leaves_target_environment_incomplete(self) -> None:
        self.require_environment_gate()
        self.receipt = self._write_kova_run(
            platform={
                "os": "darwin",
                "arch": "arm64",
                "libc": "none",
                "node": "v22.14.0",
                "npm": "11.4.2",
            }
        )

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertIn(
            "target-environment-incomplete",
            document["evidence_content"]["error_codes"],
        )

    def test_partial_harness_platform_is_not_target_environment_proof(self) -> None:
        self.require_environment_gate()
        self.receipt = self._write_kova_run(
            platform={"os": "darwin", "arch": "arm64", "node": "v22.14.0"}
        )

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertIn(
            "target-environment-incomplete",
            document["evidence_content"]["error_codes"],
        )

    def require_environment_gate(self) -> None:
        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        policy["scenarios"][0]["gate_ids"].append("environment-matched-rehearsal")
        self.policy.write_bytes(json_bytes(policy))

    def test_harness_platform_cannot_attest_target_toolchain(self) -> None:
        self.require_environment_gate()
        self.assertEqual(self.run_import().returncode, 2)
        self.assertEqual(self.read_output()["status"], "incomplete")

    def test_upstream_harness_platform_accepts_core_evidence_only(self) -> None:
        self.receipt = self._write_kova_run(platform={
            "os": "darwin", "arch": "arm64", "release": "test", "node": "v26.8.1",
        })
        self.assertEqual(self.run_import().returncode, 0)
        document = self.read_output()["evidence_content"]
        self.assertEqual(document["candidate_binding"]["scope"], "core_npm_artifact_only")
        self.assertNotIn("environment-matched-rehearsal", [g["id"] for g in document["eligible_gates"]])

    def test_mixed_record_target_identity_is_rejected(self) -> None:
        report = {"targetIdentity": self.identity, "records": [
            {"status": "PASS", "targetIdentity": {**self.identity, "resolvedVersion": "2.0.0"}},
        ]}
        with self.assertRaises(SAFE_UPDATE.KovaEvidenceImportError):
            SAFE_UPDATE.validate_kova_target_identity(
                {"targetIdentity": self.identity}, report, {}, ["npm_integrity"],
            )

    def test_missing_record_identity_stays_incomplete(self) -> None:
        binding, missing, errors = SAFE_UPDATE.validate_kova_target_identity(
            {"targetIdentity": self.identity},
            {"targetIdentity": self.identity, "records": [{"status": "PASS"}]},
            {}, ["npm_integrity"],
        )
        self.assertEqual(binding["status"], "missing")
        self.assertIn("record-target-identity", missing)

    def test_snapshot_presence_alone_does_not_prove_preservation(self) -> None:
        record = self._record("upgrade-existing-user")
        ledger = record["evidenceLedger"]
        ledger["entries"] = [e for e in ledger["entries"] if e["id"] in {
            "invariant:upgrade-state-snapshots-present", "collector:final-metrics",
        }]
        ledger["summary"] = {
            "total": 2, "required": 2, "requiredMissing": 0, "requiredFailed": 0,
            "byStatus": {"passed": 2}, "byCategory": {"invariant": 1, "collector": 1},
        }
        policy = json.loads(self.policy.read_text())
        _, missing, errors = SAFE_UPDATE.aggregate_kova_scenarios(
            {"records": [record], "summary": {"total": 1, "statuses": {"PASS": 1}}}, policy,
        )
        self.assertIn("ledger-proof:upgrade-existing-user", missing)
        self.assertIn("required-ledger-proof-missing", errors)

    def test_each_negative_or_unknown_status_fails_closed(self) -> None:
        for status in ("FAIL", "BLOCKED", "INCOMPLETE", "SKIPPED", "DRY-RUN", "TIMED_OUT"):
            with self.subTest(status=status):
                self.receipt = self._write_kova_run(
                    statuses={"mcp-tool-call": status}
                )
                result = self.run_import()
                self.assertEqual(result.returncode, 2)
                self.assertIn(
                    self.read_output()["status"],
                    {"incomplete", "rejected"},
                )

    def test_missing_required_scenario_is_incomplete(self) -> None:
        self.receipt = self._write_kova_run(omit_scenario="plugin-lifecycle")

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertIn(
            "scenario:plugin-lifecycle",
            document["evidence_content"]["missing_requirements"],
        )

    def test_unknown_receipt_or_report_schema_is_rejected(self) -> None:
        for kwargs in (
            {"receipt_schema": "kova.matrix.run.receipt.v999"},
            {"report_schema": "kova.report.v999"},
        ):
            with self.subTest(kwargs=kwargs):
                self.receipt = self._write_kova_run(**kwargs)
                result = self.run_import()
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.read_output()["status"], "rejected")

    def test_candidate_identity_mismatch_is_rejected(self) -> None:
        identity = copy.deepcopy(self.identity)
        identity["npmIntegrity"] = "sha512-" + "c" * 64
        self.receipt = self._write_kova_run(identity=identity)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "rejected")
        self.assertEqual(document["evidence_content"]["candidate_binding"]["status"], "mismatch")

    def test_empty_evidence_ledgers_cannot_produce_gate_evidence(self) -> None:
        self.receipt = self._write_kova_run(empty_ledgers=True)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertEqual(document["evidence_content"]["eligible_gates"], [])

    def test_malformed_evidence_ledger_entry_is_rejected_without_crashing(self) -> None:
        self.receipt = self._write_kova_run(malformed_ledger=True)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.read_output()["status"], "incomplete")

    def test_candidate_lock_package_coordinate_must_match_policy_ref(self) -> None:
        self._write_candidate_lock(artifact_identity="attacker@1.1.0")

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "rejected")
        self.assertIn("candidate-binding-mismatch", document["evidence_content"]["error_codes"])

    def test_policy_cannot_advertise_unverifiable_git_sha_binding(self) -> None:
        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        policy["target_binding"]["accepted_identity_kinds"] = ["git_sha"]
        self.policy.write_bytes(json_bytes(policy))

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.read_output()["status"], "rejected")

    def test_malformed_npm_integrity_cannot_be_exact_identity(self) -> None:
        self.identity["npmIntegrity"] = "sha512-"
        self._write_candidate_lock()
        self.receipt = self._write_kova_run(identity=self.identity)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.read_output()["status"], "rejected")

    def test_contradictory_ledger_summary_cannot_produce_gate_evidence(self) -> None:
        self.receipt = self._write_kova_run(contradictory_ledger_summary=True)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertEqual(document["evidence_content"]["eligible_gates"], [])

    def test_arbitrary_typed_ledger_tokens_cannot_satisfy_policy(self) -> None:
        self.receipt = self._write_kova_run(arbitrary_evidence=True)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "incomplete")
        self.assertIn("required-ledger-proof-missing", document["evidence_content"]["error_codes"])

    def test_bundle_member_tamper_is_rejected_even_with_fresh_outer_checksum(self) -> None:
        self.receipt = self._write_kova_run(corrupt_indexed_member=True)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        document = self.read_output()
        self.assertEqual(document["status"], "rejected")
        self.assertIn(
            "bundle-member-digest-mismatch",
            document["evidence_content"]["error_codes"],
        )

    def test_publication_omission_is_rejected(self) -> None:
        self.receipt = self._write_kova_run(publication_omission=True)

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "publication-omission",
            self.read_output()["evidence_content"]["error_codes"],
        )

    def test_evidence_digest_is_stable_across_output_envelopes(self) -> None:
        first = self.root / "first.json"
        second = self.root / "second.json"

        self.assertEqual(self.run_import(first).returncode, 0)
        self.assertEqual(self.run_import(second).returncode, 0)

        self.assertEqual(
            self.read_output(first)["evidence_digest"],
            self.read_output(second)["evidence_digest"],
        )

    def test_duplicate_policy_scenario_ids_are_rejected(self) -> None:
        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        policy["scenarios"].append(copy.deepcopy(policy["scenarios"][0]))
        self.policy.write_bytes(json_bytes(policy))

        result = self.run_import()

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "policy-invalid",
            self.read_output()["evidence_content"]["error_codes"],
        )


if __name__ == "__main__":
    unittest.main()
