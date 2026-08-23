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
            "npmIntegrity": "sha512-" + "b" * 64,
            "gitSha": None,
            "buildDigest": None,
        }
        self._write_candidate_lock()
        self.receipt = self._write_kova_run()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_candidate_lock(self) -> None:
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
                            "identity": "openclaw@1.1.0",
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
        return {
            "scenario": scenario,
            "status": status,
            "privateLog": "PRIVATE-CONVERSATION-MUST-NOT-LEAK",
            "evidenceLedger": {
                "schemaVersion": "kova.evidenceLedger.v1",
                "completeness": "complete" if status == "PASS" else "failed",
                "summary": {
                    "required": 1,
                    "byStatus": {"passed" if status == "PASS" else "failed": 1},
                },
                "entries": [
                    {
                        "id": f"{scenario}-proof",
                        "required": True,
                        "status": "passed" if status == "PASS" else "failed",
                    }
                ],
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
    ) -> Path:
        records = [
            self._record(scenario, (statuses or {}).get(scenario, "PASS"))
            for scenario in REQUIRED_SCENARIOS
            if scenario != omit_scenario
        ]
        counts: dict[str, int] = {}
        for record in records:
            status = str(record["status"])
            counts[status] = counts.get(status, 0) + 1
        summary = {"total": len(records), "statuses": counts}
        target_identity = self.identity if identity is True else identity
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
            report_path.name: report_payload,
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
                "environment-matched-rehearsal",
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
