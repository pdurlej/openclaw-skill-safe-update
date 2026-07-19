from __future__ import annotations

import base64
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
import threading
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "openclaw_safe_update.py"
WORKFLOW = ROOT / "assets" / "github-workflows" / "openclaw-safe-update.yml"
VALIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
README = ROOT / "README.md"
LICENSE = ROOT / "LICENSE"
UPGRADE_ISSUE_TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE" / "upgrade-experience.yml"
HERO = ROOT / "assets" / "brand" / "openclaw-safe-upgrade-hero.png"
CLAWHUB_IGNORE = ROOT / ".clawhubignore"
STATUS_SCHEMA = ROOT / "schemas" / "openclaw.safe_update.status.v2.schema.json"
INSTALLATION_CANDIDATE_SCHEMA = (
    ROOT / "schemas" / "openclaw.safe_update.installation_candidate_lock.v1.schema.json"
)
INSTALLATION_ATTESTATION_SCHEMA = (
    ROOT / "schemas" / "openclaw.safe_update.installation_attestation.v1.schema.json"
)
CONSERVATIVE_GATES_SCHEMA = (
    ROOT / "schemas" / "openclaw.safe_update.conservative_gates.v1.schema.json"
)
CONSERVATIVE_INPUTS_SCHEMA = (
    ROOT / "schemas" / "openclaw.safe_update.conservative_inputs.v1.schema.json"
)
IMPACT_SHADOW_SCHEMA = (
    ROOT / "schemas" / "openclaw.safe_update.impact_shadow.v1.schema.json"
)
ANALYSIS_CACHE_SCHEMA = (
    ROOT / "schemas" / "openclaw.safe_update.analysis_cache.v1.schema.json"
)
ARCHIVE_EXECUTION_SCHEMA = (
    ROOT / "schemas" / "openclaw.safe_update.archive_execution.v1.schema.json"
)
BASELINE = ROOT / "references" / "v1.1-baseline.json"
SIGNAL_VOICE_CONTRACT = ROOT / "examples" / "signal-voice.installation-contract.json"
COMPOSED_INSTALLATION_CONTRACT = (
    ROOT / "examples" / "composed-installation.installation-contract.json"
)
BASELINE_SHA = "58f98a3c6a6448fb7e54124c030a18a47e1f7d1c"
BASELINE_TEST_CASES = [
    "test_archive_filename_traversal_blocks",
    "test_coverage_rejects_required_surface_without_postcheck",
    "test_fetch_pins_public_npm_registry",
    "test_fetch_rejects_version_ranges",
    "test_green_rehearsal_produces_hash_bound_evidence",
    "test_incompatible_runtime_node_blocks",
    "test_integrity_mismatch_blocks",
    "test_inventory_writes_public_safe_draft_profiles",
    "test_lifecycle_script_change_blocks",
    "test_missing_coverage_profile_blocks",
    "test_missing_customization_manifest_blocks_and_keeps_artifacts",
    "test_public_product_surface_preserves_rehearsal_boundary",
    "test_workflow_has_no_apply_or_external_write_surface",
]

SCRIPT_SPEC = importlib.util.spec_from_file_location("openclaw_safe_update", SCRIPT)
assert SCRIPT_SPEC is not None and SCRIPT_SPEC.loader is not None
SAFE_UPDATE = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(SAFE_UPDATE)


def core_closure(
    version: str,
    dependencies: list[tuple[str, str]] | None = None,
    *,
    root_integrity: str | None = None,
    environment: dict[str, str] | None = None,
    optional_selector: dict[str, list[str]] | None = None,
    install_script_packages: set[str] | None = None,
) -> dict[str, object]:
    packages: dict[str, object] = {
        "": {
            "name": "openclaw-safe-update-candidate",
            "version": "0.0.0",
            "dependencies": {"openclaw": version},
        },
        "node_modules/openclaw": {
            "version": version,
            "resolved": f"https://registry.npmjs.org/openclaw/-/openclaw-{version}.tgz",
            "integrity": root_integrity
            or "sha512-" + ("a" if version == "1.0.0" else "b") * 64,
        },
    }
    for name, dependency_version in dependencies or []:
        path = f"node_modules/{name}"
        entry: dict[str, object] = {
            "version": dependency_version,
            "resolved": (
                f"https://registry.npmjs.org/{name}/-/"
                f"{name.rsplit('/', 1)[-1]}-{dependency_version}.tgz"
            ),
            "integrity": "sha512-" + hashlib.sha256(
                f"{name}@{dependency_version}".encode()
            ).hexdigest(),
        }
        if optional_selector and name in optional_selector:
            entry["optional"] = True
            entry["os"] = optional_selector[name]
        if install_script_packages and name in install_script_packages:
            entry["hasInstallScript"] = True
        packages[path] = entry
    return SAFE_UPDATE.build_core_closure(
        {"lockfileVersion": 3, "packages": packages},
        "openclaw",
        version,
        environment
        or {
            "node_version": "22.14.0",
            "npm_version": "11.4.2",
            "os": "linux",
            "arch": "x64",
            "libc": "glibc",
        },
    )


def write_archive(
    path: Path,
    version: str,
    members: dict[str, str],
    package_metadata: dict[str, object] | None = None,
) -> None:
    package_document: dict[str, object] = {"name": "openclaw", "version": version}
    package_document.update(package_metadata or {})
    package_json = json.dumps(package_document)
    values = {"package/package.json": package_json, **members}
    with tarfile.open(path, "w:gz") as archive:
        for name, text in values.items():
            payload = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))


def integrity(path: Path) -> str:
    digest = hashlib.sha512(path.read_bytes()).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


class SafeUpdateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.input = self.root / "input"
        (self.input / "current").mkdir(parents=True)
        (self.input / "target").mkdir(parents=True)
        self.current_archive = self.input / "current" / "openclaw-current.tgz"
        self.target_archive = self.input / "target" / "openclaw-target.tgz"
        write_archive(
            self.current_archive,
            "1.0.0",
            {
                "package/dist/runtime.js": "const agentRuntime = 'old';\n",
                "package/extensions/signal/index.js": "signal old\n",
                "package/removed.js": "removed\n",
            },
            {"engines": {"node": ">=22.0.0"}},
        )
        write_archive(
            self.target_archive,
            "1.1.0",
            {
                "package/dist/runtime.js": "const agentRuntime = 'new';\n",
                "package/extensions/signal/index.js": "signal new\n",
                "package/added.js": "added\n",
            },
            {"engines": {"node": ">=22.0.0"}},
        )
        metadata = {
            "schema": "openclaw.safe_update.input.v1",
            "current_version": "1.0.0",
            "target_version": "1.1.0",
            "packages": [
                {
                    "name": "openclaw",
                    "current": {
                        "name": "openclaw",
                        "version": "1.0.0",
                        "archive": self.current_archive.name,
                        "integrity": integrity(self.current_archive),
                        "shasum": hashlib.sha1(self.current_archive.read_bytes()).hexdigest(),
                    },
                    "target": {
                        "name": "openclaw",
                        "version": "1.1.0",
                        "archive": self.target_archive.name,
                        "integrity": integrity(self.target_archive),
                        "shasum": hashlib.sha1(self.target_archive.read_bytes()).hexdigest(),
                    },
                }
            ],
            "core_candidate": {
                "package": "openclaw",
                "current": core_closure(
                    "1.0.0",
                    [("@example/message-codec", "3.4.2")],
                    root_integrity=integrity(self.current_archive),
                ),
                "target": core_closure(
                    "1.1.0",
                    [("@example/message-codec", "3.4.2")],
                    root_integrity=integrity(self.target_archive),
                ),
            },
        }
        (self.input / "input-metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        self.customizations = self.root / "customizations.json"
        self.customizations.write_text(
            json.dumps(
                {
                    "schema": "openclaw.safe_update.customizations.v1",
                    "checks": [
                        {
                            "id": "signal-entrypoint",
                            "package": "openclaw",
                            "kind": "required_member",
                            "member": "package/extensions/signal/index.js",
                        },
                        {
                            "id": "runtime-hook",
                            "package": "openclaw",
                            "kind": "member_contains",
                            "member": "package/dist/runtime.js",
                            "needle": "agentRuntime",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.coverage = self.root / "coverage.json"
        self.coverage.write_text(
            json.dumps(
                {
                    "schema": "openclaw.safe_update.coverage.v1",
                    "install_shape": "npm_global_linux",
                    "runtime": {
                        "node_version": "22.14.0",
                        "os": "linux",
                        "arch": "x64",
                        "libc": "glibc",
                    },
                    "surfaces": [
                        {
                            "id": "signal",
                            "category": "channel",
                            "required": True,
                            "customization_checks": ["signal-entrypoint"],
                            "post_update_checks": [
                                "inbound text reaches the agent",
                                "outbound reply reaches Signal",
                                "voice note is transcribed",
                            ],
                        },
                        {
                            "id": "conversation-runtime",
                            "category": "persona",
                            "required": True,
                            "customization_checks": ["runtime-hook"],
                            "post_update_checks": ["casual conversation preserves the expected voice"],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        checks, _, _ = SAFE_UPDATE.load_customizations(self.customizations, False)
        coverage_profile, _, _ = SAFE_UPDATE.load_coverage(self.coverage, False)
        installation_contract = SAFE_UPDATE.adapt_v1_installation_contract(
            checks,
            coverage_profile,
        )
        candidate_lock, candidate_status = SAFE_UPDATE.build_installation_candidate_lock(
            metadata,
            installation_contract,
            {
                "generated_at": SAFE_UPDATE.now_iso(),
                **SAFE_UPDATE.safety_fields(),
            },
        )
        self.assertEqual(candidate_status, "success")
        self.default_candidate_lock = candidate_lock
        self.attestation = self.root / "installation-attestation.json"
        attestation = SAFE_UPDATE.build_installation_attestation(
            candidate_lock,
            {
                "schema": SAFE_UPDATE.INSTALLATION_OBSERVATION_SCHEMA,
                "components": [],
                "services": [],
            },
            generated_at=SAFE_UPDATE.now_iso(),
            ttl_seconds=3600,
        )
        self.assertEqual(attestation["status"], "success")
        self.attestation.write_text(json.dumps(attestation), encoding="utf-8")
        self.conservative_inputs = self.root / "conservative-inputs.json"
        self.conservative_inputs.write_text(
            json.dumps(
                {
                    "schema": SAFE_UPDATE.CONSERVATIVE_INPUTS_SCHEMA,
                    "satisfied_gates": [
                        {
                            "id": "rollback-evidence",
                            "evidence_digest": "sha256:" + "a" * 64,
                        }
                    ],
                    "operator_escalations": [],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_simulation(
        self,
        *extra: str,
        include_attestation: bool = True,
        output_dir: Path | None = None,
        cache_dir: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        attestation_args = (
            ["--installation-attestation", str(self.attestation)]
            if include_attestation
            else []
        )
        cache_args = ["--cache-dir", str(cache_dir)] if cache_dir else []
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "simulate",
                "--input-dir",
                str(self.input),
                "--output-dir",
                str(output_dir or self.root / "output"),
                "--coverage",
                str(self.coverage),
                "--conservative-inputs",
                str(self.conservative_inputs),
                *cache_args,
                *attestation_args,
                *extra,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_green_rehearsal_produces_hash_bound_evidence(self) -> None:
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "output"
        verdict = json.loads((output / "verdict.json").read_text())
        evidence = json.loads((output / "evidence-bundle.json").read_text())
        synthetic = json.loads((output / "synthetic-update.json").read_text())
        coverage = json.loads((output / "coverage-report.json").read_text())
        postchecks = json.loads((output / "post-upgrade-e2e.json").read_text())
        candidate_lock = json.loads((output / "core-candidate-lock.json").read_text())
        self.assertEqual(verdict["schema"], "openclaw.safe_update.status.v2")
        self.assertEqual(verdict["phase"], "preflight")
        self.assertEqual(verdict["post_activation_e2e"], "not_run")
        self.assertEqual(verdict["verdict"], "ready_for_operator_plan")
        self.assertFalse(verdict["production_apply_allowed"])
        self.assertFalse(verdict["operator_approval"])
        self.assertEqual(verdict["external_effect"], "npm_registry_read_only")
        self.assertEqual(verdict["external_write_effect"], "none")
        self.assertEqual(evidence["repair_class"], "openclaw_upgrade")
        self.assertTrue(all(item["status"] == "success" for item in evidence["evidence"]))
        self.assertEqual(coverage["status"], "success")
        self.assertEqual(candidate_lock["status"], "success")
        self.assertTrue(candidate_lock["current_root"].startswith("sha256:"))
        self.assertTrue(candidate_lock["target_root"].startswith("sha256:"))
        self.assertEqual(len(postchecks["surfaces"]), 2)
        self.assertTrue((output / "operator-plan.md").is_file())
        self.assertIn("STOP BEFORE APPLY", (output / "operator-plan.md").read_text())
        diff = synthetic["packages"][0]["diff"]
        self.assertIn("package/added.js", diff["added"]["members"])
        self.assertIn("package/removed.js", diff["removed"]["members"])
        self.assertFalse((output / "upgrade-status.json").exists())

    def test_transitive_resolution_drift_changes_candidate_root(self) -> None:
        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["core_candidate"]["target"] = core_closure(
            "1.1.0",
            [("@example/message-codec", "3.5.0")],
            root_integrity=integrity(self.target_archive),
        )
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = self.run_simulation("--customizations", str(self.customizations))

        self.assertEqual(result.returncode, 0, result.stderr)
        candidate_lock = json.loads(
            (self.root / "output" / "core-candidate-lock.json").read_text()
        )
        conservative = json.loads(
            (self.root / "output" / "conservative-gates.json").read_text()
        )
        verdict = json.loads((self.root / "output" / "verdict.json").read_text())
        self.assertNotEqual(candidate_lock["current_root"], candidate_lock["target_root"])
        codec = next(
            item
            for item in candidate_lock["changed_packages"]
            if item["name"] == "@example/message-codec"
        )
        self.assertEqual(codec["current_version"], "3.4.2")
        self.assertEqual(codec["target_version"], "3.5.0")
        self.assertEqual(conservative["handling"], "conservative")
        self.assertEqual(
            verdict["decision_content"]["gate_decision"]["handling"],
            "conservative",
        )
        self.assertEqual(
            verdict["decision_content"]["gate_decision"]["decision_digest"],
            conservative["decision_digest"],
        )

    def test_candidate_root_is_stable_across_lockfile_order(self) -> None:
        first = core_closure(
            "1.1.0",
            [("alpha", "1.0.0"), ("beta", "2.0.0")],
        )
        second = core_closure(
            "1.1.0",
            [("beta", "2.0.0"), ("alpha", "1.0.0")],
        )
        self.assertEqual(first["root"], second["root"])
        self.assertEqual(first["packages"], second["packages"])

    def test_optional_platform_selection_is_bound_into_candidate_root(self) -> None:
        linux = core_closure(
            "1.1.0",
            [("native-helper", "1.0.0")],
            optional_selector={"native-helper": ["linux"]},
        )
        darwin = core_closure(
            "1.1.0",
            [("native-helper", "1.0.0")],
            environment={
                "node_version": "22.14.0",
                "npm_version": "11.4.2",
                "os": "darwin",
                "arch": "x64",
                "libc": "unknown",
            },
            optional_selector={"native-helper": ["linux"]},
        )
        self.assertNotEqual(linux["root"], darwin["root"])
        self.assertTrue(
            next(item for item in linux["packages"] if item["name"] == "native-helper")[
                "selected_for_platform"
            ]
        )
        self.assertFalse(
            next(item for item in darwin["packages"] if item["name"] == "native-helper")[
                "selected_for_platform"
            ]
        )

    def test_missing_or_environment_mismatched_candidate_lock_blocks(self) -> None:
        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata.pop("core_candidate")
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        missing = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(missing.returncode, 2)

        metadata["core_candidate"] = {
            "package": "openclaw",
            "current": core_closure("1.0.0"),
            "target": core_closure(
                "1.1.0",
                environment={
                    "node_version": "22.14.0",
                    "npm_version": "11.4.2",
                    "os": "darwin",
                    "arch": "arm64",
                    "libc": "unknown",
                },
            ),
        }
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        mismatched = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(mismatched.returncode, 2)
        candidate_lock = json.loads(
            (self.root / "output" / "core-candidate-lock.json").read_text()
        )
        self.assertIn("different environments", candidate_lock["errors"][0])

    def test_candidate_platform_must_match_declared_runtime(self) -> None:
        value = json.loads(self.coverage.read_text())
        value["runtime"].update({"os": "darwin", "arch": "arm64", "libc": "none"})
        self.coverage.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 2)
        candidate_lock = json.loads(
            (self.root / "output" / "core-candidate-lock.json").read_text()
        )
        self.assertIn("declared runtime platform", candidate_lock["errors"][0])

    def test_candidate_closure_is_bound_to_top_level_package_integrity(self) -> None:
        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["core_candidate"]["target"] = core_closure(
            "1.1.0",
            root_integrity="sha512-" + "c" * 64,
        )
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 2)
        candidate_lock = json.loads(
            (self.root / "output" / "core-candidate-lock.json").read_text()
        )
        self.assertIn("does not match package evidence", candidate_lock["errors"][0])

    def test_candidate_rejects_links_and_new_transitive_install_scripts(self) -> None:
        linked_lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"openclaw": "1.1.0"}},
                "node_modules/openclaw": {
                    "version": "1.1.0",
                    "resolved": "https://registry.npmjs.org/openclaw/-/openclaw-1.1.0.tgz",
                    "integrity": "sha512-" + "a" * 64,
                },
                "node_modules/local-helper": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/local-helper/-/local-helper-1.0.0.tgz",
                    "integrity": "sha512-" + "b" * 64,
                    "link": "../local-helper",
                },
            },
        }
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "mutable link"):
            SAFE_UPDATE.build_core_closure(
                linked_lock,
                "openclaw",
                "1.1.0",
                {
                    "node_version": "22.14.0",
                    "npm_version": "11.4.2",
                    "os": "linux",
                    "arch": "x64",
                    "libc": "glibc",
                },
            )

        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["core_candidate"]["target"] = core_closure(
            "1.1.0",
            [("native-helper", "1.0.0")],
            root_integrity=integrity(self.target_archive),
            install_script_packages={"native-helper"},
        )
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 2)
        candidate_lock = json.loads(
            (self.root / "output" / "core-candidate-lock.json").read_text()
        )
        self.assertIn("transitive install script", candidate_lock["errors"][0])

    def test_core_resolver_invocation_is_lock_only_and_ignores_scripts(self) -> None:
        environment = {
            "node_version": "22.14.0",
            "npm_version": "11.4.2",
            "os": "linux",
            "arch": "x64",
            "libc": "glibc",
        }
        captured: dict[str, object] = {}

        def fake_run(
            arguments: list[str],
            cache_dir: Path,
            working_dir: Path | None = None,
            environment_overrides: dict[str, str] | None = None,
        ) -> dict[str, object]:
            captured.update(
                {
                    "arguments": arguments,
                    "working_dir": working_dir,
                    "environment_overrides": environment_overrides,
                }
            )
            assert working_dir is not None
            lock = {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"openclaw": "1.1.0"}},
                    "node_modules/openclaw": {
                        "version": "1.1.0",
                        "resolved": "https://registry.npmjs.org/openclaw/-/openclaw-1.1.0.tgz",
                        "integrity": "sha512-" + "a" * 64,
                    },
                },
            }
            (working_dir / "package-lock.json").write_text(
                json.dumps(lock), encoding="utf-8"
            )
            return {}

        with tempfile.TemporaryDirectory() as cache, patch.object(
            SAFE_UPDATE, "run_npm_json", side_effect=fake_run
        ):
            closure = SAFE_UPDATE.resolve_core_closure(
                "openclaw",
                "1.1.0",
                Path(cache),
                environment,
            )

        self.assertIn("--package-lock-only", captured["arguments"])
        self.assertIn("--ignore-scripts", captured["arguments"])
        self.assertIn("--include=optional", captured["arguments"])
        self.assertEqual(
            captured["environment_overrides"],
            {
                "NPM_CONFIG_OS": "linux",
                "NPM_CONFIG_CPU": "x64",
                "NPM_CONFIG_LIBC": "glibc",
            },
        )
        self.assertEqual(closure["resolver"]["ignore_scripts"], True)

    def test_status_decision_is_stable_across_volatile_run_envelopes(self) -> None:
        evidence_status = {
            "runtime_truth": "success",
            "core_candidate_lock": "success",
            "installation_candidate_lock": "success",
            "installation_attestation": "success",
            "conservative_gates": "success",
            "synthetic_update": "success",
            "customization_compatibility": "success",
            "installation_coverage": "success",
            "post_upgrade_e2e_plan": "success",
        }
        first = SAFE_UPDATE.build_status(
            generated_at="2026-07-17T10:00:00+00:00",
            verdict="ready_for_operator_plan",
            reason="first advisory wording",
            reason_code="baseline_rehearsal_passed",
            evidence_status=evidence_status,
            gate_decision={
                "status": "success",
                "handling": "baseline",
                "required_gates": ["rollback-evidence"],
                "decision_digest": "sha256:" + "5" * 64,
            },
            candidate_roots={"current": "sha256:" + "3" * 64, "target": "sha256:" + "4" * 64},
            evidence_bundle={"path": "evidence-bundle.json", "sha256": "1" * 64},
            next_step="first operator wording",
            next_step_code="prepare_operator_plan",
        )
        second = SAFE_UPDATE.build_status(
            generated_at="2026-07-18T11:12:13+00:00",
            verdict="ready_for_operator_plan",
            reason="different advisory wording",
            reason_code="baseline_rehearsal_passed",
            evidence_status=evidence_status,
            gate_decision={
                "status": "success",
                "handling": "baseline",
                "required_gates": ["rollback-evidence"],
                "decision_digest": "sha256:" + "5" * 64,
            },
            candidate_roots={"current": "sha256:" + "3" * 64, "target": "sha256:" + "4" * 64},
            evidence_bundle={"path": "evidence-bundle.json", "sha256": "2" * 64},
            next_step="different operator wording",
            next_step_code="prepare_operator_plan",
        )

        self.assertEqual(first["decision_content"], second["decision_content"])
        self.assertEqual(first["decision_digest"], second["decision_digest"])
        self.assertNotEqual(first["run_envelope"], second["run_envelope"])
        self.assertEqual(SAFE_UPDATE.parse_status(first), first)
        self.assertEqual(SAFE_UPDATE.parse_status(second), second)

    def test_status_parser_rejects_tampering_and_true_mutation_fields(self) -> None:
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 0, result.stderr)
        status = json.loads((self.root / "output" / "verdict.json").read_text())

        unknown_root = copy.deepcopy(status)
        unknown_root["shadow_verdict"] = "ready_for_operator_plan"
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "status contains"):
            SAFE_UPDATE.parse_status(unknown_root)

        extended_bundle = copy.deepcopy(status)
        extended_bundle["evidence_bundle"]["shadow"] = "ignored"
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "evidence_bundle"):
            SAFE_UPDATE.parse_status(extended_bundle)

        tampered = copy.deepcopy(status)
        tampered["decision_content"]["verdict"] = "blocked"
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "decision_digest"):
            SAFE_UPDATE.parse_status(tampered)

        for field in ("production_apply_allowed", "operator_approval"):
            unsafe = copy.deepcopy(status)
            unsafe[field] = True
            with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, field):
                SAFE_UPDATE.parse_status(unsafe)

        activated = copy.deepcopy(status)
        activated["post_activation_e2e"] = "passed"
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "post_activation_e2e"):
            SAFE_UPDATE.parse_status(activated)

        volatile_decision = copy.deepcopy(status)
        volatile_decision["decision_content"]["generated_at"] = status["generated_at"]
        volatile_decision["decision_digest"] = SAFE_UPDATE.canonical_digest(
            volatile_decision["decision_content"]
        )
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "unknown or missing"):
            SAFE_UPDATE.parse_status(volatile_decision)

        contradictory = copy.deepcopy(status)
        contradictory["decision_content"]["reason_code"] = "required_evidence_failed"
        contradictory["decision_digest"] = SAFE_UPDATE.canonical_digest(
            contradictory["decision_content"]
        )
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "reason_code"):
            SAFE_UPDATE.parse_status(contradictory)

        for evidence_mutation in ("missing", "unknown"):
            malformed_evidence = copy.deepcopy(status)
            if evidence_mutation == "missing":
                malformed_evidence["decision_content"]["evidence_status"].pop(
                    "runtime_truth"
                )
            else:
                malformed_evidence["decision_content"]["evidence_status"][
                    "shadow"
                ] = "success"
            malformed_evidence["decision_digest"] = SAFE_UPDATE.canonical_digest(
                malformed_evidence["decision_content"]
            )
            with self.assertRaisesRegex(
                SAFE_UPDATE.RehearsalError,
                "evidence_status contains unknown or missing",
            ):
                SAFE_UPDATE.parse_status(malformed_evidence)

    def test_status_parser_rejects_unknown_fields_on_blocked_status(self) -> None:
        result = self.run_simulation()
        self.assertEqual(result.returncode, 2)
        status = json.loads((self.root / "output" / "verdict.json").read_text())
        self.assertEqual(status["verdict"], "blocked")

        status["shadow_reason"] = "advisory only"
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "status contains"):
            SAFE_UPDATE.parse_status(status)

    def test_status_preserves_the_v1_1_compatibility_view(self) -> None:
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 0, result.stderr)
        status = json.loads((self.root / "output" / "verdict.json").read_text())
        compatibility = status["compatibility_view"]

        self.assertFalse(compatibility["authoritative"])
        self.assertEqual(
            compatibility["schema"],
            "openclaw.safe_update.compatibility_view.v1",
        )
        self.assertEqual(
            compatibility["payload"],
            SAFE_UPDATE.legacy_verdict_payload(status),
        )
        for field in (
            "verdict",
            "reason",
            "evidence_bundle",
            "next_step",
            "production_apply_allowed",
            "operator_approval",
        ):
            self.assertEqual(status[field], compatibility["payload"][field])

    def test_status_schema_and_frozen_baseline_are_pinned(self) -> None:
        schema = json.loads(STATUS_SCHEMA.read_text())
        baseline = json.loads(BASELINE.read_text())

        self.assertEqual(
            schema["properties"]["schema"]["const"],
            "openclaw.safe_update.status.v2",
        )
        self.assertFalse(schema["properties"]["production_apply_allowed"]["const"])
        self.assertFalse(schema["properties"]["operator_approval"]["const"])
        self.assertEqual(schema["properties"]["phase"]["const"], "preflight")
        self.assertEqual(
            schema["properties"]["post_activation_e2e"]["const"],
            "not_run",
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]), SAFE_UPDATE.STATUS_FIELDS)
        evidence_status_schema = schema["$defs"]["decisionContent"]["properties"][
            "evidence_status"
        ]
        self.assertFalse(evidence_status_schema["additionalProperties"])
        self.assertEqual(
            set(evidence_status_schema["properties"]),
            SAFE_UPDATE.EVIDENCE_STATUS_FIELDS,
        )
        gate_schema = json.loads(CONSERVATIVE_GATES_SCHEMA.read_text())
        input_schema = json.loads(CONSERVATIVE_INPUTS_SCHEMA.read_text())
        impact_schema = json.loads(IMPACT_SHADOW_SCHEMA.read_text())
        cache_schema = json.loads(ANALYSIS_CACHE_SCHEMA.read_text())
        execution_schema = json.loads(ARCHIVE_EXECUTION_SCHEMA.read_text())
        self.assertEqual(
            gate_schema["properties"]["schema"]["const"],
            SAFE_UPDATE.CONSERVATIVE_GATES_SCHEMA,
        )
        self.assertEqual(
            input_schema["properties"]["schema"]["const"],
            SAFE_UPDATE.CONSERVATIVE_INPUTS_SCHEMA,
        )
        self.assertFalse(gate_schema["additionalProperties"])
        self.assertFalse(input_schema["additionalProperties"])
        self.assertEqual(
            impact_schema["properties"]["schema"]["const"],
            SAFE_UPDATE.IMPACT_SHADOW_SCHEMA,
        )
        self.assertFalse(impact_schema["properties"]["authoritative"]["const"])
        self.assertEqual(
            impact_schema["properties"]["would_omit_checks"]["maxItems"],
            0,
        )
        self.assertFalse(impact_schema["additionalProperties"])
        self.assertEqual(
            cache_schema["properties"]["schema"]["const"],
            SAFE_UPDATE.ANALYSIS_CACHE_SCHEMA,
        )
        self.assertFalse(cache_schema["properties"]["authoritative"]["const"])
        self.assertFalse(cache_schema["additionalProperties"])
        self.assertEqual(
            execution_schema["properties"]["schema"]["const"],
            SAFE_UPDATE.ARCHIVE_EXECUTION_SCHEMA,
        )
        self.assertFalse(
            execution_schema["properties"]["authoritative"]["const"]
        )
        self.assertEqual(
            execution_schema["properties"]["workers_requested"]["maximum"],
            SAFE_UPDATE.MAX_ARCHIVE_WORKERS,
        )
        self.assertFalse(execution_schema["additionalProperties"])
        self.assertEqual(baseline["commit"], BASELINE_SHA)
        self.assertEqual(baseline["test_case_count"], 13)
        self.assertEqual(baseline["test_cases"], BASELINE_TEST_CASES)

    def test_conservative_policy_has_a_focused_fixture_for_every_required_row(
        self,
    ) -> None:
        base_lock = {
            "status": "success",
            "changed_packages": [],
            "errors": [],
        }
        rollback = {
            "satisfied_gates": {
                "rollback-evidence": "sha256:" + "a" * 64,
            },
            "operator_escalations": set(),
        }
        fixtures = [
            (
                "unresolved candidate closure",
                {**base_lock, "status": "failed"},
                "success",
                [],
                False,
                rollback,
                "candidate-closure-resolved",
            ),
            (
                "stale or incomplete attestation",
                base_lock,
                "failed",
                [],
                True,
                rollback,
                "installation-attestation-fresh-complete",
            ),
            (
                "lossy or unparsable authority input",
                base_lock,
                "success",
                [],
                False,
                rollback,
                "authority-input-lossless",
            ),
            (
                "changed lifecycle script",
                base_lock,
                "success",
                [
                    {
                        "name": "openclaw",
                        "archive_diff": {"added": [], "removed": [], "changed": []},
                        "metadata_changed_fields": ["scripts"],
                        "risk_findings": [
                            {
                                "id": "lifecycle-script-changed",
                                "severity": "blocked",
                                "detail": "changed",
                            }
                        ],
                    }
                ],
                True,
                rollback,
                "lifecycle-download-evidence",
            ),
            (
                "state migration surface",
                base_lock,
                "success",
                [
                    {
                        "name": "openclaw",
                        "archive_diff": {
                            "added": ["package/dist/migrations/v2.js"],
                            "removed": [],
                            "changed": [],
                        },
                        "metadata_changed_fields": [],
                        "risk_findings": [],
                    }
                ],
                True,
                rollback,
                "state-migration-rehearsal",
            ),
            (
                "unknown rollback boundary",
                base_lock,
                "success",
                [],
                True,
                SAFE_UPDATE.empty_conservative_inputs(),
                "rollback-evidence",
            ),
            (
                "plugin SDK contract surface",
                base_lock,
                "success",
                [
                    {
                        "name": "openclaw",
                        "archive_diff": {
                            "added": [],
                            "removed": [],
                            "changed": ["package/dist/plugin-sdk/index.js"],
                        },
                        "metadata_changed_fields": [],
                        "risk_findings": [],
                    }
                ],
                True,
                rollback,
                "plugin-sdk-contract",
            ),
            (
                "launcher and service contract surface",
                base_lock,
                "success",
                [
                    {
                        "name": "openclaw",
                        "archive_diff": {
                            "added": [],
                            "removed": [],
                            "changed": ["package/dist/service/launcher.js"],
                        },
                        "metadata_changed_fields": [],
                        "risk_findings": [],
                    }
                ],
                True,
                rollback,
                "launcher-service-contract",
            ),
            (
                "permissions contract surface",
                base_lock,
                "success",
                [
                    {
                        "name": "openclaw",
                        "archive_diff": {
                            "added": [],
                            "removed": [],
                            "changed": ["package/dist/permissions/acl.js"],
                        },
                        "metadata_changed_fields": [],
                        "risk_findings": [],
                    }
                ],
                True,
                rollback,
                "permissions-contract",
            ),
            (
                "protocol contract surface",
                base_lock,
                "success",
                [
                    {
                        "name": "openclaw",
                        "archive_diff": {
                            "added": [],
                            "removed": [],
                            "changed": ["package/dist/protocol/wire.js"],
                        },
                        "metadata_changed_fields": [],
                        "risk_findings": [],
                    }
                ],
                True,
                rollback,
                "protocol-contract",
            ),
            (
                "channel crypto contract surface",
                base_lock,
                "success",
                [
                    {
                        "name": "openclaw",
                        "archive_diff": {
                            "added": [],
                            "removed": [],
                            "changed": ["package/extensions/signal/crypto.js"],
                        },
                        "metadata_changed_fields": [],
                        "risk_findings": [],
                    }
                ],
                True,
                rollback,
                "channel-crypto-contract",
            ),
            (
                "environment install shape",
                base_lock,
                "success",
                [
                    {
                        "name": "openclaw",
                        "archive_diff": {"added": [], "removed": [], "changed": []},
                        "metadata_changed_fields": ["engines"],
                        "risk_findings": [],
                    }
                ],
                True,
                rollback,
                "environment-matched-rehearsal",
            ),
            (
                "unknown optional native dependency",
                {
                    **base_lock,
                    "changed_packages": [
                        {
                            "current_flags": {"optional": True},
                            "target_flags": {"optional": True},
                            "current_selectors": {
                                "os": ["linux"],
                                "cpu": [],
                                "libc": [],
                            },
                            "target_selectors": {
                                "os": ["linux"],
                                "cpu": [],
                                "libc": [],
                            },
                            "current_selected": None,
                            "target_selected": True,
                        }
                    ],
                },
                "success",
                [],
                True,
                rollback,
                "native-optional-dependency-known",
            ),
        ]
        for (
            name,
            candidate_lock,
            attestation_status,
            authority_packages,
            authority_complete,
            inputs,
            expected_gate,
        ) in fixtures:
            with self.subTest(name=name):
                report, status = SAFE_UPDATE.evaluate_conservative_gates(
                    core_candidate_lock=candidate_lock,
                    installation_attestation_status=attestation_status,
                    authority_packages=authority_packages,
                    authority_complete=authority_complete,
                    inputs=inputs,
                    common={
                        "generated_at": "2026-07-18T12:00:00+00:00",
                        **SAFE_UPDATE.safety_fields(),
                    },
                )
                decision = next(
                    item for item in report["decisions"] if item["id"] == expected_gate
                )
                self.assertEqual(status, "failed")
                self.assertEqual(report["handling"], "blocked")
                self.assertTrue(decision["triggered"])
                self.assertEqual(decision["outcome"], "blocked")

    def test_operator_evidence_can_satisfy_a_named_gate_but_never_a_hard_block(
        self,
    ) -> None:
        inputs = SAFE_UPDATE.parse_conservative_inputs(
            {
                "schema": SAFE_UPDATE.CONSERVATIVE_INPUTS_SCHEMA,
                "satisfied_gates": [
                    {
                        "id": "rollback-evidence",
                        "evidence_digest": "sha256:" + "1" * 64,
                    },
                    {
                        "id": "state-migration-rehearsal",
                        "evidence_digest": "sha256:" + "2" * 64,
                    },
                ],
                "operator_escalations": ["state-migration-rehearsal"],
            }
        )
        report, status = SAFE_UPDATE.evaluate_conservative_gates(
            core_candidate_lock={
                "status": "failed",
                "changed_packages": [],
                "errors": ["unresolved closure"],
            },
            installation_attestation_status="success",
            authority_packages=[],
            authority_complete=True,
            inputs=inputs,
            common={
                "generated_at": "2026-07-18T12:00:00+00:00",
                **SAFE_UPDATE.safety_fields(),
            },
        )

        self.assertEqual(status, "failed")
        self.assertEqual(report["handling"], "blocked")
        closure = next(
            item
            for item in report["decisions"]
            if item["id"] == "candidate-closure-resolved"
        )
        state = next(
            item
            for item in report["decisions"]
            if item["id"] == "state-migration-rehearsal"
        )
        self.assertEqual(closure["outcome"], "blocked")
        self.assertEqual(state["outcome"], "conservative")

    def test_conservative_inputs_cannot_set_or_waive_a_verdict(self) -> None:
        with self.assertRaisesRegex(
            SAFE_UPDATE.RehearsalError,
            "unknown or missing",
        ):
            SAFE_UPDATE.parse_conservative_inputs(
                {
                    "schema": SAFE_UPDATE.CONSERVATIVE_INPUTS_SCHEMA,
                    "satisfied_gates": [],
                    "operator_escalations": [],
                    "verdict": "ready_for_operator_plan",
                }
            )

    def test_gate_decision_digest_covers_input_parse_errors(self) -> None:
        arguments = {
            "core_candidate_lock": {
                "status": "success",
                "changed_packages": [],
                "errors": [],
            },
            "installation_attestation_status": "success",
            "authority_packages": [],
            "authority_complete": False,
            "inputs": {
                "satisfied_gates": {
                    "rollback-evidence": "sha256:" + "a" * 64,
                },
                "operator_escalations": set(),
            },
            "common": {
                "generated_at": "2026-07-18T12:00:00+00:00",
                **SAFE_UPDATE.safety_fields(),
            },
        }
        without_detail, _ = SAFE_UPDATE.evaluate_conservative_gates(**arguments)
        with_detail, _ = SAFE_UPDATE.evaluate_conservative_gates(
            **arguments,
            input_errors=["conservative inputs contain an unknown field"],
        )

        self.assertNotEqual(
            without_detail["decision_digest"],
            with_detail["decision_digest"],
        )
        self.assertIn(
            "conservative inputs contain an unknown field",
            with_detail["errors"],
        )

    def test_missing_rollback_evidence_blocks_the_authoritative_status(self) -> None:
        self.conservative_inputs.write_text(
            json.dumps(
                {
                    "schema": SAFE_UPDATE.CONSERVATIVE_INPUTS_SCHEMA,
                    "satisfied_gates": [],
                    "operator_escalations": [],
                }
            ),
            encoding="utf-8",
        )

        result = self.run_simulation("--customizations", str(self.customizations))

        self.assertEqual(result.returncode, 2)
        gates = json.loads(
            (self.root / "output" / "conservative-gates.json").read_text()
        )
        verdict = json.loads((self.root / "output" / "verdict.json").read_text())
        self.assertEqual(gates["status"], "failed")
        self.assertIn("rollback-evidence", gates["required_gates"])
        self.assertEqual(verdict["verdict"], "blocked")
        self.assertEqual(
            verdict["decision_content"]["evidence_status"]["conservative_gates"],
            "failed",
        )

    def test_bounded_human_report_cannot_replace_lossless_authority_input(self) -> None:
        values = [f"package/dist/member-{index}.js" for index in range(251)]
        human_report = SAFE_UPDATE.bounded(values)
        self.assertTrue(human_report["truncated"])
        self.assertEqual(len(human_report["members"]), SAFE_UPDATE.DIFF_MEMBER_LIMIT)

        report, status = SAFE_UPDATE.evaluate_conservative_gates(
            core_candidate_lock={
                "status": "success",
                "changed_packages": [],
                "errors": [],
            },
            installation_attestation_status="success",
            authority_packages=[],
            authority_complete=False,
            inputs={
                "satisfied_gates": {
                    "rollback-evidence": "sha256:" + "a" * 64,
                },
                "operator_escalations": set(),
            },
            common={
                "generated_at": "2026-07-18T12:00:00+00:00",
                **SAFE_UPDATE.safety_fields(),
            },
        )

        self.assertEqual(status, "failed")
        self.assertIn(
            "authority-input-lossless: hard-blocking deterministic condition",
            report["errors"],
        )

    def test_resolved_closure_drift_is_never_classified_fast(self) -> None:
        report, status = SAFE_UPDATE.evaluate_conservative_gates(
            core_candidate_lock={
                "status": "success",
                "changed_packages": [
                    {
                        "name": "@example/message-codec",
                        "current_flags": {"optional": False},
                        "target_flags": {"optional": False},
                        "current_selectors": {"os": [], "cpu": [], "libc": []},
                        "target_selectors": {"os": [], "cpu": [], "libc": []},
                        "current_selected": True,
                        "target_selected": True,
                    }
                ],
                "errors": [],
            },
            installation_attestation_status="success",
            authority_packages=[],
            authority_complete=True,
            inputs={
                "satisfied_gates": {
                    "rollback-evidence": "sha256:" + "a" * 64,
                },
                "operator_escalations": set(),
            },
            common={
                "generated_at": "2026-07-18T12:00:00+00:00",
                **SAFE_UPDATE.safety_fields(),
            },
        )

        self.assertEqual(status, "success")
        self.assertEqual(report["handling"], "conservative")
        self.assertNotIn("fast", SAFE_UPDATE.GATE_HANDLING)

    def test_impact_shadow_is_removable_without_changing_ready_decision(self) -> None:
        enabled_output = self.root / "shadow-enabled"
        disabled_output = self.root / "shadow-disabled"

        enabled = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=enabled_output,
        )
        disabled = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--disable-impact-shadow",
            output_dir=disabled_output,
        )

        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        enabled_status = json.loads((enabled_output / "verdict.json").read_text())
        disabled_status = json.loads((disabled_output / "verdict.json").read_text())
        shadow = json.loads((enabled_output / "impact-shadow.json").read_text())
        evidence = json.loads((enabled_output / "evidence-bundle.json").read_text())
        self.assertEqual(
            enabled_status["decision_content"],
            disabled_status["decision_content"],
        )
        self.assertEqual(
            enabled_status["decision_digest"],
            disabled_status["decision_digest"],
        )
        self.assertEqual(enabled_status["verdict"], disabled_status["verdict"])
        self.assertFalse((disabled_output / "impact-shadow.json").exists())
        self.assertNotIn("impact_shadow", enabled_status["decision_content"])
        self.assertFalse(
            any(
                item["path"] == "impact-shadow.json"
                for item in evidence["evidence"]
            )
        )
        self.assertFalse(shadow["authoritative"])
        self.assertEqual(shadow["would_omit_checks"], [])
        self.assertIn("conversation-runtime", shadow["affected_capabilities"])
        self.assertIn("signal", shadow["affected_capabilities"])
        self.assertIn(
            "shadow:risk:unmapped-members",
            {item["id"] for item in shadow["would_flag_risks"]},
        )
        self.assertTrue(
            all(
                item["id"].startswith(SAFE_UPDATE.SHADOW_ID_PREFIX)
                for item in shadow["would_add_checks"]
            )
        )
        unmapped = {
            (item["package"], item["change"], item["member"])
            for item in shadow["unmapped_members"]
        }
        self.assertIn(("openclaw", "added", "package/added.js"), unmapped)
        self.assertIn(("openclaw", "removed", "package/removed.js"), unmapped)

    def test_impact_shadow_digest_is_stable_across_run_envelopes(self) -> None:
        first_output = self.root / "shadow-first"
        second_output = self.root / "shadow-second"

        first = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=first_output,
        )
        second = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=second_output,
        )

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        first_shadow = json.loads((first_output / "impact-shadow.json").read_text())
        second_shadow = json.loads((second_output / "impact-shadow.json").read_text())
        self.assertEqual(first_shadow["shadow_digest"], second_shadow["shadow_digest"])
        for shadow in (first_shadow, second_shadow):
            shadow.pop("generated_at")
        self.assertEqual(first_shadow, second_shadow)

    def test_impact_shadow_is_removable_without_changing_blocked_decision(self) -> None:
        enabled_output = self.root / "blocked-shadow-enabled"
        disabled_output = self.root / "blocked-shadow-disabled"

        enabled = self.run_simulation(output_dir=enabled_output)
        disabled = self.run_simulation(
            "--disable-impact-shadow",
            output_dir=disabled_output,
        )

        self.assertEqual(enabled.returncode, 2)
        self.assertEqual(disabled.returncode, 2)
        enabled_status = json.loads((enabled_output / "verdict.json").read_text())
        disabled_status = json.loads((disabled_output / "verdict.json").read_text())
        self.assertEqual(enabled_status["verdict"], "blocked")
        self.assertEqual(
            enabled_status["decision_content"],
            disabled_status["decision_content"],
        )
        self.assertEqual(
            enabled_status["decision_digest"],
            disabled_status["decision_digest"],
        )

    def test_impact_shadow_preserves_transitive_false_green_as_unmapped(
        self,
    ) -> None:
        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["core_candidate"]["target"] = core_closure(
            "1.1.0",
            [("@example/message-codec", "3.5.0")],
            root_integrity=integrity(self.target_archive),
        )
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        enabled_output = self.root / "closure-shadow-enabled"
        disabled_output = self.root / "closure-shadow-disabled"

        enabled = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=enabled_output,
        )
        disabled = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--disable-impact-shadow",
            output_dir=disabled_output,
        )

        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        shadow = json.loads((enabled_output / "impact-shadow.json").read_text())
        enabled_status = json.loads((enabled_output / "verdict.json").read_text())
        disabled_status = json.loads((disabled_output / "verdict.json").read_text())
        self.assertIn("@example/message-codec", shadow["unmapped_packages"])
        self.assertTrue(shadow["would_block"])
        self.assertEqual(
            enabled_status["decision_content"],
            disabled_status["decision_content"],
        )
        self.assertEqual(enabled_status["verdict"], "ready_for_operator_plan")

    def test_impact_shadow_rejects_reserved_namespace_without_blocking_baseline(
        self,
    ) -> None:
        checks, _, _ = SAFE_UPDATE.load_customizations(self.customizations, False)
        coverage, _, _ = SAFE_UPDATE.load_coverage(self.coverage, False)
        contract = SAFE_UPDATE.adapt_v1_installation_contract(checks, coverage)
        shadow = SAFE_UPDATE.build_impact_shadow(
            authority_packages=[],
            core_candidate_lock={
                "status": "success",
                "changed_packages": [],
                "errors": [],
            },
            installation_contract=contract,
            baseline_check_ids={"shadow:baseline-collision"},
            authority_complete=True,
            common={
                "generated_at": "2026-07-18T12:00:00+00:00",
                **SAFE_UPDATE.safety_fields(),
            },
        )

        self.assertEqual(shadow["status"], "failed")
        self.assertIn(
            "baseline or component ID collides with reserved shadow namespace",
            shadow["errors"],
        )

    def test_impact_shadow_preserves_unparseable_archive_refs_as_errors(self) -> None:
        checks, _, _ = SAFE_UPDATE.load_customizations(self.customizations, False)
        coverage, _, _ = SAFE_UPDATE.load_coverage(self.coverage, False)
        contract = SAFE_UPDATE.adapt_v1_installation_contract(checks, coverage)
        contract["components"][0]["artifacts"][0]["ref"] = "missing-package-separator"

        shadow = SAFE_UPDATE.build_impact_shadow(
            authority_packages=[
                {
                    "name": "openclaw",
                    "archive_diff": {
                        "added": [],
                        "removed": [],
                        "changed": ["package/extensions/signal/index.js"],
                    },
                    "metadata_changed_fields": [],
                    "risk_findings": [],
                }
            ],
            core_candidate_lock={
                "status": "success",
                "changed_packages": [],
                "errors": [],
            },
            installation_contract=contract,
            baseline_check_ids={item["id"] for item in checks},
            authority_complete=True,
            common={
                "generated_at": "2026-07-18T12:00:00+00:00",
                **SAFE_UPDATE.safety_fields(),
            },
        )

        self.assertEqual(shadow["status"], "failed")
        self.assertTrue(
            any("unparseable npm_archive_member ref" in error for error in shadow["errors"])
        )
        self.assertIn(
            "package/extensions/signal/index.js",
            {item["member"] for item in shadow["unmapped_members"]},
        )

    def test_analysis_cache_cold_and_warm_runs_are_decision_equivalent(self) -> None:
        cache = self.root / "analysis-cache-store"
        cold_output = self.root / "cache-cold"
        warm_output = self.root / "cache-warm"

        cold = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=cold_output,
            cache_dir=cache,
        )
        warm = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=warm_output,
            cache_dir=cache,
        )

        self.assertEqual(cold.returncode, 0, cold.stderr)
        self.assertEqual(warm.returncode, 0, warm.stderr)
        cold_status = json.loads((cold_output / "verdict.json").read_text())
        warm_status = json.loads((warm_output / "verdict.json").read_text())
        cold_cache = json.loads((cold_output / "analysis-cache.json").read_text())
        warm_cache = json.loads((warm_output / "analysis-cache.json").read_text())
        self.assertEqual(cold_status["decision_content"], warm_status["decision_content"])
        self.assertEqual(cold_status["decision_digest"], warm_status["decision_digest"])
        self.assertEqual(cold_status["verdict"], warm_status["verdict"])
        self.assertGreater(cold_cache["counts"]["miss"], 0)
        self.assertEqual(cold_cache["counts"]["hit"], 0)
        self.assertGreater(warm_cache["counts"]["hit"], 0)
        self.assertEqual(warm_cache["counts"]["miss"], 0)
        self.assertEqual(
            cold_cache["rehearsal_input_digest"],
            warm_cache["rehearsal_input_digest"],
        )
        self.assertNotIn("analysis_cache", cold_status["decision_content"])
        self.assertTrue(
            {
                item["namespace"]
                for item in warm_cache["entries"]
            }
            <= SAFE_UPDATE.CACHE_NAMESPACES
        )

    def test_sequential_and_parallel_archive_runs_are_decision_equivalent(
        self,
    ) -> None:
        sequential_output = self.root / "archive-sequential"
        parallel_output = self.root / "archive-parallel"
        sequential = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--archive-workers",
            "1",
            output_dir=sequential_output,
        )
        parallel = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--archive-workers",
            "2",
            output_dir=parallel_output,
        )

        self.assertEqual(sequential.returncode, 0, sequential.stderr)
        self.assertEqual(parallel.returncode, 0, parallel.stderr)
        sequential_status = json.loads(
            (sequential_output / "verdict.json").read_text()
        )
        parallel_status = json.loads(
            (parallel_output / "verdict.json").read_text()
        )
        sequential_synthetic = json.loads(
            (sequential_output / "synthetic-update.json").read_text()
        )
        parallel_synthetic = json.loads(
            (parallel_output / "synthetic-update.json").read_text()
        )
        sequential_execution = json.loads(
            (sequential_output / "archive-execution.json").read_text()
        )
        parallel_execution = json.loads(
            (parallel_output / "archive-execution.json").read_text()
        )
        sequential_cache = json.loads(
            (sequential_output / "analysis-cache.json").read_text()
        )
        parallel_cache = json.loads(
            (parallel_output / "analysis-cache.json").read_text()
        )
        self.assertEqual(
            sequential_status["decision_content"],
            parallel_status["decision_content"],
        )
        self.assertEqual(
            sequential_status["decision_digest"],
            parallel_status["decision_digest"],
        )
        self.assertEqual(sequential_status["verdict"], parallel_status["verdict"])
        self.assertEqual(
            sequential_synthetic["packages"],
            parallel_synthetic["packages"],
        )
        self.assertEqual(
            [entry["task_id"] for entry in sequential_execution["entries"]],
            [entry["task_id"] for entry in parallel_execution["entries"]],
        )
        self.assertEqual(
            sequential_cache["entries"],
            parallel_cache["entries"],
        )
        self.assertEqual(sequential_execution["workers_used"], 1)
        self.assertEqual(parallel_execution["workers_used"], 2)
        self.assertNotIn(
            "archive_execution",
            parallel_status["decision_content"],
        )

    def test_blocked_archive_result_has_sequential_parallel_parity(self) -> None:
        write_archive(
            self.target_archive,
            "1.1.0",
            {
                "package/dist/runtime.js": "const agentRuntime = 'new';\n",
                "package/extensions/signal/index.js": "signal new\n",
            },
            {
                "engines": {"node": ">=22.0.0"},
                "scripts": {"postinstall": "node install.js"},
            },
        )
        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["packages"][0]["target"]["integrity"] = integrity(
            self.target_archive
        )
        metadata["packages"][0]["target"]["shasum"] = hashlib.sha1(
            self.target_archive.read_bytes()
        ).hexdigest()
        metadata["core_candidate"]["target"] = core_closure(
            "1.1.0",
            [("@example/message-codec", "3.4.2")],
            root_integrity=integrity(self.target_archive),
        )
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        sequential_output = self.root / "blocked-sequential"
        parallel_output = self.root / "blocked-parallel"

        sequential = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--archive-workers",
            "1",
            output_dir=sequential_output,
        )
        parallel = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--archive-workers",
            "2",
            output_dir=parallel_output,
        )

        self.assertEqual(sequential.returncode, 2, sequential.stderr)
        self.assertEqual(parallel.returncode, 2, parallel.stderr)
        sequential_status = json.loads(
            (sequential_output / "verdict.json").read_text()
        )
        parallel_status = json.loads(
            (parallel_output / "verdict.json").read_text()
        )
        self.assertEqual(
            sequential_status["decision_content"],
            parallel_status["decision_content"],
        )
        self.assertEqual(
            sequential_status["decision_digest"],
            parallel_status["decision_digest"],
        )
        self.assertEqual(sequential_status["verdict"], "blocked")
        self.assertEqual(parallel_status["verdict"], "blocked")

    def test_archive_executor_bounds_concurrency_and_preserves_task_order(
        self,
    ) -> None:
        lock = threading.Lock()
        active = 0
        maximum_active = 0

        def unit_runner(
            task: dict[str, object],
            cache_dir: Path | None,
            timeout_seconds: float,
        ) -> dict[str, object]:
            del cache_dir, timeout_seconds
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return {
                "task_id": task["task_id"],
                "package": task["name"],
                "lane": task["lane"],
                "status": "success",
                "inspection": {},
                "error": None,
                "cache_provenance": [],
                "duration_ms": 30,
            }

        tasks = [
            {
                "task_id": f"{index}:package-{index}:target",
                "name": f"package-{index}",
                "lane": "target",
                "path": self.root / f"package-{index}.tgz",
                "metadata": {
                    "name": f"package-{index}",
                    "version": "1.0.0",
                },
            }
            for index in range(4)
        ]
        results = SAFE_UPDATE.execute_archive_analyses(
            tasks,
            cache_dir=None,
            workers=2,
            timeout_seconds=1,
            unit_runner=unit_runner,
        )

        self.assertEqual(
            [result["task_id"] for result in results],
            [task["task_id"] for task in tasks],
        )
        self.assertTrue(all(result["status"] == "success" for result in results))
        self.assertEqual(maximum_active, 2)

    def test_archive_executor_reports_mixed_failure_and_timeout(self) -> None:
        def unit_runner(
            task: dict[str, object],
            cache_dir: Path | None,
            timeout_seconds: float,
        ) -> dict[str, object]:
            del cache_dir
            metadata = task["metadata"]
            if metadata["behavior"] == "failed":
                return {
                    "task_id": task["task_id"],
                    "package": task["name"],
                    "lane": task["lane"],
                    "status": "failed",
                    "inspection": None,
                    "error": "seeded archive failure",
                    "cache_provenance": [],
                    "duration_ms": 0,
                }
            if metadata["behavior"] == "slow":
                return SAFE_UPDATE.archive_timeout_result(
                    task,
                    timeout_seconds,
                )
            return {
                "task_id": task["task_id"],
                "package": task["name"],
                "lane": task["lane"],
                "status": "success",
                "inspection": {},
                "error": None,
                "cache_provenance": [],
                "duration_ms": 0,
            }

        tasks = [
            {
                "task_id": f"{index}:{behavior}:target",
                "name": behavior,
                "lane": "target",
                "path": self.root / f"{behavior}.tgz",
                "metadata": {"name": behavior, "behavior": behavior},
            }
            for index, behavior in enumerate(("success", "failed", "slow"))
        ]
        results = SAFE_UPDATE.execute_archive_analyses(
            tasks,
            cache_dir=None,
            workers=3,
            timeout_seconds=0.01,
            unit_runner=unit_runner,
        )

        self.assertEqual(
            [result["status"] for result in results],
            ["success", "failed", "timed_out"],
        )
        self.assertEqual(results[1]["error"], "seeded archive failure")
        self.assertIn("timed out", results[2]["error"])
        with self.assertRaises(SAFE_UPDATE.RehearsalError):
            SAFE_UPDATE.execute_archive_analyses(
                tasks,
                cache_dir=None,
                workers=SAFE_UPDATE.MAX_ARCHIVE_WORKERS + 1,
                timeout_seconds=1,
                unit_runner=unit_runner,
            )
        with patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit):
                SAFE_UPDATE.parser().parse_args(
                    [
                        "simulate",
                        "--input-dir",
                        str(self.input),
                        "--output-dir",
                        str(self.root / "invalid-workers"),
                        "--archive-workers",
                        "0",
                    ]
                )

    def test_archive_subprocess_timeout_is_killed_and_reported(self) -> None:
        task = {
            "task_id": "0:openclaw:target",
            "name": "openclaw",
            "lane": "target",
            "path": self.target_archive,
            "metadata": {
                "name": "openclaw",
                "version": "1.1.0",
            },
        }
        with patch.object(
            SAFE_UPDATE.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(
                cmd=["archive-worker"],
                timeout=0.01,
            ),
        ):
            result = SAFE_UPDATE.run_archive_subprocess_unit(
                task,
                None,
                0.01,
            )

        self.assertEqual(result["status"], "timed_out")
        self.assertIn("timed out", result["error"])
        self.assertEqual(result["cache_provenance"], [])

    def test_archive_timeout_prevents_late_subprocess_write(self) -> None:
        marker = self.root / "late-write-marker"
        task = {
            "task_id": "0:openclaw:target",
            "name": "openclaw",
            "lane": "target",
            "path": self.target_archive,
            "metadata": {
                "name": "openclaw",
                "version": "1.1.0",
            },
        }
        command = [
            sys.executable,
            "-c",
            (
                "import pathlib,sys,time;"
                "time.sleep(0.2);"
                "pathlib.Path(sys.argv[1]).write_text('late')"
            ),
            str(marker),
        ]

        result = SAFE_UPDATE.run_archive_subprocess_unit(
            task,
            None,
            0.02,
            command_override=command,
        )
        time.sleep(0.25)

        self.assertEqual(result["status"], "timed_out")
        self.assertFalse(marker.exists())

    def test_corrupt_cache_entry_is_ignored_and_recomputed(self) -> None:
        cache = self.root / "corrupt-cache-store"
        cold_output = self.root / "corrupt-cache-cold"
        warm_output = self.root / "corrupt-cache-warm"
        cold = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=cold_output,
            cache_dir=cache,
        )
        self.assertEqual(cold.returncode, 0, cold.stderr)
        archive_entry = next((cache / "archive").glob("*.json"))
        archive_entry.write_text('{"schema":"partial"}\n', encoding="utf-8")

        warm = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=warm_output,
            cache_dir=cache,
        )

        self.assertEqual(warm.returncode, 0, warm.stderr)
        cold_status = json.loads((cold_output / "verdict.json").read_text())
        warm_status = json.loads((warm_output / "verdict.json").read_text())
        report = json.loads((warm_output / "analysis-cache.json").read_text())
        self.assertEqual(cold_status["decision_digest"], warm_status["decision_digest"])
        self.assertEqual(cold_status["verdict"], warm_status["verdict"])
        self.assertEqual(report["counts"]["ignored"], 1)
        self.assertEqual(report["counts"]["miss"], 1)

    def test_rehashed_but_unauthenticated_cache_tampering_is_ignored(self) -> None:
        cache = self.root / "tampered-cache-store"
        cold_output = self.root / "tampered-cache-cold"
        warm_output = self.root / "tampered-cache-warm"
        cold = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=cold_output,
            cache_dir=cache,
        )
        self.assertEqual(cold.returncode, 0, cold.stderr)
        policy_entry_path = next((cache / "policy").glob("*.json"))
        policy_entry = json.loads(policy_entry_path.read_text())
        policy_entry["payload"] = {
            condition_id: False
            for condition_id in SAFE_UPDATE.CONSERVATIVE_CONDITION_IDS
        }
        policy_entry["payload_digest"] = SAFE_UPDATE.canonical_digest(
            policy_entry["payload"]
        )
        policy_entry_path.write_text(
            json.dumps(policy_entry),
            encoding="utf-8",
        )

        warm = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=warm_output,
            cache_dir=cache,
        )

        self.assertEqual(warm.returncode, 0, warm.stderr)
        cold_status = json.loads((cold_output / "verdict.json").read_text())
        warm_status = json.loads((warm_output / "verdict.json").read_text())
        report = json.loads((warm_output / "analysis-cache.json").read_text())
        self.assertEqual(cold_status["decision_digest"], warm_status["decision_digest"])
        self.assertEqual(cold_status["verdict"], warm_status["verdict"])
        self.assertTrue(
            any(
                item["namespace"] == "policy" and item["result"] == "ignored"
                for item in report["entries"]
            )
        )

    def test_transitive_dependency_change_invalidates_policy_and_shadow_cache(
        self,
    ) -> None:
        cache = self.root / "drift-cache-store"
        first_output = self.root / "drift-cache-first"
        second_output = self.root / "drift-cache-second"
        first = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=first_output,
            cache_dir=cache,
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["core_candidate"]["target"] = core_closure(
            "1.1.0",
            [("@example/message-codec", "3.5.0")],
            root_integrity=integrity(self.target_archive),
        )
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        second = self.run_simulation(
            "--customizations",
            str(self.customizations),
            output_dir=second_output,
            cache_dir=cache,
        )

        self.assertEqual(second.returncode, 0, second.stderr)
        first_cache = json.loads((first_output / "analysis-cache.json").read_text())
        second_cache = json.loads((second_output / "analysis-cache.json").read_text())
        results = {
            (item["namespace"], item["result"])
            for item in second_cache["entries"]
        }
        self.assertIn(("archive", "hit"), results)
        self.assertIn(("contract", "hit"), results)
        self.assertIn(("policy", "miss"), results)
        self.assertIn(("shadow", "miss"), results)
        self.assertNotEqual(
            first_cache["rehearsal_input_digest"],
            second_cache["rehearsal_input_digest"],
        )

    def test_cache_keys_invalidate_on_contract_policy_and_analyzer_change(self) -> None:
        cache = self.root / "key-cache-store"
        provenance: list[dict[str, str]] = []
        first = SAFE_UPDATE.cached_analysis(
            cache_dir=cache,
            namespace="contract",
            key_material={"contract": "v1"},
            provenance=provenance,
            build=lambda: {"value": 1},
        )
        second = SAFE_UPDATE.cached_analysis(
            cache_dir=cache,
            namespace="contract",
            key_material={"contract": "v2"},
            provenance=provenance,
            build=lambda: {"value": 2},
        )
        with patch.object(
            SAFE_UPDATE,
            "DETERMINISTIC_POLICY_VERSION",
            "conservative-gates:v2",
        ):
            policy = SAFE_UPDATE.cached_analysis(
                cache_dir=cache,
                namespace="contract",
                key_material={"contract": "v1"},
                provenance=provenance,
                build=lambda: {"value": 3},
            )
        with patch.object(SAFE_UPDATE, "ANALYZER_VERSION", "analyzer:v2"):
            analyzer = SAFE_UPDATE.cached_analysis(
                cache_dir=cache,
                namespace="contract",
                key_material={"contract": "v1"},
                provenance=provenance,
                build=lambda: {"value": 4},
            )

        self.assertEqual(first, {"value": 1})
        self.assertEqual(second, {"value": 2})
        self.assertEqual(policy, {"value": 3})
        self.assertEqual(analyzer, {"value": 4})
        self.assertEqual(
            [item["result"] for item in provenance],
            ["miss", "miss", "miss", "miss"],
        )

    def test_rehearsal_input_digest_covers_every_authoritative_input_class(
        self,
    ) -> None:
        arguments = {
            "candidate_roots": {
                "current": "sha256:" + "1" * 64,
                "target": "sha256:" + "2" * 64,
            },
            "installation_contract": {"schema": "contract", "value": 1},
            "installation_attestation": {"schema": "attestation", "value": 1},
            "conservative_inputs": {
                "satisfied_gates": [],
                "operator_escalations": [],
            },
            "authoritative_analysis": {
                "core_candidate_lock": {"status": "success"},
                "authority_packages": [],
                "coverage_profile": {"mode": "required"},
                "customization_checks": [],
            },
            "options": {"impact_shadow_enabled": True},
        }
        baseline = SAFE_UPDATE.canonical_digest(
            SAFE_UPDATE.build_rehearsal_input(**arguments)
        )
        mutations = [
            {
                **arguments,
                "candidate_roots": {
                    **arguments["candidate_roots"],
                    "target": "sha256:" + "3" * 64,
                },
            },
            {
                **arguments,
                "installation_contract": {"schema": "contract", "value": 2},
            },
            {
                **arguments,
                "installation_attestation": {
                    "schema": "attestation",
                    "value": 2,
                },
            },
            {
                **arguments,
                "conservative_inputs": {
                    "satisfied_gates": [],
                    "operator_escalations": ["state-migration-rehearsal"],
                },
            },
            {
                **arguments,
                "authoritative_analysis": {
                    **arguments["authoritative_analysis"],
                    "authority_packages": [{"name": "changed"}],
                },
            },
            {
                **arguments,
                "options": {"impact_shadow_enabled": False},
            },
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(
                    baseline,
                    SAFE_UPDATE.canonical_digest(
                        SAFE_UPDATE.build_rehearsal_input(**mutation)
                    ),
                )

    def test_missing_customization_manifest_blocks_and_keeps_artifacts(self) -> None:
        result = self.run_simulation()
        self.assertEqual(result.returncode, 2)
        verdict = json.loads((self.root / "output" / "verdict.json").read_text())
        custom = json.loads((self.root / "output" / "customization-compatibility.json").read_text())
        self.assertEqual(verdict["verdict"], "blocked")
        self.assertEqual(custom["mode"], "missing")

    def test_missing_coverage_profile_blocks(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "simulate",
                "--input-dir",
                str(self.input),
                "--customizations",
                str(self.customizations),
                "--output-dir",
                str(self.root / "no-coverage-output"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        coverage = json.loads((self.root / "no-coverage-output" / "coverage-report.json").read_text())
        self.assertEqual(coverage["status"], "failed")
        self.assertIn("coverage profile is required", coverage["errors"])

    def test_coverage_rejects_required_surface_without_postcheck(self) -> None:
        value = json.loads(self.coverage.read_text())
        value["surfaces"][0]["post_update_checks"] = []
        self.coverage.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 2)
        coverage = json.loads((self.root / "output" / "coverage-report.json").read_text())
        self.assertTrue(any("post-update check" in error for error in coverage["errors"]))

    def test_incompatible_runtime_node_blocks(self) -> None:
        value = json.loads(self.coverage.read_text())
        value["runtime"]["node_version"] = "20.18.0"
        self.coverage.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 2)
        synthetic = json.loads((self.root / "output" / "synthetic-update.json").read_text())
        risks = synthetic["packages"][0]["package_metadata"]["risk_findings"]
        self.assertTrue(any(item["id"] == "target-node-engine-incompatible" for item in risks))

    def test_lifecycle_script_change_blocks(self) -> None:
        write_archive(
            self.target_archive,
            "1.1.0",
            {
                "package/dist/runtime.js": "const agentRuntime = 'new';\n",
                "package/extensions/signal/index.js": "signal new\n",
            },
            {"engines": {"node": ">=22.0.0"}, "scripts": {"postinstall": "node download.js"}},
        )
        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["packages"][0]["target"]["integrity"] = integrity(self.target_archive)
        metadata["packages"][0]["target"]["shasum"] = hashlib.sha1(self.target_archive.read_bytes()).hexdigest()
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 2)
        synthetic = json.loads((self.root / "output" / "synthetic-update.json").read_text())
        risks = synthetic["packages"][0]["package_metadata"]["risk_findings"]
        self.assertTrue(any(item["id"] == "lifecycle-script-changed" for item in risks))

    def test_inventory_writes_public_safe_draft_profiles(self) -> None:
        package_root = self.root / "installed" / "openclaw"
        package_root.mkdir(parents=True)
        (package_root / "package.json").write_text(
            json.dumps({"name": "openclaw", "version": "1.0.0", "engines": {"node": ">=22"}}),
            encoding="utf-8",
        )
        output = self.root / "inventory"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "inventory",
                "--package-root",
                str(package_root),
                "--output-dir",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads((output / "inventory.json").read_text())
        coverage = json.loads((output / "coverage.draft.json").read_text())
        self.assertEqual(inventory["installed_version"], "1.0.0")
        self.assertEqual(coverage["schema"], "openclaw.safe_update.coverage.v1")
        self.assertEqual(coverage["surfaces"], [])
        self.assertFalse(inventory["production_apply_allowed"])

    def test_v1_1_manifests_translate_to_installation_contract(self) -> None:
        output = self.root / "installation-contract.json"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "contract",
                "--customizations",
                str(self.customizations),
                "--coverage",
                str(self.coverage),
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        contract = SAFE_UPDATE.parse_installation_contract(
            json.loads(output.read_text())
        )
        signal = next(item for item in contract["capabilities"] if item["id"] == "signal")
        self.assertEqual(signal["business_criticality"], "critical")
        self.assertEqual(signal["evidence_policy"], "always")
        self.assertEqual(signal["post_activation_checks"], [
            "inbound text reaches the agent",
            "outbound reply reaches Signal",
            "voice note is transcribed",
        ])
        self.assertEqual(signal["component_ids"], ["compatibility:signal-entrypoint"])

    def test_installation_contract_rejects_duplicates_dangling_edges_and_bad_policy(self) -> None:
        contract = json.loads(SIGNAL_VOICE_CONTRACT.read_text())

        duplicate = copy.deepcopy(contract)
        duplicate["components"].append(copy.deepcopy(duplicate["components"][0]))
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "duplicate component"):
            SAFE_UPDATE.parse_installation_contract(duplicate)

        dangling = copy.deepcopy(contract)
        dangling["components"][1]["depends_on"][0]["component_id"] = "missing"
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "unknown dependency"):
            SAFE_UPDATE.parse_installation_contract(dangling)

        bad_policy = copy.deepcopy(contract)
        bad_policy["capabilities"][0]["evidence_policy"] = "unaffected"
        with self.assertRaisesRegex(SAFE_UPDATE.RehearsalError, "evidence policy"):
            SAFE_UPDATE.parse_installation_contract(bad_policy)

    def test_signal_voice_contract_spans_core_addon_configuration_and_postcheck(self) -> None:
        contract = SAFE_UPDATE.parse_installation_contract(
            json.loads(SIGNAL_VOICE_CONTRACT.read_text())
        )
        capability = contract["capabilities"][0]
        roles = {
            role
            for component in contract["components"]
            for role in component["roles"]
        }
        self.assertEqual(capability["id"], "signal.voice")
        self.assertEqual(
            set(capability["component_ids"]),
            {
                "core.message-normalizer",
                "addon.signal-adapter",
                "configuration.signal-media",
            },
        )
        self.assertTrue({"core", "addon", "configuration", "personalization"} <= roles)
        self.assertEqual(
            capability["post_activation_checks"],
            ["receive and transcribe a Signal voice message"],
        )

    def test_composed_candidate_root_is_independent_of_declaration_order(self) -> None:
        metadata = json.loads((self.input / "input-metadata.json").read_text())
        contract = json.loads(COMPOSED_INSTALLATION_CONTRACT.read_text())
        reordered = copy.deepcopy(contract)
        reordered["capabilities"].reverse()
        reordered["components"].reverse()
        reordered["contracts"].reverse()
        for component in reordered["components"]:
            component["roles"].reverse()
            component["application_phases"].reverse()
            component["artifacts"].reverse()
            component["contract_ids"].reverse()
            component["depends_on"].reverse()
            component["supports"].reverse()

        first = SAFE_UPDATE.compose_installation_candidate("target", metadata, contract)
        second = SAFE_UPDATE.compose_installation_candidate(
            "target", metadata, reordered
        )

        self.assertEqual(first["root"], second["root"])
        self.assertEqual(first, second)
        self.assertEqual(
            [item["id"] for item in first["components"]],
            sorted(item["id"] for item in first["components"]),
        )

    def test_composed_candidate_changes_with_artifact_contract_and_policy(self) -> None:
        metadata = json.loads((self.input / "input-metadata.json").read_text())
        contract = json.loads(COMPOSED_INSTALLATION_CONTRACT.read_text())
        baseline = SAFE_UPDATE.compose_installation_candidate(
            "target", metadata, contract
        )

        artifact_drift = copy.deepcopy(contract)
        sidecar = next(
            item for item in artifact_drift["components"] if item["id"] == "sidecar.mcp"
        )
        sidecar["artifacts"][0]["ref"] = (
            "mcp-broker@2.1.0#sha256:"
            + "f" * 64
        )
        contract_drift = copy.deepcopy(contract)
        contract_drift["contracts"][0]["evidence_refs"].append(
            "second deterministic contract reference"
        )

        artifact_candidate = SAFE_UPDATE.compose_installation_candidate(
            "target", metadata, artifact_drift
        )
        contract_candidate = SAFE_UPDATE.compose_installation_candidate(
            "target", metadata, contract_drift
        )
        with patch.object(
            SAFE_UPDATE,
            "INSTALLATION_COMPOSITION_POLICY_VERSION",
            "2",
        ):
            policy_candidate = SAFE_UPDATE.compose_installation_candidate(
                "target", metadata, contract
            )

        self.assertNotEqual(baseline["root"], artifact_candidate["root"])
        self.assertNotEqual(baseline["root"], contract_candidate["root"])
        self.assertNotEqual(baseline["root"], policy_candidate["root"])

    def test_composed_candidate_fails_closed_on_unbound_artifacts(self) -> None:
        metadata = json.loads((self.input / "input-metadata.json").read_text())
        contract = json.loads(COMPOSED_INSTALLATION_CONTRACT.read_text())
        cases: list[tuple[str, dict[str, object], str]] = []

        missing = copy.deepcopy(contract)
        missing["components"][0]["artifacts"] = []
        cases.append(("missing", missing, "has no artifacts"))

        floating = copy.deepcopy(contract)
        next(
            item for item in floating["components"] if item["id"] == "sidecar.mcp"
        )["artifacts"][0]["ref"] = "mcp-broker@2.1.0"
        cases.append(("floating", floating, "must pin exact version and sha256"))

        duplicate = copy.deepcopy(contract)
        component = next(
            item for item in duplicate["components"] if item["id"] == "sidecar.mcp"
        )
        component["artifacts"].append(copy.deepcopy(component["artifacts"][0]))
        cases.append(("duplicate", duplicate, "duplicate artifacts"))

        duplicate_dependency = copy.deepcopy(contract)
        component = next(
            item
            for item in duplicate_dependency["components"]
            if item["id"] == "addon.signal-adapter"
        )
        component["depends_on"].append(copy.deepcopy(component["depends_on"][0]))
        cases.append(
            (
                "duplicate_dependency",
                duplicate_dependency,
                "duplicate dependencies",
            )
        )

        unsupported = copy.deepcopy(contract)
        next(
            item for item in unsupported["components"] if item["id"] == "sidecar.mcp"
        )["artifacts"][0]["kind"] = "container_guess"
        cases.append(("unsupported", unsupported, "unsupported installation artifact kind"))

        common = {
            "generated_at": "2026-07-18T10:00:00+00:00",
            **SAFE_UPDATE.safety_fields(),
        }
        for name, malformed, expected in cases:
            with self.subTest(name=name):
                report, status = SAFE_UPDATE.build_installation_candidate_lock(
                    metadata,
                    malformed,
                    common,
                )
                self.assertEqual(status, "failed")
                self.assertIsNone(report["current_root"])
                self.assertIsNone(report["target_root"])
                self.assertTrue(any(expected in error for error in report["errors"]))

    def test_simulation_binds_one_composed_root_into_status_and_evidence(self) -> None:
        contract = json.loads(COMPOSED_INSTALLATION_CONTRACT.read_text())
        sidecar_path = self.root / "mcp-broker.tgz"
        sidecar_path.write_bytes(b"pinned sidecar artifact")
        sidecar_digest = hashlib.sha256(sidecar_path.read_bytes()).hexdigest()
        sidecar_component = next(
            item for item in contract["components"] if item["id"] == "sidecar.mcp"
        )
        sidecar_component["artifacts"][0]["ref"] = (
            f"mcp-broker@2.1.0#sha256:{sidecar_digest}"
        )
        contract_path = self.root / "composed-contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        config_path = self.root / "signal-media.json"
        config_path.write_text("SECRET_VALUE=not-for-output", encoding="utf-8")
        personalization_path = self.root / "conversation-voice"
        personalization_path.mkdir()
        metadata = json.loads((self.input / "input-metadata.json").read_text())
        candidate_lock, candidate_status = SAFE_UPDATE.build_installation_candidate_lock(
            metadata,
            contract,
            {
                "generated_at": SAFE_UPDATE.now_iso(),
                **SAFE_UPDATE.safety_fields(),
            },
        )
        self.assertEqual(candidate_status, "success")
        external_artifacts = {
            component["id"]: component["artifacts"][0]["ref"]
            for component in contract["components"]
            if component["id"]
            in {
                "configuration.signal-media",
                "sidecar.mcp",
                "personalization.voice",
            }
        }
        observation = {
            "schema": SAFE_UPDATE.INSTALLATION_OBSERVATION_SCHEMA,
            "components": [
                {
                    "component_id": "configuration.signal-media",
                    "artifact_ref": external_artifacts["configuration.signal-media"],
                    "name": "signal-media",
                    "path": str(config_path),
                    "mode": "identity_only",
                },
                {
                    "component_id": "sidecar.mcp",
                    "artifact_ref": external_artifacts["sidecar.mcp"],
                    "name": "mcp-broker",
                    "path": str(sidecar_path),
                    "mode": "content_sha256",
                },
                {
                    "component_id": "personalization.voice",
                    "artifact_ref": external_artifacts["personalization.voice"],
                    "name": "conversation-voice",
                    "path": str(personalization_path),
                    "mode": "identity_only",
                },
            ],
            "services": [],
        }
        attestation = SAFE_UPDATE.build_installation_attestation(
            candidate_lock,
            observation,
            generated_at=SAFE_UPDATE.now_iso(),
            ttl_seconds=3600,
        )
        attestation_path = self.root / "composed-attestation.json"
        attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
        result = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--installation-contract",
            str(contract_path),
            "--installation-attestation",
            str(attestation_path),
            include_attestation=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "output"
        candidate = json.loads(
            (output / "installation-candidate-lock.json").read_text()
        )
        status = json.loads((output / "verdict.json").read_text())
        evidence = json.loads((output / "evidence-bundle.json").read_text())
        schema = json.loads(INSTALLATION_CANDIDATE_SCHEMA.read_text())

        self.assertEqual(candidate["status"], "success")
        self.assertEqual(
            status["candidate_roots"],
            {
                "current": candidate["current_root"],
                "target": candidate["target_root"],
            },
        )
        self.assertEqual(
            status["decision_content"]["candidate_roots"],
            status["candidate_roots"],
        )
        self.assertEqual(
            status["decision_content"]["evidence_status"][
                "installation_candidate_lock"
            ],
            "success",
        )
        self.assertIn(
            "installation-candidate-lock.json",
            {item["path"] for item in evidence["evidence"]},
        )
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            SAFE_UPDATE.INSTALLATION_CANDIDATE_LOCK_SCHEMA,
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertNotIn("SECRET_VALUE", json.dumps(attestation))
        self.assertEqual(SAFE_UPDATE.parse_status(status), status)

    def test_attestation_detects_undeclared_overlay(self) -> None:
        overlay = self.root / "undeclared-overlay.js"
        overlay.write_text("not emitted", encoding="utf-8")
        attestation = SAFE_UPDATE.build_installation_attestation(
            self.default_candidate_lock,
            {
                "schema": SAFE_UPDATE.INSTALLATION_OBSERVATION_SCHEMA,
                "components": [
                    {
                        "component_id": "overlay.undeclared",
                        "artifact_ref": (
                            "overlay@1.0.0#sha256:" + "a" * 64
                        ),
                        "name": "undeclared-overlay",
                        "path": str(overlay),
                        "mode": "content_sha256",
                    }
                ],
                "services": [],
            },
            generated_at=SAFE_UPDATE.now_iso(),
            ttl_seconds=900,
        )

        self.assertEqual(attestation["status"], "failed")
        self.assertEqual(attestation["axes"]["observation"], "success")
        self.assertEqual(attestation["axes"]["completeness"], "incomplete")
        self.assertEqual(
            attestation["attestation_content"]["residue"][0]["kind"],
            "undeclared_component",
        )
        self.assertNotIn(str(self.root), json.dumps(attestation))
        self.assertNotIn("not emitted", json.dumps(attestation))

    def test_attestation_detects_service_pointer_to_undeclared_config(self) -> None:
        generated_config = self.root / "generated-openclaw.json"
        generated_config.write_text("TOKEN=must-not-be-read", encoding="utf-8")
        directives = {
            "exec": f"ExecStart=/usr/bin/openclaw gateway --config {generated_config}\n",
            "environment_file": f"EnvironmentFile={generated_config}\n",
        }
        for name, directive in directives.items():
            with self.subTest(name=name):
                service = self.root / f"{name}.service"
                service.write_text(
                    "[Service]\n" + directive,
                    encoding="utf-8",
                )
                attestation = SAFE_UPDATE.build_installation_attestation(
                    self.default_candidate_lock,
                    {
                        "schema": SAFE_UPDATE.INSTALLATION_OBSERVATION_SCHEMA,
                        "components": [],
                        "services": [
                            {
                                "name": f"{name}.service",
                                "path": str(service),
                            }
                        ],
                    },
                    generated_at=SAFE_UPDATE.now_iso(),
                    ttl_seconds=900,
                )

                self.assertEqual(attestation["status"], "failed")
                self.assertEqual(attestation["axes"]["completeness"], "incomplete")
                self.assertEqual(
                    attestation["attestation_content"]["residue"][0]["kind"],
                    "undeclared_generated_config",
                )
                serialized = json.dumps(attestation)
                self.assertNotIn(str(self.root), serialized)
                self.assertNotIn("TOKEN=must-not-be-read", serialized)

    def test_matching_attestation_digest_is_stable(self) -> None:
        observation = {
            "schema": SAFE_UPDATE.INSTALLATION_OBSERVATION_SCHEMA,
            "components": [],
            "services": [],
        }
        first = SAFE_UPDATE.build_installation_attestation(
            self.default_candidate_lock,
            observation,
            generated_at="2026-07-18T00:00:00+00:00",
            ttl_seconds=900,
        )
        second = SAFE_UPDATE.build_installation_attestation(
            self.default_candidate_lock,
            observation,
            generated_at="2026-07-18T01:00:00+00:00",
            ttl_seconds=900,
        )

        self.assertEqual(first["status"], "success")
        self.assertEqual(first["attestation_content"], second["attestation_content"])
        self.assertEqual(first["attestation_digest"], second["attestation_digest"])

    def test_attest_command_writes_strict_public_safe_artifact(self) -> None:
        candidate_path = self.root / "candidate-lock.json"
        candidate_path.write_text(
            json.dumps(self.default_candidate_lock),
            encoding="utf-8",
        )
        observation_path = self.root / "observation.json"
        observation_path.write_text(
            json.dumps(
                {
                    "schema": SAFE_UPDATE.INSTALLATION_OBSERVATION_SCHEMA,
                    "components": [],
                    "services": [],
                }
            ),
            encoding="utf-8",
        )
        output = self.root / "attested.json"

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "attest",
                "--candidate-lock",
                str(candidate_path),
                "--observation",
                str(observation_path),
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        attestation = json.loads(output.read_text())
        schema = json.loads(INSTALLATION_ATTESTATION_SCHEMA.read_text())
        self.assertEqual(attestation["status"], "success")
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            SAFE_UPDATE.INSTALLATION_ATTESTATION_SCHEMA,
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertNotIn(str(self.root), output.read_text())

    def test_missing_and_expired_attestation_block_ready_status(self) -> None:
        missing = self.run_simulation(
            "--customizations",
            str(self.customizations),
            include_attestation=False,
        )
        self.assertEqual(missing.returncode, 2)
        verdict = json.loads((self.root / "output" / "verdict.json").read_text())
        self.assertEqual(verdict["verdict"], "blocked")
        self.assertEqual(
            verdict["decision_content"]["evidence_status"][
                "installation_attestation"
            ],
            "failed",
        )
        failed_attestation = json.loads(
            (self.root / "output" / "installation-attestation.json").read_text()
        )
        schema = json.loads(INSTALLATION_ATTESTATION_SCHEMA.read_text())
        self.assertEqual(set(failed_attestation), set(schema["required"]))

        expired = json.loads(self.attestation.read_text())
        expired["expires_at"] = "2026-01-01T00:00:00+00:00"
        expired_path = self.root / "expired-attestation.json"
        expired_path.write_text(json.dumps(expired), encoding="utf-8")
        stale = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--installation-attestation",
            str(expired_path),
            include_attestation=False,
        )
        self.assertEqual(stale.returncode, 2)
        verdict = json.loads((self.root / "output" / "verdict.json").read_text())
        self.assertEqual(verdict["verdict"], "blocked")

        stale_root = json.loads(self.attestation.read_text())
        stale_root["attestation_content"]["candidate_root"] = "sha256:" + "9" * 64
        stale_root["attestation_digest"] = SAFE_UPDATE.canonical_digest(
            stale_root["attestation_content"]
        )
        stale_root_path = self.root / "stale-root-attestation.json"
        stale_root_path.write_text(json.dumps(stale_root), encoding="utf-8")
        stale = self.run_simulation(
            "--customizations",
            str(self.customizations),
            "--installation-attestation",
            str(stale_root_path),
            include_attestation=False,
        )
        self.assertEqual(stale.returncode, 2)
        verdict = json.loads((self.root / "output" / "verdict.json").read_text())
        self.assertEqual(
            verdict["decision_content"]["evidence_status"][
                "installation_attestation"
            ],
            "failed",
        )

    def test_integrity_mismatch_blocks(self) -> None:
        with self.target_archive.open("ab") as handle:
            handle.write(b"tampered")
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 2)
        synthetic = json.loads((self.root / "output" / "synthetic-update.json").read_text())
        self.assertEqual(synthetic["status"], "failed")
        self.assertIn("integrity mismatch", synthetic["packages"][0]["errors"][0])

    def test_archive_filename_traversal_blocks(self) -> None:
        metadata_path = self.input / "input-metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["packages"][0]["target"]["archive"] = "../openclaw-target.tgz"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.run_simulation("--customizations", str(self.customizations))
        self.assertEqual(result.returncode, 2)
        synthetic = json.loads((self.root / "output" / "synthetic-update.json").read_text())
        self.assertIn("unsafe archive filename", synthetic["packages"][0]["errors"][0])

    def test_fetch_rejects_version_ranges(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "fetch",
                "--current-version",
                "1.0.0",
                "--target-version",
                "latest",
                "--output-dir",
                str(self.root / "fetch"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("exact semver", result.stderr)

    def test_workflow_has_no_apply_or_external_write_surface(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        forbidden = [
            "openclaw update",
            "npm install",
            "systemctl",
            "operator-approval",
            "pull_request_comment",
            "issues: write",
            "contents: write",
        ]
        for value in forbidden:
            self.assertNotIn(value, text)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", text)
        self.assertNotIn("uses: actions/checkout@v4", text)
        self.assertIn("ready_for_operator_plan", text)
        self.assertIn("COVERAGE_FILE", text)
        self.assertIn("coverage-report.json", text)
        self.assertIn("post-upgrade-e2e.json", text)
        self.assertIn("operator-plan.md", text)

    def test_fetch_pins_public_npm_registry(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('NPM_REGISTRY = "https://registry.npmjs.org"', text)
        self.assertIn('"NPM_CONFIG_REGISTRY": NPM_REGISTRY', text)

    def test_public_product_surface_preserves_rehearsal_boundary(self) -> None:
        readme = README.read_text(encoding="utf-8")
        self.assertIn("OpenClaw Safe Upgrade Rehearsal Kit", readme)
        self.assertIn("openclaw skills install git:pdurlej/openclaw-skill-safe-update@main", readme)
        self.assertIn("openclaw skills info openclaw-safe-update", readme)
        self.assertIn("openclaw skills install @pdurlej/safe-upgrade-rehearsal", readme)
        self.assertIn("openclaw skills verify @pdurlej/safe-upgrade-rehearsal --card", readme)
        self.assertIn("mode-dry%20run%20only", readme)
        self.assertIn("OpenClaw%20skill-validated", readme)
        self.assertNotIn("verdict-fail%20closed", readme)
        self.assertIn("That is what “fail closed” means here", readme)
        self.assertIn("ready_for_operator_plan", readme)
        self.assertIn("does not update OpenClaw", readme)
        self.assertIn("forward recovery", readme)
        self.assertIn("Know what will break before it breaks", readme)
        self.assertIn("No two real OpenClaw installations are quite the same", readme)
        self.assertIn("coverage-report.json", readme)
        self.assertIn("post-upgrade-e2e.json", readme)
        self.assertIn("optional model reviewers stay\noutside the verdict path", readme)
        self.assertIn("scripts/openclaw_advisory.py prepare", readme)
        self.assertIn("upgrade-experience.yml", readme)
        self.assertIn("MIT License", LICENSE.read_text(encoding="utf-8"))
        issue_template = UPGRADE_ISSUE_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("upgrade-report", issue_template)
        self.assertIn("I removed secrets", issue_template)
        self.assertIn("green rehearsal is not approval", issue_template)
        self.assertGreater(HERO.stat().st_size, 100_000)
        self.assertEqual(HERO.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        clawhub_ignore = CLAWHUB_IGNORE.read_text(encoding="utf-8")
        self.assertIn("assets/brand/", clawhub_ignore)
        self.assertIn("tests/", clawhub_ignore)
        validate_workflow = VALIDATE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("clawhub@0.23.1 skill publish", validate_workflow)
        self.assertIn("--slug safe-upgrade-rehearsal", validate_workflow)
        self.assertIn("--version 1.3.0", validate_workflow)
        self.assertNotIn("--slug openclaw-", validate_workflow)
        self.assertIn("--dry-run", validate_workflow)
        self.assertNotIn("CLAWHUB_TOKEN", validate_workflow)


if __name__ == "__main__":
    unittest.main()
