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
BASELINE = ROOT / "references" / "v1.1-baseline.json"
SIGNAL_VOICE_CONTRACT = ROOT / "examples" / "signal-voice.installation-contract.json"
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

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_simulation(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "simulate",
                "--input-dir",
                str(self.input),
                "--output-dir",
                str(self.root / "output"),
                "--coverage",
                str(self.coverage),
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
        self.assertNotEqual(candidate_lock["current_root"], candidate_lock["target_root"])
        codec = next(
            item
            for item in candidate_lock["changed_packages"]
            if item["name"] == "@example/message-codec"
        )
        self.assertEqual(codec["current_version"], "3.4.2")
        self.assertEqual(codec["target_version"], "3.5.0")

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
        self.assertEqual(baseline["commit"], BASELINE_SHA)
        self.assertEqual(baseline["test_case_count"], 13)
        self.assertEqual(baseline["test_cases"], BASELINE_TEST_CASES)

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
        self.assertIn("planned for\n1.2", readme)
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
        self.assertIn("--version 1.1.0", validate_workflow)
        self.assertNotIn("--slug openclaw-", validate_workflow)
        self.assertIn("--dry-run", validate_workflow)
        self.assertNotIn("CLAWHUB_TOKEN", validate_workflow)


if __name__ == "__main__":
    unittest.main()
