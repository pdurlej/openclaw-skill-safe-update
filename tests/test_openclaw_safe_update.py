from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "openclaw_safe_update.py"
WORKFLOW = ROOT / "assets" / "github-workflows" / "openclaw-safe-update.yml"
VALIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
README = ROOT / "README.md"
LICENSE = ROOT / "LICENSE"
UPGRADE_ISSUE_TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE" / "upgrade-experience.yml"
HERO = ROOT / "assets" / "brand" / "openclaw-safe-upgrade-hero.png"
CLAWHUB_IGNORE = ROOT / ".clawhubignore"


def write_archive(path: Path, version: str, members: dict[str, str]) -> None:
    package_json = json.dumps({"name": "openclaw", "version": version})
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
        )
        write_archive(
            self.target_archive,
            "1.1.0",
            {
                "package/dist/runtime.js": "const agentRuntime = 'new';\n",
                "package/extensions/signal/index.js": "signal new\n",
                "package/added.js": "added\n",
            },
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
        self.assertEqual(verdict["verdict"], "ready_for_operator_plan")
        self.assertFalse(verdict["production_apply_allowed"])
        self.assertFalse(verdict["operator_approval"])
        self.assertEqual(verdict["external_effect"], "npm_registry_read_only")
        self.assertEqual(verdict["external_write_effect"], "none")
        self.assertEqual(evidence["repair_class"], "openclaw_upgrade")
        self.assertTrue(all(item["status"] == "success" for item in evidence["evidence"]))
        diff = synthetic["packages"][0]["diff"]
        self.assertIn("package/added.js", diff["added"]["members"])
        self.assertIn("package/removed.js", diff["removed"]["members"])

    def test_missing_customization_manifest_blocks_and_keeps_artifacts(self) -> None:
        result = self.run_simulation()
        self.assertEqual(result.returncode, 2)
        verdict = json.loads((self.root / "output" / "verdict.json").read_text())
        custom = json.loads((self.root / "output" / "customization-compatibility.json").read_text())
        self.assertEqual(verdict["verdict"], "blocked")
        self.assertEqual(custom["mode"], "missing")

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
        self.assertNotIn("--slug openclaw-", validate_workflow)
        self.assertIn("--dry-run", validate_workflow)
        self.assertNotIn("CLAWHUB_TOKEN", validate_workflow)


if __name__ == "__main__":
    unittest.main()
