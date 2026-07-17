#!/usr/bin/env python3
"""Read-only OpenClaw package update rehearsal."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from typing import Any


EFFECT = "read_only_openclaw_update_rehearsal"
INPUT_SCHEMA = "openclaw.safe_update.input.v1"
CUSTOMIZATIONS_SCHEMA = "openclaw.safe_update.customizations.v1"
COVERAGE_SCHEMA = "openclaw.safe_update.coverage.v1"
INSTALLATION_CONTRACT_SCHEMA = "openclaw.safe_update.installation_contract.v1"
STATUS_SCHEMA = "openclaw.safe_update.status.v2"
DECISION_SCHEMA = "openclaw.safe_update.decision.v1"
LEGACY_VERDICT_SCHEMA = "openclaw.safe_update.verdict.v1"
STATUS_FIELDS = frozenset(
    {
        "schema",
        "generated_at",
        "effect",
        "runtime_effect",
        "external_effect",
        "external_write_effect",
        "production_apply_allowed",
        "operator_approval",
        "phase",
        "post_activation_e2e",
        "verdict",
        "reason",
        "evidence_bundle",
        "next_step",
        "decision_content",
        "decision_digest",
        "run_envelope",
        "compatibility_view",
    }
)
DECISION_FIELDS = frozenset(
    {
        "schema",
        "phase",
        "verdict",
        "reason_code",
        "evidence_status",
        "production_apply_allowed",
        "operator_approval",
        "post_activation_e2e",
        "next_step_code",
    }
)
EVIDENCE_STATUS_FIELDS = frozenset(
    {
        "runtime_truth",
        "synthetic_update",
        "customization_compatibility",
        "installation_coverage",
        "post_upgrade_e2e_plan",
    }
)
EVIDENCE_BUNDLE_FIELDS = frozenset({"path", "sha256"})
PACKAGE_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
MAX_TEXT_MEMBER_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 512 * 1024 * 1024
DIFF_MEMBER_LIMIT = 250
NPM_REGISTRY = "https://registry.npmjs.org"
SUPPORTED_INSTALL_SHAPES = {"npm_global_linux"}
SURFACE_CATEGORIES = {
    "attachment",
    "channel",
    "mcp",
    "memory",
    "other",
    "persona",
    "plugin",
    "provider",
    "service",
    "voice",
}
BUSINESS_CRITICALITIES = {"critical", "important", "best_effort"}
EVIDENCE_POLICIES = {"always", "impact_triggered", "sampled"}
COMPONENT_ROLES = {"core", "compatibility", "addon", "personalization", "configuration"}
DEPENDENCY_KINDS = {"runtime", "configuration", "state", "contract"}
PACKAGE_METADATA_FIELDS = (
    "engines",
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "scripts",
    "bin",
)
LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepack", "prepare"}


class RehearsalError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safety_fields() -> dict[str, Any]:
    return {
        "effect": EFFECT,
        "runtime_effect": "none",
        "external_effect": "npm_registry_read_only",
        "external_write_effect": "none",
        "production_apply_allowed": False,
        "operator_approval": False,
    }


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def legacy_verdict_payload(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": LEGACY_VERDICT_SCHEMA,
        "generated_at": status["generated_at"],
        **safety_fields(),
        "verdict": status["verdict"],
        "reason": status["reason"],
        "evidence_bundle": status["evidence_bundle"],
        "next_step": status["next_step"],
    }


def build_status(
    *,
    generated_at: str,
    verdict: str,
    reason: str,
    reason_code: str,
    evidence_status: dict[str, str],
    evidence_bundle: dict[str, str],
    next_step: str,
    next_step_code: str,
) -> dict[str, Any]:
    decision_content = {
        "schema": DECISION_SCHEMA,
        "phase": "preflight",
        "verdict": verdict,
        "reason_code": reason_code,
        "evidence_status": evidence_status,
        "production_apply_allowed": False,
        "operator_approval": False,
        "post_activation_e2e": "not_run",
        "next_step_code": next_step_code,
    }
    status = {
        "schema": STATUS_SCHEMA,
        "generated_at": generated_at,
        **safety_fields(),
        "phase": "preflight",
        "post_activation_e2e": "not_run",
        "verdict": verdict,
        "reason": reason,
        "evidence_bundle": evidence_bundle,
        "next_step": next_step,
        "decision_content": decision_content,
        "decision_digest": canonical_digest(decision_content),
        "run_envelope": {
            "generated_at": generated_at,
            "evidence_bundle": evidence_bundle,
        },
    }
    status["compatibility_view"] = {
        "schema": "openclaw.safe_update.compatibility_view.v1",
        "authoritative": False,
        "payload": legacy_verdict_payload(status),
    }
    return status


def parse_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RehearsalError("status must be a JSON object")
    if value.get("schema") != STATUS_SCHEMA:
        raise RehearsalError(f"status schema must be {STATUS_SCHEMA}")
    if set(value) != STATUS_FIELDS:
        raise RehearsalError("status contains unknown or missing fields")

    hard_invariants = {
        "effect": EFFECT,
        "runtime_effect": "none",
        "external_effect": "npm_registry_read_only",
        "external_write_effect": "none",
        "production_apply_allowed": False,
        "operator_approval": False,
        "phase": "preflight",
        "post_activation_e2e": "not_run",
    }
    for field, expected in hard_invariants.items():
        if value.get(field) != expected:
            raise RehearsalError(f"status invariant {field} must be {expected!r}")

    if not isinstance(value.get("generated_at"), str) or not value["generated_at"]:
        raise RehearsalError("status generated_at must be a non-empty string")
    if value.get("verdict") not in {"blocked", "ready_for_operator_plan"}:
        raise RehearsalError("status verdict is invalid")
    if not isinstance(value.get("reason"), str) or not value["reason"]:
        raise RehearsalError("status reason must be a non-empty string")
    if not isinstance(value.get("next_step"), str) or not value["next_step"]:
        raise RehearsalError("status next_step must be a non-empty string")
    bundle = value.get("evidence_bundle")
    if (
        not isinstance(bundle, dict)
        or set(bundle) != EVIDENCE_BUNDLE_FIELDS
        or not isinstance(bundle.get("path"), str)
        or not bundle["path"]
        or not re.fullmatch(r"[0-9a-f]{64}", str(bundle.get("sha256", "")))
    ):
        raise RehearsalError("status evidence_bundle is invalid")
    decision = value.get("decision_content")
    if not isinstance(decision, dict) or decision.get("schema") != DECISION_SCHEMA:
        raise RehearsalError(f"decision_content schema must be {DECISION_SCHEMA}")
    if set(decision) != DECISION_FIELDS:
        raise RehearsalError("decision_content contains unknown or missing fields")
    if value.get("decision_digest") != canonical_digest(decision):
        raise RehearsalError("decision_digest does not match decision_content")
    for field in (
        "phase",
        "verdict",
        "production_apply_allowed",
        "operator_approval",
        "post_activation_e2e",
    ):
        if decision.get(field) != value.get(field):
            raise RehearsalError(f"decision_content {field} does not match status")
    if not isinstance(decision.get("evidence_status"), dict):
        raise RehearsalError("decision_content evidence_status must be an object")
    if set(decision["evidence_status"]) != EVIDENCE_STATUS_FIELDS:
        raise RehearsalError(
            "decision_content evidence_status contains unknown or missing fields"
        )
    evidence_values = set(decision["evidence_status"].values())
    if not evidence_values or not evidence_values <= {"success", "failed"}:
        raise RehearsalError("decision_content evidence_status is invalid")
    expected_reason_code = (
        "required_evidence_failed"
        if value["verdict"] == "blocked"
        else "baseline_rehearsal_passed"
    )
    expected_next_step_code = (
        "repair_and_rerun"
        if value["verdict"] == "blocked"
        else "prepare_operator_plan"
    )
    if decision.get("reason_code") != expected_reason_code:
        raise RehearsalError("decision_content reason_code does not match verdict")
    if decision.get("next_step_code") != expected_next_step_code:
        raise RehearsalError("decision_content next_step_code does not match verdict")
    if value["verdict"] == "blocked" and "failed" not in evidence_values:
        raise RehearsalError("blocked status must contain failed evidence")
    if value["verdict"] == "ready_for_operator_plan" and evidence_values != {"success"}:
        raise RehearsalError("ready status requires all evidence to succeed")

    envelope = value.get("run_envelope")
    if not isinstance(envelope, dict):
        raise RehearsalError("run_envelope must be an object")
    if set(envelope) != {"generated_at", "evidence_bundle"}:
        raise RehearsalError("run_envelope contains unknown or missing fields")
    if envelope.get("generated_at") != value.get("generated_at"):
        raise RehearsalError("run_envelope generated_at does not match status")
    if envelope.get("evidence_bundle") != value.get("evidence_bundle"):
        raise RehearsalError("run_envelope evidence_bundle does not match status")

    compatibility = value.get("compatibility_view")
    if not isinstance(compatibility, dict):
        raise RehearsalError("compatibility_view must be an object")
    if set(compatibility) != {"schema", "authoritative", "payload"}:
        raise RehearsalError("compatibility_view contains unknown or missing fields")
    if compatibility.get("schema") != "openclaw.safe_update.compatibility_view.v1":
        raise RehearsalError("compatibility_view schema is invalid")
    if compatibility.get("authoritative") is not False:
        raise RehearsalError("compatibility_view must be non-authoritative")
    if compatibility.get("payload") != legacy_verdict_payload(value):
        raise RehearsalError("compatibility_view payload does not match status")
    return value


def write_status(path: Path, value: dict[str, Any]) -> None:
    write_json(path, parse_status(value))


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RehearsalError(f"cannot read JSON {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    write_text(path, payload)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def detect_node_version() -> str:
    try:
        completed = subprocess.run(
            ["node", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        candidate = completed.stdout.strip().removeprefix("v")
        if VERSION_RE.fullmatch(candidate):
            return candidate
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def inventory(args: argparse.Namespace) -> int:
    package_root = args.package_root.resolve()
    package_json_path = package_root / "package.json"
    package_json = read_json(package_json_path)
    if not isinstance(package_json, dict):
        raise RehearsalError("installed package.json must be an object")
    if package_json.get("name") != args.package_name:
        raise RehearsalError(f"installed package is not {args.package_name}")
    version = package_json.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise RehearsalError("installed package version is not exact semver")

    node_version = detect_node_version()

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    common = {"generated_at": now_iso(), **safety_fields()}
    inventory_document = {
        "schema": "openclaw.safe_update.inventory.v1",
        **common,
        "status": "success",
        "package_name": args.package_name,
        "installed_version": version,
        "package_root_name": package_root.name,
        "host": {
            "platform": platform.system().lower(),
            "machine": platform.machine(),
            "node_version": node_version,
        },
        "declared_node_engine": (package_json.get("engines") or {}).get("node")
        if isinstance(package_json.get("engines"), dict)
        else None,
        "note": "No OpenClaw configuration, credentials, conversations, or service state were read.",
    }
    coverage_draft = {
        "schema": COVERAGE_SCHEMA,
        "install_shape": "npm_global_linux",
        "runtime": {"node_version": node_version},
        "surfaces": [],
        "draft": True,
        "instructions": (
            "Add every required channel, plugin, MCP, memory, provider, service, persona, "
            "attachment, and voice surface before simulation."
        ),
    }
    packages_draft = [
        {"name": args.package_name, "current": version, "target": "REPLACE_WITH_EXACT_VERSION"}
    ]
    write_json(output / "inventory.json", inventory_document)
    write_json(output / "coverage.draft.json", coverage_draft)
    write_json(output / "packages.draft.json", packages_draft)
    print(output / "inventory.json")
    return 0


def digest_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def integrity_for(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha512-" + base64.b64encode(digest.digest()).decode("ascii")


def parse_packages(raw: str, current_version: str, target_version: str) -> list[dict[str, str]]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RehearsalError(f"packages JSON is invalid: {exc}") from exc
    if not isinstance(value, list) or not value:
        raise RehearsalError("packages JSON must be a non-empty list")

    packages: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in value:
        if isinstance(entry, str):
            package = {"name": entry, "current": current_version, "target": target_version}
        elif isinstance(entry, dict):
            package = {
                "name": entry.get("name"),
                "current": entry.get("current", current_version),
                "target": entry.get("target", target_version),
            }
        else:
            raise RehearsalError("each package must be a string or object")
        if not all(isinstance(package[key], str) and package[key] for key in package):
            raise RehearsalError("package name and versions must be non-empty strings")
        if not PACKAGE_RE.fullmatch(package["name"]):
            raise RehearsalError(f"invalid npm package name: {package['name']!r}")
        if not VERSION_RE.fullmatch(package["current"]) or not VERSION_RE.fullmatch(package["target"]):
            raise RehearsalError(f"package versions must be exact semver values: {package['name']}")
        if package["name"] in seen:
            raise RehearsalError(f"duplicate package: {package['name']}")
        seen.add(package["name"])
        packages.append(package)
    return packages


def run_npm_json(arguments: list[str], cache_dir: Path) -> Any:
    environment = os.environ.copy()
    environment.update(
        {
            "NPM_CONFIG_IGNORE_SCRIPTS": "true",
            "NPM_CONFIG_AUDIT": "false",
            "NPM_CONFIG_FUND": "false",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "NPM_CONFIG_CACHE": str(cache_dir),
            "NPM_CONFIG_LOGS_DIR": str(cache_dir / "_logs"),
            "NPM_CONFIG_REGISTRY": NPM_REGISTRY,
        }
    )
    try:
        completed = subprocess.run(
            ["npm", *arguments],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise RehearsalError("npm is not installed") from exc
    except subprocess.CalledProcessError as exc:
        lines = (exc.stderr or exc.stdout or "npm command failed").strip().splitlines()
        useful = [line for line in lines if "complete log" not in line.lower()]
        detail = " | ".join(useful[-3:] or lines[-1:])
        raise RehearsalError(f"npm command failed: {detail}") from exc
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RehearsalError("npm returned non-JSON output") from exc


def registry_metadata(package: str, version: str, cache_dir: Path) -> dict[str, Any]:
    value = run_npm_json(["view", f"{package}@{version}", "--json"], cache_dir)
    if not isinstance(value, dict) or value.get("name") != package or value.get("version") != version:
        raise RehearsalError(f"registry metadata mismatch for {package}@{version}")
    dist = value.get("dist")
    if not isinstance(dist, dict) or not isinstance(dist.get("integrity"), str) or not isinstance(dist.get("shasum"), str):
        raise RehearsalError(f"registry metadata lacks integrity for {package}@{version}")
    return {
        "name": package,
        "version": version,
        "integrity": dist["integrity"],
        "shasum": dist["shasum"],
    }


def pack_archive(package: str, version: str, destination: Path, cache_dir: Path) -> str:
    destination.mkdir(parents=True, exist_ok=True)
    value = run_npm_json(
        ["pack", f"{package}@{version}", "--json", "--pack-destination", str(destination)],
        cache_dir,
    )
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RehearsalError(f"unexpected npm pack result for {package}@{version}")
    filename = value[0].get("filename")
    if not isinstance(filename, str) or not (destination / filename).is_file():
        raise RehearsalError(f"npm pack did not create an archive for {package}@{version}")
    return filename


def fetch(args: argparse.Namespace) -> int:
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise RehearsalError(f"output directory must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    packages = parse_packages(args.packages_json, args.current_version, args.target_version)
    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="openclaw-safe-update-npm-") as cache:
        cache_dir = Path(cache)
        for package in packages:
            record: dict[str, Any] = {"name": package["name"]}
            for lane in ("current", "target"):
                version = package[lane]
                metadata = registry_metadata(package["name"], version, cache_dir)
                metadata["archive"] = pack_archive(
                    package["name"], version, output / lane, cache_dir
                )
                record[lane] = metadata
            records.append(record)

    document = {
        "schema": INPUT_SCHEMA,
        "generated_at": now_iso(),
        **safety_fields(),
        "current_version": args.current_version,
        "target_version": args.target_version,
        "packages": records,
    }
    write_json(output / "input-metadata.json", document)
    print(output / "input-metadata.json")
    return 0


def validate_member(member: tarfile.TarInfo) -> None:
    pure = PurePosixPath(member.name)
    if pure.is_absolute() or ".." in pure.parts or not member.name:
        raise RehearsalError(f"unsafe archive member path: {member.name!r}")
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        raise RehearsalError(f"unsupported archive member type: {member.name}")
    if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
        raise RehearsalError(f"archive member exceeds size limit: {member.name}")


def inspect_archive(path: Path) -> dict[str, Any]:
    file_hashes: dict[str, str] = {}
    package_json: dict[str, Any] | None = None
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            validate_member(member)
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RehearsalError(f"cannot read archive member: {member.name}")
            digest = hashlib.sha256()
            payload = bytearray() if member.name == "package/package.json" else None
            for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                digest.update(chunk)
                if payload is not None:
                    if len(payload) + len(chunk) > MAX_TEXT_MEMBER_BYTES:
                        raise RehearsalError("package/package.json exceeds size limit")
                    payload.extend(chunk)
            file_hashes[member.name] = digest.hexdigest()
            if payload is not None:
                try:
                    package_json = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                    raise RehearsalError("package/package.json is invalid") from exc
    if package_json is None:
        raise RehearsalError("archive lacks package/package.json")
    return {"package_json": package_json, "file_hashes": file_hashes}


def read_archive_text(path: Path, member_name: str) -> str:
    with tarfile.open(path, "r:gz") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise RehearsalError(f"archive member is missing: {member_name}") from exc
        validate_member(member)
        if not member.isfile() or member.size > MAX_TEXT_MEMBER_BYTES:
            raise RehearsalError(f"archive member is not a small regular file: {member_name}")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise RehearsalError(f"cannot read archive member: {member_name}")
        try:
            return extracted.read(MAX_TEXT_MEMBER_BYTES + 1).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RehearsalError(f"archive member is not UTF-8 text: {member_name}") from exc


def verify_archive(path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        raise RehearsalError(f"archive is missing: {path}")
    if integrity_for(path) != metadata.get("integrity"):
        raise RehearsalError(f"integrity mismatch for {metadata.get('name')}@{metadata.get('version')}")
    if digest_file(path, "sha1") != metadata.get("shasum"):
        raise RehearsalError(f"shasum mismatch for {metadata.get('name')}@{metadata.get('version')}")
    inspected = inspect_archive(path)
    if integrity_for(path) != metadata.get("integrity") or digest_file(path, "sha1") != metadata.get("shasum"):
        raise RehearsalError(f"archive changed during inspection: {metadata.get('name')}")
    package_json = inspected["package_json"]
    if package_json.get("name") != metadata.get("name") or package_json.get("version") != metadata.get("version"):
        raise RehearsalError(f"package identity mismatch in {path.name}")
    return inspected


def archive_path(input_dir: Path, lane: str, metadata: dict[str, Any]) -> Path:
    filename = metadata.get("archive")
    if not isinstance(filename, str) or not filename or PurePosixPath(filename).name != filename:
        raise RehearsalError(f"unsafe archive filename for {metadata.get('name')}")
    return input_dir / lane / filename


def bounded(values: list[str]) -> dict[str, Any]:
    return {
        "count": len(values),
        "members": values[:DIFF_MEMBER_LIMIT],
        "truncated": len(values) > DIFF_MEMBER_LIMIT,
    }


def compare_archives(current: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    current_files = current["file_hashes"]
    target_files = target["file_hashes"]
    current_names = set(current_files)
    target_names = set(target_files)
    changed = sorted(name for name in current_names & target_names if current_files[name] != target_files[name])
    return {
        "added": bounded(sorted(target_names - current_names)),
        "removed": bounded(sorted(current_names - target_names)),
        "changed": bounded(changed),
    }


def semver_tuple(value: str) -> tuple[int, int, int] | None:
    candidate = value.removeprefix("v").split("-", 1)[0].split("+", 1)[0]
    parts = candidate.split(".")
    if not 1 <= len(parts) <= 3 or any(not part.isdigit() for part in parts):
        return None
    values = [int(part) for part in parts]
    return tuple((values + [0, 0])[:3])


def node_version_satisfies(version: str, expression: str) -> bool | None:
    actual = semver_tuple(version)
    if actual is None or not isinstance(expression, str) or not expression.strip():
        return None
    outcomes: list[bool | None] = []
    for alternative in expression.split("||"):
        clauses = alternative.strip().split()
        if not clauses:
            continue
        clause_outcomes: list[bool] = []
        for clause in clauses:
            match = re.fullmatch(r"(>=|<=|>|<|=|\^|~)?v?(\d+(?:\.\d+){0,2})(?:\.x)?", clause)
            if not match:
                outcomes.append(None)
                clause_outcomes = []
                break
            operator = match.group(1) or "="
            expected = semver_tuple(match.group(2))
            if expected is None:
                return None
            if operator == ">=":
                clause_outcomes.append(actual >= expected)
            elif operator == "<=":
                clause_outcomes.append(actual <= expected)
            elif operator == ">":
                clause_outcomes.append(actual > expected)
            elif operator == "<":
                clause_outcomes.append(actual < expected)
            elif operator == "^":
                clause_outcomes.append(actual >= expected and actual[0] == expected[0])
            elif operator == "~":
                clause_outcomes.append(actual >= expected and actual[:2] == expected[:2])
            else:
                specified_parts = len(match.group(2).split("."))
                clause_outcomes.append(actual[:specified_parts] == expected[:specified_parts])
        if clause_outcomes:
            outcomes.append(all(clause_outcomes))
    if True in outcomes:
        return True
    if outcomes and all(outcome is False for outcome in outcomes):
        return False
    return None


def compare_package_metadata(
    current: dict[str, Any], target: dict[str, Any], runtime_node_version: str | None
) -> dict[str, Any]:
    current_values = {field: current.get(field) for field in PACKAGE_METADATA_FIELDS}
    target_values = {field: target.get(field) for field in PACKAGE_METADATA_FIELDS}
    changed_fields = [
        field for field in PACKAGE_METADATA_FIELDS if current_values[field] != target_values[field]
    ]
    findings: list[dict[str, str]] = []

    current_scripts = (
        current_values.get("scripts") if isinstance(current_values.get("scripts"), dict) else {}
    )
    target_scripts = (
        target_values.get("scripts") if isinstance(target_values.get("scripts"), dict) else {}
    )
    changed_lifecycle = sorted(
        name
        for name in LIFECYCLE_SCRIPTS
        if current_scripts.get(name) != target_scripts.get(name)
    )
    if changed_lifecycle:
        findings.append(
            {
                "id": "lifecycle-script-changed",
                "severity": "blocked",
                "detail": "Lifecycle scripts changed: " + ", ".join(changed_lifecycle),
            }
        )

    target_engines = target_values.get("engines")
    target_node_engine = target_engines.get("node") if isinstance(target_engines, dict) else None
    if isinstance(target_node_engine, str):
        compatibility = node_version_satisfies(runtime_node_version or "", target_node_engine)
        if compatibility is False:
            findings.append(
                {
                    "id": "target-node-engine-incompatible",
                    "severity": "blocked",
                    "detail": f"Runtime Node {runtime_node_version} does not satisfy target engines.node {target_node_engine}",
                }
            )
        elif compatibility is None:
            findings.append(
                {
                    "id": "target-node-engine-unproven",
                    "severity": "blocked",
                    "detail": f"Cannot prove runtime Node {runtime_node_version or 'unknown'} satisfies target engines.node {target_node_engine}",
                }
            )

    return {
        "current": current_values,
        "target": target_values,
        "changed_fields": changed_fields,
        "risk_findings": findings,
    }


def load_coverage(
    path: Path | None, allow_none: bool
) -> tuple[dict[str, Any], list[str], str]:
    empty = {"install_shape": None, "runtime": {}, "surfaces": []}
    if path is None:
        if allow_none:
            return empty, [], "explicitly_not_required"
        return empty, ["coverage profile is required"], "missing"
    try:
        value = read_json(path)
    except RehearsalError as exc:
        return empty, [str(exc)], "invalid"
    if not isinstance(value, dict) or value.get("schema") != COVERAGE_SCHEMA:
        return empty, [f"coverage schema must be {COVERAGE_SCHEMA}"], "invalid"

    errors: list[str] = []
    install_shape = value.get("install_shape")
    if install_shape not in SUPPORTED_INSTALL_SHAPES:
        errors.append(f"unsupported install shape: {install_shape}")
    runtime = value.get("runtime")
    if not isinstance(runtime, dict):
        errors.append("coverage runtime must be an object")
        runtime = {}
    node_version = runtime.get("node_version")
    if not isinstance(node_version, str) or semver_tuple(node_version) is None:
        errors.append("coverage runtime.node_version must be an exact version")

    surfaces = value.get("surfaces")
    if not isinstance(surfaces, list):
        return empty, errors + ["coverage surfaces must be a list"], "invalid"
    if not surfaces and not allow_none:
        errors.append("coverage profile must declare at least one surface")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, surface in enumerate(surfaces):
        if not isinstance(surface, dict):
            errors.append(f"coverage surface {index} must be an object")
            continue
        surface_id = surface.get("id")
        category = surface.get("category")
        required = surface.get("required")
        customization_checks = surface.get("customization_checks", [])
        post_update_checks = surface.get("post_update_checks")
        if not isinstance(surface_id, str) or not surface_id or surface_id in seen:
            errors.append(f"coverage surface {index} has an invalid or duplicate id")
            continue
        seen.add(surface_id)
        if category not in SURFACE_CATEGORIES:
            errors.append(f"coverage surface {surface_id} has unsupported category")
            continue
        if not isinstance(required, bool):
            errors.append(f"coverage surface {surface_id} must declare required as boolean")
            continue
        if not isinstance(customization_checks, list) or any(
            not isinstance(item, str) or not item for item in customization_checks
        ):
            errors.append(f"coverage surface {surface_id} has invalid customization checks")
            continue
        if not isinstance(post_update_checks, list) or any(
            not isinstance(item, str) or not item.strip() for item in post_update_checks
        ):
            errors.append(f"coverage surface {surface_id} has invalid post-update checks")
            continue
        if required and not post_update_checks:
            errors.append(f"required coverage surface {surface_id} needs a post-update check")
        normalized.append(
            {
                "id": surface_id,
                "category": category,
                "required": required,
                "customization_checks": customization_checks,
                "post_update_checks": post_update_checks,
            }
        )
    return {
        "install_shape": install_shape,
        "runtime": {"node_version": node_version},
        "surfaces": normalized,
    }, errors, "configured"


def load_customizations(path: Path | None, allow_none: bool) -> tuple[list[dict[str, Any]], list[str], str]:
    if path is None:
        if allow_none:
            return [], [], "explicitly_not_required"
        return [], ["customization manifest is required"], "missing"
    try:
        value = read_json(path)
    except RehearsalError as exc:
        return [], [str(exc)], "invalid"
    errors: list[str] = []
    if not isinstance(value, dict) or value.get("schema") != CUSTOMIZATIONS_SCHEMA:
        return [], [f"customization schema must be {CUSTOMIZATIONS_SCHEMA}"], "invalid"
    checks = value.get("checks")
    if not isinstance(checks, list):
        return [], ["customization checks must be a list"], "invalid"
    if not checks and not allow_none:
        errors.append("customization manifest has no checks")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            errors.append(f"customization check {index} must be an object")
            continue
        check_id = check.get("id")
        package = check.get("package")
        kind = check.get("kind")
        member = check.get("member")
        if not isinstance(check_id, str) or not check_id or check_id in seen:
            errors.append(f"customization check {index} has an invalid or duplicate id")
            continue
        seen.add(check_id)
        if not isinstance(package, str) or not PACKAGE_RE.fullmatch(package):
            errors.append(f"customization check {check_id} has an invalid package")
            continue
        if kind not in {"required_member", "member_contains"}:
            errors.append(f"customization check {check_id} has unsupported kind")
            continue
        if not isinstance(member, str) or not member or PurePosixPath(member).is_absolute() or ".." in PurePosixPath(member).parts:
            errors.append(f"customization check {check_id} has an unsafe member")
            continue
        normalized_check = {"id": check_id, "package": package, "kind": kind, "member": member}
        if kind == "member_contains":
            needle = check.get("needle")
            if not isinstance(needle, str) or not needle:
                errors.append(f"customization check {check_id} needs a non-empty needle")
                continue
            normalized_check["needle"] = needle
        normalized.append(normalized_check)
    return normalized, errors, "configured"


def parse_installation_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != INSTALLATION_CONTRACT_SCHEMA:
        raise RehearsalError(
            f"installation contract schema must be {INSTALLATION_CONTRACT_SCHEMA}"
        )
    if set(value) != {
        "schema",
        "install_shape",
        "runtime",
        "capabilities",
        "components",
        "contracts",
    }:
        raise RehearsalError("installation contract contains unknown or missing fields")
    if value.get("install_shape") not in SUPPORTED_INSTALL_SHAPES:
        raise RehearsalError("installation contract install shape is unsupported")
    if not isinstance(value.get("runtime"), dict):
        raise RehearsalError("installation contract runtime must be an object")

    capabilities = value.get("capabilities")
    components = value.get("components")
    contracts = value.get("contracts")
    if not isinstance(capabilities, list) or not capabilities:
        raise RehearsalError("installation contract capabilities must be a non-empty list")
    if not isinstance(components, list):
        raise RehearsalError("installation contract components must be a list")
    if not isinstance(contracts, list):
        raise RehearsalError("installation contract contracts must be a list")

    capability_ids: set[str] = set()
    component_ids: set[str] = set()
    contract_ids: set[str] = set()
    for contract in contracts:
        if (
            not isinstance(contract, dict)
            or set(contract) != {"id", "kind", "evidence_refs"}
            or not isinstance(contract.get("id"), str)
            or not contract["id"]
            or contract["id"] in contract_ids
            or not isinstance(contract.get("kind"), str)
            or not contract["kind"]
            or not isinstance(contract.get("evidence_refs"), list)
            or any(not isinstance(item, str) or not item for item in contract["evidence_refs"])
        ):
            raise RehearsalError("installation contract has an invalid or duplicate contract")
        contract_ids.add(contract["id"])

    for component in components:
        if not isinstance(component, dict) or set(component) != {
            "id",
            "roles",
            "application_phases",
            "artifacts",
            "contract_ids",
            "depends_on",
            "supports",
            "governance",
        }:
            raise RehearsalError("installation contract component shape is invalid")
        component_id = component.get("id")
        if (
            not isinstance(component_id, str)
            or not component_id
            or component_id in component_ids
        ):
            raise RehearsalError("installation contract has an invalid or duplicate component")
        component_ids.add(component_id)
        roles = component.get("roles")
        if (
            not isinstance(roles, list)
            or not roles
            or len(roles) != len(set(roles))
            or any(role not in COMPONENT_ROLES for role in roles)
        ):
            raise RehearsalError(f"component {component_id} has invalid roles")
        phases = component.get("application_phases")
        if not isinstance(phases, list) or any(
            not isinstance(item, str) or not item for item in phases
        ):
            raise RehearsalError(f"component {component_id} has invalid application phases")
        artifacts = component.get("artifacts")
        if not isinstance(artifacts, list) or any(
            not isinstance(item, dict)
            or set(item) != {"kind", "ref"}
            or not isinstance(item.get("kind"), str)
            or not isinstance(item.get("ref"), str)
            or not item["kind"]
            or not item["ref"]
            for item in artifacts
        ):
            raise RehearsalError(f"component {component_id} has invalid artifacts")
        if not isinstance(component.get("contract_ids"), list) or any(
            not isinstance(item, str) for item in component["contract_ids"]
        ):
            raise RehearsalError(f"component {component_id} has invalid contract references")
        dependencies = component.get("depends_on")
        if not isinstance(dependencies, list) or any(
            not isinstance(item, dict)
            or set(item) != {"component_id", "kind"}
            or item.get("kind") not in DEPENDENCY_KINDS
            or not isinstance(item.get("component_id"), str)
            for item in dependencies
        ):
            raise RehearsalError(f"component {component_id} has invalid dependencies")
        if not isinstance(component.get("supports"), list) or any(
            not isinstance(item, str) for item in component["supports"]
        ):
            raise RehearsalError(f"component {component_id} has invalid capability references")
        governance = component.get("governance")
        if not isinstance(governance, dict) or any(
            key not in {"owner", "removal", "upstream_reference", "kill_criteria"}
            for key in governance
        ):
            raise RehearsalError(f"component {component_id} has invalid governance")

    for capability in capabilities:
        if not isinstance(capability, dict) or set(capability) != {
            "id",
            "category",
            "business_criticality",
            "evidence_policy",
            "component_ids",
            "post_activation_checks",
        }:
            raise RehearsalError("installation contract capability shape is invalid")
        capability_id = capability.get("id")
        if (
            not isinstance(capability_id, str)
            or not capability_id
            or capability_id in capability_ids
        ):
            raise RehearsalError("installation contract has an invalid or duplicate capability")
        capability_ids.add(capability_id)
        if capability.get("category") not in SURFACE_CATEGORIES:
            raise RehearsalError(f"capability {capability_id} has an invalid category")
        if capability.get("business_criticality") not in BUSINESS_CRITICALITIES:
            raise RehearsalError(f"capability {capability_id} has invalid criticality")
        if capability.get("evidence_policy") not in EVIDENCE_POLICIES:
            raise RehearsalError(f"capability {capability_id} has invalid evidence policy")
        checks = capability.get("post_activation_checks")
        if not isinstance(checks, list) or not checks or any(
            not isinstance(item, str) or not item for item in checks
        ):
            raise RehearsalError(f"capability {capability_id} needs post-activation checks")
        if not isinstance(capability.get("component_ids"), list) or any(
            not isinstance(item, str) for item in capability["component_ids"]
        ):
            raise RehearsalError(f"capability {capability_id} has invalid component references")

    for component in components:
        component_id = component["id"]
        for contract_id in component["contract_ids"]:
            if contract_id not in contract_ids:
                raise RehearsalError(
                    f"component {component_id} references unknown contract {contract_id}"
                )
        for dependency in component["depends_on"]:
            if dependency["component_id"] not in component_ids:
                raise RehearsalError(
                    f"component {component_id} references unknown dependency "
                    f"{dependency['component_id']}"
                )
        for capability_id in component["supports"]:
            if capability_id not in capability_ids:
                raise RehearsalError(
                    f"component {component_id} references unknown capability {capability_id}"
                )
    for capability in capabilities:
        for component_id in capability["component_ids"]:
            if component_id not in component_ids:
                raise RehearsalError(
                    f"capability {capability['id']} references unknown component {component_id}"
                )
            component = next(item for item in components if item["id"] == component_id)
            if capability["id"] not in component["supports"]:
                raise RehearsalError(
                    f"capability {capability['id']} and component {component_id} disagree"
                )
    for component in components:
        for capability_id in component["supports"]:
            capability = next(
                item for item in capabilities if item["id"] == capability_id
            )
            if component["id"] not in capability["component_ids"]:
                raise RehearsalError(
                    f"component {component['id']} and capability {capability_id} disagree"
                )
    return value


def adapt_v1_installation_contract(
    checks: list[dict[str, Any]],
    coverage_profile: dict[str, Any],
) -> dict[str, Any]:
    checks_by_id = {item["id"]: item for item in checks}
    component_supports: dict[str, list[str]] = {item["id"]: [] for item in checks}
    capabilities: list[dict[str, Any]] = []
    for surface in coverage_profile["surfaces"]:
        component_ids = [
            f"compatibility:{check_id}" for check_id in surface["customization_checks"]
        ]
        for check_id in surface["customization_checks"]:
            if check_id not in checks_by_id:
                raise RehearsalError(
                    f"coverage surface {surface['id']} references unknown check {check_id}"
                )
            component_supports[check_id].append(surface["id"])
        capabilities.append(
            {
                "id": surface["id"],
                "category": surface["category"],
                "business_criticality": "critical" if surface["required"] else "best_effort",
                "evidence_policy": "always" if surface["required"] else "impact_triggered",
                "component_ids": component_ids,
                "post_activation_checks": surface["post_update_checks"],
            }
        )
    contracts = [
        {
            "id": f"customization:{check['id']}",
            "kind": check["kind"],
            "evidence_refs": [check["id"]],
        }
        for check in checks
    ]
    components = [
        {
            "id": f"compatibility:{check['id']}",
            "roles": ["compatibility"],
            "application_phases": ["customization"],
            "artifacts": [
                {
                    "kind": "npm_archive_member",
                    "ref": f"{check['package']}:{check['member']}",
                }
            ],
            "contract_ids": [f"customization:{check['id']}"],
            "depends_on": [],
            "supports": component_supports[check["id"]],
            "governance": {},
        }
        for check in checks
    ]
    return parse_installation_contract(
        {
            "schema": INSTALLATION_CONTRACT_SCHEMA,
            "install_shape": coverage_profile["install_shape"],
            "runtime": coverage_profile["runtime"],
            "capabilities": capabilities,
            "components": components,
            "contracts": contracts,
        }
    )


def contract(args: argparse.Namespace) -> int:
    checks, customization_errors, _ = load_customizations(
        args.customizations.resolve(), False
    )
    coverage_profile, coverage_errors, _ = load_coverage(
        args.coverage.resolve(), False
    )
    errors = customization_errors + coverage_errors
    if errors:
        raise RehearsalError("; ".join(errors))
    document = adapt_v1_installation_contract(checks, coverage_profile)
    write_json(args.output.resolve(), document)
    print(args.output.resolve())
    return 0


def artifact_reference(path: Path, status: str) -> dict[str, Any]:
    return {"path": path.name, "sha256": digest_file(path), "status": status}


def simulate(args: argparse.Namespace) -> int:
    input_dir = args.input_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = input_dir / "input-metadata.json"
    generated_at = now_iso()
    common = {"generated_at": generated_at, **safety_fields()}
    runtime_errors: list[str] = []
    package_results: list[dict[str, Any]] = []
    target_archives: dict[str, tuple[Path, dict[str, Any], dict[str, Any]]] = {}
    coverage_profile, coverage_errors, coverage_mode = load_coverage(
        args.coverage.resolve() if args.coverage else None,
        args.allow_no_coverage,
    )
    if coverage_mode == "explicitly_not_required":
        if (
            not isinstance(args.runtime_node_version, str)
            or semver_tuple(args.runtime_node_version) is None
        ):
            coverage_errors.append(
                "--runtime-node-version is required when --allow-no-coverage is used"
            )
        else:
            coverage_profile["runtime"]["node_version"] = args.runtime_node_version
    runtime_node_version = coverage_profile.get("runtime", {}).get("node_version")

    try:
        metadata = read_json(metadata_path)
    except RehearsalError as exc:
        metadata = {}
        runtime_errors.append(str(exc))
    if not isinstance(metadata, dict) or metadata.get("schema") != INPUT_SCHEMA:
        runtime_errors.append(f"input schema must be {INPUT_SCHEMA}")
    packages = metadata.get("packages") if isinstance(metadata, dict) else None
    if not isinstance(packages, list) or not packages:
        runtime_errors.append("input metadata must contain packages")
        packages = []

    seen_packages: set[str] = set()
    for entry in packages:
        package_result: dict[str, Any] = {"status": "failed", "errors": []}
        try:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise RehearsalError("package metadata entry is invalid")
            name = entry["name"]
            package_result["name"] = name
            if name in seen_packages:
                raise RehearsalError(f"duplicate package metadata: {name}")
            seen_packages.add(name)
            current_metadata = entry.get("current")
            target_metadata = entry.get("target")
            if not isinstance(current_metadata, dict) or not isinstance(target_metadata, dict):
                raise RehearsalError(f"package metadata is incomplete for {name}")
            if current_metadata.get("name") != name or target_metadata.get("name") != name:
                raise RehearsalError(f"package metadata name mismatch for {name}")
            current_path = archive_path(input_dir, "current", current_metadata)
            target_path = archive_path(input_dir, "target", target_metadata)
            current_inspection = verify_archive(current_path, current_metadata)
            target_inspection = verify_archive(target_path, target_metadata)
            package_metadata = compare_package_metadata(
                current_inspection["package_json"],
                target_inspection["package_json"],
                runtime_node_version,
            )
            blocking_findings = [
                finding
                for finding in package_metadata["risk_findings"]
                if finding.get("severity") == "blocked"
            ]
            package_result.update(
                {
                    "current_version": current_metadata["version"],
                    "target_version": target_metadata["version"],
                    "current_archive_sha256": digest_file(current_path),
                    "target_archive_sha256": digest_file(target_path),
                    "registry": {
                        "current": {
                            "integrity": current_metadata["integrity"],
                            "shasum": current_metadata["shasum"],
                        },
                        "target": {
                            "integrity": target_metadata["integrity"],
                            "shasum": target_metadata["shasum"],
                        },
                    },
                    "diff": compare_archives(current_inspection, target_inspection),
                    "package_metadata": package_metadata,
                    "status": "failed" if blocking_findings else "success",
                }
            )
            target_archives[name] = (target_path, target_inspection, target_metadata)
            package_result["errors"].extend(finding["detail"] for finding in blocking_findings)
        except (KeyError, RehearsalError, OSError, tarfile.TarError) as exc:
            package_result["errors"].append(str(exc))
        package_results.append(package_result)

    runtime_status = (
        "success"
        if not runtime_errors and package_results and all(item["status"] == "success" for item in package_results)
        else "failed"
    )
    synthetic_status = "success" if package_results and all(item["status"] == "success" for item in package_results) else "failed"
    runtime_truth = {
        "schema": "openclaw.safe_update.runtime_truth.v1",
        **common,
        "status": runtime_status,
        "current_version": metadata.get("current_version"),
        "target_version": metadata.get("target_version"),
        "packages": [
            {
                "name": item.get("name"),
                "current_version": item.get("current_version"),
                "target_version": item.get("target_version"),
                "status": item["status"],
            }
            for item in package_results
        ],
        "errors": runtime_errors,
    }
    synthetic = {
        "schema": "openclaw.safe_update.synthetic_update.v1",
        **common,
        "status": synthetic_status,
        "packages": package_results,
    }

    checks, customization_errors, customization_mode = load_customizations(
        args.customizations.resolve() if args.customizations else None,
        args.allow_no_customizations,
    )
    check_results: list[dict[str, Any]] = []
    for check in checks:
        result = {key: check[key] for key in ("id", "package", "kind", "member")}
        result["status"] = "failed"
        result["reason"] = None
        archive_record = target_archives.get(check["package"])
        if archive_record is None:
            result["reason"] = "target package evidence is unavailable"
        elif check["member"] not in archive_record[1]["file_hashes"]:
            result["reason"] = "required member is missing"
        elif check["kind"] == "required_member":
            result["status"] = "success"
        else:
            try:
                text = read_archive_text(archive_record[0], check["member"])
                if check["needle"] in text:
                    result["status"] = "success"
                else:
                    result["reason"] = "required text anchor is missing"
            except (RehearsalError, OSError, tarfile.TarError) as exc:
                result["reason"] = str(exc)
        check_results.append(result)

    for name, (archive_path_value, _inspection, archive_metadata) in target_archives.items():
        if (
            integrity_for(archive_path_value) != archive_metadata.get("integrity")
            or digest_file(archive_path_value, "sha1") != archive_metadata.get("shasum")
        ):
            customization_errors.append(f"target archive changed during customization checks: {name}")

    customization_status = (
        "success"
        if not customization_errors and all(item["status"] == "success" for item in check_results)
        else "failed"
    )
    customizations = {
        "schema": "openclaw.safe_update.customization_compatibility.v1",
        **common,
        "status": customization_status,
        "mode": customization_mode,
        "checks": check_results,
        "errors": customization_errors,
    }

    customization_results_by_id = {item["id"]: item["status"] for item in check_results}
    known_customization_ids = set(customization_results_by_id)
    coverage_surface_results: list[dict[str, Any]] = []
    for surface in coverage_profile["surfaces"]:
        surface_errors: list[str] = []
        for check_id in surface["customization_checks"]:
            if check_id not in known_customization_ids:
                surface_errors.append(f"referenced customization check is missing: {check_id}")
            elif customization_results_by_id[check_id] != "success":
                surface_errors.append(f"referenced customization check failed: {check_id}")
        coverage_surface_results.append(
            {
                **surface,
                "status": "failed" if surface_errors else "success",
                "errors": surface_errors,
            }
        )
        coverage_errors.extend(f"surface {surface['id']}: {error}" for error in surface_errors)
    coverage_status = (
        "success"
        if not coverage_errors and all(item["status"] == "success" for item in coverage_surface_results)
        else "failed"
    )
    coverage_report = {
        "schema": "openclaw.safe_update.coverage_report.v1",
        **common,
        "status": coverage_status,
        "mode": coverage_mode,
        "install_shape": coverage_profile["install_shape"],
        "runtime": coverage_profile["runtime"],
        "surfaces": coverage_surface_results,
        "errors": coverage_errors,
    }
    postcheck_plan = {
        "schema": "openclaw.safe_update.post_upgrade_e2e.v1",
        **common,
        "status": "success" if coverage_status == "success" else "failed",
        "execution_status": "not_run",
        "surfaces": [
            {
                "id": surface["id"],
                "category": surface["category"],
                "required": surface["required"],
                "checks": [
                    {"description": check, "status": "not_run"}
                    for check in surface["post_update_checks"]
                ],
            }
            for surface in coverage_surface_results
        ],
        "note": "This is a post-upgrade test plan, not evidence that the checks have run.",
    }

    runtime_path = output_dir / "runtime-truth.json"
    synthetic_path = output_dir / "synthetic-update.json"
    customization_path = output_dir / "customization-compatibility.json"
    coverage_path = output_dir / "coverage-report.json"
    postcheck_path = output_dir / "post-upgrade-e2e.json"
    write_json(runtime_path, runtime_truth)
    write_json(synthetic_path, synthetic)
    write_json(customization_path, customizations)
    write_json(coverage_path, coverage_report)
    write_json(postcheck_path, postcheck_plan)

    blocked = any(
        status != "success"
        for status in (runtime_status, synthetic_status, customization_status, coverage_status)
    )
    verdict_value = "blocked" if blocked else "ready_for_operator_plan"
    evidence = {
        "schema": "openclaw.safe_update.evidence_bundle.v1",
        **common,
        "repair_class": "openclaw_upgrade",
        "verdict": verdict_value,
        "evidence": [
            artifact_reference(runtime_path, runtime_status),
            artifact_reference(synthetic_path, synthetic_status),
            artifact_reference(customization_path, customization_status),
            artifact_reference(coverage_path, coverage_status),
            artifact_reference(postcheck_path, postcheck_plan["status"]),
        ],
    }
    evidence_path = output_dir / "evidence-bundle.json"
    write_json(evidence_path, evidence)
    verdict = build_status(
        generated_at=generated_at,
        verdict=verdict_value,
        reason=(
            "required package, customization, runtime, or installation coverage evidence failed"
            if blocked
            else "package-level rehearsal passed; live mutation still requires an operator plan and approval"
        ),
        reason_code="required_evidence_failed" if blocked else "baseline_rehearsal_passed",
        evidence_status={
            "runtime_truth": runtime_status,
            "synthetic_update": synthetic_status,
            "customization_compatibility": customization_status,
            "installation_coverage": coverage_status,
            "post_upgrade_e2e_plan": postcheck_plan["status"],
        },
        evidence_bundle={"path": evidence_path.name, "sha256": digest_file(evidence_path)},
        next_step=(
            "repair evidence and rerun"
            if blocked
            else "prepare rollback-aware operator plan and stop before apply"
        ),
        next_step_code="repair_and_rerun" if blocked else "prepare_operator_plan",
    )
    verdict_path = output_dir / "verdict.json"
    write_status(verdict_path, verdict)
    operator_plan = (
        "# OpenClaw Upgrade Operator Plan\n\n"
        "## STOP BEFORE APPLY\n\n"
        "This rehearsal does not authorize or execute an upgrade. A human operator must review "
        "the evidence, choose a maintenance window, verify a lossless rollback, and separately approve "
        "the exact mutation.\n\n"
        f"- Verdict: `{verdict_value}`\n"
        f"- Current version: `{metadata.get('current_version', 'unknown')}`\n"
        f"- Target version: `{metadata.get('target_version', 'unknown')}`\n"
        f"- Install shape: `{coverage_profile.get('install_shape') or 'unknown'}`\n"
        f"- Evidence bundle: `{evidence_path.name}` (`{digest_file(evidence_path)}`)\n"
        f"- Post-upgrade E2E plan: `{postcheck_path.name}`\n\n"
        "## Required operator inputs\n\n"
        "- Exact maintenance window\n"
        "- Verified backup and lossless rollback command\n"
        "- Exact update command and affected paths\n"
        "- Separate approval for update, restart, or deploy\n\n"
        "## Exit criteria\n\n"
        "Every required post-upgrade check must be recorded as passed. Any failed or unproven surface "
        "means rollback or forward recovery, not acceptance.\n"
    )
    write_text(output_dir / "operator-plan.md", operator_plan)
    summary = (
        "# OpenClaw Safe Update Rehearsal\n\n"
        f"- Verdict: `{verdict_value}`\n"
        f"- Current version: `{metadata.get('current_version', 'unknown')}`\n"
        f"- Target version: `{metadata.get('target_version', 'unknown')}`\n"
        f"- Runtime evidence: `{runtime_status}`\n"
        f"- Package evidence: `{synthetic_status}`\n"
        f"- Customization evidence: `{customization_status}`\n"
        f"- Installation coverage: `{coverage_status}`\n"
        f"- Declared surfaces: `{len(coverage_surface_results)}`\n"
        "- Runtime effect: `none`\n"
        "- Production apply allowed: `false`\n"
        "- Operator approval: `false`\n\n"
        f"Next step: {verdict['next_step']}.\n"
    )
    write_text(output_dir / "summary.md", summary)
    print(verdict_path)
    return 2 if blocked else 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subcommands = root.add_subparsers(dest="command", required=True)

    inventory_parser = subcommands.add_parser(
        "inventory", help="create a public-safe local installation inventory and coverage draft"
    )
    inventory_parser.add_argument("--package-root", type=Path, required=True)
    inventory_parser.add_argument("--package-name", default="openclaw")
    inventory_parser.add_argument("--output-dir", type=Path, required=True)
    inventory_parser.set_defaults(handler=inventory)

    fetch_parser = subcommands.add_parser("fetch", help="fetch immutable npm package evidence")
    fetch_parser.add_argument("--current-version", required=True)
    fetch_parser.add_argument("--target-version", required=True)
    fetch_parser.add_argument("--packages-json", default='["openclaw"]')
    fetch_parser.add_argument("--output-dir", type=Path, required=True)
    fetch_parser.set_defaults(handler=fetch)

    simulate_parser = subcommands.add_parser("simulate", help="run a read-only package rehearsal")
    simulate_parser.add_argument("--input-dir", type=Path, required=True)
    simulate_parser.add_argument("--customizations", type=Path)
    simulate_parser.add_argument("--allow-no-customizations", action="store_true")
    simulate_parser.add_argument("--coverage", type=Path)
    simulate_parser.add_argument("--allow-no-coverage", action="store_true")
    simulate_parser.add_argument("--runtime-node-version")
    simulate_parser.add_argument("--output-dir", type=Path, required=True)
    simulate_parser.set_defaults(handler=simulate)

    contract_parser = subcommands.add_parser(
        "contract", help="translate v1.1 manifests into an installation contract"
    )
    contract_parser.add_argument("--customizations", type=Path, required=True)
    contract_parser.add_argument("--coverage", type=Path, required=True)
    contract_parser.add_argument("--output", type=Path, required=True)
    contract_parser.set_defaults(handler=contract)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        return args.handler(args)
    except (RehearsalError, OSError, tarfile.TarError, RecursionError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
