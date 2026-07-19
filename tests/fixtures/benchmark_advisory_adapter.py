#!/usr/bin/env python3
"""Test fixture adapter for the benchmark advisory arm.

This is NOT a real advisory worker. It reads the full ``#15`` advisory input
envelope (``openclaw.safe_update.advisory_input.v1``) on stdin and emits a
deterministic runner envelope ``{result, usage}`` whose ``result`` mirrors
``openclaw.safe_update.advisory_result.v1``. It is used only by the benchmark
test suite (and by manual smoke runs) to exercise the advisory-arm invocation
path without invoking any model, opening the network, or touching the
canonical verdict path.

The adapter derives deterministic finding IDs from the structural facts in
``advisory_input.content`` (the worker-visible prompt_payload). It echoes the
envelope ``input_digest`` so the result binds the same input the runner
validated. It never reads ``scoring_key`` (absent from the envelope) and never
emits a forbidden claim or a blocked-verdict signal. Every evidence reference
uses the #15 source id ``advisory_input_content`` and a pointer that resolves
inside ``content``, so a successful result passes
``openclaw_advisory.validate_result`` exactly.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from typing import Any


ADVISORY_INPUT_SCHEMA = "openclaw.safe_update.advisory_input.v1"
RESULT_SCHEMA = "openclaw.safe_update.advisory_result.v1"


def _usage(compute_tokens: int, review_minutes: float) -> dict[str, Any]:
    return {"compute_tokens": int(compute_tokens), "review_minutes": float(review_minutes)}


def _failed_envelope(message: str) -> dict[str, Any]:
    """Return a runner envelope carrying a valid-shape failed result.

    The transport contract is ``{result, usage}``. On a parse failure the
    adapter still returns that shape with a non-authoritative ``failed``
    result; the runner's #15 validator will accept the shape and the row is
    scored honestly without degrading the whole arm to ``not_available``.
    """
    result = {
        "schema": RESULT_SCHEMA,
        "authoritative": False,
        "input_digest": None,
        "worker": {
            "id": "fixture-adapter",
            "model_family": "fixture",
            "role": "fixture-reviewer",
        },
        "status": "failed",
        "hypotheses": [],
        "suggested_checks": [],
        "residual_risks": [],
        "review_requests": [],
        "agreement_is_confidence": False,
        "can_promote": False,
        "can_waive_checks": False,
        "can_emit_verdict": False,
        "error": message,
    }
    return {"result": result, "usage": _usage(0, 0.0)}


def _evidence_refs(advisory_input: dict[str, Any]) -> list[dict[str, str]]:
    # #15 evidence references bind the envelope content: source_id is the
    # fixed "advisory_input_content", source_digest is the envelope
    # input_digest, and the pointer resolves inside content. A pointer at
    # /facts/packages/0 is structurally present in every frozen prompt_payload.
    input_digest = advisory_input.get("input_digest")
    if not isinstance(input_digest, str):
        return []
    return [
        {
            "source_id": "advisory_input_content",
            "source_digest": input_digest,
            "pointer": "/facts/packages/0",
        }
    ]


def _findings_for(advisory_input: dict[str, Any]) -> dict[str, Any]:
    """Emit a small, deterministic set of namespaced findings.

    The IDs are derived from the structural facts only. They use the reserved
    advisory namespaces so the runner's evidence and duplicate accounting has
    something realistic to score.
    """
    content = advisory_input.get("content") or {}
    facts = content.get("facts", {}) or {}
    refs = _evidence_refs(advisory_input)
    hypotheses: list[dict[str, Any]] = []
    residual_risks: list[dict[str, Any]] = []
    review_requests: list[dict[str, Any]] = []

    for package in facts.get("unmapped_packages", []) or []:
        slug = re.sub(r"[^a-z0-9]+", "-", str(package).lower()).strip("-")
        residual_risks.append(
            {
                "id": f"advisory:risk:unmapped-{slug}",
                "summary": f"Unmapped transitive package {package} requires review.",
                "evidence_refs": refs,
            }
        )
    for member in facts.get("unmapped_members", []) or []:
        residual_risks.append(
            {
                "id": "advisory:risk:unmapped-member",
                "summary": f"Unmapped member {member.get('member')} requires review.",
                "evidence_refs": refs,
            }
        )
    for risk in facts.get("deterministic_risks", []) or []:
        kind = risk.get("kind")
        if kind in {"closure-drift", "local-overlay-residue", "advisory-prose-excluded"}:
            continue
        residual_risks.append(
            {
                "id": f"advisory:risk:{kind}",
                "summary": f"Deterministic risk kind {kind} surfaced for review.",
                "evidence_refs": refs,
            }
        )
    for contract in facts.get("affected_contracts", []) or []:
        slug = re.sub(r"[^a-z0-9]+", "-", str(contract).lower()).strip("-")
        review_requests.append(
            {
                "id": f"advisory:review:confirm-{slug}",
                "question": f"Confirm semantics for affected contract {contract}.",
                "evidence_refs": refs,
            }
        )

    # Always emit one conservative hypothesis so the adapter is non-empty.
    hypotheses.append(
        {
            "id": "advisory:hypothesis:conservative-review",
            "summary": "Treat the rehearsal as evidence, not authorization.",
            "evidence_refs": refs,
        }
    )

    return {
        "hypotheses": hypotheses,
        "residual_risks": residual_risks,
        "review_requests": review_requests,
        "suggested_checks": [],
    }


def main() -> int:
    raw = sys.stdin.read()
    try:
        advisory_input = json.loads(raw)
    except json.JSONDecodeError:
        json.dump(_failed_envelope("advisory input is not JSON"), sys.stdout, ensure_ascii=True, sort_keys=True)
        return 0
    if not isinstance(advisory_input, dict) or advisory_input.get("schema") != ADVISORY_INPUT_SCHEMA:
        json.dump(_failed_envelope("advisory input schema mismatch"), sys.stdout, ensure_ascii=True, sort_keys=True)
        return 0
    input_digest = advisory_input.get("input_digest")
    if not isinstance(input_digest, str):
        json.dump(_failed_envelope("advisory input missing input_digest"), sys.stdout, ensure_ascii=True, sort_keys=True)
        return 0
    result = {
        "schema": RESULT_SCHEMA,
        "authoritative": False,
        "input_digest": input_digest,
        "worker": {
            "id": "fixture-adapter",
            "model_family": "fixture",
            "role": "fixture-reviewer",
        },
        "status": "completed",
        **_findings_for(advisory_input),
        "agreement_is_confidence": False,
        "can_promote": False,
        "can_waive_checks": False,
        "can_emit_verdict": False,
    }
    envelope = {"result": result, "usage": _usage(128, 0.25)}
    json.dump(envelope, sys.stdout, ensure_ascii=True, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
