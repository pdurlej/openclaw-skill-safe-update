---
name: openclaw-safe-update
description: Rehearse an OpenClaw version update without touching a live runtime. Use when comparing current and target OpenClaw packages, checking customized Signal, Matrix, MCP, provider, or runtime integration surfaces, producing synthetic-update evidence, preparing a Patchwarden-compatible review bundle, or writing a rollback-aware operator plan before an update.
---

# OpenClaw Safe Upgrade Rehearsal Kit

Prepare evidence for an OpenClaw update while keeping production unchanged. Treat the generated verdict as input to an operator decision, never as permission to update.

## Safety Contract

- Do not run `openclaw update`, install packages globally, repair dependencies, deploy, restart services, or mutate live configuration.
- Do not execute package lifecycle scripts or code from downloaded archives.
- Do not include secrets, private conversations, live configuration values, or raw production logs in cloud reviews or artifacts.
- Fail closed when package metadata, integrity, required packages, customization checks, or required evidence are missing.
- Stop at `ready_for_operator_plan`. A separate, explicit operator approval is required for every live mutation.

Read [references/evidence-contract.md](references/evidence-contract.md) before changing the artifact schema or interpreting a verdict.

## Workflow

### 1. Establish Exact Inputs

Record the currently deployed OpenClaw version from read-only runtime evidence. Select an exact target version, not `latest`, for the final rehearsal.

Create a package matrix. Strings inherit the global versions; objects can pin package-specific versions:

```json
[
  "openclaw",
  {"name":"example-openclaw-plugin","current":"1.2.0","target":"1.3.0"}
]
```

Include every separately distributed package that the deployment relies on. Do not claim Signal, Matrix, MCP, provider, or harness coverage when its package or customization contract is absent.

### 2. Describe Customizations

Create `.openclaw-safe-update/customizations.json` in the target repository:

```json
{
  "schema": "openclaw.safe_update.customizations.v1",
  "checks": [
    {
      "id": "mcp-runtime-entrypoint",
      "package": "openclaw",
      "kind": "required_member",
      "member": "package/dist/mcp/openclaw-tools-serve.js"
    },
    {
      "id": "mcporter-skill-contract",
      "package": "openclaw",
      "kind": "member_contains",
      "member": "package/skills/mcporter/SKILL.md",
      "needle": "mcporter"
    }
  ]
}
```

Use `required_member` for overlay targets, entrypoints, and integration files. Use `member_contains` only for small textual contract anchors. Prefer several narrow checks over a broad archive dump.

### 3. Fetch Immutable Package Evidence

```bash
python3 scripts/openclaw_safe_update.py fetch \
  --current-version 2026.6.11 \
  --target-version 2026.7.1 \
  --packages-json '["openclaw"]' \
  --output-dir artifacts/input
```

`fetch` uses `npm view` and `npm pack`. It records registry integrity metadata and downloads archives without installing or running them.

### 4. Run the Synthetic Rehearsal

```bash
python3 scripts/openclaw_safe_update.py simulate \
  --input-dir artifacts/input \
  --customizations .openclaw-safe-update/customizations.json \
  --output-dir artifacts/safe-update
```

The rehearsal safely inspects archives, verifies exact package identity and integrity, compares current and target file trees, evaluates customization checks, and emits a hash-bound evidence bundle.

For a genuinely vanilla deployment, `--allow-no-customizations` may be used only after explicitly confirming that there are no local overlays, patches, wrappers, plugin contracts, or runtime-specific integrations.

### 5. Review and Stop

Inspect these artifacts:

- `runtime-truth.json`
- `synthetic-update.json`
- `customization-compatibility.json`
- `evidence-bundle.json`
- `verdict.json`
- `summary.md`

If the verdict is `blocked`, fix the evidence or compatibility problem and rerun. If it is `ready_for_operator_plan`, prepare a plan containing exact target versions, evidence hashes, expected changed paths, risk surfaces, postchecks, rollback, and a maintenance window. Stop before apply.

For an independent model review, send only the generated sanitized summaries and public package diffs. Reviewer success does not change the verdict or grant approval.

## GitHub Workflow

Copy [assets/github-workflows/openclaw-safe-update.yml](assets/github-workflows/openclaw-safe-update.yml) into the target repository's `.github/workflows/` directory. Configure the package matrix and customization file in that repository, then invoke the workflow with exact current and target versions.

The workflow uploads evidence even when the rehearsal blocks, performs no deploy or notification, and fails the job unless the result is `ready_for_operator_plan`.
