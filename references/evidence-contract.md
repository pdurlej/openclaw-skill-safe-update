# Evidence Contract

The safe-update rehearsal is a read-only package compatibility check. It does not prove live runtime behavior and cannot authorize an update.

## Inputs

- Exact current and target versions for each package.
- Registry metadata containing package name, version, `dist.integrity`, and `dist.shasum`.
- Current and target package archives downloaded without installation.
- A customization manifest describing deployment-specific compatibility checks, unless the operator explicitly confirms a vanilla deployment.

## Outputs

Every JSON output includes `effect: read_only_openclaw_update_rehearsal`, `runtime_effect: none`, `external_effect: npm_registry_read_only`, `external_write_effect: none`, `production_apply_allowed: false`, and `operator_approval: false` where applicable. Package fetches are network egress pinned to `https://registry.npmjs.org`, but they do not write to external systems.

`runtime-truth.json` records exact package coordinates and integrity validation.

`synthetic-update.json` records archive safety, package identity, and bounded added, removed, and changed member lists.

`customization-compatibility.json` records every requested customization check and its result. Missing members, unreadable text, or absent anchors fail closed.

`evidence-bundle.json` binds the evidence artifacts by SHA-256. A downstream gate may translate this bundle to its own schema, but must preserve failures and the no-approval state.

`verdict.json` has only two valid outcomes:

- `blocked`: required evidence or compatibility checks failed.
- `ready_for_operator_plan`: package-level evidence passed; prepare a rollback-aware plan and request separate approval for any live mutation.

`summary.md` is a human-readable view and is not authoritative over the JSON artifacts.

## Non-Claims

A green rehearsal does not prove:

- Signal or Matrix inbound and outbound behavior;
- read receipts, reactions, attachments, or voice transcription;
- MCP discovery and calls;
- provider authentication or quotas;
- memory, persona, or conversation continuity;
- systemd, container, filesystem ownership, or gateway behavior;
- rollback against live persistent state.

Those surfaces require fresh post-deploy E2E evidence during an approved maintenance window. The operator plan must enumerate them explicitly.

## Customization Manifest

Schema: `openclaw.safe_update.customizations.v1`.

Each check requires:

- `id`: stable unique identifier;
- `package`: npm package name;
- `kind`: `required_member` or `member_contains`;
- `member`: exact tar member path.

`member_contains` additionally requires a non-empty `needle`. It is restricted to regular text files no larger than 4 MiB.

Archive paths must be relative, must not traverse outside the package root, and must not be links. Unsafe archives are blocked before customization checks run.
