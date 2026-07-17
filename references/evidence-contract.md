# Evidence Contract

The safe-update rehearsal is a read-only package compatibility check. It does not prove live runtime behavior and cannot authorize an update.

## Inputs

- Exact current and target versions for each package.
- Registry metadata containing package name, version, `dist.integrity`, and `dist.shasum`.
- Current and target package archives downloaded without installation.
- Current and target OpenClaw dependency closures resolved with an isolated npm configuration, lifecycle scripts disabled, and exact Node, npm, OS, architecture, and libc identity.
- A customization manifest describing deployment-specific compatibility checks, unless the operator explicitly confirms a vanilla deployment.
- An installation coverage profile declaring the runtime Node version, required surfaces, their customization evidence, and concrete post-upgrade checks.

## Outputs

Every JSON output includes `effect: read_only_openclaw_update_rehearsal`, `runtime_effect: none`, `external_effect: npm_registry_read_only`, `external_write_effect: none`, `production_apply_allowed: false`, and `operator_approval: false` where applicable. Package fetches are network egress pinned to `https://registry.npmjs.org`, but they do not write to external systems.

`runtime-truth.json` records exact package coordinates and integrity validation.

`core-candidate-lock.json` records canonical SHA-256 roots for the current and
target resolved OpenClaw core closures. It includes exact transitive, peer, and
optional package identities, integrity values, platform selectors and
selection results, resolver policy, and toolchain/environment identity. Missing
integrity, mutable links, unsupported lockfiles, non-registry resolutions,
truncated closure data, or current/target environment drift fail closed.
Lifecycle scripts are declared and hash-bound by package integrity but are
never executed during resolution.

`synthetic-update.json` records archive safety, package identity, bounded added, removed, and changed member lists, plus current-to-target changes in Node engines, dependencies, optional and peer dependencies, lifecycle scripts, and executable declarations. Changed lifecycle scripts and incompatible or unproven Node requirements block the rehearsal.

`customization-compatibility.json` records every requested customization check and its result. Missing members, unreadable text, or absent anchors fail closed.

`coverage-report.json` records every declared installation surface and verifies that required surfaces have post-upgrade checks and that referenced customization checks exist and passed.

`post-upgrade-e2e.json` is a generated test plan. Its checks remain `not_run`; generation is not proof of live behavior.

`evidence-bundle.json` binds the evidence artifacts by SHA-256. A downstream gate may translate this bundle to its own schema, but must preserve failures and the no-approval state.

`verdict.json` is the single authoritative preflight status using schema
`openclaw.safe_update.status.v2`. It has only two valid outcomes:

- `blocked`: required evidence or compatibility checks failed.
- `ready_for_operator_plan`: package-level evidence passed; prepare a rollback-aware plan and request separate approval for any live mutation.

Its timestamp-free `decision_content` is bound by `decision_digest`. Volatile
run metadata, evidence paths and hashes, and operator-facing prose do not affect
that digest. The status is always `phase: preflight`,
`post_activation_e2e: not_run`, `production_apply_allowed: false`, and
`operator_approval: false`.

The embedded, non-authoritative `compatibility_view` preserves the previous
`openclaw.safe_update.verdict.v1` payload for v1.1 consumers. It is derived from
the v2 status and cannot override it. There is no parallel
`upgrade-status.json`.

`summary.md` is a human-readable view and is not authoritative over the JSON artifacts.

`operator-plan.md` binds the target and evidence into a review surface, lists the still-missing operator inputs, and stops before apply.

## Non-Claims

A green rehearsal does not prove:

- Signal or Matrix inbound and outbound behavior;
- read receipts, reactions, attachments, or voice transcription;
- MCP discovery and calls;
- provider authentication or quotas;
- memory, persona, or conversation continuity;
- systemd, container, filesystem ownership, or gateway behavior;
- rollback against live persistent state.

Those surfaces require fresh post-deploy E2E evidence during an approved maintenance window. The coverage profile and generated operator plan must enumerate them explicitly.

## Installation Coverage Profile

Schema: `openclaw.safe_update.coverage.v1`.

The supported 1.1 install shape is `npm_global_linux`. `runtime.node_version` must be an exact version, and `runtime.os`, `runtime.arch`, and `runtime.libc` must explicitly identify the target platform. The declared platform must match the core candidate closure. Every surface requires a unique `id`, a supported `category`, a boolean `required` flag, a list of customization check IDs, and a list of concrete post-update checks. A required surface with no post-update check is blocked.

Supported categories are `channel`, `plugin`, `mcp`, `memory`, `persona`, `provider`, `service`, `attachment`, `voice`, and `other`.

The profile is a declaration of expected behavior, not an automatic discovery claim. The `inventory` command deliberately does not read secrets, configuration values, conversations, or service state.

## Customization Manifest

Schema: `openclaw.safe_update.customizations.v1`.

Each check requires:

- `id`: stable unique identifier;
- `package`: npm package name;
- `kind`: `required_member` or `member_contains`;
- `member`: exact tar member path.

`member_contains` additionally requires a non-empty `needle`. It is restricted to regular text files no larger than 4 MiB.

Archive paths must be relative, must not traverse outside the package root, and must not be links. Unsafe archives are blocked before customization checks run.
