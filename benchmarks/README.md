# OpenClaw Advisory Benchmark

A frozen, public-safe corpus and scoring protocol for evaluating OpenClaw
safe-update advisory reviewers. This is evaluation only and can never affect a
canonical verdict.

- Protocol: [`references/benchmark-scoring-protocol.md`](../references/benchmark-scoring-protocol.md)
- Manifest (frozen, digest-bound): [`corpus/manifest.json`](corpus/manifest.json)
- Blinded fixtures: [`corpus/fixtures/`](corpus/fixtures/)
- Schemas: [`schemas/openclaw.benchmark.manifest.v1.schema.json`](../schemas/openclaw.benchmark.manifest.v1.schema.json),
  [`...fixture.v1...`](../schemas/openclaw.benchmark.fixture.v1.schema.json),
  [`...scorecard.v1...`](../schemas/openclaw.benchmark.scorecard.v1.schema.json)
- Tests: [`tests/test_openclaw_benchmark.py`](../tests/test_openclaw_benchmark.py)

The runner and reporting tooling are a separate contribution (issue #22). The
artifacts here are static data, schemas, and protocol documentation only; they
invoke no model, open no network, and never reach the verdict path.

## Arm semantics and case kinds

The corpus freezes three comparison arms. The **baseline** is authoritative
for rehearsal evidence and the only arm whose `expected_outcome` may be
`pass` or `block`. The **shadow_impact** arm is non-authoritative and cannot
block: its `expected_outcome` uses the neutral `risk_detected` /
`no_risk_detected` pair, never `pass`/`block`. The **advisory** arm is the
optional arm that may honestly return `not_available`.

Every fixture carries a machine-readable `case_kind`:

- `seeded_regression` — the fixture seeds a regression a reviewer must not
  miss and carries a private `{severity, seed}` record.
- `benign_control` — the fixture has no seeded regression (`regression` is
  `null`); it exists so `false_blocks` has a true-negative case.

The hostile-prompt-prose fixture seeds a public-safe simulated untrusted
package-prose sample in a top-level `non_worker_sources` field. Deterministic
preprocessing binds that prose by digest through `prompt_payload`; the raw
prose text is verified absent from worker prompts.

## Verifying a frozen corpus

```bash
python3 -m unittest tests.test_openclaw_benchmark -v
```

The tests recompute every fixture digest and `corpus_digest`, enforces the
blinding invariants, validates each artifact against its schema with the
standard library, and exercises the incremental-recall scoring primitives
against sample worker results.
