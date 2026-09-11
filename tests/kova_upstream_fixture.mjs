// Contract fixture only: generate artifacts with upstream Kova, without OCM
// or OpenClaw execution. The importer must consume the actual producer format.
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [checkout, fixtureRoot] = process.argv.slice(2);
const upstream = (path) => import(pathToFileURL(join(resolve(checkout), path)).href);
const { buildEvidenceLedger } = await upstream("src/evidence-ledger.mjs");
const { buildRunReport } = await upstream("src/run/report-finalization.mjs");
const { buildReportOutputPaths, writeReportOutputs } = await upstream("src/run/report-output.mjs");
const { bundleReport } = await upstream("src/reporting/artifacts.mjs");
const original = JSON.parse(await readFile(join(fixtureRoot, "kova-run.json"), "utf8"));
const template = JSON.parse(await readFile(join(checkout, "tests/fixtures/reports/pass.json"), "utf8"));
const records = original.records.map((record) => {
  const entries = record.evidenceLedger.entries;
  const phases = new Map();
  for (const entry of entries.filter((e) => e.category === "command")) {
    const [, phaseId, index] = entry.id.split(":");
    const phase = phases.get(phaseId) ?? { id: phaseId, commands: [], results: [] };
    phase.commands[Number(index) - 1] = "fixture-command";
    phase.results[Number(index) - 1] = { status: 0, stdout: "fixture", stderr: "" };
    phases.set(phaseId, phase);
  }
  const result = {
    ...template.records[0],
    scenario: record.scenario,
    surface: record.scenario,
    target: original.target,
    targetIdentity: record.targetIdentity,
    phases: [...phases.values()],
    evidenceInvariants: entries.filter((e) => e.category === "invariant").map((e) => ({
      id: e.id.slice("invariant:".length), required: e.required,
      status: e.status, summary: "Synthetic contract fixture",
    })),
    evidenceArtifacts: [], cleanupEvidence: [], channelCapabilityEvidence: [],
    finalMetrics: { service: { gatewayState: "running" }, health: { ok: true } },
  };
  result.evidenceLedger = buildEvidenceLedger(result);
  return result;
});
const runId = "kova-260911-000000-abcdef";
const report = buildRunReport({
  ...template, runId, mode: "execution", target: original.target, records,
  outputPaths: buildReportOutputPaths(fixtureRoot, runId),
});
await writeReportOutputs(fixtureRoot, report);
const bundle = await bundleReport(report.outputPaths.json, {
  outputDir: fixtureRoot, artifactsDir: join(fixtureRoot, "empty-artifacts"),
});
await writeFile(join(fixtureRoot, "kova-receipt.json"), JSON.stringify({
  schemaVersion: "kova.matrix.run.receipt.v1", mode: report.mode, runId,
  targetIdentity: report.targetIdentity, jsonPath: report.outputPaths.json,
  bundlePath: bundle.outputPath, checksumPath: bundle.checksumPath,
  gate: report.gate, summary: report.summary,
}, null, 2));
