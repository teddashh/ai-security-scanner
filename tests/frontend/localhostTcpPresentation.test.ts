import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import type { EngineRun, LocalhostTcpOutcome } from "../../src/types.ts";

const bundled = await build({
  entryPoints: [fileURLToPath(new URL("../../src/localhostTcpPresentation.ts", import.meta.url))],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const source = bundled.outputFiles[0]?.text;
assert.ok(source, "localhost result presentation bundle should contain JavaScript");
const { localhostTcpBeginnerSummary } = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
);

const engine = (overrides: Partial<EngineRun> = {}): EngineRun => ({
  id: "localhost-check-1",
  engineId: "built-in-localhost-tcp",
  engineName: "Localhost TCP reachability",
  category: "built_in_localhost_tcp",
  taskKind: {
    kind: "built_in_localhost_tcp",
    port: 9001,
    timeoutMs: 3000,
    payloadBytes: 0,
  },
  warnings: [],
  status: "completed",
  progress: 100,
  phase: "completed",
  assetIds: ["localhost-asset"],
  rawArtifactCount: 0,
  findingCount: 0,
  resumable: false,
  ...overrides,
});

test("reachable, closed, and timed-out observations state the exact bounded result", () => {
  const expected: Record<LocalhostTcpOutcome, RegExp> = {
    reachable: /accepted a TCP connection/u,
    closed: /refused the TCP connection/u,
    timed_out: /timed out/u,
  };

  for (const outcome of ["reachable", "closed", "timed_out"] as const) {
    const summary = localhostTcpBeginnerSummary(engine({
      status: outcome === "timed_out" ? "partial" : "completed",
      localhostTcpObservation: { outcome, observedAt: "2026-08-30T12:00:00Z" },
    }));
    assert.ok(summary);
    assert.equal(summary.outcome, outcome);
    assert.match(summary.title.en, expected[outcome]);
    assert.match(summary.title.zhTW, /9001/u);
    assert.match(summary.description.en, /127\.0\.0\.1:9001/u);
    assert.match(summary.description.en, /3000 ms/u);
    assert.match(summary.description.en, /0 application-data bytes/u);
    assert.match(summary.exclusions.en, /vulnerabilities/u);
    assert.match(summary.exclusions.en, /other ports/u);
    assert.match(summary.exclusions.en, /other hosts/u);
  }
});

test("missing observations never turn completed, failed, or cancelled work into a clean result", () => {
  const cases = [
    ["completed", "missing"],
    ["failed", "failed"],
    ["cancelled", "cancelled"],
    ["pending", "in_progress"],
    ["running", "in_progress"],
  ] as const;
  for (const [status, outcome] of cases) {
    const summary = localhostTcpBeginnerSummary(engine({ status, localhostTcpObservation: undefined }));
    assert.ok(summary);
    assert.equal(summary.outcome, outcome);
    assert.match(summary.outcomeLabel.en, /no observation|not recorded/iu);
    assert.doesNotMatch(
      `${summary.title.en} ${summary.description.en} ${summary.nextStep.en}`,
      /came from one TCP connection attempt|made one TCP|connection attempt finishes/iu,
    );
  }
});

test("a conflicting terminal status and observation is disclosed instead of presented as reachability", () => {
  for (const mismatch of [
    engine({
      status: "partial",
      localhostTcpObservation: { outcome: "reachable", observedAt: "2026-08-30T12:00:00Z" },
    }),
    engine({
      status: "completed",
      localhostTcpObservation: { outcome: "timed_out", observedAt: "2026-08-30T12:00:00Z" },
    }),
  ]) {
    const summary = localhostTcpBeginnerSummary(mismatch);
    assert.ok(summary);
    assert.equal(summary.outcome, "inconsistent");
    assert.doesNotMatch(summary.title.en, /accepted|refused|timed out/iu);
    assert.doesNotMatch(summary.description.en, /came from one TCP connection attempt/iu);
  }
});

test("localhost beginner wording makes no safe, secure, or zero-problem inference", () => {
  for (const outcome of ["reachable", "closed", "timed_out"] as const) {
    const summary = localhostTcpBeginnerSummary(engine({
      status: outcome === "timed_out" ? "partial" : "completed",
      localhostTcpObservation: { outcome, observedAt: "2026-08-30T12:00:00Z" },
    }));
    assert.ok(summary);
    const allCopy = Object.values(summary)
      .flatMap((value) => typeof value === "object" && value && "en" in value
        ? [value.en, value.zhTW]
        : [])
      .join(" ");
    assert.doesNotMatch(allCopy, /\b(?:safe|secure|secured|security)\b|zero problems|沒有問題|安全/u);
  }
});

test("catalog work is not relabeled as a localhost result", () => {
  assert.equal(localhostTcpBeginnerSummary(engine({
    engineId: "trivy",
    taskKind: { kind: "catalog_engine" },
    localhostTcpObservation: undefined,
  })), undefined);
});

test("result pages use the bounded summary and keep catalog provenance out of the built-in branch", async () => {
  const [findings, progress] = await Promise.all([
    readFile(new URL("../../src/pages/FindingsPage.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/pages/ProgressPage.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(findings, /localhostTcpBeginnerSummary\(engine\)/u);
  assert.match(findings, /text\(localhostSummary\.exclusions\)/u);
  assert.doesNotMatch(findings, /Good news:/u);
  assert.match(
    progress,
    /localhostSummary\.outcome === "reachable"[\s\S]*?\? "info"/u,
  );
  assert.doesNotMatch(
    progress,
    /localhostSummary\.outcome === "reachable"[\s\S]{0,80}\? "positive"/u,
  );

  const provenanceSummary = progress.indexOf(
    '<summary>{text(localhostSummary ? copy.technicalDetails : copy.provenance)}</summary>',
  );
  const builtInStart = progress.indexOf("{localhostSummary ? (", provenanceSummary);
  const catalogStart = progress.indexOf(") : (", builtInStart);
  assert.ok(provenanceSummary >= 0 && builtInStart > provenanceSummary && catalogStart > builtInStart);
  const builtInTechnicalBranch = progress.slice(builtInStart, catalogStart);
  assert.match(builtInTechnicalBranch, /copy\.endpoint/u);
  assert.match(builtInTechnicalBranch, /copy\.observedOutcome/u);
  assert.match(builtInTechnicalBranch, /localhostSummary\.exclusions/u);
  assert.doesNotMatch(
    builtInTechnicalBranch,
    /copy\.(?:engineId|scannerVersion|imageDigest|manifestSchema|sourceRepository|runtimeSecurity)/u,
  );
});
