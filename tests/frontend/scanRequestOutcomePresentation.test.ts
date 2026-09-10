import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import type { ScanRequestOutcome } from "../../src/types.ts";

const bundled = await build({
  entryPoints: [fileURLToPath(new URL("../../src/scanRequestOutcomePresentation.ts", import.meta.url))],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const source = bundled.outputFiles[0]?.text;
assert.ok(source, "scan request outcome presentation bundle should contain JavaScript");
const { scanRequestOutcomeBeginnerSummary } = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
);

test("every no-checks code has stable bilingual first-layer guidance", () => {
  const reasons = {
    no_effective_scope_grants: ["The saved permission was missing or expired.", "已保存的許可不存在或已過期。"],
    no_ownership_confirmed_targets: ["None of the selected targets was confirmed as yours.", "所選目標都還沒有確認為你所控制。"],
    no_applicable_checks: ["No available check matched what you selected.", "目前沒有可用的檢查符合你選擇的內容。"],
  } as const;
  for (const code of Object.keys(reasons) as Array<keyof typeof reasons>) {
    const outcome: ScanRequestOutcome = {
      status: "no_checks_completed",
      code,
      requestedAssetIds: ["asset-private"],
      requestedEngineIds: [],
    };
    const summary = scanRequestOutcomeBeginnerSummary(outcome);
    assert.ok(summary);
    assert.equal(summary.title.en, "No checks completed");
    assert.equal(summary.title.zhTW, "沒有完成任何檢查");
    assert.ok(summary.title.en);
    assert.ok(summary.title.zhTW);
    assert.equal(summary.description.en, reasons[code][0]);
    assert.equal(summary.description.zhTW, reasons[code][1]);
    assert.doesNotMatch(summary.description.en, /No target was contacted|not a result with zero problems/u);
    assert.ok(summary.nextStep.en);
    assert.ok(summary.nextStep.zhTW);
    assert.doesNotMatch(`${summary.nextStep.en} ${summary.nextStep.zhTW}`, /only if|只有在/u);
  }
});

test("progress treats no-checks-completed as terminal without resume, cancel, or failure copy", async () => {
  const progress = await readFile(
    new URL("../../src/pages/ProgressPage.tsx", import.meta.url),
    "utf8",
  );
  const resumeRule = progress.slice(
    progress.indexOf("const canResume"),
    progress.indexOf("const canCancel"),
  );
  const cancelRule = progress.slice(
    progress.indexOf("const canCancel"),
    progress.indexOf("const hasReleaseIncompatibleWork"),
  );
  assert.doesNotMatch(resumeRule, /no_checks_completed/u);
  assert.doesNotMatch(cancelRule, /no_checks_completed/u);
  assert.match(progress, /runStatusMeta\[selectedRun\.status\]/u);
  assert.match(progress, /run_no_checks_completed/u);
});
