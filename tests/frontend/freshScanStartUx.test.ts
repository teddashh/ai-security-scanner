import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  canStartPreparedScan,
  findRunCreatedAfterStart,
  hasActiveScanWork,
} from "../../src/freshScanSelection.ts";

const readSource = (path: string) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("a fresh scan request immediately replaces the empty state and prevents a duplicate start", async () => {
  const [app, progress] = await Promise.all([
    readSource("src/App.tsx"),
    readSource("src/pages/ProgressPage.tsx"),
  ]);

  assert.match(app, /const \[startingScanCaseId, setStartingScanCaseId\] = useState<string>\(\)/u);
  assert.match(app, /<ProgressPage[\s\S]*caseId=\{currentCaseId\}/u);
  assert.match(app, /starting=\{Boolean\(currentCaseId && busyAction === "start-scan" && startingScanCaseId === currentCaseId\)\}/u);
  assert.match(app, /onStart=\{async \(\) => \{[\s\S]*if \(currentCaseId\) await startScan\(\{ caseId: currentCaseId \}\);/u);
  assert.match(progress, /starting\?: boolean/u);
  assert.match(progress, /startRunIds\.current = \{ caseId, ids: new Set\(runs\.map\(\(run\) => run\.id\)\) \}/u);
  assert.match(progress, /if \(!baseline \|\| baseline\.caseId !== caseId\) return/u);

  const noRunStart = progress.indexOf("if (!selectedRun)");
  const noRunEnd = progress.indexOf("const runMeta", noRunStart);
  const noRun = progress.slice(noRunStart, noRunEnd);
  assert.ok(noRunStart >= 0 && noRunEnd > noRunStart);
  assert.match(noRun, /title=\{text\(starting \? copy\.startingTitle : emptyTitle\)\}/u);
  assert.match(noRun, /description=\{text\(starting \? copy\.startingDescription : emptyDescription\)\}/u);
  assert.match(
    noRun,
    /action=\{starting \? \([\s\S]*?<button[^>]*disabled aria-busy="true">[\s\S]*?copy\.startingAction[\s\S]*?\) : canStart \?/u,
  );
  assert.match(noRun, /\{starting && \([\s\S]*?className="scan-activity__current" role="status"/u);
  assert.doesNotMatch(noRun, /selectedRun\.id/u);
});

test("a fresh rescan selects the run created after the request", () => {
  const baseline = new Set(["older-run", "oldest-run"]);
  assert.equal(
    findRunCreatedAfterStart(
      [{ id: "new-run" }, { id: "older-run" }, { id: "oldest-run" }],
      baseline,
    ),
    "new-run",
  );
  assert.equal(
    findRunCreatedAfterStart([{ id: "older-run" }, { id: "oldest-run" }], baseline),
    undefined,
  );
});

test("a prepared case can start a new scan while terminal history remains visible", () => {
  const terminalHistory = [
    { status: "completed" },
    { status: "failed" },
  ];

  assert.equal(hasActiveScanWork(terminalHistory), false);
  assert.equal(canStartPreparedScan({ ready: true }, false, terminalHistory), true);
  assert.equal(
    canStartPreparedScan({ ready: false, blockerCode: "no_compatible_authorized_targets" }, false, terminalHistory),
    false,
    "an unsupported target cannot expose a Start action that the backend rejects without a run",
  );
  assert.equal(
    canStartPreparedScan({ ready: false, blockerCode: "runtime_unavailable" }, false, terminalHistory),
    true,
    "a disposable runtime failure must become a task outcome after Start",
  );
  assert.equal(
    canStartPreparedScan({ ready: false, blockerCode: "no_runnable_authorized_targets" }, false, terminalHistory),
    true,
    "zero runnable engines must still produce an honest durable report",
  );
  assert.equal(
    canStartPreparedScan({ ready: false, blockerCode: "no_effective_scope_grants" }, false, terminalHistory),
    false,
    "a repeat scan needs an existing exact target assertion",
  );
  assert.equal(canStartPreparedScan(undefined, true, terminalHistory), true);

  for (const status of ["queued", "running", "paused"]) {
    assert.equal(
      canStartPreparedScan({ ready: true }, false, [...terminalHistory, { status }]),
      false,
      `${status} work must block a second scan`,
    );
  }
});

test("scan history renders the prepared Start action instead of trapping the user in the prior run", async () => {
  const progress = await readSource("src/pages/ProgressPage.tsx");
  const historyStart = progress.indexOf("const runMeta");
  const historyPage = progress.slice(historyStart);

  assert.match(
    progress,
    /const canStart = !terminalExactLocalhostQuickScan\s*&& canStartPreparedScan\(readiness, Boolean\(readinessCheckFailed\), runs\)/u,
  );
  assert.match(
    historyPage,
    /\{canStart && !hasReleaseIncompatibleWork && \([\s\S]*?onClick=\{requestStart\}[\s\S]*?copy\.start/u,
  );
});

test("fresh-start feedback is visible, bilingual, and does not invent a scan record", async () => {
  const progress = await readSource("src/pages/ProgressPage.tsx");

  for (const phrase of [
    "Starting your scan…",
    "正在開始掃描…",
    "Creating the scan record.",
    "正在建立掃描紀錄。",
    "Starting a new scan…",
    "正在開始新的掃描…",
  ]) assert.ok(progress.includes(phrase), phrase);

  const historyStart = progress.indexOf("{starting && (", progress.indexOf("const runMeta"));
  const historyEnd = progress.indexOf("{!terminalExactLocalhostQuickScan && readinessCheckFailed && (", historyStart);
  const historyStartingNotice = progress.slice(historyStart, historyEnd);
  assert.ok(historyStart >= 0 && historyEnd > historyStart);
  assert.match(historyStartingNotice, /<InlineNotice tone="info" title=\{text\(copy\.startingNewTitle\)\}>/u);
  assert.match(historyStartingNotice, /<p role="status">\{text\(copy\.startingNewDescription\)\}<\/p>/u);
  assert.doesNotMatch(historyStartingNotice, /selectedRun\.id|runIdTitle/u);
});

test("release-incompatible saved checks offer a direct fresh-scan path", async () => {
  const [progress, presentation] = await Promise.all([
    readSource("src/pages/ProgressPage.tsx"),
    readSource("src/scanPresentation.ts"),
  ]);

  for (const phrase of [
    "Some saved checks need a new scan",
    "部分已保存的檢查需要新的掃描",
    "These checks were created by a different app release. Start a new scan to run them with this release.",
    "這些檢查由不同版本建立；請開始新的掃描，以目前版本執行。",
    "Compatible checks continue in this run.",
    "相容的檢查繼續在這一輪執行",
    "Readiness step required below.",
    "需要完成下方的準備步驟",
  ]) assert.ok(progress.includes(phrase), phrase);

  assert.doesNotMatch(progress, /Nothing from the earlier scan|先前掃描的內容不會重新執行|After this scan ends|這次掃描結束後/u);

  assert.match(
    progress,
    /const hasReleaseIncompatibleWork = selectedRun\.engineRuns\.some\([\s\S]*?engine\.errorCode === "resume_release_incompatible"/u,
  );
  assert.match(
    progress,
    /const scanWorkActive = hasActiveScanWork\(runs\)/u,
  );
  assert.match(
    progress,
    /\{canStart && !hasReleaseIncompatibleWork && \(/u,
    "release-incompatible history must suppress the generic header Start action",
  );
  const noticeStart = progress.indexOf("{hasReleaseIncompatibleWork && (");
  const noticeEnd = progress.indexOf("{!terminalExactLocalhostQuickScan && readinessCheckFailed && (", noticeStart);
  const notice = progress.slice(noticeStart, noticeEnd);
  assert.ok(noticeStart >= 0 && noticeEnd > noticeStart);
  assert.match(notice, /<InlineNotice tone="warning" title=\{text\(copy\.releaseIncompatibleTitle\)\}>/u);
  assert.match(notice, /\{canStart && \([\s\S]*?onClick=\{requestStart\}[\s\S]*?copy\.startFreshScan/u);
  assert.doesNotMatch(notice, /!scanWorkActive && \(/u);
  assert.doesNotMatch(notice, /engine\.message|error_message/u);

  assert.match(
    presentation,
    /if \(engine\.errorCode === "resume_release_incompatible"\) return nextStepCopy\.releaseIncompatible/u,
  );
  assert.match(
    presentation,
    /if \(engine\.errorCode === "resume_work_plan_invalid"\) return nextStepCopy\.savedPlanUnavailable/u,
  );
  assert.ok(
    presentation.includes("Start a new scan to run this check with the installed release."),
    "the per-check next step must not suggest retrying frozen work",
  );
});
