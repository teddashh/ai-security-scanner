import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { ProgressPage } from "../../src/pages/ProgressPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { EngineRun, EngineRunStatus, ScanRun } from "../../src/types";

// The progress view is read while a scan is still the user's live picture of
// what happened. Two of its states are easy to lose on the way to the screen:
// a check that never ran, which is filtered out of the main engine list and
// re-added as one aggregate row, and a check that ran without finishing.
//
// `scanDiagnostics.ts` decides both, and its rules are covered by unit tests.
// What was not covered is whether the page honours them: a filter that drops
// never-run checks and an aggregate row that fails to render would remove them
// from the account entirely, and every count on the page would still add up.

const engine = (
  id: string,
  status: EngineRunStatus,
  overrides: Partial<EngineRun> = {},
): EngineRun => ({
  id,
  engineId: id,
  engineName: id,
  category: "cloud",
  taskKind: "engine_container",
  warnings: [],
  status,
  progress: status === "completed" ? 100 : 40,
  phase: status,
  assetIds: ["asset-1"],
  rawArtifactCount: 0,
  findingCount: 0,
  resumable: false,
  ...overrides,
});

const run = (engineRuns: EngineRun[], status: ScanRun["status"] = "partial"): ScanRun => ({
  id: "run-1",
  caseId: "case-1",
  label: "Scan 1",
  status,
  progress: 100,
  startedAt: "2026-09-04T12:00:00Z",
  finishedAt: "2026-09-04T12:05:00Z",
  knowledgeDate: "2026-09-04",
  engineRuns,
  coveredAssetCount: 1,
  totalAssetCount: 1,
});

const renderProgress = (value: ScanRun) =>
  render(
    <I18nProvider>
      <ProgressPage
        caseId="case-1"
        runs={[value]}
        selectedRunId={value.id}
        onStart={() => Promise.resolve()}
        onRetryLocalhostQuickScan={() => Promise.resolve()}
        onFixSetup={() => {}}
        onPause={() => Promise.resolve()}
        onResume={() => Promise.resolve()}
        onCancel={() => Promise.resolve()}
      />
    </I18nProvider>,
  );

/** The engine row naming `engineName`; id and name both render, so match on text. */
const engineRow = (container: HTMLElement, name: string): HTMLElement => {
  const row = Array.from(container.querySelectorAll<HTMLElement>(".engine-row")).find(
    (candidate) => candidate.textContent?.includes(name),
  );
  if (!row) throw new Error(`no engine row rendered for ${name}`);
  return row;
};

const pillTexts = (container: HTMLElement): string[] =>
  Array.from(container.querySelectorAll<HTMLElement>(".status-pill")).map(
    (pill) => pill.textContent ?? "",
  );

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("a check that never ran is still accounted for on screen", () => {
  // Never-run checks are filtered out of the engine list and re-added as one
  // aggregate row. If that row goes missing they leave the page silently, and
  // a reader is left believing the scan covered only what it happened to try.
  const { container } = renderProgress(
    run([engine("ran", "completed", { progress: 100 }), engine("never-ran", "not_executed")]),
  );

  const notRunCard = Array.from(container.querySelectorAll<HTMLElement>(".metric-card")).find(
    (card) => card.querySelector(".metric-card__label")?.textContent === "Not run",
  );
  if (!notRunCard) throw new Error("the not-run metric card did not render");
  expect(notRunCard.querySelector(".metric-card__value")?.textContent).toBe("1");
  expect(notRunCard.className).toContain("metric-card--warning");

  // And it is present as its own row, not only as a number in a tally.
  expect(container.querySelector(".engine-not-executed")).not.toBeNull();
});

test("a check that ran without finishing does not read as completed", () => {
  const { container } = renderProgress(
    run([engine("finished-check", "completed", { progress: 100 }), engine("unfinished-check", "partial")]),
  );

  const unfinished = engineRow(container, "unfinished-check");
  const finished = engineRow(container, "finished-check");

  const unfinishedPill = unfinished.querySelector<HTMLElement>(".status-pill");
  const finishedPill = finished.querySelector<HTMLElement>(".status-pill");
  expect(unfinishedPill?.textContent).not.toEqual(finishedPill?.textContent);
  expect(unfinishedPill?.className).not.toContain("status-pill--positive");
  expect(finishedPill?.className).toContain("status-pill--positive");
});

test("a failed check is not presented in the same tone as a stopped one", () => {
  // "failed" is danger and "cancelled" is neutral: one is the product going
  // wrong, the other is the user's own choice, and merging them would either
  // alarm or reassure wrongly.
  const { container } = renderProgress(
    run([engine("broke-check", "failed"), engine("stopped-check", "cancelled")]),
  );

  const failed = engineRow(container, "broke-check");
  const cancelled = engineRow(container, "stopped-check");

  expect(failed.querySelector(".status-pill")?.className).toContain("status-pill--danger");
  expect(cancelled.querySelector(".status-pill")?.className).not.toContain("status-pill--danger");
});

test("no engine state is rendered without a label", () => {
  // Every EngineRunStatus reaches this page. A state with no presentation would
  // render an empty pill rather than failing, which reads as nothing wrong.
  const states: EngineRunStatus[] = [
    "pending",
    "running",
    "paused",
    "completed",
    "partial",
    "failed",
    "cancelled",
  ];
  const { container } = renderProgress(
    run(states.map((state, index) => engine(`check-${index}`, state))),
  );

  const labels = pillTexts(container).filter((label) => label.trim().length === 0);
  expect(labels).toEqual([]);
});
