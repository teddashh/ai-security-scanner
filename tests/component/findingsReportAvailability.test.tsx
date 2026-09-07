import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Finding, ScanRun } from "../../src/types";

const canonicalFinding: Finding = {
  id: "canonical-finding",
  fingerprint: "canonical-fingerprint",
  assetId: "asset-1",
  assetName: "Sample server",
  title: "Canonical sample finding",
  summary: "A canonical finding summary.",
  impact: "A canonical finding impact.",
  recommendation: "A canonical recommendation.",
  expertType: "security",
  severity: "high",
  confidence: "high",
  priority: 1,
  workflowState: "unreviewed",
  evidence: [],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-04T12:00:00Z",
  lastSeenAt: "2026-09-04T12:00:00Z",
};

const savedRun: ScanRun = {
  id: "saved-run",
  caseId: "case-1",
  label: "Saved scan",
  status: "completed",
  progress: 100,
  startedAt: "2026-09-04T12:00:00Z",
  finishedAt: "2026-09-04T12:00:03Z",
  knowledgeDate: "2026-09-04",
  coveredAssetCount: 1,
  totalAssetCount: 1,
  engineRuns: [{
    id: "engine-run",
    engineId: "saved-check",
    engineName: "Saved check",
    category: "security",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    startedAt: "2026-09-04T12:00:00Z",
    finishedAt: "2026-09-04T12:00:03Z",
    assetIds: ["asset-1"],
    rawArtifactCount: 0,
    findingCount: 0,
    resumable: false,
  }],
};

const renderPage = (
  reportUnavailable: boolean,
  runs: ScanRun[] = [],
  selectedRunId?: string,
) => render(
  <I18nProvider>
    <FindingsPage
      report={undefined}
      selectedRunId={selectedRunId}
      reportUnavailable={reportUnavailable}
      findings={[canonicalFinding]}
      findingGroups={[]}
      findingGroupEvents={[]}
      coverage={[]}
      runs={runs}
      workflowEvents={[]}
      busy={false}
      onUpdateWorkflow={() => Promise.resolve(true)}
      onGroupFindings={() => Promise.resolve(true)}
      onUngroupFindings={() => Promise.resolve()}
      onOpenCoverage={() => {}}
      onOpenProgress={() => {}}
      onOpenExport={() => {}}
    />
  </I18nProvider>,
);

beforeEach(() => window.localStorage.setItem(localeStorageKey, "en"));

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("canonical findings render when no beginner report is required", () => {
  const { container } = renderPage(false);
  expect(container.querySelectorAll(".finding-row")).toHaveLength(1);
  expect(container.textContent).toContain("Canonical sample finding");
});

test("the finding browser keeps native list semantics, a non-complementary detail region, and accessible fields", () => {
  const { container } = renderPage(false);
  const findingList = container.querySelector(".finding-list");
  const firstFinding = findingList?.querySelector<HTMLButtonElement>("button.finding-row");
  if (!firstFinding) throw new Error("expected a finding row");
  fireEvent.click(firstFinding);
  const findingDetail = container.querySelector(".finding-detail");
  const sourceForms = container.querySelectorAll("form.source-connect-panel--stacked");

  expect(findingList?.tagName).toBe("UL");
  expect(findingList?.querySelectorAll(":scope > li")).toHaveLength(1);
  expect(findingList?.querySelector(":scope > li > button.finding-row")).not.toBeNull();
  expect(findingList?.querySelector("[role='list'], [role='listitem']")).toBeNull();
  expect(findingDetail?.tagName).toBe("SECTION");
  expect(findingDetail?.getAttribute("role")).toBeNull();
  expect(sourceForms).toHaveLength(2);

  for (const form of sourceForms) {
    const directLabels = Array.from(form.children).filter((element) => element.tagName === "LABEL");
    expect(directLabels.length).toBeGreaterThan(0);
    for (const label of directLabels) expect(label.classList.contains("field")).toBe(true);
  }
});

test("a missing durable run-bound report suppresses cross-run findings and keeps its scoped notice", () => {
  const { container } = renderPage(true, [savedRun]);
  expect(container.querySelectorAll(".finding-row")).toHaveLength(0);
  expect(container.textContent).toContain("This scan has no durable master report");
  expect(container.textContent).toContain("exact saved run remains available from the Review scanner status view and can still be exported");
  expect(container.textContent).toContain("Review scanner status");
  expect(container.textContent).toContain("Save or share report");
  expect(container.textContent).not.toContain("available below");
  expect(container.textContent).not.toContain("Canonical sample finding");
});

test("a stale selected run fails closed without offering Progress or Export for another run", () => {
  const { container } = renderPage(true, [savedRun], "missing-run");

  expect(container.querySelectorAll(".finding-row")).toHaveLength(0);
  expect(container.textContent).toContain("This selected scan is no longer available");
  expect(container.textContent).toContain("will not substitute a different scan run");
  expect(container.textContent).not.toContain("exact saved run remains available");
  expect(container.textContent).not.toContain("Review scanner status");
  expect(container.textContent).not.toContain("Save or share report");
  expect(container.textContent).not.toContain("Canonical sample finding");
});
