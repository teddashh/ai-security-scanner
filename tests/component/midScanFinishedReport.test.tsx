import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { pageForSelectedRunLifecycle } from "../../src/pageNavigation";
import { FindingsPage } from "../../src/pages/FindingsPage";
import type { Finding, ScanRun } from "../../src/types";

const finishedRun: ScanRun = {
  id: "finished-run",
  caseId: "case-1",
  label: "Scan 1",
  sequence: 1,
  status: "completed",
  progress: 100,
  startedAt: "2026-09-18T12:00:00Z",
  finishedAt: "2026-09-18T12:05:00Z",
  knowledgeDate: "2026-09-18",
  engineRuns: [],
  coveredAssetCount: 1,
  totalAssetCount: 1,
};

const runningRun: ScanRun = {
  ...finishedRun,
  id: "running-run",
  label: "Scan 2",
  sequence: 2,
  status: "running",
  progress: 50,
  startedAt: "2026-09-19T12:00:00Z",
  finishedAt: undefined,
};

const savedFinding: Finding = {
  id: "saved-finding",
  fingerprint: "saved-fingerprint",
  assetId: "asset-1",
  assetName: "Saved server",
  title: "Saved finished-scan finding",
  summary: "This finding belongs to the finished scan.",
  impact: "The saved server could be affected.",
  recommendation: "Apply the saved recommendation.",
  expertType: "security",
  severity: "high",
  confidence: "high",
  priority: 1,
  workflowState: "unreviewed",
  evidence: [],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-18T12:01:00Z",
  lastSeenAt: "2026-09-18T12:01:00Z",
};

beforeEach(() => window.localStorage.setItem(localeStorageKey, "en"));

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("mid-scan Results renders the finished run and explains when the running scan opens", () => {
  const runs = [runningRun, finishedRun];
  const resolution = pageForSelectedRunLifecycle("findings", runningRun, runs);

  expect(resolution.page).toBe("findings");
  expect(resolution.run?.id).toBe(finishedRun.id);

  const { container } = render(
    <I18nProvider>
      <FindingsPage
        report={undefined}
        selectedRunId={resolution.run?.id}
        runningScanResultsPending={resolution.showingFinishedRunWhileActive}
        findings={[savedFinding]}
        findingGroups={[]}
        findingGroupEvents={[]}
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

  const picker = container.querySelector<HTMLSelectElement>("select");
  expect(picker?.value).toBe(finishedRun.id);
  expect(container.textContent).toContain("Saved finished-scan finding");
  expect(container.textContent).toContain(
    "Showing a finished scan; the latest results open automatically.",
  );
});

test("the mid-scan finished-report sentence is localized in Traditional Chinese", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const runs = [runningRun, finishedRun];
  const resolution = pageForSelectedRunLifecycle("findings", runningRun, runs);
  const { container } = render(
    <I18nProvider>
      <FindingsPage
        selectedRunId={resolution.run?.id}
        runningScanResultsPending={resolution.showingFinishedRunWhileActive}
        findings={[savedFinding]}
        findingGroups={[]}
        findingGroupEvents={[]}
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

  expect(container.textContent).toContain(
    "目前顯示已完成的掃描；最新結果將自動開啟。",
  );
});
