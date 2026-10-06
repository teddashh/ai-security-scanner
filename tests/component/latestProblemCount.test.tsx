import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { I18nProvider, localeStorageKey, type Locale } from "../../src/i18n";
import { en } from "../../src/i18n/locales/en";
import { zhTW } from "../../src/i18n/locales/zh-TW";
import { latestProblemCount } from "../../src/latestProblemCount";
import { CasesPage } from "../../src/pages/CasesPage";
import type { CasesPageProps } from "../../src/pages/CasesPage";
import { scanRunIdentityPresentation } from "../../src/scanRunIdentityPresentation";
import type { AssessmentCase, BeginnerReportFinding, ScanRun } from "../../src/types";

const assessmentCase = (): AssessmentCase => ({
  id: "case-1",
  name: "Acme scan",
  aiGeneratedArtifact: "no",
  organizationName: "Acme",
  companySize: "small",
  dataClasses: [],
  requestedActivities: [],
  platforms: [],
  createdAt: "2026-10-01T10:00:00Z",
  updatedAt: "2026-10-06T02:00:00Z",
  phase: "needs_attention",
});

const scan = (
  id: string,
  sequence: number,
  startedAt: string,
): ScanRun => ({
  id,
  caseId: "case-1",
  label: "stored label",
  sequence,
  status: "completed",
  progress: 100,
  startedAt,
  finishedAt: startedAt,
  knowledgeDate: "2026-10-01",
  engineRuns: [],
  coveredAssetCount: 1,
  totalAssetCount: 1,
});

const reportFinding = (id: string): BeginnerReportFinding => ({
  findingId: id,
  targetAssetIds: ["asset-1"],
  severity: "high",
  priority: 10,
} as BeginnerReportFinding);

const renderCases = (overrides: Partial<CasesPageProps>) => {
  const selected = assessmentCase();
  return render(
    <I18nProvider>
      <CasesPage
        cases={[selected]}
        selectedCase={selected}
        assetCount={1}
        findingCount={0}
        unknownSourceCount={0}
        connectedNoAssetSourceCount={0}
        runs={[]}
        nativeMode
        onCreate={() => Promise.resolve(true)}
        onCreateWithWorkspace={() => Promise.resolve(true)}
        onChooseWorkspace={() => Promise.resolve(null)}
        onSeedDemo={() => Promise.resolve()}
        onArchive={() => Promise.resolve()}
        onDelete={() => Promise.resolve(true)}
        onDeleteArtifacts={() => Promise.resolve(true)}
        onDismissArtifactCleanup={() => {}}
        onStartNewScan={() => {}}
        onOpenCase={() => {}}
        onContinue={() => {}}
        onOpenProgress={() => {}}
        onOpenResults={() => {}}
        onSelectVerificationBaseline={() => {}}
        onStartRescan={() => Promise.resolve()}
        onOpenVerification={() => {}}
        {...overrides}
      />
    </I18nProvider>,
  );
};

const catalogs = { en, "zh-TW": zhTW } as const;

// CasesPage pageCopy.findingsMetric, read from src/pages/CasesPage.tsx.
const findingsMetric = { en: "Problems found", "zh-TW": "找到的問題" } as const;

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test.each(["en", "zh-TW"] as const)("My scans shows the latest report's problem count in %s", (locale: Locale) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const earlier = scan("run-1", 1, "2026-10-01T00:00:00Z");
  const latest = scan("run-2", 2, "2026-10-06T02:00:00Z");
  const savedFindings = Array.from({ length: 32 }, () => ({}));
  const shown = latestProblemCount({
    runs: [latest, earlier],
    beginnerReports: [{
      runId: latest.id,
      findings: Array.from({ length: 16 }, (_, index) => reportFinding(`problem-${index}`)),
    }],
    findings: savedFindings,
    isDemo: false,
  });
  const { container } = renderCases({
    findingCount: shown.count,
    problemCountRun: shown.run,
    latestRun: latest,
    runs: [latest, earlier],
  });

  const card = Array.from(container.querySelectorAll<HTMLElement>(".page-outcome-metrics .metric-card")).find(
    (node) => node.querySelector(".metric-card__label")?.textContent === findingsMetric[locale],
  );
  const detail = `${scanRunIdentityPresentation(latest, locale)} · ${catalogs[locale]["status.run.completed"]}`;
  expect(card?.querySelector(".metric-card__value")?.textContent).toBe("16");
  expect(card?.querySelector(".metric-card__detail")?.textContent).toBe(detail);
  expect(card?.className).toContain("metric-card--danger");
  expect(card?.textContent).not.toContain("32");
});
