import { cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { ExportPage } from "../../src/pages/ExportPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { CaseWorkspace, ExportPreview, ScanRun } from "../../src/types";

// "(recommended)" is advice for choosing a format, so only the chooser card
// carries it. The Save button stands in for every other place that names the
// format: the file summary, its exact type, and the export history.

const CHOSEN = "run-2026-08-31";

const run = (id: string): ScanRun => ({
  id,
  caseId: "case-1",
  label: id,
  status: "completed",
  progress: 100,
  startedAt: "2026-08-31T12:00:00Z",
  finishedAt: "2026-08-31T12:01:00Z",
  knowledgeDate: "2026-08-31",
  engineRuns: [],
  coveredAssetCount: 3,
  totalAssetCount: 3,
});

const workspace: CaseWorkspace = {
  case: {
    id: "case-1",
    name: "Contoso baseline",
    aiGeneratedArtifact: "no",
    organizationName: "Contoso",
    companySize: "small",
    dataClasses: [],
    requestedActivities: [],
    platforms: [],
    createdAt: "2026-08-31T11:00:00Z",
    updatedAt: "2026-09-02T11:00:00Z",
    phase: "reporting",
    latestRunId: CHOSEN,
  },
  sources: [],
  coverage: [],
  assets: [],
  scopeGrants: [],
  runs: [run(CHOSEN)],
  findings: [],
  findingGroups: [],
  findingGroupEvents: [],
  workflowEvents: [],
  exports: [],
};

/** A preview that answers whatever coordinate it was asked about. */
const renderExport = () => {
  const onPreview = vi.fn((request: {
    runId: string;
    locale: "en" | "zh-Hant";
    format: string;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => Promise.resolve({
    caseId: "case-1",
    runId: request.runId,
    locale: request.locale,
    format: request.format,
    redactionProfile: request.redactSensitiveValues ? "standard" : "none",
    includeRawEvidence: request.includeRawEvidence,
    dataSourceCount: 2,
    coverageEntryCount: 4,
    assetCount: 3,
    candidateAssetCount: 3,
    canonicalFindingCount: 7,
    selectedRunFindingCount: 7,
    evidenceIndexCount: 7,
    selectedRunEvidenceCount: 7,
    scanRunCount: 1,
    selectedEngineRunCount: 2,
    externalScopeGrantCount: 0,
    incompleteEngineRunCount: 0,
    notExecutedEngineRunCount: 0,
    unknownSourceCount: 0,
    connectedNoAssetCount: 0,
    rawArtifactCount: 4,
    rawArtifactsIncluded: 0,
    rawArtifactsOmitted: 4,
    sensitiveRawArtifactsOmitted: 4,
    sensitiveDataWarning: "backend warning",
    coverageManifestIncluded: true,
  } as ExportPreview));

  const { container } = render(
    <I18nProvider>
      <ExportPage
        workspace={workspace}
        selectedRunId={CHOSEN}
        exports={[]}
        demoMode={false}
        onPreview={onPreview}
        onExport={() => Promise.resolve()}
        onVerify={() => Promise.resolve()}
        onVerifyReceived={() => Promise.resolve()}
      />
    </I18nProvider>,
  );
  return { container };
};

/** The `<strong>` title text of the format chooser card for one format id. */
const formatCardTitle = (container: HTMLElement, value: string): string => {
  const input = container.querySelector<HTMLInputElement>(`input[name="export-format"][value="${value}"]`);
  const card = input?.closest("label.format-card");
  const strong = card?.querySelector("strong");
  if (!strong) throw new Error(`no format card title rendered for "${value}"`);
  return strong.textContent ?? "";
};

/** The Save button's visible label (the only `.button--primary` on the page). */
const saveButtonText = (container: HTMLElement): string => {
  const button = container.querySelector<HTMLButtonElement>(".button--primary");
  if (!button) throw new Error("no primary save button rendered");
  return button.textContent ?? "";
};

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("in English, the HTML chooser card carries the recommendation and the Save button does not", async () => {
  window.localStorage.setItem(localeStorageKey, "en");
  const { container } = renderExport();

  await waitFor(() => expect(saveButtonText(container)).toContain("HTML"));

  expect(formatCardTitle(container, "html")).toBe("HTML report (recommended)");
  expect(formatCardTitle(container, "json")).toBe("JSON report");

  expect(saveButtonText(container)).toContain("HTML report");
  expect(saveButtonText(container)).not.toContain("recommended");
});

test("in Traditional Chinese, the HTML chooser card carries the recommendation and the Save button does not", async () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderExport();

  await waitFor(() => expect(saveButtonText(container)).toContain("HTML"));

  expect(formatCardTitle(container, "html")).toBe("HTML 報告（建議）");
  expect(formatCardTitle(container, "json")).toBe("JSON 報告");

  expect(saveButtonText(container)).toContain("HTML 報告");
  expect(saveButtonText(container)).not.toContain("建議");
});
