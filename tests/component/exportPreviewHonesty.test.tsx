import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { ExportPage } from "../../src/pages/ExportPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { CaseWorkspace, ExportPreview, ScanRun } from "../../src/types";

// An export is the artifact that leaves this machine, so the numbers shown
// beside the save button are the last thing a user checks before handing the
// file to somebody else. ExportPage guards that in two layers: the preview is
// discarded unless its coordinates match the selection, and the save button is
// gated on the same match. Until now both layers were only asserted by matching
// this page's own source text in `tests/frontend/exportRunSelection.test.ts`,
// which would stay green if the rendering were deleted outright.
//
// Two properties are pinned here:
//   1. the preview must describe the run, locale, format and redaction profile
//      the user actually chose — never another run's statistics wearing this
//      run's label;
//   2. work that did not finish, or never ran at all, must be disclosed rather
//      than folded into a clean-looking zero.

const CHOSEN = "run-2026-08-31";
const NEWEST = "run-2026-09-02";

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
    latestRunId: NEWEST,
  },
  sources: [],
  coverage: [],
  assets: [],
  scopeGrants: [],
  runs: [run(NEWEST), run(CHOSEN)],
  findings: [],
  findingGroups: [],
  findingGroupEvents: [],
  workflowEvents: [],
  exports: [],
};

/** A preview that answers exactly the coordinate the page asks for by default. */
const preview = (overrides: Partial<ExportPreview> = {}): ExportPreview => ({
  caseId: "case-1",
  runId: CHOSEN,
  locale: "en",
  format: "html",
  redactionProfile: "standard",
  includeRawEvidence: false,
  dataSourceCount: 2,
  coverageEntryCount: 4,
  assetCount: 3,
  candidateAssetCount: 3,
  canonicalFindingCount: 7,
  selectedRunFindingCount: 7,
  evidenceIndexCount: 7,
  selectedRunEvidenceCount: 7,
  scanRunCount: 2,
  selectedEngineRunCount: 2,
  externalScopeGrantCount: 0,
  incompleteEngineRunCount: 0,
  notExecutedEngineRunCount: 0,
  unknownSourceCount: 0,
  connectedNoAssetCount: 0,
  rawArtifactCount: 0,
  rawArtifactsIncluded: 0,
  rawArtifactsOmitted: 0,
  sensitiveRawArtifactsOmitted: 0,
  sensitiveDataWarning: "",
  coverageManifestIncluded: true,
  ...overrides,
});

const renderExport = (answer: ExportPreview | undefined) => {
  const onPreview = vi.fn(() => Promise.resolve(answer));
  const onExport = vi.fn(() => Promise.resolve());
  const { container } = render(
    <I18nProvider>
      <ExportPage
        workspace={workspace}
        selectedRunId={CHOSEN}
        exports={[]}
        demoMode={false}
        onPreview={onPreview}
        onExport={onExport}
        onVerify={() => Promise.resolve()}
        onVerifyReceived={() => Promise.resolve()}
      />
    </I18nProvider>,
  );
  return { container, onPreview, onExport };
};

/** The single primary action on the page: the button that writes the file. */
const saveButton = (container: HTMLElement): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll<HTMLButtonElement>("button.button--primary"));
  if (buttons.length !== 1) throw new Error(`expected one primary action, found ${buttons.length}`);
  return buttons[0];
};

/** One card in the coverage disclosure grid, located by its visible label. */
const disclosureFor = (container: HTMLElement, label: string): HTMLElement => {
  const card = Array.from(container.querySelectorAll<HTMLElement>("article.export-disclosure")).find(
    (candidate) => candidate.querySelector("span")?.textContent === label,
  );
  if (!card) throw new Error(`no disclosure card rendered for ${label}`);
  return card;
};

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("the export writes the run the user chose, not the newest one", async () => {
  const { container, onPreview, onExport } = renderExport(preview());

  await waitFor(() => expect(saveButton(container).disabled).toBe(false));

  // The preview was asked about the selected run, and the page reports back the
  // identity of the run the numbers on screen actually came from.
  expect(onPreview).toHaveBeenCalledWith(expect.objectContaining({ runId: CHOSEN }));
  const facts = container.querySelector<HTMLElement>(".export-facts");
  expect(facts).not.toBeNull();
  expect(within(facts!).getByText(CHOSEN)).toBeTruthy();

  fireEvent.click(saveButton(container));
  expect(onExport).toHaveBeenCalledTimes(1);
  expect(onExport).toHaveBeenCalledWith(expect.objectContaining({ runId: CHOSEN }));
});

test("a preview describing another run is never presented as this run's numbers", async () => {
  // The backend answered about the newest run while the user is looking at an
  // older one. Showing those counts would attribute one scan's results to
  // another; the file itself would be built from the selection, so the summary
  // the user approved and the file they shared would disagree.
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  const { container, onExport } = renderExport(preview({ runId: NEWEST }));

  await waitFor(() => expect(container.textContent).toContain("export_preview_coordinate_mismatch"));

  const facts = container.querySelector<HTMLElement>(".export-facts");
  expect(within(facts!).queryByText(NEWEST)).toBeNull();
  expect(within(facts!).queryByText("7")).toBeNull();

  // No count survives, and none of them degrade to a reassuring zero.
  expect(container.textContent).toContain("Exact count unavailable; do not treat this as zero.");

  expect(saveButton(container).disabled).toBe(true);
  fireEvent.click(saveButton(container));
  expect(onExport).not.toHaveBeenCalled();
  consoleError.mockRestore();
});

test("a preview computed without redaction cannot stand in for a redacted export", async () => {
  // Redaction is on by default outside demo mode. A preview measured with
  // redaction off would understate what the file withholds — most visibly
  // "sensitive values omitted" — so it is rejected on the same coordinate check.
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  const { container, onPreview } = renderExport(preview({ redactionProfile: "none" }));

  await waitFor(() => expect(container.textContent).toContain("export_preview_coordinate_mismatch"));
  expect(onPreview).toHaveBeenCalledWith(expect.objectContaining({ redactSensitiveValues: true }));
  expect(saveButton(container).disabled).toBe(true);
  consoleError.mockRestore();
});

test("scanner work that did not finish or never ran is disclosed before saving", async () => {
  const { container } = renderExport(
    preview({ incompleteEngineRunCount: 2, notExecutedEngineRunCount: 1 }),
  );

  await waitFor(() => expect(saveButton(container).disabled).toBe(false));

  const incomplete = disclosureFor(container, "Scanner work not fully completed");
  expect(incomplete.querySelector("strong")?.textContent).toBe("2");
  expect(incomplete.className).toContain("export-disclosure--warning");

  const notRun = disclosureFor(container, "Scanner jobs not run");
  expect(notRun.querySelector("strong")?.textContent).toBe("1");
  expect(notRun.textContent).toContain("never rewritten as passed");
});

test("a clean run is allowed to read as clean", async () => {
  // The disclosure has to be able to say zero, or a reader learns to ignore it.
  const { container } = renderExport(preview());

  await waitFor(() => expect(saveButton(container).disabled).toBe(false));

  const incomplete = disclosureFor(container, "Scanner work not fully completed");
  expect(incomplete.querySelector("strong")?.textContent).toBe("0");
  expect(incomplete.className).not.toContain("export-disclosure--warning");
});
