import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { CasesPage } from "../../src/pages/CasesPage";
import type { CasesPageProps } from "../../src/pages/CasesPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { AssessmentCase, ScanRun } from "../../src/types";

// Two things on this page can mislead badly and neither is visible to source
// matching, because both are conditions rather than strings.
//
// The first is what a zero means. "We looked and found nothing" and "we never
// resolved what to look at" produce the same number, and the page has separate
// notices for them; picking the reassuring one when a source is unresolved
// turns an unfinished inventory into a clean bill of health.
//
// The second is the evidence-deletion panel. It reports on an irreversible
// local action, and its three outcomes -- removed, retained, already absent --
// are worded so a user knows which one happened. Reporting removal that did not
// occur leaves someone believing evidence is gone when it is on disk.

const assessmentCase = (overrides: Partial<AssessmentCase> = {}): AssessmentCase => ({
  id: "case-1",
  name: "Acme scan",
  aiGeneratedArtifact: "no",
  organizationName: "Acme",
  companySize: "small",
  dataClasses: [],
  requestedActivities: [],
  platforms: [],
  createdAt: "2026-09-01T10:00:00Z",
  updatedAt: "2026-09-02T10:00:00Z",
  phase: "discovering",
  ...overrides,
});

const run = (overrides: Partial<ScanRun> = {}): ScanRun => ({
  id: "run-1",
  caseId: "case-1",
  label: "Scan 1",
  status: "completed",
  progress: 100,
  startedAt: "2026-09-02T09:00:00Z",
  finishedAt: "2026-09-02T09:30:00Z",
  knowledgeDate: "2026-09-02",
  engineRuns: [],
  coveredAssetCount: 0,
  totalAssetCount: 0,
  ...overrides,
});

const selected = assessmentCase();

const renderCases = (overrides: Partial<CasesPageProps> = {}) =>
  render(
    <I18nProvider>
      <CasesPage
        cases={[selected]}
        selectedCase={selected}
        assetCount={0}
        findingCount={0}
        unknownSourceCount={0}
        connectedNoAssetSourceCount={0}
        runs={[]}
        onCreate={() => Promise.resolve(true)}
        onArchive={() => Promise.resolve()}
        onDelete={() => Promise.resolve(true)}
        onDeleteArtifacts={() => Promise.resolve(true)}
        onDismissArtifactCleanup={() => {}}
        onStartNewScan={() => {}}
        onSelect={() => {}}
        onContinue={() => {}}
        onOpenProgress={() => {}}
        onSelectVerificationBaseline={() => {}}
        onStartRescan={() => Promise.resolve()}
        onOpenVerification={() => {}}
        {...overrides}
      />
    </I18nProvider>,
  );

const notices = (container: HTMLElement): string[] =>
  Array.from(container.querySelectorAll<HTMLElement>(".inline-notice")).map(
    (notice) => notice.textContent ?? "",
  );

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("zero systems with an unresolved source is not reported as having found nothing", () => {
  // Both counts are present here. The connected source really did return
  // nothing, so the reassuring notice is not false on its own terms -- but an
  // unresolved source means the inventory is unfinished, and showing "No systems
  // were found this time" as the account of a zero would let a user read an
  // incomplete search as a completed one.
  const { container } = renderCases({
    assetCount: 0,
    unknownSourceCount: 2,
    connectedNoAssetSourceCount: 1,
  });

  const rendered = notices(container);
  expect(rendered.some((notice) => notice.includes("Add a source to start finding your systems"))).toBe(true);
  expect(rendered.some((notice) => notice.includes("does not mean the organization has no assets"))).toBe(true);
  expect(rendered.some((notice) => notice.includes("No systems were found this time"))).toBe(false);
});

test("zero systems from a connected source states the narrow scope of that zero", () => {
  const { container } = renderCases({
    assetCount: 0,
    unknownSourceCount: 0,
    connectedNoAssetSourceCount: 1,
  });

  const rendered = notices(container);
  expect(rendered.some((notice) => notice.includes("No systems were found this time"))).toBe(true);
  // A zero is a statement about one snapshot at one time, not about the estate.
  expect(rendered.some((notice) => notice.includes("applies only to the saved source snapshot"))).toBe(true);
  expect(rendered.some((notice) => notice.includes("Add a source to start finding your systems"))).toBe(false);
});

test("systems that were found do not carry a zero-result notice", () => {
  // The mirror of the two tests above: without this, always rendering a zero
  // notice would satisfy one of them while telling every user their scan found
  // nothing.
  //
  // Each case leaves `assetCount` as the only clause suppressing its notice. A
  // single case carrying both other counts cannot do that -- whichever clause
  // was removed, the other still hides the notice and the mutation survives.
  const connected = renderCases({
    assetCount: 12,
    unknownSourceCount: 0,
    connectedNoAssetSourceCount: 1,
  });
  expect(notices(connected.container).some((notice) => notice.includes("No systems were found this time"))).toBe(false);

  const unresolved = renderCases({
    assetCount: 12,
    unknownSourceCount: 2,
    connectedNoAssetSourceCount: 0,
  });
  expect(notices(unresolved.container).some((notice) => notice.includes("Add a source to start finding your systems"))).toBe(false);
});

test("an unknown-source count is never presented as a pass", () => {
  const { container } = renderCases({ assetCount: 3, unknownSourceCount: 4 });

  const card = Array.from(container.querySelectorAll<HTMLElement>(".metric-card")).find(
    (candidate) => candidate.querySelector(".metric-card__label")?.textContent === "Unknown data sources",
  );
  expect(card).toBeTruthy();
  expect(card!.querySelector(".metric-card__value")?.textContent).toBe("4");
  expect(card!.querySelector(".metric-card__detail")?.textContent).toContain(
    "Unknown never means no assets or passed",
  );
});

test("evidence still on disk is not described as removed, and says so with the exact path", () => {
  const { container } = renderCases({
    artifactCleanupPlan: {
      caseId: "case-1",
      exactPath: "/home/user/.local/share/scanner/cases/case-1",
      exists: true,
      requiresExplicitConfirmation: true,
    },
  });

  const panel = container.querySelector(".artifact-cleanup-panel")!;
  expect(panel.querySelector("h2")?.textContent).toBe(
    "The case record was deleted; evidence is still retained",
  );
  expect(panel.textContent).toContain("Keeping evidence does not undo deletion of the case record");
  expect(panel.textContent).not.toContain("was permanently removed");
  // The claim is about one folder, so the folder is named rather than implied.
  expect(panel.querySelector("code")?.textContent).toBe(
    "/home/user/.local/share/scanner/cases/case-1",
  );
});

test("permanent deletion stays disabled until the exact phrase is typed", () => {
  // This is the confirmation guarding an irreversible local deletion. A prefix
  // or case-insensitive match would let a half-typed phrase arm the button.
  const { container } = renderCases({
    artifactCleanupPlan: {
      caseId: "case-1",
      exactPath: "/home/user/.local/share/scanner/cases/case-1",
      exists: true,
      requiresExplicitConfirmation: true,
    },
  });

  const input = container.querySelector<HTMLInputElement>(".artifact-cleanup-panel input")!;
  const deleteButton = container.querySelector<HTMLButtonElement>(".button--danger")!;
  expect(deleteButton.disabled).toBe(true);

  for (const attempt of ["DELETE", "DELETE case", "delete case-1", "DELETE case-1 ", " DELETE case-1"]) {
    fireEvent.change(input, { target: { value: attempt } });
    expect(deleteButton.disabled, `"${attempt}" must not arm deletion`).toBe(true);
  }

  fireEvent.change(input, { target: { value: "DELETE case-1" } });
  expect(deleteButton.disabled).toBe(false);
});

test("a folder that was never there says no deletion command was sent", () => {
  // Reporting this as a removal would credit the app with an action it did not
  // take, and would tell a user their evidence was destroyed when it may simply
  // have been somewhere else.
  const { container } = renderCases({
    artifactCleanupPlan: {
      caseId: "case-1",
      exactPath: "/home/user/.local/share/scanner/cases/case-1",
      exists: false,
      requiresExplicitConfirmation: false,
    },
  });

  const panel = container.querySelector(".artifact-cleanup-panel")!;
  expect(panel.querySelector("h2")?.textContent).toBe("The case evidence folder is already absent");
  expect(panel.textContent).toContain("no evidence-deletion command is needed or sent");
  expect(panel.textContent).not.toContain("was permanently removed");
  // Nothing exists to delete, so no deletion control is offered.
  expect(container.querySelector(".button--danger")).toBeNull();
});

test("a completed removal is stated as irreversible rather than as a tidy-up", () => {
  const { container } = renderCases({
    artifactCleanupPlan: {
      caseId: "case-1",
      exactPath: "/home/user/.local/share/scanner/cases/case-1",
      exists: true,
      requiresExplicitConfirmation: true,
    },
    artifactCleanupResult: {
      removed: true,
      exactPath: "/home/user/.local/share/scanner/cases/case-1",
      recoverable: false,
    },
  });

  const panel = container.querySelector(".artifact-cleanup-panel")!;
  expect(panel.querySelector("h2")?.textContent).toBe("Case evidence was permanently removed");
  expect(panel.textContent).toContain("This cannot be undone");
  // The confirmation form is gone once the deletion has happened.
  expect(container.querySelector(".button--danger")).toBeNull();
});

test("work interrupted by a restart is counted and does not claim it will resume itself", () => {
  const latestRun = run({
    id: "run-interrupted",
    status: "partial",
    engineRuns: [
      // Either signal counts as interrupted, so both are present here: a page
      // that recognised only one would still report a plausible number.
      {
        id: "engine-run-1",
        engineId: "prowler",
        engineName: "prowler",
        category: "cloud",
        taskKind: "engine_container",
        warnings: [],
        status: "running",
        progress: 40,
        phase: "interrupted_restart",
        assetIds: ["asset-1"],
        rawArtifactCount: 0,
        findingCount: 0,
        resumable: true,
        checkpoint: { attempt: 1, stage: "running", artifactCount: 0, cleanupCompleted: false, scopeBound: true },
      },
      {
        id: "engine-run-2",
        engineId: "trivy",
        engineName: "trivy",
        category: "container",
        taskKind: "engine_container",
        warnings: [],
        status: "failed",
        progress: 20,
        phase: "failed",
        errorCode: "desktop_process_restarted",
        assetIds: ["asset-2"],
        rawArtifactCount: 0,
        findingCount: 0,
        resumable: true,
      },
    ],
  });

  const { container } = renderCases({ latestRun, runs: [latestRun] });

  const rendered = notices(container);
  const interrupted = rendered.find((notice) => notice.includes("Checks paused when the app restarted"));
  expect(interrupted).toBeTruthy();
  expect(interrupted).toContain("Checks paused when the app restarted: 2");
  expect(interrupted).toContain("will not reconnect automatically");
});

test("a run that failed is offered as a baseline without being called completed", () => {
  // `terminalRuns` deliberately admits failed and cancelled runs: comparing
  // against one is legitimate, and the backend records the resulting comparison
  // as incomplete. What is not legitimate is the label. The picker used to be
  // headed "Completed baseline run", so a user choosing the only run they had
  // was told it completed while its own option said Failed. The Traditional
  // Chinese label has always said 已結束 -- finished, not succeeded.
  const failedRun = run({ id: "run-failed", status: "failed", progress: 30 });
  const { container } = renderCases({ runs: [failedRun], latestRun: failedRun });

  const picker = Array.from(container.querySelectorAll<HTMLLabelElement>("label.field")).find(
    (label) => label.querySelector("select") && label.textContent?.includes("baseline"),
  );
  expect(picker).toBeTruthy();
  expect(picker!.querySelector("span")?.textContent).toBe("Finished baseline run");
  expect(picker!.textContent).not.toContain("Completed baseline run");
  expect(picker!.querySelector("small")?.textContent).toBe("Choose a finished run.");

  // The run's real state is still shown, so the offer is not silent about it.
  const option = picker!.querySelector("option");
  expect(option?.textContent).toContain("Failed");
});

test("a page with no case selected reports no counts at all", () => {
  // `assetCount` and `findingCount` default to 0 when no workspace is loaded.
  // Rendering "Problems found: 0" then states a result for a scan that has not
  // happened, which on first launch is the most reassuring possible lie.
  const withoutCase = renderCases({ selectedCase: undefined, cases: [] });
  const labels = (root: HTMLElement) =>
    Array.from(root.querySelectorAll<HTMLElement>(".metric-card__label")).map((node) => node.textContent);

  expect(labels(withoutCase.container)).not.toContain("Problems found");
  expect(labels(withoutCase.container)).not.toContain("Systems found");

  // With a case, the same counts are shown -- so this is a gate, not a removal.
  const withCase = renderCases({ assetCount: 0, findingCount: 0 });
  expect(labels(withCase.container)).toContain("Problems found");
  expect(labels(withCase.container)).toContain("Systems found");
});

test("the optional organization field does not promise an edit the app cannot make", () => {
  // There is no case-update path: `commands.rs` exposes create, select,
  // archive and delete only, and `CasesPageProps` has no update callback. The
  // placeholder used to read "You can add this later", which is an offer the
  // product cannot honour -- the value can only be set at creation.
  // The create button only opens the form once a use case has been chosen;
  // without one it routes back to the start page instead.
  const { container } = renderCases({
    selectedCase: undefined,
    cases: [],
    selectedUseCase: "deployed_website",
    selectionKey: 1,
  });

  const openForm = Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
    (button) => button.textContent?.includes("Start a new scan"),
  );
  expect(openForm).toBeTruthy();
  fireEvent.click(openForm!);
  expect(container.querySelector(".create-case-panel")).not.toBeNull();

  const organization = Array.from(container.querySelectorAll<HTMLInputElement>("input")).find(
    (input) => input.placeholder.length > 0
      && input.placeholder !== "Example: 2026 first security check",
  );
  expect(organization).toBeTruthy();
  expect(organization!.placeholder).not.toContain("later");
  expect(organization!.placeholder).toBe("Optional, and fixed once the project is created");
});
