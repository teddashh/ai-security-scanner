import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { useState } from "react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { CasesPage } from "../../src/pages/CasesPage";
import type { CasesPageProps } from "../../src/pages/CasesPage";
import { createStoredDemoCase } from "../../src/data/demo";
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
        nativeMode
        onCreate={() => Promise.resolve(true)}
        onSeedDemo={() => Promise.resolve()}
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

test("native deletion keeps its database-record and separate-evidence warning", () => {
  const { container, getByRole } = renderCases();
  const trigger = getByRole("button", { name: "Begin deleting Acme scan" });

  expect(trigger.getAttribute("title")).toBe("Delete case database record");
  fireEvent.click(trigger);

  const confirmation = container.querySelector<HTMLElement>(".case-delete-confirmation");
  expect(confirmation).toBeTruthy();
  expect(confirmation!.querySelector("h3")?.textContent).toBe("Confirm deletion of the case record");
  expect(confirmation!.textContent).toContain("does not automatically delete the evidence folder");
  expect(getByRole("button", { name: "Delete case record only" })).toBeTruthy();
});

test.each([
  {
    locale: "en",
    triggerName: "Begin removing Browser-only project from this browser",
    tooltip: "Remove browser-saved preview project",
    eyebrow: "Browser preview only",
    title: "Remove this preview project from this browser?",
    help: "This removes only the preview project saved in this browser. It does not change projects in the installed desktop app.",
    action: "Remove browser preview",
    forbidden: /database|evidence|folder|path/iu,
  },
  {
    locale: "zh-TW",
    triggerName: "開始從這個瀏覽器移除 Browser-only project",
    tooltip: "移除瀏覽器儲存的預覽專案",
    eyebrow: "僅限瀏覽器預覽",
    title: "要從這個瀏覽器移除這個預覽專案嗎？",
    help: "這只會移除儲存在這個瀏覽器中的預覽專案，不會變更已安裝桌面應用程式中的專案。",
    action: "移除瀏覽器預覽",
    forbidden: /資料庫|證據|目錄|路徑/u,
  },
] as const)("a stored browser preview gets truthful localized removal copy in $locale", ({
  locale,
  triggerName,
  tooltip,
  eyebrow,
  title,
  help,
  action,
  forbidden,
}) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const preview = createStoredDemoCase({
    name: "Browser-only project",
    aiGeneratedArtifact: "no",
    organizationName: "",
    companySize: "small",
    dataClasses: ["none"],
    requestedActivities: ["configuration_assessment"],
    platforms: ["external"],
  });
  const { container, getByRole } = renderCases({
    cases: [preview],
    selectedCase: preview,
    nativeMode: false,
  });
  const trigger = getByRole("button", { name: triggerName });

  expect(trigger.getAttribute("title")).toBe(tooltip);
  fireEvent.click(trigger);

  const confirmation = container.querySelector<HTMLElement>(".case-delete-confirmation");
  expect(confirmation).toBeTruthy();
  expect(confirmation!.querySelector(".eyebrow")?.textContent).toBe(eyebrow);
  expect(confirmation!.querySelector("h3")?.textContent).toBe(title);
  expect(confirmation!.textContent).toContain(help);
  expect(confirmation!.textContent).not.toMatch(forbidden);
  expect(getByRole("button", { name: action })).toBeTruthy();
});

test("the browser preview does not offer deletion for immutable built-in demo projects", () => {
  const builtIn = assessmentCase({
    id: "case-demo-northstar",
    name: "Built-in example",
    isDemo: true,
  });
  const { container, queryByRole } = renderCases({
    cases: [builtIn],
    selectedCase: builtIn,
    nativeMode: false,
  });

  expect(queryByRole("button", { name: "Begin removing Built-in example from this browser" })).toBeNull();
  expect(container.querySelector(".case-row__actions .icon-button--danger")).toBeNull();
  expect(container.querySelector(".case-delete-confirmation")).toBeNull();
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

test("an invalid public target stays in the form with field-specific accessible feedback", async () => {
  const onCreate = vi.fn(() => Promise.resolve(true));
  const { container, getByLabelText } = renderCases({
    selectedCase: undefined,
    cases: [],
    selectedUseCase: "external_ip_or_domain",
    selectionKey: 1,
    onCreate,
  });

  const nameInput = getByLabelText("Scan project name");
  const targetsInput = getByLabelText(/Public domains, IP addresses, or small network ranges/u);
  fireEvent.change(nameInput, { target: { value: "External perimeter" } });
  fireEvent.change(targetsInput, {
    target: { value: "127.0.0.1\nhttps://example.com/path\nnot a host" },
  });
  fireEvent.submit(container.querySelector(".create-case-panel")!);

  const error = await waitFor(() => {
    const alert = container.querySelector<HTMLElement>("#public-targets-error");
    expect(alert).toBeTruthy();
    return alert!;
  });
  expect(onCreate).not.toHaveBeenCalled();
  expect(error.getAttribute("role")).toBe("alert");
  expect(error.textContent).toContain("https://example.com/path includes URL or service details");
  expect(targetsInput.getAttribute("aria-invalid")).toBe("true");
  expect(targetsInput.getAttribute("aria-describedby")).toBe("public-targets-help public-targets-error");
  expect(document.activeElement).toBe(targetsInput);

  fireEvent.change(targetsInput, {
    target: { value: "scanner.example.test\n203.0.113.10\n2001:db8::10\n2001:db8::/64" },
  });
  expect(container.querySelector("#public-targets-error")).toBeNull();
  fireEvent.submit(container.querySelector(".create-case-panel")!);

  await waitFor(() => expect(onCreate).toHaveBeenCalledTimes(1));
  expect(onCreate.mock.calls[0]?.[0].knownAssets).toEqual([
    { kind: "external_target", value: "scanner.example.test", internetExposure: "public" },
    { kind: "external_target", value: "203.0.113.10", internetExposure: "public" },
    { kind: "external_target", value: "2001:db8::10", internetExposure: "public" },
    { kind: "external_target", value: "2001:db8::/64", internetExposure: "public" },
  ]);
});

test("an invalid internal CIDR is reported by the internal target field", async () => {
  const onCreate = vi.fn(() => Promise.resolve(true));
  const { container, getByLabelText } = renderCases({
    selectedCase: undefined,
    cases: [],
    selectedUseCase: "internal_it_environment",
    selectionKey: 1,
    onCreate,
  });

  const nameInput = getByLabelText("Scan project name");
  const targetsInput = getByLabelText(/Internal IP addresses or small network ranges/u);
  fireEvent.change(nameInput, { target: { value: "Internal network" } });
  fireEvent.change(targetsInput, { target: { value: "10.20.0.8\n10.20.0.0/99" } });
  fireEvent.submit(container.querySelector(".create-case-panel")!);

  const error = await waitFor(() => {
    const alert = container.querySelector<HTMLElement>("#internal-targets-error");
    expect(alert).toBeTruthy();
    return alert!;
  });
  expect(onCreate).not.toHaveBeenCalled();
  expect(error.textContent).toContain("10.20.0.0/99 is not a valid IP CIDR range");
  expect(targetsInput.getAttribute("aria-invalid")).toBe("true");
  expect(targetsInput.getAttribute("aria-describedby")).toBe("internal-targets-help internal-targets-error");
  expect(document.activeElement).toBe(targetsInput);
});

test("an invalid optional target opens its advanced section and receives focus", async () => {
  const onCreate = vi.fn(() => Promise.resolve(true));
  const { container, getByLabelText } = renderCases({
    selectedCase: undefined,
    cases: [],
    selectedUseCase: "deployed_website",
    selectionKey: 1,
    onCreate,
  });

  fireEvent.change(getByLabelText("Scan project name"), { target: { value: "Website check" } });
  fireEvent.change(getByLabelText(/Website or API URL/u), { target: { value: "https://app.example.test/" } });
  const targetsInput = getByLabelText(/Public domains, IP addresses, or small network ranges/u);
  fireEvent.change(targetsInput, { target: { value: "app.example.test:443" } });
  fireEvent.submit(container.querySelector(".create-case-panel")!);

  await waitFor(() => expect(container.querySelector(".case-more-details")?.hasAttribute("open")).toBe(true));
  expect(onCreate).not.toHaveBeenCalled();
  expect(container.querySelector("#public-targets-error")?.textContent).toContain("includes URL or service details");
  expect(document.activeElement).toBe(targetsInput);
});

test("the empty native project list offers and opens the synthetic example", async () => {
  const demo = assessmentCase({ id: "demo-case", name: "Example project", isDemo: true });
  const onSeedDemo = vi.fn(() => Promise.resolve());
  const Harness = () => {
    const [opened, setOpened] = useState(false);
    return (
      <I18nProvider>
        <CasesPage
          cases={opened ? [demo] : []}
          selectedCase={opened ? demo : undefined}
          assetCount={0}
          findingCount={0}
          unknownSourceCount={0}
          connectedNoAssetSourceCount={0}
          runs={[]}
          nativeMode
          onCreate={() => Promise.resolve(true)}
          onSeedDemo={async () => { await onSeedDemo(); setOpened(true); }}
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
        />
      </I18nProvider>
    );
  };
  const { container, getByRole } = render(<Harness />);

  const action = getByRole("button", { name: "See an example project" });
  expect(container.textContent).toContain("synthetic demonstration project");
  fireEvent.click(action);

  await waitFor(() => expect(onSeedDemo).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(container.querySelector("#current-case-title")?.textContent).toBe("Example project"));
});

test("the example action is absent once a project exists and in the browser preview", () => {
  const populated = renderCases();
  expect(populated.queryByRole("button", { name: "See an example project" })).toBeNull();
  cleanup();
  const browserEmpty = renderCases({ cases: [], selectedCase: undefined, nativeMode: false });
  expect(browserEmpty.queryByRole("button", { name: "See an example project" })).toBeNull();
});

test.each([
  ["en", "Demo"],
  ["zh-TW", "展示"],
] as const)("a selected demo project is visibly marked in %s", (locale, label) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const demo = assessmentCase({ isDemo: true });
  const { container } = renderCases({ cases: [demo], selectedCase: demo });
  const hero = container.querySelector(".current-case-hero");
  expect(hero?.querySelector(".status-pill--demo")?.textContent).toBe(label);
});
