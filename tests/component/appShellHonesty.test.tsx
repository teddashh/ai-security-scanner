import { act, cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { AppShell } from "../../src/components/AppShell";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { AssessmentCase } from "../../src/types";

// The shell wraps every page, so its banners are the app's answer to "is what
// I am looking at real, current, and mine". Three of those answers matter:
//
// - Sample data must announce itself. The export path is stamped
//   DEMO_ONLY_NOT_A_SCAN; this is the on-screen counterpart, and without it a
//   demo case's findings read exactly like an assessment.
// - A view the app could not refresh must say it is stale. The failure mode is
//   not an error message, it is silence: the last snapshot keeps rendering and
//   looks current.
// - Recovery must report per project. Summarising "some projects needed
//   recovery" without saying which kept their data is where a user stops being
//   able to tell whether anything was lost.

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

const shellElement = (overrides: Partial<Parameters<typeof AppShell>[0]> = {}) => (
  <I18nProvider>
    <AppShell
      page="cases"
      mode="native"
      cases={[assessmentCase()]}
      selectedCase={assessmentCase()}
      onRetryData={() => {}}
      onRetryCaseSelection={() => {}}
      onNavigate={() => {}}
      onSelectCase={() => {}}
      appUpdate={{ phase: "idle" }}
      onCheckForUpdate={() => {}}
      onInstallUpdate={() => {}}
      onSetupRuntime={() => {}}
      onCancelRuntime={() => {}}
      {...overrides}
    >
      <p>page content</p>
    </AppShell>
  </I18nProvider>
);

const renderShell = (overrides: Partial<Parameters<typeof AppShell>[0]> = {}) =>
  render(shellElement(overrides));

const banners = (container: HTMLElement): string[] =>
  Array.from(container.querySelectorAll<HTMLElement>(".data-status-banner, .demo-banner")).map(
    (banner) => banner.textContent ?? "",
  );

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
  // jsdom implements no media queries. The shell subscribes to one to decide
  // its navigation layout; this stub only lets it mount and is unrelated to
  // every assertion below.
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.localStorage.clear();
  document.body.removeAttribute("style");
  document.documentElement.removeAttribute("style");
  Object.defineProperty(window, "scrollX", { configurable: true, value: 0 });
  Object.defineProperty(window, "scrollY", { configurable: true, value: 0 });
});

test("a preview project announces that no target is contacted", () => {
  const { container } = renderShell({ selectedCase: assessmentCase({ isDemo: true }) });

  const demo = container.querySelector(".demo-banner");
  expect(demo).not.toBeNull();
  expect(demo!.textContent).toContain("Preview only");
  expect(demo!.textContent).toContain("No target is contacted.");
});

test("preview mode announces itself even when the open project is not itself a sample", () => {
  // The two conditions are independent: the app can be running against sample
  // data wholesale, or have one sample project open. Losing either check hides
  // the marker in a case where the findings on screen are still not real.
  const { container } = renderShell({ mode: "demo", selectedCase: assessmentCase({ isDemo: false }) });

  const demo = container.querySelector(".demo-banner");
  expect(demo).not.toBeNull();
  expect(demo!.textContent).toContain("Preview only");
  expect(demo!.textContent).toContain("No target is contacted.");
});

test("a real project in native mode carries no sample marker", () => {
  // The mirror: a banner shown unconditionally would satisfy both tests above
  // while telling every user their real results are samples.
  const { container } = renderShell();

  expect(container.querySelector(".demo-banner")).toBeNull();
});

test("a view the app could not refresh says so instead of looking current", () => {
  // Silence is the dangerous outcome here. The previous snapshot keeps
  // rendering and nothing distinguishes it from fresh data.
  const { container } = renderShell({ dataUnavailable: true });

  const alert = Array.from(container.querySelectorAll<HTMLElement>(".data-status-banner")).find(
    (banner) => banner.getAttribute("role") === "alert",
  );
  expect(alert).toBeTruthy();
  expect(alert!.textContent).toContain("Saved scans couldn't be refreshed");
  expect(alert!.textContent).toContain("last saved information on this device");
  expect(alert!.textContent).toContain("Nothing was replaced or changed");
});

test("a project that failed to open says the current one is untouched", () => {
  const { container } = renderShell({ caseSelectionUnavailable: true });

  const text = banners(container).join(" ");
  expect(text).toContain("That scan project couldn't be opened");
  expect(text).toContain("still open and unchanged");
});

test("recovery reports each project's outcome rather than one reassuring summary", () => {
  // `preserved` is the whole answer to "did I lose anything". Rendering the
  // headline without the per-project line, or the same line for both, leaves a
  // user unable to tell a preserved project from one whose saved selection is
  // gone.
  const { container } = renderShell({
    caseRecoveryDiagnostics: [
      { caseId: "case-1", title: "Acme scan", code: "document_unreadable", preserved: true, documentBytes: 2048 },
      { caseId: "case-2", title: "Second scan", code: "selection_missing", preserved: false, documentBytes: 0 },
    ],
  });

  const banner = Array.from(container.querySelectorAll<HTMLElement>(".data-status-banner")).find(
    (candidate) => candidate.textContent?.includes("need recovery"),
  );
  expect(banner).toBeTruthy();
  expect(banner!.textContent).toContain("left their original local data unchanged");
  expect(banner!.textContent).toContain("no sample data was substituted");

  const entries = Array.from(banner!.querySelectorAll("li")).map((item) => item.textContent ?? "");
  expect(entries.length).toBe(2);
  expect(entries[0]).toContain("Acme scan");
  expect(entries[0]).toContain("Original project data preserved");
  expect(entries[0]).toContain("document_unreadable");
  expect(entries[1]).toContain("Second scan");
  expect(entries[1]).toContain("Saved selection is no longer present");
  // The two outcomes must not read the same.
  expect(entries[1]).not.toContain("Original project data preserved");
});

test("recovery uses a localized unknown title but preserves a real project title", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderShell({
    caseRecoveryDiagnostics: [
      {
        caseId: "missing-case",
        title: "Saved project",
        code: "selected_case_missing",
        preserved: false,
        documentBytes: 0,
      },
      {
        caseId: "unreadable-case",
        title: "Project Name Typed By Its Owner",
        code: "stored_case_unreadable",
        preserved: true,
        documentBytes: 2048,
      },
    ],
  });

  const entries = Array.from(container.querySelectorAll(".data-status-banner li"))
    .map((item) => item.textContent ?? "");
  expect(entries[0]).toContain("名稱不明的已保存專案");
  expect(entries[0]).not.toContain("Saved project");
  expect(entries[1]).toContain("Project Name Typed By Its Owner");
});

test("a shell with nothing wrong raises no banner at all", () => {
  const { container } = renderShell({ caseRecoveryDiagnostics: [] });

  expect(banners(container)).toEqual([]);
});

test("the shell keeps repeated navigation and privacy copy concise", () => {
  const { container, queryByRole } = renderShell();

  expect(container.querySelector(".language-switcher")).toBeNull();
  expect(container.querySelector(".brand__copy small")).toBeNull();
  expect(container.querySelectorAll(".nav-item small")).toHaveLength(0);
  expect(container.querySelector(".privacy-note strong")?.textContent).toBe("Local by default");
  expect(container.querySelector(".privacy-note small")?.textContent).toBe(
    "Data may leave this device when you connect a source or export results.",
  );
  expect(queryByRole("button", { name: "English" })).toBeNull();
  expect(queryByRole("button", { name: "繁體中文" })).toBeNull();
});

test("active runtime setup keeps exact stage and progress visible while mechanics stay collapsed", () => {
  const { container, getByRole } = renderShell({
    runtime: {
      provider: "managed_local",
      available: false,
      phase: "preparing",
      detail: "test-only runtime detail",
    },
    runtimeSetup: {
      phase: "download",
      active: true,
      prerequisiteRepairActive: false,
      cancelRequested: false,
      receivedBytes: 40,
      totalBytes: 100,
      progressPercent: 40,
      resumedFromBytes: 10,
      canCancel: true,
      canRetry: false,
      detail: "test-only setup detail",
    },
  });

  expect(container.querySelector(".runtime-badge")?.textContent).toContain("Setting up local tools");
  const visibleProgress = container.querySelector<HTMLElement>(".runtime-setup > .runtime-setup__progress--visible");
  expect(visibleProgress).not.toBeNull();
  expect(visibleProgress?.closest("details")).toBeNull();
  expect(visibleProgress?.textContent).toContain("Downloading advanced local scan tools");
  expect(visibleProgress?.textContent).toContain("40 bytes / 100 bytes · 40%");
  const progress = visibleProgress?.querySelector("progress");
  expect(progress?.getAttribute("aria-label")).toBe("Scan tool download progress");
  expect(progress?.getAttribute("value")).toBe("40");
  expect(progress?.getAttribute("max")).toBe("100");

  const details = container.querySelector<HTMLDetailsElement>(".runtime-setup__details");
  expect(details).not.toBeNull();
  expect(details!.open).toBe(false);
  expect(details!.textContent).toContain("download can be cancelled and resumed without starting over");
  expect(details!.textContent).toContain("Continuing from 10 bytes already downloaded");
  expect(details!.textContent).not.toContain("40 bytes / 100 bytes");
  expect(container.querySelectorAll(".runtime-setup > .button")).toHaveLength(1);
  expect(getByRole("button", { name: "Pause setup and keep download progress" })).toBeTruthy();
});

test("one recovery banner composes every concurrent truth and relevant retry action", () => {
  const onRetryData = vi.fn();
  const onRetryCaseSelection = vi.fn();
  const { container } = renderShell({
    dataUnavailable: true,
    caseSelectionUnavailable: true,
    onRetryData,
    onRetryCaseSelection,
    caseRecoveryDiagnostics: [
      { caseId: "case-1", title: "Acme scan", code: "document_unreadable", preserved: true, documentBytes: 2048 },
    ],
  });

  expect(container.querySelectorAll(".data-status-banner")).toHaveLength(1);
  const banner = container.querySelector<HTMLElement>(".data-status-banner")!;
  expect(banner.getAttribute("role")).toBe("alert");
  expect(banner.textContent).toContain("need recovery");
  expect(banner.textContent).toContain("Saved scans couldn't be refreshed");
  expect(banner.textContent).toContain("That scan project couldn't be opened");
  expect(banner.querySelectorAll(".data-status-banner__fact")).toHaveLength(3);
  expect(banner.querySelectorAll(".data-status-banner__actions .button")).toHaveLength(2);

  fireEvent.click(within(banner).getByRole("button", { name: "Refresh saved scans" }));
  fireEvent.click(within(banner).getByRole("button", { name: "Open selected scan again" }));
  expect(onRetryData).toHaveBeenCalledOnce();
  expect(onRetryCaseSelection).toHaveBeenCalledOnce();
});

test("the mobile navigation modal locks page scroll and restores prior inline state on cleanup", async () => {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: true,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
  Object.defineProperty(window, "scrollX", { configurable: true, value: 7 });
  Object.defineProperty(window, "scrollY", { configurable: true, value: 412 });
  document.documentElement.style.overflow = "auto";
  document.body.style.overflow = "clip";
  document.body.style.position = "relative";
  document.body.style.top = "3px";
  document.body.style.left = "4px";
  document.body.style.width = "95%";
  const scrollTo = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  const view = renderShell();

  fireEvent.click(view.getByRole("button", { name: "Open navigation" }));

  await waitFor(() => expect(view.getByRole("dialog", { name: "Primary navigation" })).toBeTruthy());
  expect(document.documentElement.style.overflow).toBe("hidden");
  expect(document.body.style.overflow).toBe("hidden");
  expect(document.body.style.position).toBe("fixed");
  expect(document.body.style.top).toBe("-412px");
  expect(document.body.style.left).toBe("-7px");
  expect(document.body.style.width).toBe("100%");

  view.unmount();

  expect(document.documentElement.style.overflow).toBe("auto");
  expect(document.body.style.overflow).toBe("clip");
  expect(document.body.style.position).toBe("relative");
  expect(document.body.style.top).toBe("3px");
  expect(document.body.style.left).toBe("4px");
  expect(document.body.style.width).toBe("95%");
  expect(scrollTo).toHaveBeenCalledWith(7, 412);
});

test("changing an open mobile drawer to desktop closes it and releases the scroll lock", async () => {
  let viewportListener: ((event: MediaQueryListEvent) => void) | undefined;
  const viewport = {
    matches: true,
    media: "(max-width: 820px)",
    onchange: null,
    addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
      viewportListener = listener;
    },
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  };
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: () => viewport,
  });
  Object.defineProperty(window, "scrollY", { configurable: true, value: 275 });
  const scrollTo = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  const view = renderShell();
  fireEvent.click(view.getByRole("button", { name: "Open navigation" }));
  await waitFor(() => expect(document.body.style.position).toBe("fixed"));

  await act(async () => {
    viewport.matches = false;
    viewportListener?.({ matches: false } as MediaQueryListEvent);
  });

  await waitFor(() => expect(view.queryByRole("dialog", { name: "Primary navigation" })).toBeNull());
  expect(document.documentElement.style.overflow).toBe("");
  expect(document.body.style.overflow).toBe("");
  expect(document.body.style.position).toBe("");
  expect(scrollTo).toHaveBeenCalledWith(0, 275);
});

test("a page transition behind the drawer keeps the new page at the top instead of restoring stale scroll", async () => {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: true,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
  Object.defineProperty(window, "scrollY", { configurable: true, value: 525 });
  const scrollTo = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  const view = renderShell();
  fireEvent.click(view.getByRole("button", { name: "Open navigation" }));
  await waitFor(() => expect(document.body.style.position).toBe("fixed"));

  view.rerender(shellElement({ page: "findings" }));

  await waitFor(() => expect(view.queryByRole("dialog", { name: "Primary navigation" })).toBeNull());
  expect(document.body.style.position).toBe("");
  expect(scrollTo).not.toHaveBeenCalledWith(0, 525);
  expect(scrollTo).toHaveBeenLastCalledWith({ top: 0, left: 0, behavior: "auto" });
});
