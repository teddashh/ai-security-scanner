import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
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

test("a sample project announces that nothing is being tested", () => {
  const { container } = renderShell({ selectedCase: assessmentCase({ isDemo: true }) });

  const demo = container.querySelector(".demo-banner");
  expect(demo).not.toBeNull();
  expect(demo!.textContent).toContain("Sample scan — nothing is being tested");
});

test("demo mode announces itself even when the open project is not itself a sample", () => {
  // The two conditions are independent: the app can be running against sample
  // data wholesale, or have one sample project open. Losing either check hides
  // the marker in a case where the findings on screen are still not real.
  const { container } = renderShell({ mode: "demo", selectedCase: assessmentCase({ isDemo: false }) });

  const demo = container.querySelector(".demo-banner");
  expect(demo).not.toBeNull();
  expect(demo!.textContent).toContain("Explore with sample results");
  expect(demo!.textContent).toContain("without scanning a real target");
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

test("language choices keep each language's own name in either interface language", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const chineseShell = renderShell();
  const englishButton = chineseShell.container.querySelector<HTMLButtonElement>('button[lang="en"]');
  expect(englishButton?.textContent).toBe("English");
  chineseShell.unmount();

  window.localStorage.setItem(localeStorageKey, "en");
  const englishShell = renderShell();
  const chineseButton = englishShell.container.querySelector<HTMLButtonElement>('button[lang="zh-Hant"]');
  expect(chineseButton?.textContent).toBe("繁體中文");
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
