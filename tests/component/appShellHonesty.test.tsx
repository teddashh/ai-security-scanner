import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

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

const renderShell = (overrides: Partial<Parameters<typeof AppShell>[0]> = {}) =>
  render(
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
    </I18nProvider>,
  );

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
  window.localStorage.clear();
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

test("a shell with nothing wrong raises no banner at all", () => {
  const { container } = renderShell({ caseRecoveryDiagnostics: [] });

  expect(banners(container)).toEqual([]);
});
