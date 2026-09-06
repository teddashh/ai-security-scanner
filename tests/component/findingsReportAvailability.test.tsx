import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Finding } from "../../src/types";

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

const renderPage = (reportUnavailable: boolean) => render(
  <I18nProvider>
    <FindingsPage
      report={undefined}
      reportUnavailable={reportUnavailable}
      findings={[canonicalFinding]}
      findingGroups={[]}
      findingGroupEvents={[]}
      coverage={[]}
      runs={[]}
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

test("an unavailable run-bound report suppresses findings and keeps its notice", () => {
  const { container } = renderPage(true);
  expect(container.querySelectorAll(".finding-row")).toHaveLength(0);
  expect(container.textContent).toContain("This saved report is unavailable");
  expect(container.textContent).not.toContain("Canonical sample finding");
});
