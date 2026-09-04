import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Finding } from "../../src/types";

// ScubaGear rewrites the result of any control the audited tenant marked
// incorrect in its own configuration, and the adapter marks the resulting
// finding `tenant-disputed` so the dispute travels with it rather than being
// honoured in silence. That marker is only worth writing if a reader can see it,
// and nothing between the adapter and the screen was covered by a rendering
// test. These assertions render the page.

const finding = (id: string, title: string, tags?: string[]): Finding => ({
  id,
  fingerprint: `fingerprint-${id}`,
  assetId: "asset-1",
  assetName: "contoso.onmicrosoft.com",
  title,
  summary: "Summary.",
  impact: "Impact.",
  recommendation: "Recommendation.",
  expertType: "cloud",
  severity: "high",
  confidence: "firm",
  priority: 90,
  workflowState: "unreviewed",
  evidence: [],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-04T12:00:00Z",
  lastSeenAt: "2026-09-04T12:00:00Z",
  tags,
});

const renderPage = (findings: Finding[]) =>
  render(
    <I18nProvider>
      <FindingsPage
        findings={findings}
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

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("a finding the tenant disputed says so on screen", () => {
  const { container } = renderPage([
    finding("finding-disputed", "Legacy authentication is not blocked", [
      "source-criticality:shall",
      "tenant-disputed",
    ]),
  ]);

  const tags = Array.from(container.querySelectorAll(".tag-row .tag")).map(
    (tag) => tag.textContent,
  );
  expect(tags).toContain("tenant-disputed");
});

test("an undisputed finding is not marked as disputed", () => {
  // The marker has to mean something, so it must not appear on every finding.
  const { container } = renderPage([
    finding("finding-plain", "Risky users are not blocked", ["source-criticality:shall"]),
  ]);

  const tags = Array.from(container.querySelectorAll(".tag-row .tag")).map(
    (tag) => tag.textContent,
  );
  expect(tags).toContain("source-criticality:shall");
  expect(tags).not.toContain("tenant-disputed");
});
