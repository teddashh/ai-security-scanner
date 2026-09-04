import { cleanup, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Finding, FindingGroup } from "../../src/types";

// `projectVisibleFindingGroups` is unit tested in tests/frontend, but until now
// nothing proved its output reached the page. The property that matters to a
// reader is disclosure: members belonging to other runs are counted in the open
// rather than borrowed into the current report or silently dropped. That is a
// rendering guarantee, so it can only be checked by rendering.

const finding = (id: string, title: string): Finding => ({
  id,
  fingerprint: `fingerprint-${id}`,
  assetId: "asset-1",
  assetName: "example.internal",
  title,
  summary: "Summary.",
  impact: "Impact.",
  recommendation: "Recommendation.",
  expertType: "cloud",
  severity: "medium",
  confidence: "firm",
  priority: 50,
  workflowState: "unreviewed",
  evidence: [],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-03T12:00:00Z",
  lastSeenAt: "2026-09-03T12:00:00Z",
});

const group: FindingGroup = {
  id: "group-1",
  caseId: "case-1",
  title: "Related exposure",
  // The third member is deliberately absent from `findings`: it belongs to an
  // earlier run of the same case.
  findingIds: ["finding-1", "finding-2", "historical-finding"],
  rationale: "These observations should be reviewed together.",
  groupedBy: "reviewer",
  createdAt: "2026-09-03T12:00:00Z",
};

const renderPage = (findings: Finding[], groups: FindingGroup[]) =>
  render(
    <I18nProvider>
      <FindingsPage
        findings={findings}
        findingGroups={groups}
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

const groupSection = () =>
  document.querySelector<HTMLElement>('section[aria-labelledby="finding-groups-title"]');

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("a group states how many members are held back in case history", () => {
  renderPage([finding("finding-1", "First issue"), finding("finding-2", "Second issue")], [group]);

  const section = groupSection();
  expect(section).not.toBeNull();
  const article = within(section!).getByText(group.title).closest("article");
  expect(article).not.toBeNull();

  // One of the three members is not in this run, and the count must say so.
  expect(article!.textContent).toContain("Other members kept in case history: 1");
  // The absent member must not be rendered as if it were part of this run.
  expect(article!.textContent).not.toContain("historical-finding");
});

test("only the members visible in this run are offered as links", () => {
  renderPage([finding("finding-1", "First issue"), finding("finding-2", "Second issue")], [group]);

  const article = within(groupSection()!).getByText(group.title).closest("article")!;
  const memberButtons = Array.from(article.querySelectorAll("ul.detail-list button"));
  expect(memberButtons.map((button) => button.textContent)).toEqual([
    "First issue",
    "Second issue",
  ]);
});

test("a group with a single visible member is withheld rather than shown alone", () => {
  // Below two visible members a group adds repetition instead of reducing it,
  // so the section must not appear at all.
  renderPage([finding("finding-1", "First issue")], [group]);

  expect(groupSection()).toBeNull();
});
