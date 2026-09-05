import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { CorrelationReport, Finding, FindingCorrelationSuggestion, FindingGroup } from "../../src/types";

// The backend computes correlation suggestions and its own unit tests cover the
// equivalence rule. What those cannot show is what a beginner is told. Spec 9.3
// requires that agreement between two engines is never presented as independent
// confirmation, that an unverifiable comparison is disclosed rather than left as
// silence, and that a truncated list never reads as the complete set. All three
// are rendering guarantees, so they can only be checked by rendering.

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

const suggestion: FindingCorrelationSuggestion = {
  id: "correlation-abc",
  caseId: "case-1",
  comparisonKey: "cross-engine-vulnerability-id-1|vuln:CVE-2024-3094|pkg:xz-utils|asset:asset-1",
  keyVersion: "cross-engine-vulnerability-id-1",
  vulnerabilityId: "CVE-2024-3094",
  package: "xz-utils",
  title: "CVE-2024-3094 in xz-utils",
  // English prose the page must not surface to a zh-TW reader.
  basis: "2 engines (grype, trivy) reported vulnerability CVE-2024-3094 against package xz-utils on the same asset.",
  uncertainty: "Grouping these is a presentation choice.",
  corroboration: "not-established",
  findingIds: ["finding-trivy", "finding-grype"],
  engineIds: ["grype", "trivy"],
};

const report = (overrides: Partial<CorrelationReport> = {}): CorrelationReport => ({
  keyVersion: "cross-engine-vulnerability-id-1",
  suggestions: [suggestion],
  unverifiable: [],
  truncatedSuggestions: 0,
  ...overrides,
});

const members = [
  finding("finding-trivy", "Outdated compression library"),
  finding("finding-grype", "Vulnerable package in image"),
];

const renderPage = (
  correlationReport: CorrelationReport | undefined,
  options: { findings?: Finding[]; groups?: FindingGroup[]; onGroupFindings?: () => Promise<boolean>; busy?: boolean } = {},
) =>
  render(
    <I18nProvider>
      <FindingsPage
        findings={options.findings ?? members}
        findingGroups={options.groups ?? []}
        findingGroupEvents={[]}
        correlationReport={correlationReport}
        coverage={[]}
        runs={[]}
        workflowEvents={[]}
        busy={options.busy ?? false}
        onUpdateWorkflow={() => Promise.resolve(true)}
        onGroupFindings={options.onGroupFindings ?? (() => Promise.resolve(true))}
        onUngroupFindings={() => Promise.resolve()}
        onOpenCoverage={() => {}}
        onOpenProgress={() => {}}
        onOpenExport={() => {}}
      />
    </I18nProvider>,
  );

const correlationSection = () =>
  document.querySelector<HTMLElement>('section[aria-labelledby="finding-correlations-title"]');

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("a suggestion names the shared vulnerability, the package, and every engine that reported it", () => {
  renderPage(report());

  const section = correlationSection();
  expect(section).not.toBeNull();
  const article = within(section!).getByText("CVE-2024-3094 in xz-utils").closest("article")!;
  expect(article.textContent).toContain("Reported by these tools: grype, trivy");
  expect(article.textContent).toContain("Problems it would combine: 2");

  // Each member is reachable, so the user can check the claim rather than
  // accept it on the product's word.
  const memberButtons = Array.from(article.querySelectorAll("ul.detail-list button"));
  expect(memberButtons.map((button) => button.textContent)).toEqual([
    "Outdated compression library",
    "Vulnerable package in image",
  ]);
});

test("agreement between two engines is disclosed as not independently confirmed", () => {
  renderPage(report());

  const article = within(correlationSection()!).getByText("CVE-2024-3094 in xz-utils").closest("article")!;
  expect(article.textContent).toContain("Not double-checked");
  expect(article.textContent).toContain("agreement is not two independent confirmations");
});

test("accepting a suggestion asks to group exactly its members and nothing more", () => {
  const onGroupFindings = vi.fn(() => Promise.resolve(true));
  renderPage(report(), { onGroupFindings });

  const article = within(correlationSection()!).getByText("CVE-2024-3094 in xz-utils").closest("article")!;
  fireEvent.click(within(article).getByRole("button", { name: "Combine these for handoff" }));

  expect(onGroupFindings).toHaveBeenCalledTimes(1);
  const input = onGroupFindings.mock.calls[0][0] as { title: string; findingIds: string[]; rationale: string };
  expect(input.findingIds).toEqual(["finding-trivy", "finding-grype"]);
  expect(input.title).toBe("CVE-2024-3094 in xz-utils");
  // The recorded rationale must say the grouping changes presentation only.
  expect(input.rationale).toContain("Presentation only");
});

test("findings that share an identifier but cannot be compared are disclosed, not omitted", () => {
  renderPage(report({
    suggestions: [],
    unverifiable: [{
      caseId: "case-1",
      vulnerabilityId: "CVE-2024-9999",
      findingIds: ["finding-trivy", "finding-grype"],
      reason: "At least one finding does not record both the affected package and the affected asset.",
    }],
  }));

  const section = correlationSection();
  expect(section).not.toBeNull();
  expect(section!.textContent).toContain("Shared an identifier, but could not be compared: 1");
  expect(section!.textContent).toContain("CVE-2024-9999 — problems sharing this identifier: 2");
});

test("a capped suggestion list says so instead of reading as the complete set", () => {
  renderPage(report({ truncatedSuggestions: 7 }));

  expect(correlationSection()!.textContent).toContain("Further suggestions not shown: 7");
});

test("no panel appears while the suggestion read has not returned", () => {
  // `undefined` means unknown, which is not the same as "nothing is related".
  // Rendering an empty panel here would assert an all-clear the product cannot
  // support, so the section must be absent entirely.
  renderPage(undefined);

  expect(correlationSection()).toBeNull();
});

test("an empty report renders no panel rather than an all-clear claim", () => {
  renderPage(report({ suggestions: [] }));

  expect(correlationSection()).toBeNull();
});

test("a suggestion naming a finding this page does not have is withheld", () => {
  // The report was computed against a larger finding set. Offering it would
  // propose grouping a finding the user cannot open to check.
  renderPage(report(), { findings: [members[0]] });

  expect(correlationSection()).toBeNull();
});

test("a suggestion whose members are already grouped is withheld", () => {
  // `group_findings` would reject it, so offering the button would promise an
  // action that cannot succeed.
  renderPage(report(), {
    groups: [{
      id: "group-1",
      caseId: "case-1",
      title: "Already combined",
      findingIds: ["finding-trivy", "finding-grype"],
      rationale: "Handled together.",
      groupedBy: "reviewer",
      createdAt: "2026-09-03T12:00:00Z",
    }],
  });

  expect(correlationSection()).toBeNull();
});

test("the backend's English basis prose is not rendered", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  renderPage(report());

  const section = correlationSection();
  expect(section).not.toBeNull();
  // The page composes its own sentence from the structured fields, so a zh-TW
  // reader is never handed an untranslated English paragraph.
  expect(section!.textContent).not.toContain(suggestion.basis);
  expect(section!.textContent).not.toContain(suggestion.uncertainty);
  expect(section!.textContent).toContain("回報的工具：grype、trivy");
});
