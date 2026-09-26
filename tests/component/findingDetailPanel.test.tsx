import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Evidence, Finding } from "../../src/types";

// The Results detail panel is where a beginner decides what to do about one
// finding. Two things in it stopped reading cleanly on a real 47-finding
// project scan:
//
// - Every official reference rendered with the same link text ("Open source
//   document" / "查看來源文件"). A KICS finding's three references (the
//   engine's repository, its homepage, and the upstream rule documentation)
//   were indistinguishable without hovering each one.
// - The "recommended next step" section's run-in labels had no colon in
//   English ("Scanner-provided remediation Upgrade PyYAML to 5.4") and a
//   colon-plus-space in Chinese ("變更前考量： 請先…"), because one copy of
//   the colon lived in the label's own copy and another in the surrounding
//   markup.
//
// (Fixture and render-helper shape follow the neighbouring component tests,
// e.g. tests/component/findingNarrativeLocalization.test.tsx and
// tests/component/beginnerReportHonesty.test.tsx; neither exports its
// helpers, so the smallest equivalent is reproduced here.)

const baseFinding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "finding-1",
  fingerprint: "fingerprint-1",
  assetId: "asset-1",
  assetName: "example.internal",
  title: "S3 Bucket ACL Allows Read Or Write to All Users",
  summary: "The scanner reported this condition on the assessed asset.",
  impact: "Public access could expose stored data.",
  recommendation: "Restrict the bucket ACL to authorized principals.",
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
  ...overrides,
});

const renderPage = (findings: Finding[]) => {
  const result = render(
    <I18nProvider>
      <FindingsPage
        findings={findings}
        findingGroups={[]}
        findingGroupEvents={[]}
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
  const firstFinding = result.container.querySelector<HTMLButtonElement>(".finding-row");
  if (firstFinding) fireEvent.click(firstFinding);
  return result;
};

/** The official-references section's own list, addressed structurally so it
 * cannot be confused with the evidence card or the advice section beside it. */
const referenceLinks = (container: HTMLElement): HTMLAnchorElement[] => {
  const list = container.querySelector<HTMLElement>(".reference-list");
  if (!list) throw new Error("the reference list did not render");
  return Array.from(list.querySelectorAll<HTMLAnchorElement>("a"));
};

const adviceSection = (container: HTMLElement): HTMLElement => {
  const section = container.querySelector<HTMLElement>(".detail-section--advice");
  if (!section) throw new Error("the advice section did not render");
  return section;
};

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("each official reference names its own document, in both languages", () => {
  const references = [
    "https://github.com/Checkmarx/kics",
    "https://kics.io/",
    "https://docs.kics.io/latest/queries/terraform-queries/aws/38c5ee0d-7f22-4260-ab72-5073048df100/",
  ];
  const expectedText = [
    "github.com/Checkmarx/kics",
    "kics.io",
    "docs.kics.io/latest/queries/terraform-queries/aws/38c5ee0d-7f22-4260-ab72-5073048df100",
  ];

  for (const locale of ["en", "zh-TW"] as const) {
    window.localStorage.setItem(localeStorageKey, locale);
    const { container } = renderPage([baseFinding({ officialReferences: references })]);

    const links = referenceLinks(container);
    expect(links.map((link) => link.textContent?.trim())).toEqual(expectedText);
    links.forEach((link, index) => {
      expect(link.getAttribute("href")).toBe(references[index]);
      expect(link.getAttribute("title")).toBe(references[index]);
    });
    expect(links.some((link) => link.textContent?.includes("Open source document"))).toBe(false);
    expect(links.some((link) => link.textContent?.includes("查看來源文件"))).toBe(false);

    cleanup();
  }
});

test("the advice section's run-in labels carry exactly one colon, set per language", () => {
  const evidence: Evidence[] = [{
    id: "evidence-1",
    sourceEngine: "Trivy",
    scannerDetails: { remediation: "Upgrade PyYAML to 5.4", fixedVersion: "5.4" },
    observedAt: "2026-09-04T12:00:00Z",
    summary: "Trivy reported a vulnerable package.",
    rawArtifactHash: "hash-1",
  }];
  const finding = baseFinding({
    evidence,
    rollbackConsiderations:
      "Capture the current configuration and test its restoration path before making the change.",
  });

  window.localStorage.setItem(localeStorageKey, "en");
  const en = renderPage([finding]);
  const enText = adviceSection(en.container).textContent ?? "";
  expect(enText).toContain("Scanner-provided remediation: Upgrade PyYAML to 5.4");
  expect(enText).toContain("Scanner-reported fixed version: ");
  expect(enText).toContain("Before making a change: ");
  expect(enText).not.toContain("change::");
  cleanup();

  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const zh = renderPage([finding]);
  const zhText = adviceSection(zh.container).textContent ?? "";
  expect(zhText).toContain("掃描工具提供的修復資訊：");
  expect(zhText).toContain("掃描工具回報的修正版：");
  expect(zhText).toContain("變更前考量：");
  expect(zhText).not.toContain("： ");
  expect(zhText).not.toContain("考量：：");
});

test("a finding without references still shows the empty-state paragraph", () => {
  window.localStorage.setItem(localeStorageKey, "en");
  const { container } = renderPage([baseFinding({ officialReferences: [] })]);
  expect(container.querySelector(".reference-list")).toBeNull();
  expect(container.textContent).toContain("No official reference link is recorded for this finding.");
});
