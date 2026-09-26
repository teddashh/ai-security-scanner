import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Finding } from "../../src/types";

// The Results detail panel keeps every machine-written tag
// (`confidence-basis:*`, `engine:*`, `source-severity:*`, ...) as a raw chip.
// Every value they carry is already said in words elsewhere in the panel (the
// engine, the scanner's severity, the confidence basis), so they belong inside
// the collapsed "technical source details" disclosure, not loose beside its
// summary line where a zh-TW beginner reads them as unexplained English code.
// `tenant-disputed` is the one exception: it is the only signal that the
// tenant's own ScubaGear configuration disputed this result (`SourceResult` =
// "Incorrect result"; the finding is still reported on ScubaGear's own
// determination), so it also gets a plain-language pill in the header instead
// of staying silent in the collapsed details.

const RAW_TAGS = ["confidence-basis:derived", "engine:kics", "source-severity:critical"];

const DISPUTE_LABEL: Record<"en" | "zh-TW", string> = {
  en: "Disputed by the tenant",
  "zh-TW": "租用戶對此結果有異議",
};

/** A minimal finding carrying only the machine tags under test. */
const taggedFinding = (tags: string[]): Finding => ({
  id: "finding-tags",
  fingerprint: "fingerprint-tags",
  assetId: "asset-1",
  assetName: "example-repo",
  title: "S3 bucket allows public read",
  summary: "Summary.",
  impact: "Impact.",
  recommendation: "Recommendation.",
  expertType: "Cloud security engineer",
  severity: "high",
  confidence: "high",
  priority: 1,
  workflowState: "unreviewed",
  evidence: [],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-04T12:00:00Z",
  lastSeenAt: "2026-09-04T12:00:00Z",
  tags,
});

/** Renders the page with one tagged finding, in the given locale, and opens its detail panel. */
const renderOpenFinding = (tags: string[], locale: "en" | "zh-TW"): HTMLElement => {
  window.localStorage.setItem(localeStorageKey, locale);
  const result = render(
    <I18nProvider>
      <FindingsPage
        findings={[taggedFinding(tags)]}
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
  const findingRow = result.container.querySelector<HTMLButtonElement>(".finding-row");
  if (!findingRow) throw new Error("finding row did not render");
  fireEvent.click(findingRow);
  const panel = result.container.querySelector<HTMLElement>(".finding-detail");
  if (!panel) throw new Error("finding detail panel did not render");
  return panel;
};

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test.each(["en", "zh-TW"] as const)(
  "raw machine tags stay inside the provenance technical details, with no dispute pill (%s)",
  (locale) => {
    const panel = renderOpenFinding(RAW_TAGS, locale);

    const details = panel.querySelector<HTMLDetailsElement>(".provenance-section details.page-technical-details");
    if (!details) throw new Error("provenance technical details did not render");

    // Every chip is a descendant of the collapsed details, verbatim, in
    // order, keeping its "tag tag--light" class.
    const chipsInDetails = Array.from(details.querySelectorAll<HTMLElement>(".tag.tag--light"))
      .map((chip) => chip.textContent);
    expect(chipsInDetails).toEqual(RAW_TAGS);

    // None of the three raw tag strings appears in the panel's text once the
    // details element is removed from a clone -- i.e. they render nowhere
    // outside it.
    const clone = panel.cloneNode(true) as HTMLElement;
    clone.querySelector(".provenance-section details.page-technical-details")?.remove();
    const outsideText = clone.textContent ?? "";
    for (const tag of RAW_TAGS) {
      expect(outsideText).not.toContain(tag);
    }

    // No dispute pill: the header keeps exactly its three workflow pills
    // (severity, confidence, review status), none of which is the dispute
    // pill's label.
    const headerPills = Array.from(
      panel.querySelectorAll<HTMLElement>(".finding-detail__header .tag-row > .status-pill"),
    );
    expect(headerPills).toHaveLength(3);
    expect(headerPills.some((pill) => pill.textContent === DISPUTE_LABEL[locale])).toBe(false);
  },
);

test.each(["en", "zh-TW"] as const)(
  "a tenant-disputed finding gets exactly one plain-language header pill, and its raw tag stays in the details (%s)",
  (locale) => {
    const tags = [...RAW_TAGS, "tenant-disputed"];
    const panel = renderOpenFinding(tags, locale);

    const headerPills = Array.from(
      panel.querySelectorAll<HTMLElement>(".finding-detail__header .tag-row > .status-pill"),
    );
    const disputePills = headerPills.filter((pill) => pill.textContent === DISPUTE_LABEL[locale]);
    expect(disputePills).toHaveLength(1);
    expect(headerPills).toHaveLength(4);

    const details = panel.querySelector<HTMLDetailsElement>(".provenance-section details.page-technical-details");
    if (!details) throw new Error("provenance technical details did not render");
    const chipsInDetails = Array.from(details.querySelectorAll<HTMLElement>(".tag.tag--light"))
      .map((chip) => chip.textContent);
    expect(chipsInDetails).toEqual(tags);
  },
);
