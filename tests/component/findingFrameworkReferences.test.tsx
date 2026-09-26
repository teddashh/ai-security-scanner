import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { ControlReference, Finding } from "../../src/types";

// Results names a finding's framework mapping one way in each language:
// "framework reference" and 框架參考, in the filter, the empty state, and the
// detail panel.

/** A minimal finding carrying only the framework controls under test. */
const controlledFinding = (controls: ControlReference[]): Finding => ({
  id: "finding-controls",
  fingerprint: "fingerprint-controls",
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
  controls,
  officialReferences: [],
  firstSeenAt: "2026-09-04T12:00:00Z",
  lastSeenAt: "2026-09-04T12:00:00Z",
});

const ONE_CONTROL: ControlReference[] = [{
  framework: "NIST CSF",
  version: "2.0",
  controlId: "PR.AA-03",
  relationship: "related",
  title: "Authentication of users, services, and hardware",
}];

/** Renders the page with one finding, in the given locale, and opens its detail panel. */
const renderOpenFinding = (controls: ControlReference[], locale: "en" | "zh-TW"): HTMLElement => {
  window.localStorage.setItem(localeStorageKey, locale);
  const result = render(
    <I18nProvider>
      <FindingsPage
        findings={[controlledFinding(controls)]}
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
  return result.container;
};

/** The selected finding's detail panel, addressed structurally like the neighbouring tests. */
const detailPanel = (container: HTMLElement): HTMLElement => {
  const panel = container.querySelector<HTMLElement>(".finding-detail");
  if (!panel) throw new Error("finding detail panel did not render");
  return panel;
};

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("zh-TW: a selected finding with one framework control shows the framework-reference heading and action", () => {
  const panel = detailPanel(renderOpenFinding(ONE_CONTROL, "zh-TW"));

  const heading = Array.from(panel.querySelectorAll("h3")).find((node) => node.textContent === "相關框架參考");
  if (!heading) throw new Error("the framework references heading did not render");

  const controlButton = panel.querySelector<HTMLButtonElement>(".control-item");
  if (!controlButton) throw new Error("the control button did not render");
  expect(controlButton.textContent).toContain("查看同一框架參考的問題");
});

test("zh-TW: a selected finding with no controls shows the no-framework-reference sentence", () => {
  const panel = detailPanel(renderOpenFinding([], "zh-TW"));
  expect(panel.textContent).toContain("這筆問題沒有對應的框架參考。");
});

test("zh-TW: the page keeps none of the retired control-jargon strings", () => {
  const retired = ["控制項座標", "同座標", "控制項映射", "（導航）"];

  const withControl = renderOpenFinding(ONE_CONTROL, "zh-TW");
  for (const phrase of retired) {
    expect(withControl.textContent).not.toContain(phrase);
  }
  cleanup();

  const withoutControl = renderOpenFinding([], "zh-TW");
  for (const phrase of retired) {
    expect(withoutControl.textContent).not.toContain(phrase);
  }
});

test("zh-TW: the framework filter's \"all\" option offers 所有框架參考", () => {
  const container = renderOpenFinding(ONE_CONTROL, "zh-TW");
  const filterBar = container.querySelector<HTMLElement>(".finding-filter-stack");
  if (!filterBar) throw new Error("the filter bar did not render");

  const allOptions = Array.from(filterBar.querySelectorAll<HTMLOptionElement>("option"))
    .filter((option) => option.value === "all");
  expect(allOptions.some((option) => option.textContent === "所有框架參考")).toBe(true);
});

test("en: framework-reference copy stays in English", () => {
  const panel = detailPanel(renderOpenFinding(ONE_CONTROL, "en"));
  expect(panel.textContent).toContain("Related framework references");

  const controlButton = panel.querySelector<HTMLButtonElement>(".control-item");
  if (!controlButton) throw new Error("the control button did not render");
  expect(controlButton.textContent).toContain("View problems with the same reference");
});
