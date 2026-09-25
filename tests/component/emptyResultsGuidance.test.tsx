import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeMessages, localeStorageKey } from "../../src/i18n";

// Empty Results is the first page a beginner opens after they have not yet
// started a scan. The guidance has to name a destination that is actually in
// the sidebar.

const renderEmptyResults = () =>
  render(
    <I18nProvider>
      <FindingsPage
        report={undefined}
        findings={[]}
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

const emptyGuidance = (container: HTMLElement): string => {
  const description = container.querySelector(".empty-state p")?.textContent;
  if (!description) throw new Error("empty Results guidance did not render");
  return description;
};

beforeEach(() => window.localStorage.setItem(localeStorageKey, "en"));

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("empty Results guidance points at a real destination in both locales", () => {
  const { container: englishContainer } = renderEmptyResults();
  const english = emptyGuidance(englishContainer);
  expect(english).toContain(localeMessages.en["nav.start.label"]);
  expect(english).not.toContain(localeMessages.en["nav.progress.label"]);

  cleanup();
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container: chineseContainer } = renderEmptyResults();
  const chinese = emptyGuidance(chineseContainer);
  expect(chinese).toContain(localeMessages["zh-TW"]["nav.start.label"]);
  expect(chinese).not.toContain(localeMessages["zh-TW"]["nav.progress.label"]);
});
