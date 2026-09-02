import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  completePageTransition,
  type PageTransitionFocusTarget,
  type PageTransitionMainContent,
} from "../../src/pageNavigation.ts";

const source = async (path: string): Promise<string> =>
  readFile(new URL(path, import.meta.url), "utf8");

test("a real page transition focuses the new heading and scrolls to the viewport origin once", () => {
  const focusOptions: FocusOptions[] = [];
  const scrollOptions: ScrollToOptions[] = [];
  let mainFocusCount = 0;
  const heading: PageTransitionFocusTarget = {
    focus: (options) => focusOptions.push(options ?? {}),
  };
  const mainContent: PageTransitionMainContent = {
    querySelector: (selector) => {
      assert.equal(selector, "[data-page-heading]");
      return heading;
    },
    focus: () => { mainFocusCount += 1; },
  };

  assert.equal(completePageTransition({
    previousKey: "start:case-a",
    nextKey: "cases:case-a",
    mainContent,
    viewport: { scrollTo: (options) => scrollOptions.push(options) },
  }), true);

  assert.deepEqual(focusOptions, [{ preventScroll: true }]);
  assert.equal(mainFocusCount, 0);
  assert.deepEqual(scrollOptions, [{ top: 0, left: 0, behavior: "auto" }]);
});

test("same-page rerenders preserve reading position and focus", () => {
  let focusCount = 0;
  let scrollCount = 0;
  const mainContent: PageTransitionMainContent = {
    querySelector: () => ({ focus: () => { focusCount += 1; } }),
    focus: () => { focusCount += 1; },
  };

  assert.equal(completePageTransition({
    previousKey: "findings:case-a",
    nextKey: "findings:case-a",
    mainContent,
    viewport: { scrollTo: () => { scrollCount += 1; } },
  }), false);
  assert.equal(focusCount, 0);
  assert.equal(scrollCount, 0);
});

test("a page without a marked heading falls back to the main landmark", () => {
  const focusOptions: FocusOptions[] = [];
  const mainContent: PageTransitionMainContent = {
    querySelector: () => null,
    focus: (options) => focusOptions.push(options ?? {}),
  };

  assert.equal(completePageTransition({
    previousKey: "cases:case-a",
    nextKey: "progress:case-a",
    mainContent,
    viewport: { scrollTo: () => undefined },
  }), true);
  assert.deepEqual(focusOptions, [{ preventScroll: true }]);
});

test("switching projects on the same page resets focus and scroll for the new content", () => {
  let focusCount = 0;
  let scrollCount = 0;
  const mainContent: PageTransitionMainContent = {
    querySelector: () => ({ focus: () => { focusCount += 1; } }),
    focus: () => { focusCount += 1; },
  };

  assert.equal(completePageTransition({
    previousKey: "findings:case-a",
    nextKey: "findings:case-b",
    mainContent,
    viewport: { scrollTo: () => { scrollCount += 1; } },
  }), true);
  assert.equal(focusCount, 1);
  assert.equal(scrollCount, 1);
});

test("the shell settles navigation after render and all primary page headings are focusable", async () => {
  const [app, shell, shared, startPage] = await Promise.all([
    source("../../src/App.tsx"),
    source("../../src/components/AppShell.tsx"),
    source("../../src/components/Shared.tsx"),
    source("../../src/pages/StartPage.tsx"),
  ]);

  assert.doesNotMatch(app, /document\.getElementById\("main-content"\)\?\.focus/u);
  assert.match(shell, /pageTransitionKey = `\$\{page\}:\$\{selectedCase\?\.id \?\? ""\}`/u);
  assert.match(shell, /useLayoutEffect\(\(\) => \{[\s\S]*completePageTransition\(\{[\s\S]*previousKey: previousPageTransitionKey\.current,[\s\S]*nextKey: pageTransitionKey,[\s\S]*previousPageTransitionKey\.current = pageTransitionKey;[\s\S]*\}, \[pageTransitionKey\]\);/u);
  assert.match(shared, /<h1 data-page-heading tabIndex=\{-1\}>\{title\}<\/h1>/u);
  assert.match(startPage, /<h1 id="start-page-title" data-page-heading tabIndex=\{-1\}>/u);
});

test("terminal scan progress links directly to the localized Results page", async () => {
  const progress = await source("../../src/pages/ProgressPage.tsx");
  const statusesStart = progress.indexOf("const terminalRunStatuses");
  const statusesEnd = progress.indexOf("]);", statusesStart);
  const terminalStatuses = progress.slice(statusesStart, statusesEnd);

  assert.ok(statusesStart >= 0 && statusesEnd > statusesStart);
  for (const status of ["completed", "no_checks_completed", "partial", "failed", "cancelled"]) {
    assert.ok(terminalStatuses.includes(`"${status}"`), status);
  }
  assert.match(progress, /selectedRun && terminalRunStatuses\.has\(selectedRun\.status\)/u);
  assert.match(
    progress,
    /\{showResultsAction && \([\s\S]*?<a className="button button--secondary" href="#findings">[\s\S]*?t\("nav\.findings\.label"\)/u,
  );
});
