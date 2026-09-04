import { cleanup, render, within } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import { CoveragePage } from "../../src/pages/CoveragePage";
import { I18nProvider } from "../../src/i18n";
import type { Asset } from "../../src/types";

// The backend refuses to call a run complete when controls could not be
// evaluated: such a run resolves to `authorized_incomplete` rather than
// `discovered_authorized_scanned`. That honesty is only worth something if it
// survives to the screen, and the existing coverage test asserts by matching
// this page's own source text, so it would stay green if the rendering were
// deleted. These assertions render the page instead.
//
// Two states share `authorized_incomplete` and mean opposite things: a scan that
// ran and did not finish, and an authorized asset no scan has reached yet. The
// page separates them on `scanAttempted`. Collapsing them either cries wolf on
// an untouched asset or, far worse, presents an unfinished scan as nothing to
// worry about.

const asset = (
  id: string,
  name: string,
  coverageState: Asset["coverageState"],
  scanAttempted: boolean,
): Asset => ({
  id,
  name,
  type: "domain",
  platform: "external",
  locator: `https://${name}/`,
  coverageState,
  authorizationState: "authorized",
  allowedModes: ["public_data"],
  findingCount: 0,
  scanAttempted,
});

const FINISHED = asset("asset-finished", "finished.example", "discovered_authorized_scanned", true);
const UNFINISHED = asset("asset-unfinished", "unfinished.example", "authorized_incomplete", true);
const UNTOUCHED = asset("asset-untouched", "untouched.example", "authorized_incomplete", false);

const renderCoverage = (assets: Asset[]) =>
  render(
    <I18nProvider>
      <CoveragePage
        caseId="case-1"
        requestedActivities={[]}
        coverage={[]}
        sources={[]}
        engineManifests={[]}
        assets={assets}
        scopeGrants={[]}
        nativeMode={true}
        onChooseSnapshot={() => Promise.resolve(null)}
        onConnectSourceSnapshot={() => Promise.resolve()}
        onChooseWorkspace={() => Promise.resolve(null)}
        onAttachWorkspaceSnapshot={() => Promise.resolve(true)}
        onStartDiscovery={() => Promise.resolve()}
        onAuthorizationChanged={() => Promise.resolve()}
        onStartScan={() => Promise.resolve(true)}
      />
    </I18nProvider>,
  );

/** The status pill rendered on one asset's review card. */
const pillFor = (container: HTMLElement, name: string): HTMLElement => {
  const card = Array.from(container.querySelectorAll<HTMLElement>(".asset-review-card")).find(
    (candidate) => within(candidate).queryByText(name) !== null,
  );
  if (!card) throw new Error(`no review card rendered for ${name}`);
  const pill = card.querySelector<HTMLElement>(".status-pill");
  if (!pill) throw new Error(`no status pill rendered for ${name}`);
  return pill;
};

afterEach(cleanup);

test("a scan that did not finish is never shown as finished", () => {
  const { container } = renderCoverage([FINISHED, UNFINISHED, UNTOUCHED]);

  const finished = pillFor(container, "finished.example");
  const unfinished = pillFor(container, "unfinished.example");

  expect(finished.textContent).toContain("Scanned");
  expect(finished.className).toContain("status-pill--positive");

  // The whole point: an unfinished scan must not borrow the finished wording or
  // the reassuring tone that goes with it.
  expect(unfinished.textContent).toContain("Incomplete");
  expect(unfinished.textContent).not.toContain("Scanned");
  expect(unfinished.className).not.toContain("status-pill--positive");
});

test("an unfinished scan is not presented as one that has not started", () => {
  const { container } = renderCoverage([UNFINISHED, UNTOUCHED]);

  const unfinished = pillFor(container, "unfinished.example");
  const untouched = pillFor(container, "untouched.example");

  // Both assets carry `authorized_incomplete`. Reading the same would tell a
  // user that a scan which stopped part-way simply has not run yet.
  expect(unfinished.textContent).not.toContain("Ready to scan");
  expect(untouched.textContent).toContain("Ready to scan");
  expect(unfinished.textContent).not.toEqual(untouched.textContent);
});
