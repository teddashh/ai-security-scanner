import { cleanup, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { BeginnerMasterReport, BeginnerReportSummary } from "../../src/types";

// The beginner report is the surface a non-expert reads to learn what the scan
// actually established. Its most consequential state is `no_checks_completed`:
// a run that produced nothing. Nothing found and nothing looked at render with
// the same zeros, so the only thing separating "you are clear" from "we did not
// manage to check" is how the page presents that state.
//
// The backend is careful here -- every dimension it could not speak to is
// pushed into `coverageGaps` with an explicit instruction not to read missing
// history as completed coverage -- and all of that is spent if the last inch to
// the screen loses it.

const counts = (
  overrides: Partial<BeginnerMasterReport["coverageCounts"]> = {},
): BeginnerMasterReport["coverageCounts"] => ({
  testedComplete: 0,
  testedPartial: 0,
  failed: 0,
  timedOut: 0,
  cancelled: 0,
  notTested: 0,
  excluded: 0,
  truncated: 0,
  unavailable: 0,
  ...overrides,
});

const report = (
  summary: BeginnerReportSummary,
  overrides: Partial<BeginnerMasterReport> = {},
): BeginnerMasterReport => ({
  schemaVersion: "1.0.0",
  caseId: "case-1",
  runId: "run-1",
  projectTitle: "Contoso baseline",
  state: {
    summary,
    lifecycle: "final",
    lastDurableUpdate: "2026-09-04T12:00:00Z",
    explanation: "Recorded from the run's durable task state.",
  },
  requested: {
    targets: [{
      assetId: "asset-1",
      label: "contoso.example",
      assetKind: "domain",
      labelAvailability: "recorded",
      assetKindAvailability: "recorded",
    }],
    stage: { value: "inventory", availability: "recorded", explanation: "Recorded with the run." },
    limits: [],
    requestedCheckIds: ["check-1"],
    automaticReductions: [],
    reductionsAvailability: "recorded",
    unavailableDimensions: [],
  },
  actual: { checks: [], networkScopes: [], unavailableDimensions: [] },
  coverageGaps: [],
  coverageCounts: counts(),
  findings: [],
  nextSteps: [],
  technicalDetails: { collapsedByDefault: true, tasks: [] },
  frameworkNotice: { nonCertification: "Not a certification.", aidefendMappingStatus: "Mapped." },
  dataQualityWarnings: [],
  ...overrides,
});

const renderReport = (value: BeginnerMasterReport) =>
  render(
    <I18nProvider>
      <FindingsPage
        report={value}
        selectedRunId="run-1"
        findings={[]}
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

/** The report's own state pill, not a per-finding one. */
const statePill = (container: HTMLElement): HTMLElement => {
  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  if (!section) throw new Error("the beginner report section did not render");
  const pill = section.querySelector<HTMLElement>(".status-pill");
  if (!pill) throw new Error("the beginner report state pill did not render");
  return pill;
};

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("a run where nothing completed never reads as a clean result", () => {
  const { container } = renderReport(
    report("no_checks_completed", { coverageCounts: counts({ notTested: 4 }) }),
  );

  const pill = statePill(container);
  expect(pill.textContent).toContain("No checks completed");
  expect(pill.textContent).not.toContain("Complete");
  // Zero findings and zero completed checks look identical on the numbers, so
  // the tone is what stops this reading as an all-clear.
  expect(pill.className).not.toContain("status-pill--positive");
  expect(pill.className).toContain("status-pill--danger");
});

test("a partial run is distinguished from a complete one", () => {
  const { container: partial } = renderReport(
    report("partial", { coverageCounts: counts({ testedComplete: 2, notTested: 3 }) }),
  );
  const { container: complete } = renderReport(
    report("complete", { coverageCounts: counts({ testedComplete: 5 }) }),
  );

  const partialPill = statePill(partial);
  const completePill = statePill(complete);

  expect(partialPill.textContent).toContain("Partial results");
  expect(partialPill.className).not.toContain("status-pill--positive");
  expect(completePill.textContent).toContain("Complete");
  expect(partialPill.textContent).not.toEqual(completePill.textContent);
});

test("an absent coverage gap is reported as unrecorded rather than as none existing", () => {
  const { container } = renderReport(report("complete"));

  // "No known coverage gap was recorded" is a claim about the record. Wording
  // it as an absence of gaps would assert something the run cannot support.
  //
  // The claim is made in two places and each is asserted separately: a
  // page-wide text match passes while either one still says it, which would
  // let the other be replaced by a stronger claim unnoticed.
  const metric = Array.from(container.querySelectorAll<HTMLElement>(".metric-card")).find(
    (card) => card.querySelector(".metric-card__label")?.textContent === "Coverage gaps",
  );
  if (!metric) throw new Error("the coverage-gap metric card did not render");
  expect(metric.querySelector(".metric-card__value")?.textContent).toBe("0");
  expect(metric.querySelector(".metric-card__detail")?.textContent).toBe(
    "No known coverage gap was recorded.",
  );

  const gapsCard = Array.from(container.querySelectorAll<HTMLElement>(".coverage-card")).find(
    (card) => card.querySelector("h3")?.textContent === "What was not tested",
  );
  if (!gapsCard) throw new Error("the coverage-gap card did not render");
  expect(gapsCard.textContent).toContain("No known coverage gap was recorded.");
});

test("what the run could not establish is shown with its own dimension", () => {
  // Every dimension the backend could not speak to arrives as a gap. Two gaps
  // sharing a kind are told apart by their dimension alone, so both must reach
  // the screen or the rows become indistinguishable.
  const { container } = renderReport(
    report("partial", {
      coverageGaps: [
        {
          kind: "unavailable",
          targetAssetIds: ["asset-1"],
          dimension: "automatic scope reductions or truncations",
          reason: "This run did not retain an exact reduction record.",
          nextActionCode: "preserve_visible_limitation",
          nextAction: "Keep this limitation visible.",
        },
        {
          kind: "unavailable",
          targetAssetIds: ["asset-1"],
          dimension: "requested scan stage",
          reason: "The requested stage was not retained.",
          nextActionCode: "preserve_visible_limitation",
          nextAction: "Keep this limitation visible.",
        },
      ],
    }),
  );

  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  expect(within(section!).getByText(/automatic scope reductions or truncations/u)).toBeTruthy();
  expect(within(section!).getByText(/requested scan stage/u)).toBeTruthy();
  expect(container.textContent).not.toContain("No known coverage gap was recorded.");
});

test("saved-data limitations are surfaced, not held in the model", () => {
  const { container } = renderReport(
    report("partial", {
      dataQualityWarnings: ["One task's saved evidence index could not be read."],
    }),
  );

  expect(container.textContent).toContain("Saved-data limitations: 1");
});
