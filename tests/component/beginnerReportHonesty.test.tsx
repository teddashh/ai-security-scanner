import { cleanup, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type {
  BeginnerMasterReport,
  BeginnerReportFinding,
  BeginnerReportSummary,
  Finding,
} from "../../src/types";

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

const frozenFinding = (
  overrides: Partial<BeginnerReportFinding> = {},
): BeginnerReportFinding => ({
  findingId: "finding-1",
  fingerprint: "fp-1",
  snapshotSource: "frozen_selected_run",
  title: "Exposed management port",
  plainLanguageRisk: "Anyone on the network can reach the admin interface.",
  possibleImpact: "An attacker could try to sign in.",
  severity: "high",
  confidence: "high",
  priority: 1,
  priorityReasons: [],
  targetAssetIds: ["asset-1"],
  nextStep: "Restrict the port.",
  recommendedExpertType: "security",
  evidenceReferences: [],
  frameworkReferences: [],
  ...overrides,
});

const canonicalFinding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "finding-1",
  fingerprint: "fp-1",
  assetId: "asset-1",
  assetName: "contoso.example",
  title: "Exposed management port",
  summary: "Anyone on the network can reach the admin interface.",
  impact: "An attacker could try to sign in.",
  recommendation: "Restrict the port.",
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

const renderReport = (value: BeginnerMasterReport, canonical: Finding[] = []) =>
  render(
    <I18nProvider>
      <FindingsPage
        report={value}
        selectedRunId="run-1"
        findings={canonical}
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

// Whenever a run exists the page rebuilds every finding through
// `projectReportFindings`, so the detail pane a user reads is that projection,
// not the canonical finding. Anything the projection drops is invisible, and it
// is invisible in a way that reads as a fact about the scan rather than about
// this view.

test("the published reading behind a finding reaches the pane that offers to open it", () => {
  // Adapter findings are seeded unconditionally with the engine's repository
  // URL (adapters/mod.rs:2440), so an empty list here is a claim no adapter
  // finding can honestly make. The projection had hard-coded `[]`, which told
  // every reader the rule behind the finding had no documentation to consult.
  const { container } = renderReport(
    report("partial", { findings: [frozenFinding()] }),
    [canonicalFinding({
      officialReferences: [
        "https://github.com/example/engine",
        "https://example.org/rules/exposed-port",
      ],
    })],
  );

  const links = Array.from(container.querySelectorAll<HTMLAnchorElement>('a[href^="https://"]'))
    .filter((link) => link.href.includes("example"));
  expect(links.map((link) => link.href)).toEqual([
    "https://github.com/example/engine",
    "https://example.org/rules/exposed-port",
  ]);
  expect(container.textContent).not.toContain("No official reference link");
});

test("a finding with nothing recorded says so about the record, not about the scanner", () => {
  // The mirror, and the reason the copy changed as well as the wiring: this
  // branch is also reached when the canonical finding is gone, where "the
  // scanner provided none" would be a different and false claim.
  const { container } = renderReport(
    report("partial", { findings: [frozenFinding()] }),
    [canonicalFinding({ officialReferences: [] })],
  );

  expect(container.textContent).toContain("No official reference link is recorded for this finding");
  expect(container.textContent).not.toContain("was provided");
});

test("a coverage gap does not name a cause the kind cannot establish", () => {
  // `not_tested` is assigned to a check that saved partial work, one that never
  // started, and one still running. The row renders the gap's own dimension
  // beside this sentence, so naming a single cause made the two halves of one
  // row contradict each other.
  const { container } = renderReport(
    report("partial", {
      coverageGaps: [{
        kind: "not_tested",
        taskId: "task-1",
        targetAssetIds: ["asset-1"],
        dimension: "trivy: remaining requested dimensions",
        reason: "This check produced some durable work but did not complete every planned dimension.",
        nextActionCode: "retry_check",
        nextAction: "Review the saved results, then retry this check.",
      }],
    }),
  );

  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  const row = within(section!).getByText(/remaining requested dimensions/u).textContent ?? "";
  expect(row).toContain("not a pass");
  // The specific causes the kind cannot distinguish.
  expect(row).not.toContain("no compatible check completed");
  expect(row).not.toContain("did not start");
});

test("AIDEFEND is not presented as carrying the same standing as NIST and ISO", () => {
  // The backend writes the non-certification notice and the AIDEFEND
  // qualification as two separate sentences because the catalogues differ: NIST
  // and ISO are official, AIDEFEND is not. Rendering only the first lists all
  // three in one breath.
  const { container } = renderReport(report("partial"));

  const notice = Array.from(container.querySelectorAll<HTMLElement>(".inline-notice"))
    .find((candidate) => candidate.textContent?.includes("AIDEFEND"));
  expect(notice).toBeTruthy();
  expect(notice!.textContent).toContain("not certification, compliance, endorsement, or a pass/fail result");
  expect(notice!.textContent).toContain("independent, unofficial mapping");
});
