import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { VerificationPage } from "../../src/pages/VerificationPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Finding, ScanRun, VerificationDiff, VerificationSummary } from "../../src/types";

// This is the surface that answers "did the fix work". A wrong claim here is
// the most damaging one the app can make: a user reads it and closes the work.
//
// Three of its honesty properties are invisible to source matching because they
// are conditions, not strings. Whether the incomplete-comparison warning fires
// depends on the run status the backend attached rather than on the comparison
// summary alone; whether a "no longer observed" item still carries its caveat
// depends on a count; and whether an outcome filter that matches nothing says
// so depends on which branch renders. Each of them fails silently -- the page
// still renders, still adds up, and simply omits the qualification.

const run = (id: string, status: ScanRun["status"]): ScanRun => ({
  id,
  caseId: "case-1",
  label: id,
  status,
  progress: status === "completed" ? 100 : 60,
  startedAt: "2026-09-01T12:00:00Z",
  finishedAt: "2026-09-01T12:05:00Z",
  knowledgeDate: "2026-09-01",
  engineRuns: [],
  coveredAssetCount: 1,
  totalAssetCount: 1,
});

const diff = (overrides: Partial<VerificationDiff> & Pick<VerificationDiff, "id" | "state">): VerificationDiff => ({
  title: `Finding ${overrides.id}`,
  assetName: "acme.example",
  explanation: "Recorded comparison detail.",
  evidenceChanged: false,
  ...overrides,
});

const summary = (overrides: Partial<VerificationSummary> = {}): VerificationSummary => ({
  baselineRunId: "run-before",
  comparisonRunId: "run-after",
  baselineAt: "2026-09-01T12:00:00Z",
  comparisonAt: "2026-09-02T12:00:00Z",
  complete: true,
  diffs: [],
  ...overrides,
});

const renderVerification = (
  verification: VerificationSummary,
  runs: ScanRun[],
  findings: Finding[] = [],
) =>
  render(
    <I18nProvider>
      <VerificationPage
        verification={verification}
        runs={runs}
        findings={findings}
        baselineRunId="run-before"
        onSelectBaseline={() => {}}
        onStartRescan={() => Promise.resolve()}
        onOpenFinding={() => {}}
      />
    </I18nProvider>,
  );

/** The diff card carrying a given title; several rows render the same phrases. */
const diffRow = (container: HTMLElement, title: string): HTMLElement => {
  const row = Array.from(container.querySelectorAll<HTMLElement>(".diff-row")).find(
    (candidate) => candidate.textContent?.includes(title),
  );
  if (!row) throw new Error(`no diff row rendered for ${title}`);
  return row;
};

const bothRunsCompleted = [run("run-before", "completed"), run("run-after", "completed")];

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("a follow-up scan that stopped early is disclosed even when the comparison calls itself complete", () => {
  // `complete` is the backend's own verdict on the comparison. The page does not
  // take it as the last word: it independently requires the after-fix run to
  // have finished. Trusting the flag alone would present a comparison built on
  // a run that stopped part-way as a full one, and every "no longer observed"
  // count on it would really mean "we did not finish looking".
  const { container } = renderVerification(
    summary({ complete: true, diffs: [diff({ id: "a", state: "resolved", beforeSeverity: "critical" })] }),
    [run("run-before", "completed"), run("run-after", "partial")],
  );

  const notice = container.querySelector(".inline-notice--warning");
  expect(notice).not.toBeNull();
  expect(notice!.textContent).toContain("This verification could not compare everything");
  expect(notice!.textContent).toContain("are not counted as fixed");
  // The after-fix run's own state is shown rather than left to the notice alone.
  expect(container.querySelector(".comparison-run--current")!.textContent).toContain("Partly completed");
});

test("a comparison with both runs completed and no recorded limitation does not invent a warning", () => {
  // The mirror of the test above. Without this, an implementation that always
  // warned would pass the previous assertion while telling every user their
  // comparison was unreliable, which is its own dishonesty.
  const { container } = renderVerification(
    summary({ complete: true, diffs: [diff({ id: "a", state: "persistent", beforeSeverity: "high", afterSeverity: "high" })] }),
    bothRunsCompleted,
  );

  expect(container.querySelector(".inline-notice--warning")).toBeNull();
});

test("an item that was not seen again is never worded as fixed and keeps its caution", () => {
  const { container } = renderVerification(
    summary({ diffs: [diff({ id: "a", state: "resolved", beforeSeverity: "critical" })] }),
    bothRunsCompleted,
  );

  const row = diffRow(container, "Finding a");
  // "No longer observed" is a statement about this scan. "Fixed" or "Resolved"
  // would be a claim about the system that no scan can support.
  expect(within(row).getByText("No longer observed")).toBeTruthy();
  expect(row.textContent).not.toMatch(/\bFixed\b|\bResolved\b|\bSafe\b/u);
  expect(row.textContent).toContain("did not observe this problem this time");
  expect(row.textContent).toContain("Review the evidence before closing the work");
  // The severity line resolves the absent "after" value explicitly rather than
  // leaving it blank, which would read as no severity at all.
  expect(row.textContent).toContain("After: Not observed this time");

  // And the page-level caution accompanies any such count.
  const caution = container.querySelector(".inline-notice--info");
  expect(caution).not.toBeNull();
  expect(caution!.textContent).toContain("Not observed does not mean permanently safe");
  expect(caution!.textContent).toContain("only the checks that ran this time");
});

test("an item that could not be compared is not counted among those not seen again", () => {
  // These two outcomes are adjacent and one is good news. An unverifiable item
  // folded into the not-observed count converts "we could not tell" into "it is
  // gone", which is the exact substitution this page exists to prevent.
  const { container } = renderVerification(
    summary({
      diffs: [
        diff({ id: "a", state: "resolved", beforeSeverity: "critical" }),
        diff({ id: "b", state: "unverifiable", beforeSeverity: "critical" }),
        diff({ id: "c", state: "unverifiable", beforeSeverity: "high" }),
      ],
    }),
    bothRunsCompleted,
  );

  const cardValue = (label: string): string => {
    const card = Array.from(container.querySelectorAll<HTMLElement>(".metric-card")).find(
      (candidate) => candidate.querySelector(".metric-card__label")?.textContent === label,
    );
    if (!card) throw new Error(`no metric card labelled ${label}`);
    return card.querySelector(".metric-card__value")!.textContent ?? "";
  };
  expect(cardValue("No longer observed")).toBe("1");
  expect(cardValue("Could not verify")).toBe("2");

  const row = diffRow(container, "Finding b");
  expect(within(row).getByText("Could not verify")).toBeTruthy();
  expect(row.textContent).toContain("could not make a trustworthy comparison");
});

test("a recorded comparison limitation is labelled as not being a count of security problems", () => {
  // The number beside a warning is a count of scanner/target comparisons that
  // failed, not of problems found. Presented bare next to a red notice it reads
  // as "you have three issues", which inflates the apparent result of a scan.
  const { container } = renderVerification(
    summary({
      complete: false,
      completenessIssues: [
        { code: "engine_did_not_complete", engineId: "prowler", detail: "prowler did not complete" },
        { code: "scope_changed", assetId: "asset-1", detail: "scope changed between runs" },
      ],
      diffs: [diff({ id: "a", state: "unverifiable" })],
    }),
    bothRunsCompleted,
  );

  const notice = container.querySelector(".inline-notice--warning")!;
  expect(notice.textContent).toContain("Technical scanner/target comparison limitations recorded: 2");
  expect(notice.textContent).toContain("This is not a security-finding count");
});

test("a mapping-version-only limitation says the checks ran rather than implying they did not", () => {
  // Every limitation here is a catalog version change, so the checks did
  // complete. Reusing the generic "comparisons were incomplete" wording would
  // describe work that ran as work that did not, and would push a reader toward
  // rescanning something that was never the problem. The count also switches to
  // engines and says so.
  const { container } = renderVerification(
    summary({
      complete: false,
      completenessIssues: [
        { code: "mapping_version_changed", engineId: "prowler", detail: "catalog 1.2 to 1.3" },
        { code: "mapping_version_changed", engineId: "prowler", detail: "catalog 1.2 to 1.3" },
        { code: "mapping_version_changed", engineId: "trivy", detail: "catalog 1.2 to 1.3" },
      ],
      diffs: [diff({
        id: "a",
        state: "unverifiable",
        changeReasons: [{ code: "mapping_version_changed", engineId: "prowler", detail: "catalog 1.2 to 1.3" }],
      })],
    }),
    bothRunsCompleted,
  );

  const notice = container.querySelector(".inline-notice--warning")!;
  expect(notice.textContent).toContain("Scanner mappings changed between these scans");
  expect(notice.textContent).toContain("completed in both scans");
  // Two distinct engines across three recorded rows.
  expect(notice.textContent).toContain("Affected scanner engines: 2");
  expect(notice.textContent).toContain("not a security-finding count");
  expect(notice.textContent).not.toContain("comparisons were incomplete");

  const row = diffRow(container, "Finding a");
  expect(row.textContent).toContain("control-mapping catalog version changed");
});

test("an outcome filter that matches nothing says an empty list is not an all-clear", () => {
  const { container } = renderVerification(
    summary({ diffs: [diff({ id: "a", state: "persistent", beforeSeverity: "high", afterSeverity: "high" })] }),
    bothRunsCompleted,
  );

  const resolvedFilter = Array.from(container.querySelectorAll<HTMLButtonElement>(".segmented-filter button"))
    .find((button) => button.textContent?.startsWith("No longer observed"));
  expect(resolvedFilter).toBeTruthy();
  fireEvent.click(resolvedFilter!);

  const empty = container.querySelector(".empty-state")!;
  expect(empty.textContent).toContain("No items match this filter");
  expect(empty.textContent).toContain("does not mean there is no risk");
  expect(container.querySelectorAll(".diff-row").length).toBe(0);
});

test("a comparison row whose finding is gone records that rather than offering missing evidence", () => {
  // The baseline finding can be absent from the current list. Rendering the
  // evidence button anyway hands the user a control that opens nothing; saying
  // where the history actually lives is the honest substitute.
  const { container } = renderVerification(
    summary({
      diffs: [
        diff({ id: "a", state: "resolved", findingId: "finding-gone", beforeSeverity: "critical" }),
        diff({ id: "b", state: "persistent", findingId: "finding-present", beforeSeverity: "high", afterSeverity: "high" }),
      ],
    }),
    bothRunsCompleted,
    [{ id: "finding-present" } as Finding],
  );

  const gone = diffRow(container, "Finding a");
  expect(gone.querySelector(".diff-row__action")).toBeNull();
  expect(gone.textContent).toContain("no longer in the current list");
  expect(gone.textContent).toContain("remains in the case package");

  const present = diffRow(container, "Finding b");
  expect(present.querySelector(".diff-row__action")).not.toBeNull();
  expect(present.textContent).not.toContain("no longer in the current list");
});
