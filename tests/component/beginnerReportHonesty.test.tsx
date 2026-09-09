import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type {
  BeginnerMasterReport,
  BeginnerReportFinding,
  BeginnerReportSummary,
  Finding,
  ScanRun,
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
  unattributed: 0,
  manualReview: 0,
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

const greenboneDeadHostReport = (): BeginnerMasterReport => {
  const base = report("partial");
  return report("partial", {
    requested: {
      ...base.requested,
      targets: [{
        assetId: "asset-dead-host",
        label: "silent-host.example",
        assetKind: "host",
        labelAvailability: "recorded",
        assetKindAvailability: "recorded",
      }, {
        assetId: "asset-completed-host",
        label: "checked-host.example",
        assetKind: "host",
        labelAvailability: "recorded",
        assetKindAvailability: "recorded",
      }],
      requestedCheckIds: ["greenbone"],
    },
    actual: {
      checks: [{
        taskId: "greenbone-dead-host",
        checkId: "greenbone",
        resultKind: "security_check",
        targetAssetIds: ["asset-dead-host"],
        status: "failed",
        testedDimensions: [],
      }, {
        taskId: "greenbone-completed-host",
        checkId: "greenbone",
        resultKind: "security_check",
        targetAssetIds: ["asset-completed-host"],
        status: "tested_complete",
        testedDimensions: [{
          dimension: "Greenbone remote vulnerability scan",
          value: "greenbone on asset asset-completed-host",
          observation: "The security check completed for this target.",
        }],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageGaps: [{
      kind: "failed",
      taskId: "greenbone-dead-host",
      targetAssetIds: ["asset-dead-host"],
      dimension: "greenbone: target response",
      reason: "Greenbone reported that this host did not respond during the scan, so none of its vulnerability checks ran. This is not a clean result.",
      nextActionCode: "review_scope_and_retry",
      nextAction: "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.",
    }],
    coverageCounts: counts({ testedComplete: 1, failed: 1 }),
  });
};

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

const renderReport = (
  value: BeginnerMasterReport,
  canonical: Finding[] = [],
  runs: ScanRun[] = [],
) =>
  render(
    <I18nProvider>
      <FindingsPage
        report={value}
        selectedRunId="run-1"
        findings={canonical}
        findingGroups={[]}
        findingGroupEvents={[]}
        coverage={[]}
        runs={runs}
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

const localhostRun = (): ScanRun => ({
  id: "run-1",
  caseId: "case-1",
  label: "Scan 1",
  status: "completed",
  progress: 100,
  startedAt: "2026-09-04T12:00:00Z",
  finishedAt: "2026-09-04T12:00:03Z",
  knowledgeDate: "2026-09-04",
  coveredAssetCount: 1,
  totalAssetCount: 1,
  engineRuns: [{
    id: "localhost-check-1",
    engineId: "built-in-localhost-tcp",
    engineName: "Localhost TCP reachability",
    category: "built_in_localhost_tcp",
    taskKind: { kind: "built_in_localhost_tcp", port: 9001, timeoutMs: 3_000, payloadBytes: 0 },
    localhostTcpObservation: { outcome: "reachable", observedAt: "2026-09-04T12:00:03Z" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    startedAt: "2026-09-04T12:00:00Z",
    finishedAt: "2026-09-04T12:00:03Z",
    assetIds: ["asset-1"],
    rawArtifactCount: 0,
    findingCount: 0,
    resumable: false,
  }],
});

const catalogRun = (engineId: string): ScanRun => {
  const run = localhostRun();
  return {
    ...run,
    engineRuns: [{
      ...run.engineRuns[0]!,
      engineId,
      engineName: engineId,
      category: "inventory",
      taskKind: { kind: "catalog_engine" },
      localhostTcpObservation: undefined,
    }],
  };
};

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

/**
 * One row of the selected finding's provenance list, addressed by its own
 * label. Read this way rather than from `textContent` so a row that stops
 * rendering fails loudly instead of quietly satisfying an absence assertion,
 * and so the four run/date rows cannot be confused with one another.
 */
const provenanceValue = (container: HTMLElement, label: string): string => {
  const section = container.querySelector<HTMLElement>(".provenance-section");
  if (!section) throw new Error("the provenance section did not render");
  const row = Array.from(section.querySelectorAll("dl > div")).find(
    (candidate) => candidate.querySelector("dt")?.textContent === label,
  );
  if (!row) {
    const rendered = Array.from(section.querySelectorAll("dt"))
      .map((term) => term.textContent)
      .join(" / ");
    throw new Error(`no provenance row labelled "${label}"; rendered: ${rendered}`);
  }
  return row.querySelector("dd")?.textContent ?? "";
};

const openFirstFinding = (container: HTMLElement) => {
  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);
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
  expect(completePill.textContent).toContain("Requested checks complete");
  expect(partialPill.textContent).not.toEqual(completePill.textContent);
});

test("the first layer gives every requested asset one evidence-derived result status", () => {
  const base = report("partial");
  const targets = [
    ["asset-repo-a", "team-a/api", "repository"],
    ["asset-repo-b", "team-b/api", "repository"],
    ["asset-web", "https://portal.example", "web_service"],
    ["asset-device", "Branch gateway", "web_service"],
    ["asset-endpoint", "workstation-12", "ip_address"],
  ].map(([assetId, label, assetKind]) => ({
    assetId,
    label,
    assetKind,
    labelAvailability: "recorded" as const,
    assetKindAvailability: "recorded" as const,
  }));
  const { container } = renderReport(report("partial", {
    requested: {
      ...base.requested,
      targets,
      requestedCheckIds: ["trivy", "semgrep", "gitleaks", "naabu"],
    },
    actual: {
      checks: [{
        taskId: "task-web",
        checkId: "trivy",
        targetAssetIds: ["asset-web"],
        status: "tested_complete",
        testedDimensions: [{
          dimension: "completed check-to-target coordinate",
          value: "trivy on asset asset-web",
          observation: "The security check completed for this target.",
        }],
      }, {
        taskId: "task-device-complete",
        checkId: "semgrep",
        targetAssetIds: ["asset-device"],
        status: "tested_complete",
        testedDimensions: [{
          dimension: "completed check-to-target coordinate",
          value: "semgrep on asset asset-device",
          observation: "The security check completed for this target.",
        }],
      }, {
        taskId: "task-device-failed",
        checkId: "gitleaks",
        targetAssetIds: ["asset-device"],
        status: "failed",
        testedDimensions: [],
      }, {
        taskId: "task-endpoint-inventory",
        checkId: "naabu",
        targetAssetIds: ["asset-endpoint"],
        status: "tested_complete",
        testedDimensions: [{
          dimension: "completed planned work units",
          value: "1 of 1",
          observation: "Service discovery completed.",
        }],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    findings: [frozenFinding({
      targetAssetIds: ["asset-repo-a", "asset-repo-b"],
    })],
    coverageGaps: [{
      kind: "failed",
      taskId: "task-repo-a-secondary",
      targetAssetIds: ["asset-repo-a"],
      dimension: "dependency check",
      reason: "A second check failed.",
      nextActionCode: "retry_check",
      nextAction: "Retry the failed check.",
    }, {
      kind: "excluded",
      targetAssetIds: ["asset-web"],
      dimension: "paths outside the selected profile",
      reason: "Only the selected profile was in scope.",
      nextActionCode: "no_action_unless_scope_changes",
      nextAction: "No action is needed unless scope changes.",
    }, {
      kind: "not_tested",
      taskId: "task-web",
      targetAssetIds: ["asset-web"],
      dimension: "authenticated paths",
      reason: "The selected unauthenticated profile did not test signed-in paths.",
      nextActionCode: "preserve_visible_limitation",
      nextAction: "Keep this limit visible.",
    }, {
      kind: "unavailable",
      targetAssetIds: [],
      dimension: "run-level metadata",
      reason: "Granular historical metadata was not retained.",
      nextActionCode: "preserve_visible_limitation",
      nextAction: "Keep this report-level limit visible.",
    }, {
      kind: "not_tested",
      taskId: "task-device-complete",
      targetAssetIds: ["asset-device"],
      dimension: "authenticated administration",
      reason: "The completed profile deliberately excluded signed-in checks.",
      nextActionCode: "preserve_visible_limitation",
      nextAction: "Keep this limitation visible.",
    }, {
      kind: "failed",
      taskId: "task-device-failed",
      targetAssetIds: ["asset-device"],
      dimension: "secret check",
      reason: "The check failed.",
      nextActionCode: "retry_check",
      nextAction: "Retry the failed check.",
    }, {
      kind: "not_tested",
      targetAssetIds: ["asset-endpoint"],
      dimension: "vulnerability checks",
      reason: "Only service discovery ran.",
      nextActionCode: "choose_compatible_check",
      nextAction: "Choose an applicable security check.",
    }, {
      kind: "not_tested",
      taskId: "task-endpoint-later",
      targetAssetIds: ["asset-endpoint"],
      dimension: "later optional check",
      reason: "A later check was not selected.",
      nextActionCode: "retry_check",
      nextAction: "Retry this check.",
    }],
    coverageCounts: counts({ testedComplete: 3, failed: 2, notTested: 4, excluded: 1, unavailable: 1 }),
  }));

  const board = container.querySelector<HTMLElement>(".asset-result-board");
  if (!board) throw new Error("asset result board did not render");
  const rows = Array.from(board.querySelectorAll<HTMLElement>(".asset-result-row"));
  expect(rows).toHaveLength(5);
  const row = (label: string) => {
    const match = rows.find((candidate) =>
      candidate.querySelector(".asset-result-row__identity strong")?.textContent === label);
    if (!match) throw new Error(`no asset result row for ${label}`);
    return match;
  };

  expect(row("team-a/api").dataset.assetResult).toBe("problems_found");
  expect(row("team-a/api").textContent).toContain("1 problem was found.");
  expect(row("team-a/api").textContent).toContain("Some checks are also incomplete");
  // One frozen finding can apply to more than one target; each target must get credit for it.
  expect(row("team-b/api").dataset.assetResult).toBe("problems_found");
  expect(row("https://portal.example").dataset.assetResult).toBe("no_problems_completed");
  expect(row("https://portal.example").textContent).toContain("1 completed security check reported no problems");
  expect(row("https://portal.example").textContent).toContain("Review the stated limits");
  expect(row("Branch gateway").dataset.assetResult).toBe("incomplete_failed");
  expect(row("Branch gateway").textContent).toContain("Retry this check");
  expect(row("Branch gateway").textContent).not.toContain("Keep this limitation visible");
  // A completed inventory tool is not promoted into a completed security check.
  expect(row("workstation-12").dataset.assetResult).toBe("not_tested");
  expect(row("workstation-12").textContent).toContain("Choose an available check for this target");
  expect(row("workstation-12").textContent).not.toContain("Retry this check");

  const technicalDisclosure = container.querySelector<HTMLElement>(".report-scope-disclosure");
  expect(board.compareDocumentPosition(technicalDisclosure!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
});

test.each(["syft", "cloudquery"])(
  "%s-only reports say inventory completed without claiming a clean security check",
  (engineId) => {
    const base = report("complete");
    const value = report("complete", {
      actual: {
        checks: [{
          taskId: `${engineId}-task`,
          checkId: engineId,
          resultKind: "inventory",
          targetAssetIds: ["asset-1"],
          status: "tested_complete",
          testedDimensions: [{
            dimension: "inventory",
            value: engineId,
            observation: "Inventory completed.",
          }],
        }],
        networkScopes: [],
        unavailableDimensions: [],
      },
      requested: { ...base.requested, requestedCheckIds: [engineId] },
    });

    const { container } = renderReport(value, [], [catalogRun(engineId)]);
    const row = container.querySelector<HTMLElement>(".asset-result-row");
    expect(row?.dataset.assetResult).toBe("not_tested");
    expect(container.textContent).toContain("Inventory or connectivity only — no security check ran");
    expect(container.textContent).toContain(
      "This run did not complete a vulnerability, configuration, code, or secret check.",
    );
    expect(container.textContent).not.toContain("completed security check reported no problems");
  },
);

test("a legacy Steampipe-only report without resultKind remains inventory, not a clean security result", () => {
  const base = report("complete");
  const value = report("complete", {
    actual: {
      checks: [{
        taskId: "steampipe-task",
        checkId: "steampipe-aws",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        testedDimensions: [{
          dimension: "cloud resource inventory",
          value: "steampipe",
          observation: "Inventory completed.",
        }],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    requested: { ...base.requested, requestedCheckIds: ["steampipe"] },
  });

  const { container } = renderReport(value, [], [catalogRun("steampipe")]);
  const row = container.querySelector<HTMLElement>(".asset-result-row");
  expect(row?.dataset.assetResult).toBe("not_tested");
  expect(container.querySelector(".page-header")?.textContent).toContain(
    "Inventory or connectivity only — no security check ran",
  );
  expect(container.textContent).toContain(
    "Inventory and connectivity observations are not a no-problems security result.",
  );
  expect(container.textContent).not.toContain("completed security check reported no problems");
});

test("mixed Syft and Trivy work counts only Trivy as a completed security check", () => {
  const value = report("complete", {
    actual: {
      checks: [{
        taskId: "syft-task",
        checkId: "syft",
        resultKind: "inventory",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        testedDimensions: [],
      }, {
        taskId: "trivy-task",
        checkId: "trivy",
        resultKind: "security_check",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
  });

  const { container } = renderReport(value, [], [catalogRun("trivy")]);
  const row = container.querySelector<HTMLElement>(".asset-result-row");
  expect(row?.dataset.assetResult).toBe("no_problems_completed");
  expect(row?.textContent).toContain("1 completed security check reported no problems");
  expect(row?.textContent).not.toContain("2 completed security checks");
});

test("a completed asset stays bounded while an unrun sibling task makes another asset incomplete", () => {
  const base = report("partial");
  const { container } = renderReport(report("partial", {
    requested: {
      ...base.requested,
      targets: [{
        assetId: "asset-bounded",
        label: "ssh-bounded.example",
        assetKind: "host",
        labelAvailability: "recorded",
        assetKindAvailability: "recorded",
      }, {
        assetId: "asset-unrun-sibling",
        label: "ssh-incomplete.example",
        assetKind: "host",
        labelAvailability: "recorded",
        assetKindAvailability: "recorded",
      }],
    },
    actual: {
      checks: [{
        taskId: "task-bounded",
        checkId: "greenbone",
        targetAssetIds: ["asset-bounded"],
        status: "tested_complete",
        testedDimensions: [],
      }, {
        taskId: "task-completed-sibling",
        checkId: "greenbone",
        targetAssetIds: ["asset-unrun-sibling"],
        status: "tested_complete",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageGaps: [{
      kind: "not_tested",
      taskId: "task-bounded",
      targetAssetIds: ["asset-bounded"],
      dimension: "host operating-system checks",
      reason: "The completed SSH service profile did not inspect the host operating system.",
      nextActionCode: "preserve_visible_limitation",
      nextAction: "Keep this limitation visible.",
    }, {
      kind: "not_tested",
      taskId: "task-never-ran",
      targetAssetIds: ["asset-unrun-sibling"],
      dimension: "second requested security check",
      reason: "The second requested task did not run.",
      nextActionCode: "retry_check",
      nextAction: "Retry this check.",
    }],
    coverageCounts: counts({ testedComplete: 2, notTested: 2 }),
  }));

  const rows = Array.from(container.querySelectorAll<HTMLElement>(".asset-result-row"));
  const row = (label: string) => {
    const match = rows.find((candidate) =>
      candidate.querySelector(".asset-result-row__identity strong")?.textContent === label);
    if (!match) throw new Error(`no asset result row for ${label}`);
    return match;
  };

  expect(row("ssh-bounded.example").dataset.assetResult).toBe("no_problems_completed");
  expect(row("ssh-incomplete.example").dataset.assetResult).toBe("incomplete_failed");
  expect(row("ssh-incomplete.example").textContent).toContain("Retry this check");
});

test("a Greenbone dead host is incomplete while a completed sibling stays bounded", () => {
  const { container } = renderReport(greenboneDeadHostReport());
  const rows = Array.from(container.querySelectorAll<HTMLElement>(".asset-result-row"));
  const row = (label: string) => {
    const match = rows.find((candidate) =>
      candidate.querySelector(".asset-result-row__identity strong")?.textContent === label);
    if (!match) throw new Error(`no asset result row for ${label}`);
    return match;
  };

  expect(row("silent-host.example").dataset.assetResult).toBe("incomplete_failed");
  expect(row("silent-host.example").textContent).toContain(
    "Review the requested scope, then retry.",
  );
  expect(row("checked-host.example").dataset.assetResult).toBe("no_problems_completed");
});

test("a Greenbone dead-host gap gives a Traditional Chinese reader the exact cause", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderReport(greenboneDeadHostReport());
  const gapCard = Array.from(container.querySelectorAll<HTMLElement>(".coverage-card"))
    .find((candidate) => candidate.querySelector("h3")?.textContent === "沒有測到的內容");
  if (!gapCard) throw new Error("the coverage-gap card did not render");
  const gapRow = Array.from(gapCard.querySelectorAll<HTMLElement>(".detail-list > li"))
    .find((candidate) => candidate.querySelector("strong")?.textContent === "silent-host.example");
  if (!gapRow) throw new Error("the dead-host coverage-gap row did not render");

  expect(within(gapRow).getByText(
    /Greenbone 回報這台主機在掃描期間沒有回應，因此它的弱點檢查一項都沒有執行。這不是乾淨的結果。/u,
  )).toBeTruthy();
});

test("an in-progress asset keeps its wait-or-cancel action on the per-asset board", () => {
  const { container } = renderReport(report("partial", {
    actual: {
      checks: [{
        taskId: "task-running",
        checkId: "greenbone",
        targetAssetIds: ["asset-1"],
        status: "in_progress",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageGaps: [{
      kind: "not_tested",
      taskId: "task-running",
      targetAssetIds: ["asset-1"],
      dimension: "unfinished check dimension",
      reason: "This check is still changing and has not recorded a complete result.",
      nextActionCode: "wait_or_cancel",
      nextAction: "Let it continue or cancel it; the partial report remains available.",
    }],
    coverageCounts: counts({ notTested: 1 }),
  }));

  const row = container.querySelector<HTMLElement>(".asset-result-row");
  expect(row?.dataset.assetResult).toBe("incomplete_failed");
  expect(row?.textContent).toContain("Let it finish, or cancel and keep the partial report");
});

test("the asset result board gives a Traditional Chinese beginner the same bounded statuses and action", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderReport(report("no_checks_completed", {
    coverageGaps: [{
      kind: "not_tested",
      targetAssetIds: ["asset-1"],
      dimension: "vulnerability checks",
      reason: "No compatible check ran.",
      nextActionCode: "choose_compatible_check",
      nextAction: "Choose a compatible check.",
    }],
    coverageCounts: counts({ notTested: 1 }),
  }));

  const board = container.querySelector<HTMLElement>(".asset-result-board");
  expect(board?.textContent).toContain("哪些資產需要處理");
  expect(board?.textContent).toContain("尚未測試");
  expect(board?.textContent).toContain("這個資產沒有已完成的資安檢查紀錄");
  expect(board?.textContent).toContain("為這個目標選擇可用的檢查");
  expect(board?.textContent).not.toContain("No compatible check ran");
});

test("the first layer names the requested target, tested work, top gap, and next action", () => {
  const base = report("partial");
  const { container } = renderReport(report("partial", {
    requested: {
      ...base.requested,
      limits: [{
        name: "naabu execution timeout",
        value: "30 seconds",
        source: "frozen_task_contract",
      }],
    },
    actual: {
      observedFrom: "2026-09-04T12:00:00Z",
      observedUntil: "2026-09-04T12:01:00Z",
      checks: [{
        taskId: "task-1",
        checkId: "naabu-tcp",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        startedAt: "2026-09-04T12:00:00Z",
        finishedAt: "2026-09-04T12:01:00Z",
        testedDimensions: [{
          dimension: "completed planned work units",
          value: "1 of 1",
          observation: "The planned connection check completed.",
        }],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageGaps: [{
      kind: "not_tested",
      targetAssetIds: ["asset-1"],
      dimension: "TLS configuration",
      reason: "The TLS check did not start.",
      nextActionCode: "review_scope_and_retry",
      nextAction: "Review the target and retry.",
    }, {
      kind: "excluded",
      targetAssetIds: ["asset-1"],
      dimension: "ports outside the requested port set",
      reason: "Only the requested ports were in scope.",
      nextActionCode: "no_action_unless_scope_changes",
      nextAction: "No action is needed unless you change the scope.",
    }],
    coverageCounts: counts({ testedComplete: 1, excluded: 1 }),
    nextSteps: [{
      priority: 1,
      code: "review_scope_and_retry",
      action: "Review the target and retry.",
      reason: "The TLS check did not start.",
      taskId: "task-2",
    }],
  }));

  const strip = container.querySelector<HTMLElement>(".report-outcome-strip");
  expect(strip).not.toBeNull();
  expect(strip!.closest("details")).toBeNull();
  expect(strip!.textContent).toContain("contoso.example");
  expect(strip!.textContent).toContain("naabu-tcp");
  expect(strip!.textContent).toContain("TLS configuration");
  expect(strip!.textContent).toContain("The TLS check did not start.");
  expect(strip!.textContent).toContain("Review the requested scope, then retry.");

  const firstLayerScope = container.querySelector<HTMLElement>(".report-first-layer-scope");
  expect(firstLayerScope).not.toBeNull();
  expect(firstLayerScope!.closest("details")).toBeNull();
  expect(firstLayerScope!.textContent).toContain("Requested: contoso.example");
  expect(firstLayerScope!.textContent).toContain("Scan depth: Full inventory");
  expect(firstLayerScope!.textContent).toContain("Limits: naabu execution timeout: 30 seconds");
  expect(firstLayerScope!.textContent).toContain("completed planned work units: 1 of 1");
  expect(firstLayerScope!.textContent).toMatch(/Time: Observed .+ to .+/u);
  expect(firstLayerScope!.textContent).toContain("Recorded exclusions: contoso.example · ports outside the requested port set");
});

test("the tested time window excludes failed sibling task activity", () => {
  const testedFrom = "2026-09-04T12:00:00Z";
  const testedUntil = "2026-09-04T12:01:00Z";
  const allTasksFrom = "2026-08-01T01:00:00Z";
  const allTasksUntil = "2026-10-20T23:00:00Z";
  const formatDateTime = (value: string) => new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
  const { container } = renderReport(report("partial", {
    actual: {
      // These backend bounds cover both tasks and therefore cannot describe
      // only what was actually tested.
      observedFrom: allTasksFrom,
      observedUntil: allTasksUntil,
      checks: [{
        taskId: "task-tested",
        checkId: "naabu-tcp",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        startedAt: testedFrom,
        finishedAt: testedUntil,
        testedDimensions: [{
          dimension: "completed planned work units",
          value: "1 of 1",
          observation: "The planned connection check completed.",
          observedAt: testedUntil,
        }],
      }, {
        taskId: "task-failed",
        checkId: "tls-configuration",
        targetAssetIds: ["asset-1"],
        status: "failed",
        startedAt: allTasksFrom,
        finishedAt: allTasksUntil,
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageCounts: counts({ testedComplete: 1, failed: 1 }),
  }));

  const firstLayerScope = container.querySelector<HTMLElement>(".report-first-layer-scope");
  expect(firstLayerScope).not.toBeNull();
  expect(firstLayerScope!.textContent).toContain(
    `Time: Observed ${formatDateTime(testedFrom)} to ${formatDateTime(testedUntil)}`,
  );
  expect(firstLayerScope!.textContent).not.toContain(formatDateTime(allTasksFrom));
  expect(firstLayerScope!.textContent).not.toContain(formatDateTime(allTasksUntil));
});

test("the tested time is explicitly unavailable when only all-task bounds were retained", () => {
  const { container } = renderReport(report("partial", {
    actual: {
      observedFrom: "2026-08-01T01:00:00Z",
      observedUntil: "2026-10-20T23:00:00Z",
      checks: [{
        taskId: "task-tested-without-time",
        checkId: "configuration-review",
        targetAssetIds: ["asset-1"],
        status: "tested_partial",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageCounts: counts({ testedPartial: 1 }),
  }));

  const firstLayerScope = container.querySelector<HTMLElement>(".report-first-layer-scope");
  expect(firstLayerScope?.textContent).toContain("Time: Observation time not retained");
});

test("the first layer does not drop a completed check whose exact dimensions were not saved", () => {
  const base = report("partial");
  const { container } = renderReport(report("partial", {
    actual: {
      checks: [{
        taskId: "task-with-dimension",
        checkId: "naabu-tcp",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        testedDimensions: [{
          dimension: "completed planned work units",
          value: "1 of 1",
          observation: "The planned connection check completed.",
        }],
      }, {
        taskId: "task-without-dimension",
        checkId: "configuration-review",
        targetAssetIds: ["asset-1"],
        status: "tested_partial",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    requested: {
      ...base.requested,
      requestedCheckIds: ["naabu-tcp", "configuration-review"],
    },
  }));

  const firstLayerScope = container.querySelector<HTMLElement>(".report-first-layer-scope");
  expect(firstLayerScope?.textContent).toContain("naabu-tcp");
  expect(firstLayerScope?.textContent).toContain("configuration-review");
  expect(firstLayerScope?.textContent).toContain("Exact tested dimensions not saved for this check");
});

test("a generic completed coordinate uses display labels without leaking backend identities", () => {
  const internalAssetId = "asset-7d0e1278-43de-4cb1-a451-2b7448bd30d6";
  const rawEngineId = "catalog-secret-check-internal-v17";
  const rawCoordinate = `${rawEngineId} on asset ${internalAssetId}`;
  const targetLabel = "Contoso source repository";
  const checkLabel = "Source code secret check";
  const base = report("complete");
  const catalogRun = localhostRun();
  catalogRun.engineRuns = [{
    ...catalogRun.engineRuns[0]!,
    id: "task-catalog",
    engineId: rawEngineId,
    engineName: checkLabel,
    category: "source-code",
    taskKind: { kind: "catalog_engine" },
    localhostTcpObservation: undefined,
  }];

  const { container } = renderReport(report("complete", {
    requested: {
      ...base.requested,
      targets: [{
        assetId: internalAssetId,
        label: targetLabel,
        assetKind: "repository",
        labelAvailability: "recorded",
        assetKindAvailability: "recorded",
      }],
      requestedCheckIds: [rawEngineId],
    },
    actual: {
      checks: [{
        taskId: "task-catalog",
        checkId: rawEngineId,
        targetAssetIds: [internalAssetId],
        status: "tested_complete",
        startedAt: "2026-09-04T12:00:00Z",
        finishedAt: "2026-09-04T12:01:00Z",
        testedDimensions: [{
          dimension: "completed check-to-target coordinate",
          value: rawCoordinate,
          observation: "The durable task reached completed state for this target binding.",
          observedAt: "2026-09-04T12:01:00Z",
        }, {
          dimension: "files examined",
          value: "42 files",
          observation: "The saved result recorded a human-readable file count.",
          observedAt: "2026-09-04T12:01:00Z",
        }],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageCounts: counts({ testedComplete: 1 }),
  }), [], [catalogRun]);

  const firstLayer = container.querySelector<HTMLElement>(".report-first-layer-scope");
  expect(firstLayer).not.toBeNull();
  expect(firstLayer!.textContent).toContain(`${checkLabel} completed for ${targetLabel}`);
  expect(firstLayer!.textContent).toContain("files examined: 42 files");
  expect(firstLayer!.textContent).not.toContain(rawEngineId);
  expect(firstLayer!.textContent).not.toContain(internalAssetId);
  expect(firstLayer!.textContent).not.toContain(rawCoordinate);

  const testedOutcome = container.querySelector<HTMLElement>(".report-outcome-strip");
  expect(testedOutcome?.textContent).toContain(checkLabel);
  expect(testedOutcome?.textContent).not.toContain(rawEngineId);

  const technicalScope = container.querySelector<HTMLElement>(".report-scope-disclosure");
  expect(technicalScope?.textContent).toContain(rawCoordinate);
});

test("an absent coverage gap is scoped to the requested checks rather than implying broad security coverage", () => {
  const { container } = renderReport(report("complete"));

  // Zero is a claim about this run's requested checks, never about broader
  // security coverage. Both the label and detail keep that boundary visible.
  //
  // The claim is made in two places and each is asserted separately: a
  // page-wide text match passes while either one still says it, which would
  // let the other be replaced by a stronger claim unnoticed.
  const metric = Array.from(container.querySelectorAll<HTMLElement>(".metric-card")).find(
    (card) => card.querySelector(".metric-card__label")?.textContent === "Recorded coverage gaps",
  );
  if (!metric) throw new Error("the coverage-gap metric card did not render");
  expect(metric.querySelector(".metric-card__value")?.textContent).toBe("0");
  expect(metric.querySelector(".metric-card__detail")?.textContent).toBe(
    "No gap was recorded within the requested checks. This does not mean broader security testing was performed.",
  );

  const gapsCard = Array.from(container.querySelectorAll<HTMLElement>(".coverage-card")).find(
    (card) => card.querySelector("h3")?.textContent === "What was not tested",
  );
  if (!gapsCard) throw new Error("the coverage-gap card did not render");
  expect(gapsCard.textContent).toContain(
    "No gap was recorded within the requested checks. This does not mean broader security testing was performed.",
  );
});

test("a completed localhost connection check puts its exact exclusions in the master report", () => {
  const base = report("complete");
  const { container } = renderReport(report("complete", {
    requested: {
      ...base.requested,
      stage: {
        value: "connection_diagnostic",
        availability: "recorded",
        explanation: "A bounded connection diagnostic, not a vulnerability scan.",
      },
    },
  }), [], [localhostRun()]);
  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  if (!section) throw new Error("the beginner report section did not render");

  expect(container.querySelector(".page-header")?.textContent).toContain(
    "Connection test only — no vulnerability scan ran",
  );
  expect(statePill(container).textContent).toContain("Connection result only");
  expect(section.textContent).toContain("Connection test (not a vulnerability scan)");
  expect(section.textContent).toContain(
    "Not checked: vulnerabilities, protocol behavior, website or API content, other ports, or other hosts.",
  );
  expect(section.textContent).not.toContain(
    "No gap was recorded within the requested checks. This does not mean broader security testing was performed.",
  );
});

test("a mixed run does not apply localhost-only exclusions to the whole report", () => {
  const mixedRun = localhostRun();
  mixedRun.engineRuns.push({
    ...mixedRun.engineRuns[0]!,
    id: "other-check-1",
    engineId: "other-security-check",
    engineName: "Other security check",
    category: "other",
    taskKind: { kind: "catalog_engine" },
  });

  const { container } = renderReport(report("complete"), [], [mixedRun]);
  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  if (!section) throw new Error("the beginner report section did not render");

  expect(container.querySelector(".page-header")?.textContent).not.toContain(
    "Connection test only — no vulnerability scan ran",
  );
  expect(section.textContent).toContain(
    "No gap was recorded within the requested checks. This does not mean broader security testing was performed.",
  );
  expect(section.textContent).not.toContain(
    "Not checked: vulnerabilities, protocol behavior, website or API content, other ports, or other hosts.",
  );
});

test("two gaps of the same kind give the reader two different reasons", () => {
  // The row's sentence used to come from `kind` alone. The backend writes a
  // distinct reason for each situation and `not_tested` covers three of them --
  // a check that saved partial work, one that never started, one still running
  // -- so one sentence per kind was false for two of every three rows, and
  // contradicted the dimension printed beside it.
  window.localStorage.setItem(localeStorageKey, "en");
  const { container } = renderReport(
    report("partial", {
      coverageGaps: [
        {
          kind: "not_tested",
          targetAssetIds: ["asset-1"],
          dimension: "trivy: not-tested check dimension",
          reason: "This check did not start, so it is not a pass.",
          nextActionCode: "review_scope_and_retry",
          nextAction: "Review the target and try this check again.",
        },
        {
          kind: "not_tested",
          targetAssetIds: ["asset-1"],
          dimension: "trivy: unfinished check dimension",
          reason: "This check is still changing and has not recorded a complete result.",
          nextActionCode: "wait_or_cancel",
          nextAction: "Let it continue or cancel it; the partial report remains available.",
        },
      ],
    }),
  );

  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  const disclosure = section!.querySelector<HTMLElement>(".report-scope-disclosure");
  expect(within(disclosure!).getByText(/This check did not start, so it is not a pass\./u)).toBeTruthy();
  expect(
    within(disclosure!).getByText(/This check is still changing and has not recorded a complete result\./u),
  ).toBeTruthy();
  expect(within(disclosure!).getByText(/Review the target and try this check again\./u)).toBeTruthy();
});

test("a Traditional Chinese reader is told the same two reasons", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderReport(
    report("partial", {
      coverageGaps: [
        {
          kind: "not_tested",
          targetAssetIds: ["asset-1"],
          dimension: "trivy: not-tested check dimension",
          reason: "This check did not start, so it is not a pass.",
          nextActionCode: "review_scope_and_retry",
          nextAction: "Review the target and try this check again.",
        },
      ],
    }),
  );

  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  const disclosure = section!.querySelector<HTMLElement>(".report-scope-disclosure");
  expect(within(disclosure!).getByText(/這項檢查沒有啟動，因此不代表通過。/u)).toBeTruthy();
  expect(within(disclosure!).getByText(/trivy 的未檢測的檢查項目/u)).toBeTruthy();
  expect(section!.textContent).not.toContain("This check did not start");
  window.localStorage.setItem(localeStorageKey, "en");
});

test("a Traditional Chinese reader sees requested-limit units in their language", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderReport(
    report("complete", {
      requested: {
        ...report("complete").requested,
        limits: [{
          name: "gitleaks execution timeout",
          value: "600 seconds",
          source: "frozen_task_contract",
        }],
      },
    }),
  );

  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  expect(section!.textContent).toContain("600 秒");
  expect(section!.textContent).not.toContain("600 seconds");
});

test("a Traditional Chinese reader hears why completed network coverage is not a security pass", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const englishObservation =
    "These exact frozen work units have validated completed outcomes across all saved attempts. A completed network check reports reachability; it is not a security pass.";
  const { container } = renderReport(
    report("complete", {
      actual: {
        checks: [{
          taskId: "task-naabu",
          checkId: "naabu-tcp",
          targetAssetIds: ["asset-1"],
          status: "tested_complete",
          startedAt: "2026-09-04T12:00:00Z",
          finishedAt: "2026-09-04T12:01:00Z",
          testedDimensions: [{
            dimension: "completed planned work units",
            value: "1 of 1",
            observation: englishObservation,
            observedAt: "2026-09-04T12:01:00Z",
          }],
        }],
        networkScopes: [],
        unavailableDimensions: [],
      },
    }),
  );

  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='beginner-master-report-title']",
  );
  expect(section!.textContent).toContain("完成的網路檢查只回報連線是否可達；不代表安全性檢查通過。");
  expect(section!.textContent).not.toContain(englishObservation);
  window.localStorage.setItem(localeStorageKey, "en");
});

test("reachable-service inventory is not counted or triaged as a vulnerability", () => {
  const observation = frozenFinding({
    title: "Externally reachable network service",
    plainLanguageRisk: "Naabu observed a reachable service.",
    possibleImpact: "Legacy impact wording that must not become a problem claim.",
    severity: "info",
    severityBasisCode: "open_port",
    observationDetails: ["port:443", "protocol:tcp"],
    nextStep: "Legacy remediation that must not become a priority.",
  });
  const { container } = renderReport(report("complete", {
    actual: {
      checks: [{
        taskId: "httpx-task",
        checkId: "httpx",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    findings: [observation],
    nextSteps: [{
      priority: 0,
      code: "review_finding",
      action: observation.nextStep,
      reason: observation.title,
      findingId: observation.findingId,
    }],
  }));

  expect(container.textContent).toContain("Reachable services observed — not vulnerabilities");
  expect(container.querySelector(".page-header")?.textContent).toContain(
    "Inventory or connectivity only — no security check ran",
  );
  expect(statePill(container).textContent).toContain("Inventory or connectivity only");
  expect(container.textContent).toContain("Port 443");
  expect(container.textContent).toContain("Protocol tcp");
  expect(container.textContent).toContain("choose an applicable security check");
  expect(container.textContent).not.toContain(observation.possibleImpact);
  expect(container.textContent).not.toContain(observation.nextStep);
  expect(container.textContent).toContain(
    "Review the saved results and stated limits. Run broader checks if you need broader assurance.",
  );
  const nextActionsHeading = Array.from(container.querySelectorAll("h3"))
    .find((heading) => heading.textContent === "What to do next");
  expect(nextActionsHeading?.parentElement?.nextElementSibling?.tagName).toBe("P");
  const problemMetric = Array.from(container.querySelectorAll<HTMLElement>(".metric-card"))
    .find((card) => card.textContent?.includes("Problems found"));
  expect(problemMetric?.textContent).toContain("0");
  expect(container.querySelector("#finding-browser")).toBeNull();
});

test("typed inventory leads over legacy exposure rows and presents all three scanner-neutral kinds", () => {
  const source = (id: string, engineId: string) => ({
    observationId: id,
    engineId,
    engineRunId: `${engineId}-task`,
    artifactId: `${id}-artifact`,
    artifactSha256: "a".repeat(64),
    pointer: `/items/${id}`,
    observedAt: "2026-09-04T12:00:00Z",
  });
  const items: NonNullable<BeginnerMasterReport["inventory"]>["items"] = [{
    kind: "service",
    assetId: "asset-1",
    endpoint: "10.0.0.5",
    port: 443,
    transport: "tcp",
    schemes: ["https"],
    httpStatuses: [200],
    tlsObservations: [true],
    sources: [
      source("service-naabu", "naabu"),
      source("service-naabu-second", "naabu"),
      source("service-httpx", "httpx"),
    ],
  }, {
    kind: "software_component",
    assetId: "asset-1",
    name: "scanner <component>",
    version: "1.2.3",
    packageType: "npm",
    purl: "pkg:npm/scanner-component@1.2.3",
    sources: [source("component", "syft")],
  }, {
    kind: "cloud_resource",
    assetId: "asset-1",
    resourceType: "aws_s3_bucket",
    nativeId: "bucket-1",
    displayName: "Uploads & archives",
    sources: [source("cloud", "cloudquery")],
  }];
  const legacyExposure = frozenFinding({
    title: "Legacy reachable service that must not duplicate typed inventory",
    severity: "info",
    severityBasisCode: "open_port",
    observationDetails: ["port:443", "protocol:tcp"],
  });
  const value = report("complete", {
    actual: {
      checks: [{
        taskId: "inventory-task",
        checkId: "syft",
        resultKind: "inventory",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    inventory: {
      total: 3,
      counts: { services: 1, softwareComponents: 1, cloudResources: 1 },
      assetIds: ["asset-1"],
      representativeSample: items,
      items,
      byAsset: [{
        assetId: "asset-1",
        total: 3,
        counts: { services: 1, softwareComponents: 1, cloudResources: 1 },
        representativeSample: items,
      }],
    },
    findings: [legacyExposure],
  });

  const { container, unmount } = renderReport(value, [], [catalogRun("syft")]);
  expect(container.textContent).toContain("What the scanners inventoried");
  expect(container.textContent).toContain("3 inventory items across 1 assets");
  expect(container.textContent).toContain("10.0.0.5:443");
  expect(container.textContent).toContain("scanner <component>");
  expect(container.textContent).toContain("Uploads & archives");
  expect(container.textContent).toContain("Sources: 3 · httpx, naabu");
  expect(container.textContent).not.toContain("naabu, naabu");
  expect(container.textContent).not.toContain("Reachable services observed — not vulnerabilities");
  expect(container.textContent).not.toContain(legacyExposure.title);
  expect(container.textContent).not.toContain("completed security check reported no problems");
  expect(container.querySelector("#finding-browser")).toBeNull();
  unmount();

  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const zh = renderReport(value, [], [catalogRun("syft")]);
  expect(zh.container.textContent).toContain("掃描工具盤點到的項目");
  expect(zh.container.textContent).toContain("共 3 個盤點項目，分布於 1 個資產");
  expect(zh.container.textContent).toContain("這些是服務、軟體元件與雲端資源，不是資安問題或修復建議。");
  window.localStorage.setItem(localeStorageKey, "en");
});

test("service inventory leads with counts and three examples while retaining every observation in a collapsed list", () => {
  const observations = Array.from({ length: 5 }, (_, index) => frozenFinding({
    findingId: `observation-${index + 1}`,
    fingerprint: `observation-fingerprint-${index + 1}`,
    title: `Reachable service ${index + 1}`,
    severity: "info",
    severityBasisCode: index % 2 === 0 ? "open_port" : "reachable_http_service",
    targetAssetIds: [`asset-${(index % 3) + 1}`],
    observationDetails: [`port:${8000 + index}`, "protocol:tcp"],
  }));
  const base = report("complete");
  const { container } = renderReport({
    ...base,
    requested: {
      ...base.requested,
      targets: [1, 2, 3].map((number) => ({
        assetId: `asset-${number}`,
        label: `service-${number}.example`,
        assetKind: "domain",
        labelAvailability: "recorded" as const,
        assetKindAvailability: "recorded" as const,
      })),
    },
    findings: observations,
  });

  const section = container.querySelector<HTMLElement>(
    "section[aria-labelledby='service-observations-title']",
  );
  expect(section).not.toBeNull();
  expect(section!.querySelector(".service-observations__summary")?.textContent)
    .toContain("5 observed services across 3 assets");

  const representatives = section!.querySelector<HTMLElement>(
    ".service-observations__representatives",
  );
  expect(representatives?.querySelectorAll(".evidence-item")).toHaveLength(3);
  expect(representatives?.textContent).toContain("Port 8000");
  expect(representatives?.textContent).not.toContain("Port 8004");

  const complete = section!.querySelector<HTMLDetailsElement>(
    ".service-observations__complete",
  );
  expect(complete?.open).toBe(false);
  expect(complete?.textContent).toContain("View all 5 observed services");
  expect(complete?.querySelectorAll(".evidence-item")).toHaveLength(5);
  expect(complete?.textContent).toContain("Port 8004");
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
  const disclosure = section!.querySelector<HTMLElement>(".report-scope-disclosure");
  expect(within(disclosure!).getByText(/automatic scope reductions or truncations/u)).toBeTruthy();
  expect(within(disclosure!).getByText(/requested scan stage/u)).toBeTruthy();
  expect(container.textContent).not.toContain("No gap was recorded within the requested checks.");
});

test("saved-data limitations are surfaced, not held in the model", () => {
  const warning = "One task's saved evidence index could not be read.";
  const { container } = renderReport(
    report("partial", {
      dataQualityWarnings: [warning],
    }),
  );

  const firstLayerCount = container.querySelector<HTMLElement>(".report-data-warning-count");
  expect(firstLayerCount).not.toBeNull();
  expect(firstLayerCount!.closest("details")).toBeNull();
  expect(firstLayerCount!.textContent).toContain("Saved-data limitations: 1");
  expect(firstLayerCount!.textContent).not.toContain(warning);

  const technicalDetails = container.querySelector<HTMLElement>(".page-technical-details");
  expect(technicalDetails).not.toBeNull();
  expect(within(technicalDetails!).getByText(warning)).toBeTruthy();
});

test("priority comes before summary metrics", () => {
  const { container } = renderReport(
    report("partial", { findings: [frozenFinding()] }),
    [canonicalFinding()],
  );

  const page = container.querySelector<HTMLElement>(".page");
  const priority = container.querySelector<HTMLElement>(".priority-section");
  const metrics = container.querySelector<HTMLElement>("section[aria-label='Problem summary']");
  expect(page).not.toBeNull();
  expect(priority).not.toBeNull();
  expect(metrics).not.toBeNull();
  const children = Array.from(page!.children);
  expect(children.indexOf(priority!)).toBeLessThan(children.indexOf(metrics!));
});

test("priority cards show target, location, confidence, next action, and verification before opening details", () => {
  const combinedReport = report("partial", {
    findings: [frozenFinding({
      targetAssetIds: ["asset-1", "asset-2"],
      nextStep: "Ask the application owner to update the affected dependency.",
      verificationGuidance: "After the approved update, rerun the same dependency check.",
      evidenceReferences: [{
        evidenceId: "evidence-1",
        engineId: "trivy",
        artifactSha256: "a".repeat(64),
        observedAt: "2026-09-04T12:00:00Z",
        location: "package-lock.json · lodash@4.17.20",
      }],
    })],
  });
  combinedReport.requested.targets.push({
    assetId: "asset-2",
    label: "internal-api.example",
    assetKind: "web_service",
    labelAvailability: "recorded",
    assetKindAvailability: "recorded",
  });
  const { container } = renderReport(
    combinedReport,
    [canonicalFinding()],
  );

  const card = container.querySelector<HTMLElement>(".priority-card");
  expect(card).not.toBeNull();
  expect(card!.textContent).toContain("High confidence");
  expect(card!.textContent).toContain("Affected target");
  expect(card!.textContent).toContain("contoso.example");
  expect(card!.textContent).toContain("internal-api.example");
  expect(card!.textContent).toContain("Location");
  expect(card!.textContent).toContain("package-lock.json · lodash@4.17.20");
  expect(card!.textContent).toContain("Next action");
  expect(card!.textContent).toContain("Ask the application owner to update the affected dependency.");
  expect(card!.textContent).toContain("Verify the fix");
  expect(card!.textContent).toContain("After the approved update, rerun the same dependency check.");
  expect(container.querySelector<HTMLElement>(".finding-detail")?.classList.contains("finding-detail--empty")).toBe(true);
});

test("run-bound upstream rule identity reaches the finding evidence drawer", () => {
  const { container } = renderReport(report("partial", {
    findings: [frozenFinding({
      evidenceReferences: [{
        evidenceId: "evidence-1",
        engineId: "trivy",
        detailsFrozen: true,
        sourceRule: "CVE-2026-12345",
        summary: "Frozen evidence summary",
        artifactSha256: "a".repeat(64),
        observedAt: "2026-09-04T12:00:00Z",
      }],
    })],
  }));

  openFirstFinding(container);
  const evidenceDetails = container.querySelector<HTMLElement>(".evidence-provenance");
  expect(evidenceDetails).not.toBeNull();
  expect(evidenceDetails!.textContent).toContain("Source rule");
  expect(evidenceDetails!.textContent).toContain("CVE-2026-12345");
});

test("scanner HTML descriptions remain complete visible text and never become active markup", () => {
  const upstreamDescription =
    '<p>These policies allow a combination of IAM actions that allow a principal with these permissions to escalate their privileges - for example, by creating an access key for another IAM user, or modifying their own permissions. This research was pioneered by Spencer Gietzen at Rhino Security Labs. Remediation guidance can be found <a href="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/">here</a>.</p>';
  const { container } = renderReport(report("partial", {
    findings: [frozenFinding({
      evidenceReferences: [{
        evidenceId: "evidence-cloudsplaining-1",
        engineId: "cloudsplaining",
        detailsFrozen: true,
        sourceRule: "PrivilegeEscalation",
        scannerDetails: { description: upstreamDescription },
        artifactSha256: "a".repeat(64),
        observedAt: "2026-09-04T12:00:00Z",
      }],
    })],
  }));

  openFirstFinding(container);
  const description = container.querySelector<HTMLElement>(
    ".scanner-evidence-description p",
  );
  expect(description).not.toBeNull();
  expect(description!.textContent).toBe(upstreamDescription);
  expect(description!.querySelector("a")).toBeNull();
  expect(description!.innerHTML).toContain("&lt;p&gt;");
  expect(description!.innerHTML).toContain("&lt;a href=");
});

test.each([
  {
    locale: "en",
    heading: "AWS IAM policy context",
    sourceLabel: "Policy source",
    source: "AWS-managed",
    policyLabel: "Policy",
    findingLabel: "Upstream finding",
    actionsLabel: "Retained actions",
    actionsIncomplete: "The action list was shortened or sanitized for display. Open the raw evidence for the complete upstream list.",
    more: "+2 more",
    rolesLabel: "Attached roles",
    groupsLabel: "Attached groups",
    usersLabel: "Attached users",
    incomplete: "The retained attachment list is incomplete. Confirm the current IAM attachments before changing this policy.",
  },
  {
    locale: "zh-TW",
    heading: "AWS IAM 政策脈絡",
    sourceLabel: "政策來源",
    source: "AWS 受管",
    policyLabel: "政策",
    findingLabel: "上游問題",
    actionsLabel: "已保留的動作",
    actionsIncomplete: "動作清單為了顯示而經過縮減或清理；完整上游清單請查看原始證據。",
    more: "另有 2 項",
    rolesLabel: "附加的角色",
    groupsLabel: "附加的群組",
    usersLabel: "附加的使用者",
    incomplete: "保留的附加清單不完整；變更此政策前請先核對目前的 IAM 附加關係。",
  },
])("Cloudsplaining policy evidence is readable and inert in $locale", ({
  locale,
  heading,
  sourceLabel,
  source,
  policyLabel,
  findingLabel,
  actionsLabel,
  actionsIncomplete,
  more,
  rolesLabel,
  groupsLabel,
  usersLabel,
  incomplete,
}) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const policyName = '<img src=x onerror="window.__policyExecuted=true">AdministratorAccess';
  const findingIdentity = '<script>window.__findingExecuted=true</script>PrivilegeEscalation';
  const upstreamAction = '<svg onload="window.__actionExecuted=true">iam:PassRole</svg>';
  const role = '<a href="javascript:window.__roleExecuted=true">ApplicationRole</a>';
  const group = "<button>BillingOperators</button>";
  const user = "<iframe srcdoc='<script>window.__userExecuted=true</script>'>release-user</iframe>";
  const { container } = renderReport(report("partial", {
    findings: [frozenFinding({
      nextStep:
        "Have the recommended specialist (Cloud identity specialist) review the affected policy and source evidence, then replace the AWS-managed policy with a narrower policy.",
      recommendedExpertType: "Cloud identity specialist",
      family: "cloud_identity",
      evidenceReferences: [{
        evidenceId: "evidence-cloudsplaining-policy",
        engineId: "cloudsplaining",
        detailsFrozen: true,
        sourceRule: "PrivilegeEscalation",
        scannerDetails: {
          awsIamPolicy: {
            policySource: "aws_managed",
            policyName,
            findingIdentity,
            actions: [
              upstreamAction,
              "iam:Visible1",
              "iam:Visible2",
              "iam:Visible3",
              "iam:Visible4",
              "iam:Visible5",
              "iam:Hidden6",
              "iam:Hidden7",
            ],
            actionsComplete: false,
            attachedTo: {
              roles: [role],
              groups: [group],
              users: [user],
              complete: false,
            },
          },
        },
        artifactSha256: "a".repeat(64),
        observedAt: "2026-09-04T12:00:00Z",
      }],
    })],
  }));

  openFirstFinding(container);
  const context = Array.from(
    container.querySelectorAll<HTMLElement>(".scanner-evidence-description"),
  ).find((candidate) => candidate.querySelector("strong")?.textContent === heading);
  expect(context).not.toBeUndefined();
  for (const expected of [
    heading,
    sourceLabel,
    source,
    policyLabel,
    policyName,
    findingLabel,
    findingIdentity,
    actionsLabel,
    upstreamAction,
    actionsIncomplete,
    more,
    rolesLabel,
    role,
    groupsLabel,
    group,
    usersLabel,
    user,
    incomplete,
  ]) {
    expect(context!.textContent).toContain(expected);
  }
  expect(context!.querySelector("img, script, svg, a, button, iframe")).toBeNull();
  expect(context!.textContent).not.toContain("iam:Hidden6");
  expect(context!.textContent).not.toContain("iam:Hidden7");
});

test("selected-run evidence details and references do not drift to the current canonical finding", () => {
  const { container } = renderReport(
    report("partial", {
      findings: [frozenFinding({
        officialReferences: ["https://example.test/frozen-rule"],
        evidenceReferences: [{
          evidenceId: "evidence-1",
          engineId: "trivy",
          detailsFrozen: true,
          sourceRule: "CVE-2026-FROZEN",
          scannerDetails: {
            description: "Frozen upstream package description",
            remediation: "Frozen upstream remediation; human review required",
            installedVersion: "1.0.0",
            fixedVersion: "1.0.1",
          },
          summary: "Frozen selected-run evidence summary",
          kind: "package_inventory",
          engineRunId: "task-frozen",
          artifactId: "artifact-frozen",
          redacted: false,
          artifactSha256: "a".repeat(64),
          observedAt: "2026-09-04T12:00:00Z",
          location: "package-lock.json · frozen-package@1.0.0",
        }],
      })],
    }),
    [canonicalFinding({
      officialReferences: ["https://example.test/current-rule"],
      evidence: [{
        id: "evidence-1",
        sourceEngine: "different-current-engine",
        sourceRule: "CVE-2026-CURRENT",
        scannerDetails: {
          description: "Current scanner description must not drift backward",
          remediation: "Current scanner remediation must not drift backward",
          installedVersion: "9.0.0",
          fixedVersion: "9.0.1",
        },
        observedAt: "2026-09-08T12:00:00Z",
        summary: "Different current evidence summary",
        location: "current-location",
        rawArtifactHash: "b".repeat(64),
        kind: "configuration",
        runId: "run-current",
        engineRunId: "task-current",
        artifactId: "artifact-current",
        redacted: true,
      }],
    })],
  );

  openFirstFinding(container);
  const evidence = container.querySelector<HTMLElement>(".finding-detail .evidence-list .evidence-item");
  expect(evidence).not.toBeNull();
  expect(evidence!.textContent).toContain("Frozen selected-run evidence summary");
  expect(evidence!.textContent).toContain("CVE-2026-FROZEN");
  expect(evidence!.textContent).toContain("package inventory");
  expect(evidence!.textContent).toContain("Frozen upstream package description");
  expect(evidence!.textContent).toContain("Observed version");
  expect(evidence!.textContent).toContain("1.0.0");
  expect(evidence!.textContent).toContain("Scanner-reported fixed version");
  expect(evidence!.textContent).toContain("1.0.1");
  expect(evidence!.textContent).toContain("Scanner-provided remediation — review before acting");
  expect(evidence!.textContent).toContain("Frozen upstream remediation; human review required");
  expect(evidence!.textContent).toContain("untrusted scanner evidence, not the product's recommended next step");
  expect(evidence!.textContent).toContain("task-frozen");
  expect(evidence!.textContent).toContain("artifact-frozen");
  expect(evidence!.textContent).toContain("Not marked as redacted");
  expect(evidence!.textContent).not.toContain("CURRENT");
  expect(evidence!.textContent).not.toContain("Different current");
  expect(evidence!.textContent).not.toContain("Current scanner");
  expect(evidence!.textContent).not.toContain("9.0");

  const links = Array.from(container.querySelectorAll<HTMLAnchorElement>('a[href^="https://example.test/"]'));
  expect(links.map((link) => link.href)).toEqual(["https://example.test/frozen-rule"]);
});

test("a frozen absence stays unavailable instead of borrowing newer canonical evidence", () => {
  const { container } = renderReport(
    report("partial", {
      findings: [frozenFinding({
        officialReferences: [],
        evidenceReferences: [{
          evidenceId: "evidence-1",
          engineId: "trivy",
          detailsFrozen: true,
          artifactSha256: "a".repeat(64),
          observedAt: "2026-09-04T12:00:00Z",
        }],
      })],
    }),
    [canonicalFinding({
      officialReferences: ["https://example.test/newer-reference"],
      evidence: [{
        id: "evidence-1",
        sourceEngine: "trivy",
        sourceRule: "NEWER-RULE",
        scannerDetails: {
          description: "NEWER-SCANNER-DESCRIPTION",
          remediation: "NEWER-SCANNER-REMEDIATION",
          installedVersion: "9.0.0",
          fixedVersion: "9.0.1",
        },
        observedAt: "2026-09-08T12:00:00Z",
        summary: "Newer canonical evidence must not fill a frozen absence",
        rawArtifactHash: "b".repeat(64),
        kind: "configuration",
        engineRunId: "newer-task",
        artifactId: "newer-artifact",
        redacted: true,
      }],
    })],
  );

  openFirstFinding(container);
  const detail = container.querySelector<HTMLElement>(".finding-detail");
  expect(detail!.textContent).toContain("The selected run did not retain an evidence summary.");
  expect(detail!.textContent).not.toContain("NEWER-RULE");
  expect(detail!.textContent).not.toContain("Newer canonical evidence");
  expect(detail!.textContent).not.toContain("NEWER-SCANNER");
  expect(detail!.textContent).not.toContain("newer-task");
  expect(detail!.textContent).not.toContain("newer-artifact");
  expect(container.querySelector('a[href="https://example.test/newer-reference"]')).toBeNull();
  expect(detail!.textContent).toContain("No official reference link is recorded for this finding");
});

test("an older report falls back only through the same retained evidence ID", () => {
  const { container } = renderReport(
    report("partial", {
      findings: [frozenFinding({
        evidenceReferences: [{
          evidenceId: "evidence-legacy",
          engineId: "trivy",
          artifactSha256: "a".repeat(64),
          observedAt: "2026-09-04T12:00:00Z",
        }],
      })],
    }),
    [canonicalFinding({
      evidence: [{
        id: "evidence-legacy",
        sourceEngine: "trivy",
        sourceRule: "LEGACY-RULE",
        scannerDetails: {
          description: "Legacy exact-ID scanner description",
          remediation: "Legacy exact-ID scanner remediation",
          installedVersion: "2.0.0",
          fixedVersion: "2.0.1",
        },
        observedAt: "2026-09-04T12:00:00Z",
        summary: "Legacy exact-ID fallback summary",
        rawArtifactHash: "a".repeat(64),
        kind: "package_inventory",
        engineRunId: "legacy-task",
        artifactId: "legacy-artifact",
        redacted: true,
      }, {
        id: "different-evidence",
        sourceEngine: "trivy",
        sourceRule: "WRONG-RULE",
        observedAt: "2026-09-08T12:00:00Z",
        summary: "Wrong evidence must never be guessed",
        rawArtifactHash: "b".repeat(64),
      }],
    })],
  );

  openFirstFinding(container);
  const detail = container.querySelector<HTMLElement>(".finding-detail");
  expect(detail!.textContent).toContain("Legacy exact-ID fallback summary");
  expect(detail!.textContent).toContain("LEGACY-RULE");
  expect(detail!.textContent).toContain("legacy-task");
  expect(detail!.textContent).toContain("Legacy exact-ID scanner description");
  expect(detail!.textContent).toContain("Legacy exact-ID scanner remediation");
  expect(detail!.textContent).not.toContain("WRONG-RULE");
  expect(detail!.textContent).not.toContain("Wrong evidence must never be guessed");
});

test("target-controlled raw evidence text is never relabelled as remediation guidance", () => {
  const rawSentinel = "RAW_TARGET_SENTINEL_DO_NOT_FOLLOW";
  const { container } = renderReport(report("partial", {
    findings: [frozenFinding({
      nextStep: "Use the product-owned safe next step.",
      evidenceReferences: [{
        evidenceId: "evidence-raw",
        engineId: "nuclei",
        detailsFrozen: true,
        summary: rawSentinel,
        artifactSha256: "a".repeat(64),
        observedAt: "2026-09-04T12:00:00Z",
      }],
    })],
  }));

  openFirstFinding(container);
  const evidence = container.querySelector<HTMLElement>(".finding-detail .evidence-list .evidence-item");
  expect(evidence!.textContent).toContain(rawSentinel);
  expect(evidence!.querySelector(".scanner-evidence-remediation")).toBeNull();
  expect(evidence!.textContent).not.toContain("Scanner-provided remediation");
  expect(container.querySelector<HTMLElement>(".detail-section--advice")!.textContent)
    .toContain("Use the product-owned safe next step.");
});

test("scanner remediation keeps its review boundary in Traditional Chinese", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderReport(report("partial", {
    findings: [frozenFinding({
      evidenceReferences: [{
        evidenceId: "evidence-1",
        engineId: "trivy",
        detailsFrozen: true,
        scannerDetails: { remediation: "UPSTREAM_REMEDIATION_TEXT" },
        summary: "Frozen evidence summary",
        artifactSha256: "a".repeat(64),
        observedAt: "2026-09-04T12:00:00Z",
      }],
    })],
  }));

  openFirstFinding(container);
  const remediation = container.querySelector<HTMLElement>(".scanner-evidence-remediation");
  expect(remediation!.textContent).toContain("掃描器提供的修復資訊——採取行動前請先審查");
  expect(remediation!.textContent).toContain("未受信任的掃描器證據，不是產品建議的下一步");
  expect(remediation!.textContent).toContain("UPSTREAM_REMEDIATION_TEXT");
});

test("an affected asset without a retained label remains visible by exact ID", () => {
  const { container } = renderReport(report("partial", {
    findings: [frozenFinding({
      targetAssetIds: ["asset-1", "asset-label-unavailable"],
    })],
  }));

  const card = container.querySelector<HTMLElement>(".priority-card");
  expect(card).not.toBeNull();
  expect(card!.textContent).toContain("contoso.example");
  expect(card!.textContent).toContain("asset-label-unavailable");
});

test("the first report layer filters by exact asset identity, including shared findings", () => {
  const combinedReport = report("partial", {
    requested: {
      ...report("partial").requested,
      targets: [
        {
          assetId: "asset-1",
          label: "https://edge.example:443",
          assetKind: "web_service",
          labelAvailability: "recorded",
          assetKindAvailability: "recorded",
        },
        {
          assetId: "asset-2",
          label: "https://edge.example:8443",
          assetKind: "web_service",
          labelAvailability: "recorded",
          assetKindAvailability: "recorded",
        },
      ],
    },
    findings: [
      frozenFinding({ findingId: "finding-1", targetAssetIds: ["asset-1"], title: "Port 443 issue" }),
      frozenFinding({ findingId: "finding-2", fingerprint: "fp-2", targetAssetIds: ["asset-2"], title: "Port 8443 issue" }),
      frozenFinding({ findingId: "finding-3", fingerprint: "fp-3", targetAssetIds: ["asset-1", "asset-2"], title: "Shared certificate issue" }),
    ],
  });
  const { container } = renderReport(combinedReport, [
    canonicalFinding({ id: "finding-1", assetId: "asset-1", assetIds: ["asset-1"], title: "Port 443 issue" }),
    canonicalFinding({ id: "finding-2", fingerprint: "fp-2", assetId: "asset-2", assetIds: ["asset-2"], assetName: "https://edge.example:8443", title: "Port 8443 issue" }),
    canonicalFinding({ id: "finding-3", fingerprint: "fp-3", assetId: "asset-1", assetIds: ["asset-1", "asset-2"], title: "Shared certificate issue" }),
  ]);

  const assetRows = [...container.querySelectorAll<HTMLButtonElement>(".affected-asset-row")];
  expect(assetRows).toHaveLength(2);
  expect(assetRows.map((row) => row.textContent)).toEqual([
    expect.stringContaining("https://edge.example:443"),
    expect.stringContaining("https://edge.example:8443"),
  ]);
  expect(assetRows.every((row) => row.textContent?.includes("Problems: 2"))).toBe(true);

  fireEvent.click(assetRows[1]!);
  expect((within(container).getByRole("searchbox") as HTMLInputElement).value).toBe("");
  expect(container.querySelector(".finding-asset-filter")?.textContent).toContain("https://edge.example:8443");
  expect([...container.querySelectorAll(".finding-row")].map((row) => row.textContent)).toEqual([
    expect.stringContaining("Port 8443 issue"),
    expect.stringContaining("Shared certificate issue"),
  ]);
  expect([...container.querySelectorAll(".finding-row")].some((row) => row.textContent?.includes("Port 443 issue"))).toBe(false);
  expect(container.querySelector<HTMLElement>(".finding-detail")?.classList.contains("finding-detail--empty")).toBe(false);
});

test("specialist and framework filters are in one closed Advanced disclosure", () => {
  const { container } = renderReport(
    report("partial", { findings: [frozenFinding()] }),
    [canonicalFinding()],
  );

  const advanced = container.querySelector<HTMLDetailsElement>(".finding-advanced-filters");
  expect(advanced).not.toBeNull();
  expect(advanced!.open).toBe(false);
  expect(advanced!.querySelector("summary")?.textContent).toBe("Advanced filters");
  expect(within(advanced!).getByRole("combobox", { name: "Specialist type" })).toBeTruthy();
  expect(within(advanced!).getByRole("combobox", { name: "Framework reference" })).toBeTruthy();

  const severityFilter = within(container).getByRole("combobox", { name: "Severity" });
  const workflowFilter = within(container).getByRole("combobox", { name: "Review status" });
  expect(severityFilter.closest("details")).toBeNull();
  expect(workflowFilter.closest("details")).toBeNull();
});

test("finding pills carry review and confidence without repeating them in detail facts", () => {
  const finding = frozenFinding({ confidence: "medium" });
  const { container } = renderReport(
    report("partial", { findings: [finding] }),
    [canonicalFinding({ confidence: "medium" })],
  );

  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);

  const pills = container.querySelector<HTMLElement>(".finding-detail__header .tag-row");
  expect(pills).not.toBeNull();
  expect(pills!.textContent).toContain("Medium confidence");
  expect(pills!.textContent).toContain("Not reviewed");

  const factLabels = Array.from(container.querySelectorAll<HTMLElement>(".detail-facts dt"))
    .map((label) => label.textContent);
  expect(factLabels).not.toContain("Review status");
  expect(factLabels).not.toContain("Evidence confidence");
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
  openFirstFinding(container);

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
  openFirstFinding(container);

  expect(container.textContent).toContain("No official reference link is recorded for this finding");
  expect(container.textContent).not.toContain("was provided");
});

test("a finding carried over from earlier runs is not presented as new", () => {
  // The frozen snapshot has no first/last-seen fields, so the projection had
  // been stamping the run being viewed onto all four. Under labels that read
  // "First-seen run" and "First observed" with no qualifier, that answered "is
  // this new, or has it been here for months?" with "new" every time -- for a
  // finding the backend deliberately carries a first-seen run across every
  // merge and replacement precisely so the answer can be no.
  const { container } = renderReport(
    report("partial", { findings: [frozenFinding()] }),
    [canonicalFinding({
      firstSeenRunId: "run-0",
      lastSeenRunId: "run-3",
      firstSeenAt: "2024-03-02T09:00:00Z",
      lastSeenAt: "2025-11-20T09:00:00Z",
    })],
  );
  openFirstFinding(container);

  // The report under view is `run-1`, so neither id below can have come from it.
  expect(provenanceValue(container, "First-seen run")).toBe("run-0");
  expect(provenanceValue(container, "Last-seen run")).toBe("run-3");
  // Asserted by calendar day rather than exact string because the value goes
  // through `formatDateTime`. The frozen finding carries no evidence, so the old
  // fallback was the report's own `lastDurableUpdate` -- Sep 4, the day that has
  // to stay absent from both rows.
  expect(provenanceValue(container, "First observed")).toContain("Mar 2");
  expect(provenanceValue(container, "First observed")).not.toContain("Sep 4");
  expect(provenanceValue(container, "Last observed")).toContain("Nov 20");
  expect(provenanceValue(container, "Last observed")).not.toContain("Sep 4");
});

test("a first-seen date carries the year that makes it an age", () => {
  // Wiring the real history through is spent if the renderer drops the part
  // that makes it legible. The shared `formatDateTime` default is month, day,
  // hour, minute -- so a finding first seen two years ago renders as "Mar 2,
  // 04:00 AM", indistinguishable from one first seen this spring, and the row
  // stops answering the only question it is there to answer.
  const { container } = renderReport(
    report("partial", { findings: [frozenFinding()] }),
    [canonicalFinding({
      firstSeenAt: "2024-03-02T09:00:00Z",
      lastSeenAt: "2025-11-20T09:00:00Z",
    })],
  );
  openFirstFinding(container);

  expect(provenanceValue(container, "First observed")).toContain("2024");
  expect(provenanceValue(container, "Last observed")).toContain("2025");
  // The same claim is repeated in the prominent facts list above the fold,
  // where a year-less date is read first and by more people.
  const facts = container.querySelector<HTMLElement>(".detail-facts");
  expect(facts).toBeTruthy();
  const lastObserved = Array.from(facts!.querySelectorAll("div")).find(
    (row) => row.querySelector("dt")?.textContent === "Last observed",
  );
  expect(lastObserved?.querySelector("dd")?.textContent).toContain("2025");
});

test("a finding the case no longer holds reports no first-seen run rather than this one", () => {
  // The mirror, and the reason the run ids are dropped instead of falling back:
  // the finding appearing in this run does not establish that this run saw it
  // first, so there is nothing left to say but that it is not recorded.
  const { container } = renderReport(
    report("partial", { findings: [frozenFinding()] }),
    [],
  );
  openFirstFinding(container);

  expect(provenanceValue(container, "First-seen run")).toBe("Not reported");
  expect(provenanceValue(container, "Last-seen run")).toBe("Not reported");
});

test("a coverage gap names the cause the backend actually recorded", () => {
  // `not_tested` is assigned to a check that saved partial work, one that never
  // started, and one still running. The row used to compose its sentence from
  // the kind, which cannot tell those apart, so it named one cause and the
  // dimension printed beside it named another. It now shows the reason the
  // backend wrote for this gap, which is the one that matches.
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
  const disclosure = section!.querySelector<HTMLElement>(".report-scope-disclosure");
  const row = within(disclosure!).getByText(/remaining requested dimensions/u).textContent ?? "";
  expect(row).toContain("did not complete every planned dimension");
  // The causes this kind covers but this gap is not. Naming one of them here
  // would contradict the dimension in the same row.
  expect(row).not.toContain("did not start");
  expect(row).not.toContain("still changing");
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
  expect(notice!.textContent).toContain("not an audit, certification, compliance decision, or automatic fix");
  expect(notice!.textContent).toContain("independent, unofficial mapping");
});

test("each saved-data limitation is shown, not replaced by a coverage sentence", () => {
  // The backend writes a distinct plain-language explanation per warning: a run
  // whose stored project id does not match, a saved completion time beside a
  // still-active check, a coverage history that could not be reconciled. The
  // page rendered the count and then one fixed sentence about a run not
  // retaining enough detail -- which is about coverage, and false for every one
  // of those causes.
  const warnings = [
    "The selected run's stored project identifier does not match this project. The report remains limited to the selected in-project record.",
    "This run has a saved completion time while at least one check is still active. The report follows the check state and remains live instead of presenting a final result.",
  ];
  const { container } = renderReport(report("partial", { dataQualityWarnings: warnings }));

  const notice = Array.from(container.querySelectorAll<HTMLElement>(".inline-notice"))
    .find((candidate) => candidate.textContent?.includes("Saved-data limitations"));
  expect(notice).toBeTruthy();
  expect(notice!.textContent).toContain("Saved-data limitations: 2");

  const shown = Array.from(notice!.querySelectorAll("li")).map((item) => item.textContent);
  expect(shown).toEqual(warnings);
  expect(notice!.textContent).not.toContain("did not retain enough detail");
});

test("a Traditional Chinese reader sees translated report data-quality prose", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const english = "The selected run's stored project identifier does not match this project. The report remains limited to the selected in-project record.";
  const { container } = renderReport(report("partial", { dataQualityWarnings: [english] }));
  expect(container.textContent).toContain("所選掃描輪次儲存的專案識別碼與此專案不符。報告仍只限於專案內所選的記錄。");
  expect(container.textContent).not.toContain(english);
});

test("a report with no saved-data limitation shows no such notice", () => {
  // The mirror: without it the list above could render unconditionally and the
  // count would be the only thing distinguishing a clean report.
  const { container } = renderReport(report("partial"));

  const notice = Array.from(container.querySelectorAll<HTMLElement>(".inline-notice"))
    .find((candidate) => candidate.textContent?.includes("Saved-data limitations"));
  expect(notice).toBeUndefined();
});

// The check ran, produced results, and none of them could be tied to anything
// the reader authorized. The findings list is empty and nothing about that is
// the reader's fault -- but only they can fix it, and only if they are told
// which identifier is missing. Before this the sentence naming it existed
// solely as English prose in a collapsed technical block on another page.
const unattributedGap = {
  kind: "unattributed" as const,
  taskId: "task-1",
  targetAssetIds: [],
  dimension: "prowler: results for aws 123456789012",
  reason:
    "prowler reported 42 result(s) for aws identifier 123456789012. No authorized asset carries that identifier, so none of them were attributed and none appear in this report.",
  nextActionCode: "add_asset_identifier" as const,
  nextAction:
    "Add 123456789012 as an aws identifier on the asset you authorized, then scan again.",
  unattributed: { provider: "aws", identifier: "123456789012", discardedResults: 42 },
};

test("a completed Maester review item is visible without being labelled untested", () => {
  const base = report("complete");
  const manualReviewGap = {
    kind: "manual_review" as const,
    taskId: "task-maester",
    targetAssetIds: ["asset-1"],
    dimension: "maester: manual review for MT.1003 — Legacy methods need review",
    reason:
      "Maester evaluated this control but did not return a pass or fail verdict. It requires manual review and is not a vulnerability finding. Upstream detail: Confirm the tenant exception.",
    nextActionCode: "review_manual_control" as const,
    nextAction: "Review the upstream detail and record a human decision for this control.",
  };
  const { container } = renderReport(report("complete", {
    actual: {
      ...base.actual,
      checks: [{
        taskId: "task-maester",
        checkId: "maester",
        resultKind: "security_check",
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        testedDimensions: [],
      }],
    },
    coverageGaps: [manualReviewGap],
    coverageCounts: counts({ testedComplete: 1, manualReview: 1 }),
  }));
  const rendered = container.textContent ?? "";

  expect(rendered).toContain("Coverage limits and manual review");
  expect(rendered).toContain("What needs attention");
  expect(rendered).toContain("Manual review");
  expect(rendered).toContain("Confirm the tenant exception");
  expect(rendered).not.toContain("What was not tested");
  const assetRow = container.querySelector<HTMLElement>(".asset-result-row");
  expect(assetRow?.dataset.assetResult).toBe("no_problems_completed");
  expect(assetRow?.textContent).toContain("record a human decision");
});

test("an empty findings list caused by a missing identifier names that identifier", () => {
  const { container } = renderReport(
    report("partial", { coverageGaps: [unattributedGap], coverageCounts: counts({ unattributed: 1 }) }),
  );
  const rendered = container.textContent ?? "";

  // The identifier is the fix, so it has to be on screen, not just in the
  // payload. Both the explanation and the instruction carry it.
  expect(rendered).toContain("123456789012");
  expect(rendered).toContain("42");
  expect(rendered).toContain("aws");
});

test("the identifier a zh-TW reader must copy is not stranded in English", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderReport(
    report("partial", { coverageGaps: [unattributedGap], coverageCounts: counts({ unattributed: 1 }) }),
  );
  const rendered = container.textContent ?? "";

  expect(rendered).not.toContain(unattributedGap.reason);
  expect(rendered).not.toContain(unattributedGap.nextAction);
  expect(rendered).toContain("你已授權的資產都沒有登記這個識別碼");
  expect(rendered).toContain("然後重新掃描");
  // The identifier and the provider are the engine's own strings. Restating
  // them in Chinese would send the reader hunting for something that does not
  // exist in the console they have to open.
  expect(rendered).toContain("123456789012");
  expect(rendered).toContain("aws");
});
