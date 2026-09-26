import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { BeginnerMasterReport, Finding, ScanRun } from "../../src/types";

// The Results evidence card and the shared HTML report both start from the
// same coordinate string `source_coordinate_location` writes
// (src-tauri/src/adapters/mod.rs) and the same adapter-composed restatement
// sentence. `case_service.rs` already made three decisions about them: show
// the location on its own, drop a summary that only restates its
// neighbours, and state the untrusted-evidence caveat once in the footer
// instead of on every record. This file checks the Results page makes the
// same decisions, using the real KICS shapes from a 47-finding zh-TW scan.

const KICS_RULE = "38c5ee0d-7f22-4260-ab72-5073048df100";
const KICS_LOCATION =
  "infra/main.tf:line=3:resource=resource:demo-logs-bucket,similarity:6ed736ab0df4cde21ce2716cc0a80470709d43045ca36a0c897af1f7913f1009";
const RESTATING_SUMMARY =
  `kics reported rule ${KICS_RULE} at ${KICS_LOCATION}. Raw target text is retained only as untrusted evidence.`;
const NON_RESTATING_SUMMARY =
  "Bucket policy grants public read. Raw target text is retained only as untrusted evidence.";
const READABLE_LOCATION: Record<"en" | "zh-TW", string> = {
  en: "infra/main.tf · line 3 · demo-logs-bucket",
  "zh-TW": "infra/main.tf · 第 3 行 · demo-logs-bucket",
};
const REPORTED_LOCATION_LABEL: Record<"en" | "zh-TW", string> = { en: "Location", "zh-TW": "位置" };
const UNTRUSTED_EVIDENCE_TERM: Record<"en" | "zh-TW", string> = {
  en: "Target text quoted in an evidence summary is retained as untrusted input and is not interpreted by this report.",
  "zh-TW": "證據摘要引用的目標文字，是以不受信任的輸入形式保留，本報告不會加以解讀。",
};

/** The one engine run the fixture finding's evidence points at. */
const kicsRun = (): ScanRun => ({
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
    id: "engine-run-kics",
    engineId: "kics",
    engineName: "KICS",
    category: "infrastructure_as_code",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    startedAt: "2026-09-04T12:00:00Z",
    finishedAt: "2026-09-04T12:00:03Z",
    assetIds: ["asset-1"],
    rawArtifactCount: 1,
    savedResultArtifactCount: 1,
    findingCount: 1,
    resumable: false,
  }],
});

/** A finding with one KICS evidence record, positioned to render as a priority card. */
const kicsFinding = (summary: string): Finding => ({
  id: "finding-kics",
  fingerprint: "fingerprint-kics",
  assetId: "asset-1",
  assetName: "example-repo",
  title: "Terraform bucket allows public read",
  summary: "Bucket policy grants public read.",
  impact: "Cloud resources or data could face unexpected access, alteration, or use.",
  recommendation: "Restrict the bucket policy to approved principals.",
  expertType: "Cloud security engineer",
  severity: "high",
  confidence: "high",
  priority: 1,
  workflowState: "unreviewed",
  evidence: [{
    id: "evidence-1",
    sourceEngine: "kics",
    sourceRule: KICS_RULE,
    summary,
    location: KICS_LOCATION,
    observedAt: "2026-09-04T12:00:00Z",
    rawArtifactHash: "a".repeat(64),
    engineRunId: "engine-run-kics",
  }],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-04T12:00:00Z",
  lastSeenAt: "2026-09-04T12:00:00Z",
});

/** A minimal frozen report whose one finding's one evidence reference carries `summary`. */
const reportWithEvidenceSummary = (summary: string): BeginnerMasterReport => ({
  schemaVersion: "1.0.0",
  caseId: "case-1",
  runId: "run-1",
  projectTitle: "Contoso baseline",
  state: {
    summary: "complete",
    lifecycle: "final",
    lastDurableUpdate: "2026-09-04T12:00:00Z",
    explanation: "Recorded from the run's durable task state.",
  },
  requested: {
    targets: [],
    stage: { value: "inventory", availability: "recorded", explanation: "Recorded with the run." },
    limits: [],
    requestedCheckIds: [],
    automaticReductions: [],
    reductionsAvailability: "recorded",
    unavailableDimensions: [],
  },
  actual: { checks: [], networkScopes: [], unavailableDimensions: [] },
  coverageGaps: [],
  coverageCounts: {
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
  },
  findings: [{
    findingId: "finding-1",
    fingerprint: "fp-1",
    snapshotSource: "frozen_selected_run",
    title: "Terraform bucket allows public read",
    plainLanguageRisk: "Anyone can read the bucket contents.",
    possibleImpact: "Sensitive data could be exposed.",
    severity: "high",
    confidence: "high",
    priority: 1,
    priorityReasons: [],
    targetAssetIds: ["asset-1"],
    nextStep: "Restrict the bucket.",
    recommendedExpertType: "security",
    evidenceReferences: [{
      evidenceId: "evidence-1",
      engineId: "kics",
      detailsFrozen: true,
      summary,
      artifactSha256: "a".repeat(64),
      observedAt: "2026-09-04T12:00:00Z",
    }],
    frameworkReferences: [],
  }],
  nextSteps: [],
  technicalDetails: { collapsedByDefault: true, tasks: [] },
  frameworkNotice: { nonCertification: "Not a certification.", aidefendMappingStatus: "Mapped." },
  dataQualityWarnings: [],
});

/** Renders the plain problem list -- no frozen report -- with one finding selected. */
const renderFinding = (summary: string) => {
  const result = render(
    <I18nProvider>
      <FindingsPage
        findings={[kicsFinding(summary)]}
        findingGroups={[]}
        findingGroupEvents={[]}
        runs={[kicsRun()]}
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
  return result;
};

/** Renders only a frozen report, so `ReportEndMatter` is the surface under test. */
const renderReportEndMatter = (summary: string) =>
  render(
    <I18nProvider>
      <FindingsPage
        report={reportWithEvidenceSummary(summary)}
        selectedRunId="run-1"
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

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test.each(["en", "zh-TW"] as const)(
  "the priority card and evidence card read the KICS location as a place (%s)",
  (locale) => {
    window.localStorage.setItem(localeStorageKey, locale);
    const { container } = renderFinding(RESTATING_SUMMARY);
    const readableLocation = READABLE_LOCATION[locale];

    // 1. The priority card's location line.
    const priorityCard = container.querySelector<HTMLElement>(".priority-card");
    if (!priorityCard) throw new Error("priority card did not render");
    expect(priorityCard.textContent).toContain(readableLocation);
    expect(priorityCard.textContent).not.toContain("similarity:");

    // 2. The evidence card in the detail panel.
    const evidenceItem = container.querySelector<HTMLElement>(".evidence-item");
    if (!evidenceItem) throw new Error("evidence card did not render");
    expect(evidenceItem.querySelector(".evidence-item__header > strong")?.textContent).toBe("KICS");
    expect(evidenceItem.textContent).not.toContain("reported rule");
    expect(evidenceItem.textContent).not.toContain("Raw target text");

    const locationBlock = evidenceItem.querySelector(".scanner-evidence-location");
    if (!locationBlock) throw new Error("evidence location did not render");
    expect(locationBlock.querySelector("strong")?.textContent).toBe(REPORTED_LOCATION_LABEL[locale]);
    expect(locationBlock.querySelector("p")?.textContent).toBe(readableLocation);

    const technicalCode = Array.from(evidenceItem.querySelectorAll("code")).map((node) => node.textContent);
    expect(technicalCode).toContain(KICS_LOCATION);
  },
);

test.each(["en", "zh-TW"] as const)(
  "a summary that adds its own sentence survives caveat stripping without being dropped (%s)",
  (locale) => {
    window.localStorage.setItem(localeStorageKey, locale);
    const { container } = renderFinding(NON_RESTATING_SUMMARY);

    const evidenceItem = container.querySelector<HTMLElement>(".evidence-item");
    if (!evidenceItem) throw new Error("evidence card did not render");
    expect(evidenceItem.textContent).toContain("Bucket policy grants public read.");
    expect(evidenceItem.textContent).not.toContain("Raw target text is retained only as untrusted evidence.");
  },
);

test.each(["en", "zh-TW"] as const)(
  "the report end matter states the untrusted-evidence term once a stored summary carries it (%s)",
  (locale) => {
    window.localStorage.setItem(localeStorageKey, locale);
    const { container } = renderReportEndMatter(RESTATING_SUMMARY);

    const endMatter = container.querySelector<HTMLElement>(".report-end-matter");
    if (!endMatter) throw new Error("report end matter did not render");
    const term = UNTRUSTED_EVIDENCE_TERM[locale];
    const occurrences = (endMatter.textContent?.split(term).length ?? 1) - 1;
    expect(occurrences).toBe(1);
  },
);

test.each(["en", "zh-TW"] as const)(
  "the report end matter adds no untrusted-evidence term when no stored summary carries it (%s)",
  (locale) => {
    window.localStorage.setItem(localeStorageKey, locale);
    const { container } = renderReportEndMatter("Bucket policy grants public read.");

    const endMatter = container.querySelector<HTMLElement>(".report-end-matter");
    if (!endMatter) throw new Error("report end matter did not render");
    expect(endMatter.textContent).not.toContain(UNTRUSTED_EVIDENCE_TERM[locale]);
  },
);
