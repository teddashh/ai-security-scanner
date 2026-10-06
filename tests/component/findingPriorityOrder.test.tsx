import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { PASSWORD_COMPOSITION_ORDER_REASON } from "../../src/findingNarrative";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type {
  BeginnerMasterReport,
  BeginnerReportFinding,
  EngineRun,
  Finding,
  ScanRun,
} from "../../src/types";

// The scanner's severity stays on the pill. A benchmark the scanner reported,
// and a reason this product ordered the check lower, are separate lines.

const COMPOSITION_ZH =
  "處理順序比嚴重程度所示更後面。CIS AWS Foundations Benchmark v1.2.0 要求這項字元規則，但之後的 CIS 版本已移除，NIST SP 800-63B-4 也要求不要強制混合字元類型。請先確認密碼長度與 MFA；只有在必須通過的稽核仍要求這項規則時，才需要變更。";
const BENCHMARK_EN =
  "Benchmark: CIS Amazon Web Services Foundations 1.2.0 item 1.5 (reported by ScoutSuite)";
const BENCHMARK_ZH =
  "基準：CIS Amazon Web Services Foundations 1.2.0 第 1.5 項（ScoutSuite 回報）";
const PARTIAL_ACTION =
  "Review the account's IAM password policy. Fix the failed length or reuse settings first; change the character-mix or expiry settings only if an audit you must pass still requires them.";

const benchmark = {
  name: "CIS Amazon Web Services Foundations",
  version: "1.2.0",
  reference: "1.5",
};

const scoutRun = (): ScanRun => ({
  id: "run",
  caseId: "case",
  label: "AWS review",
  status: "completed",
  progress: 100,
  startedAt: "2026-10-06T12:00:00Z",
  finishedAt: "2026-10-06T12:05:00Z",
  knowledgeDate: "2026-10-06",
  coveredAssetCount: 1,
  totalAssetCount: 1,
  engineRuns: [{
    id: "engine-scout",
    engineId: "scoutsuite",
    engineName: "ScoutSuite",
    category: "cloud_configuration",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: ["aws"],
    rawArtifactCount: 1,
    savedResultArtifactCount: 1,
    findingCount: 1,
    resumable: false,
  } satisfies EngineRun],
});

const uppercaseFinding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "uppercase",
  fingerprint: "uppercase",
  assetId: "aws",
  assetName: "AWS account",
  title: "Password Policy Lacks Uppercase Requirement",
  summary: "ScoutSuite reported this condition on the assessed asset.",
  impact: "A password can be set without an uppercase character.",
  recommendation: "Review the account password policy.",
  expertType: "cloud",
  severity: "high",
  confidence: "medium",
  priority: 90,
  priorityReasons: [
    "Direct scanner evidence is attached.",
    PASSWORD_COMPOSITION_ORDER_REASON,
  ],
  workflowState: "unreviewed",
  evidence: [{
    id: "evidence-uppercase",
    sourceEngine: "scoutsuite",
    engineRunId: "engine-scout",
    sourceRule: "iam-password-policy-uppercase",
    observedAt: "2026-10-06T12:00:00Z",
    summary: "Password policy does not require an uppercase character.",
    rawArtifactHash: "a".repeat(64),
    scannerDetails: { benchmarks: [benchmark] },
  }],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-10-06T12:00:00Z",
  lastSeenAt: "2026-10-06T12:00:00Z",
  ...overrides,
});

const secretFinding = (): Finding => uppercaseFinding({
  id: "secret",
  fingerprint: "secret",
  title: "Hardcoded secret",
  summary: "Gitleaks reported a secret.",
  impact: "A hardcoded secret can be reused.",
  recommendation: "Remove the secret.",
  severity: "high",
  priority: 40,
  priorityReasons: ["The affected asset is internet-accessible."],
  evidence: [{
    id: "evidence-secret",
    sourceEngine: "gitleaks",
    observedAt: "2026-10-06T12:00:00Z",
    summary: "A secret pattern was found.",
    rawArtifactHash: "b".repeat(64),
  }],
});

const renderPage = (findings: Finding[], report?: BeginnerMasterReport) => {
  const result = render(
    <I18nProvider>
      <FindingsPage
        report={report}
        findings={findings}
        findingGroups={[]}
        findingGroupEvents={[]}
        runs={[scoutRun()]}
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
  const firstFinding = result.container.querySelector<HTMLButtonElement>(".finding-row");
  if (firstFinding) fireEvent.click(firstFinding);
  return result;
};

const cardText = (container: HTMLElement, title: string): string =>
  [...container.querySelectorAll(".priority-card")]
    .find((card) => card.textContent?.includes(title))
    ?.textContent ?? "";

const sectionText = (container: HTMLElement, heading: string): string =>
  [...container.querySelectorAll(".finding-detail .detail-section")]
    .find((section) => section.querySelector("h3")?.textContent === heading)
    ?.textContent ?? "";

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("the drawer keeps High and shows the scanner benchmark beside the lower order", () => {
  window.localStorage.setItem(localeStorageKey, "en");
  const english = renderPage([uppercaseFinding(), secretFinding()]);
  const advice = english.container.querySelector(".detail-section--advice")?.textContent ?? "";
  expect(advice).toContain(BENCHMARK_EN);
  expect(sectionText(english.container, "Why this order")).toContain(PASSWORD_COMPOSITION_ORDER_REASON);
  expect(sectionText(english.container, "Why this order")).not.toContain("Direct scanner evidence is attached.");
  expect(english.container.querySelector(".finding-detail__header .status-pill--danger")?.textContent?.trim()).toBe("High");
  expect(cardText(english.container, "Password Policy Lacks Uppercase Requirement")).toContain("Why this order");
  expect(cardText(english.container, "Password Policy Lacks Uppercase Requirement")).toContain(PASSWORD_COMPOSITION_ORDER_REASON);
  expect(cardText(english.container, "Hardcoded secret")).not.toContain("Why this order");
  cleanup();

  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const chinese = renderPage([uppercaseFinding()]);
  const chineseAdvice = chinese.container.querySelector(".detail-section--advice")?.textContent ?? "";
  expect(chineseAdvice).toContain(BENCHMARK_ZH);
  expect(sectionText(chinese.container, "排序原因")).toContain(COMPOSITION_ZH);
  expect(chinese.container.querySelector(".finding-detail__header .status-pill--danger")?.textContent?.trim()).toBe("高");
});

test("a partly lowered password-policy group says what to fix first", () => {
  window.localStorage.setItem(localeStorageKey, "en");
  const member = (id: string, severity: BeginnerReportFinding["severity"]): BeginnerReportFinding => ({
    findingId: id,
    fingerprint: id,
    snapshotSource: "frozen_selected_run",
    title: `Original ${id}`,
    plainLanguageRisk: `Risk ${id}`,
    possibleImpact: `Impact ${id}`,
    severity,
    confidence: "high",
    priority: 50,
    priorityReasons: [PASSWORD_COMPOSITION_ORDER_REASON],
    targetAssetIds: ["aws"],
    nextStep: `Review ${id}`,
    recommendedExpertType: "cloud",
    evidenceReferences: [{
      evidenceId: `evidence-${id}`,
      engineId: "scoutsuite",
      detailsFrozen: true,
      engineRunId: "engine-scout",
      artifactSha256: `hash-${id}`,
      observedAt: "2026-10-06T12:00:00Z",
      summary: `Evidence ${id}`,
    }],
    frameworkReferences: [],
    officialReferences: [],
  });
  const report = (lowerPriorityMembers: "partial" | "all"): BeginnerMasterReport => ({
    schemaVersion: "1.1.0",
    caseId: "case",
    runId: "run",
    projectTitle: "AWS review",
    state: { summary: "complete", lifecycle: "final", lastDurableUpdate: "2026-10-06T12:00:00Z", explanation: "Completed" },
    requested: {
      targets: [{
        assetId: "aws",
        label: "AWS account",
        assetKind: "cloud_account",
        labelAvailability: "recorded",
        assetKindAvailability: "recorded",
      }],
      stage: { availability: "not_applicable", explanation: "" },
      limits: [],
      requestedCheckIds: ["scoutsuite"],
      automaticReductions: [],
      reductionsAvailability: "recorded",
      unavailableDimensions: [],
    },
    actual: {
      checks: [{
        taskId: "engine-scout",
        checkId: "scoutsuite",
        resultKind: "security_check",
        targetAssetIds: ["aws"],
        status: "tested_complete",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageGaps: [],
    coverageCounts: {
      testedComplete: 1, testedPartial: 0, failed: 0, timedOut: 0, cancelled: 0,
      notTested: 0, excluded: 0, truncated: 0, unavailable: 0, unattributed: 0, manualReview: 0,
    },
    findings: [member("low", "low"), member("high", "high")],
    problemGroups: [{
      groupId: "password",
      ruleVersion: "aws-related-checks-1",
      kind: "iam_password_policy",
      title: "IAM password policy needs attention",
      targetAssetId: "aws",
      representativeFindingId: "high",
      findingIds: ["low", "high"],
      lowerPriorityMembers,
    }],
    nextSteps: [],
    technicalDetails: { collapsedByDefault: true, tasks: [] },
    frameworkNotice: { nonCertification: "", aidefendMappingStatus: "" },
    dataQualityWarnings: [],
  });

  const partial = renderPage([], report("partial"));
  const partialCard = cardText(partial.container, "IAM password policy needs attention");
  expect(partialCard).toContain(PARTIAL_ACTION);
  expect(partialCard).not.toContain("Why this order");
  expect(partialCard).not.toContain("address each failed setting");
  cleanup();

  const all = renderPage([], report("all"));
  const allCard = cardText(all.container, "IAM password policy needs attention");
  expect(allCard).toContain("Change these IAM password policy settings only if an audit you must pass still requires them");
  expect(allCard).toContain("Why this order");
  expect(allCard).toContain(PASSWORD_COMPOSITION_ORDER_REASON);
});

test("a frozen report keeps the scanner benchmark on the finding it recorded", () => {
  window.localStorage.setItem(localeStorageKey, "en");
  const finding: BeginnerReportFinding = {
    findingId: "uppercase",
    fingerprint: "uppercase",
    snapshotSource: "frozen_selected_run",
    title: "Password Policy Lacks Uppercase Requirement",
    plainLanguageRisk: "The scanner reported this password policy.",
    possibleImpact: "A password can be set without an uppercase character.",
    severity: "high",
    confidence: "medium",
    priority: 35,
    priorityReasons: [PASSWORD_COMPOSITION_ORDER_REASON],
    targetAssetIds: ["aws"],
    nextStep: "Review the password policy.",
    recommendedExpertType: "cloud",
    evidenceReferences: [{
      evidenceId: "evidence-uppercase",
      engineId: "scoutsuite",
      detailsFrozen: true,
      engineRunId: "engine-scout",
      sourceRule: "iam-password-policy-uppercase",
      scannerDetails: { benchmarks: [benchmark] },
      artifactSha256: "a".repeat(64),
      observedAt: "2026-10-06T12:00:00Z",
      summary: "Password policy does not require an uppercase character.",
    }],
    frameworkReferences: [],
    officialReferences: [],
  };
  const report: BeginnerMasterReport = {
    schemaVersion: "1.1.0",
    caseId: "case",
    runId: "run",
    projectTitle: "AWS review",
    state: { summary: "complete", lifecycle: "final", lastDurableUpdate: "2026-10-06T12:00:00Z", explanation: "Completed" },
    requested: {
      targets: [{
        assetId: "aws",
        label: "AWS account",
        assetKind: "cloud_account",
        labelAvailability: "recorded",
        assetKindAvailability: "recorded",
      }],
      stage: { availability: "not_applicable", explanation: "" },
      limits: [],
      requestedCheckIds: ["scoutsuite"],
      automaticReductions: [],
      reductionsAvailability: "recorded",
      unavailableDimensions: [],
    },
    actual: {
      checks: [{
        taskId: "engine-scout",
        checkId: "scoutsuite",
        resultKind: "security_check",
        targetAssetIds: ["aws"],
        status: "tested_complete",
        testedDimensions: [],
      }],
      networkScopes: [],
      unavailableDimensions: [],
    },
    coverageGaps: [],
    coverageCounts: {
      testedComplete: 1, testedPartial: 0, failed: 0, timedOut: 0, cancelled: 0,
      notTested: 0, excluded: 0, truncated: 0, unavailable: 0, unattributed: 0, manualReview: 0,
    },
    findings: [finding],
    nextSteps: [],
    technicalDetails: { collapsedByDefault: true, tasks: [] },
    frameworkNotice: { nonCertification: "", aidefendMappingStatus: "" },
    dataQualityWarnings: [],
  };
  const { container } = renderPage([], report);
  expect(container.querySelector(".detail-section--advice")?.textContent).toContain(BENCHMARK_EN);
  expect(sectionText(container, "Why this order")).toContain(PASSWORD_COMPOSITION_ORDER_REASON);
  expect(container.querySelector(".finding-detail__header .status-pill--danger")?.textContent?.trim()).toBe("High");
});
