import type {
  Asset,
  CaseWorkspace,
  Evidence,
  ExportCaseInput,
  Finding,
  ScanRun,
} from "./types";

/** Browser demos emit one honest JSON projection only. */
export const normalizeDemoExportInput = (input: ExportCaseInput): ExportCaseInput => ({
  ...input,
  format: "json",
  includeRawEvidence: false,
  redactSensitiveValues: false,
});

export interface DemoSelectedRunFinding {
  id: string;
  fingerprint: string;
  assetId: string;
  assetIds?: string[];
  assetName: string;
  title: string;
  summary: string;
  impact: string;
  recommendation: string;
  expertType: string;
  severity: Finding["severity"];
  confidence: Finding["confidence"];
  priority: number;
  priorityReasons?: string[];
  evidence: Evidence[];
  controls: Finding["controls"];
  officialReferences: string[];
  verificationGuidance?: string;
  rollbackConsiderations?: string;
  tags?: string[];
}

export interface DemoSelectedRunProjection {
  schemaVersion: "1.0.0";
  scope: "selected_run_only";
  selectedRunId: string;
  selectedRun: ScanRun;
  assets: Asset[];
  findings: DemoSelectedRunFinding[];
  coverage: [];
  verification: null;
  omissions: {
    coverage: "omitted_not_run_bound";
    verification: "omitted_cross_run_comparison";
  };
}

type ProjectionWorkspace = Pick<
  CaseWorkspace,
  "assets" | "coverage" | "findings" | "verification"
>;

/**
 * Build the browser-demo payload from the requested run only.
 *
 * Demo coverage is a mutable case-wide view and demo verification is a
 * comparison between runs, so neither can truthfully be represented as frozen
 * selected-run data. They are intentionally omitted instead of being mixed
 * into a run-scoped download.
 */
export const projectDemoSelectedRun = (
  workspace: ProjectionWorkspace,
  run: ScanRun,
): DemoSelectedRunProjection => {
  const selectedEngineRunIds = new Set(run.engineRuns.map((engineRun) => engineRun.id));
  const selectedAssetIds = new Set([
    ...run.engineRuns.flatMap((engineRun) => engineRun.assetIds),
    ...(run.requestOutcome?.requestedAssetIds ?? []),
  ]);

  const assets = workspace.assets.filter((asset) => selectedAssetIds.has(asset.id));
  const findings = workspace.findings.flatMap((finding): DemoSelectedRunFinding[] => {
    if (!selectedAssetIds.has(finding.assetId)) return [];
    const evidence = finding.evidence.filter((item) =>
      item.runId === run.id
      && (item.engineRunId === undefined || selectedEngineRunIds.has(item.engineRunId)));
    if (evidence.length === 0) return [];

    const projectedAssetIds = finding.assetIds?.filter((assetId) => selectedAssetIds.has(assetId));
    return [{
      id: finding.id,
      fingerprint: finding.fingerprint,
      assetId: finding.assetId,
      ...(projectedAssetIds && projectedAssetIds.length > 0 ? { assetIds: projectedAssetIds } : {}),
      assetName: finding.assetName,
      title: finding.title,
      summary: finding.summary,
      impact: finding.impact,
      recommendation: finding.recommendation,
      expertType: finding.expertType,
      severity: finding.severity,
      confidence: finding.confidence,
      priority: finding.priority,
      ...(finding.priorityReasons ? { priorityReasons: finding.priorityReasons } : {}),
      evidence,
      controls: finding.controls,
      officialReferences: finding.officialReferences,
      ...(finding.verificationGuidance ? { verificationGuidance: finding.verificationGuidance } : {}),
      ...(finding.rollbackConsiderations ? { rollbackConsiderations: finding.rollbackConsiderations } : {}),
      ...(finding.tags ? { tags: finding.tags } : {}),
    }];
  });

  return {
    schemaVersion: "1.0.0",
    scope: "selected_run_only",
    selectedRunId: run.id,
    selectedRun: run,
    assets,
    findings,
    coverage: [],
    verification: null,
    omissions: {
      coverage: "omitted_not_run_bound",
      verification: "omitted_cross_run_comparison",
    },
  };
};
