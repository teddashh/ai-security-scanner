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

/**
 * The exact string a demo download is stamped with. A demo file carries real
 * finding titles, severities and asset names, so nothing in its body
 * distinguishes it from an assessment; this marker is what does. It is the
 * first key in the written JSON so it is the first thing a reader sees.
 */
export const DEMO_EXPORT_PROVENANCE = "DEMO_ONLY_NOT_A_SCAN" as const;

export interface DemoExportPayload {
  provenance: typeof DEMO_EXPORT_PROVENANCE;
  warning: string;
  format: "selected_run_json";
  case: CaseWorkspace["case"];
  options: {
    locale: ExportCaseInput["locale"];
    includeRawEvidence: false;
    redactSensitiveValues: false;
  };
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

/**
 * Assemble the exact object written to a demo download.
 *
 * The stamp is written first so it leads the serialized file. That position is
 * only safe while the projection spread below carries no `provenance` or
 * `warning` key of its own -- object spread is last-write-wins, so such a key
 * would silently replace the stamp while leaving its position intact, and the
 * file would read as an assessment. `demoExportProvenance.test.ts` asserts both
 * the position and the surviving value, which is what holds that invariant.
 */
export const buildDemoExportPayload = (
  workspace: ProjectionWorkspace & Pick<CaseWorkspace, "case">,
  input: ExportCaseInput,
  run: ScanRun,
  notice: string,
): DemoExportPayload & DemoSelectedRunProjection => ({
  provenance: DEMO_EXPORT_PROVENANCE,
  warning: notice,
  format: "selected_run_json",
  case: workspace.case,
  ...projectDemoSelectedRun(workspace, run),
  options: {
    locale: input.locale,
    includeRawEvidence: false,
    redactSensitiveValues: false,
  },
});
