import type { EngineRun, ScanRun } from "./types";

export type BlockedRunKind = "no_targets" | "no_runnable_checks";

export interface BlockedRunSummary {
  kind: BlockedRunKind;
  skippedCheckCount: number;
  reasonCodes: string[];
}

/**
 * Releases before the guided preflight fix persisted one `not_executed` row
 * per catalog engine even when no scan could start. Keep that history, but
 * present it as one blocked setup attempt instead of a failed 21-check scan.
 */
export const blockedRunSummary = (run: ScanRun): BlockedRunSummary | undefined => {
  if (run.engineRuns.length === 0 || !run.engineRuns.every((engine) => engine.status === "not_executed")) {
    return undefined;
  }
  const reasonCodes = [...new Set(run.engineRuns
    .map((engine) => engine.errorCode)
    .filter((value): value is string => Boolean(value)))]
    .sort();
  const hasAnyTarget = run.engineRuns.some((engine) => engine.assetIds.length > 0);
  return {
    kind: hasAnyTarget ? "no_runnable_checks" : "no_targets",
    skippedCheckCount: run.engineRuns.length,
    reasonCodes,
  };
};

export interface ScanDiagnosticContext {
  productVersion?: string;
  runtime?: {
    provider?: string;
    phase?: string;
    version?: string;
    available?: boolean;
  };
}

const safeEngineDiagnostic = (engine: EngineRun) => ({
  engine_id: engine.engineId,
  engine_run_id: engine.id,
  status: engine.status,
  phase: engine.phase,
  error_code: engine.errorCode ?? null,
  target_count: engine.assetIds.length,
  evidence_file_count: engine.rawArtifactCount,
  finding_count: engine.findingCountKnown === false ? null : engine.findingCount,
  attempt: engine.checkpoint?.attempt ?? null,
  checkpoint_stage: engine.checkpoint?.stage ?? null,
  cleanup_completed: engine.checkpoint?.cleanupCompleted ?? null,
  engine_version: engine.version,
  adapter_version: engine.adapterVersion ?? null,
  runtime_provider: engine.runtimeProvider ?? null,
  runtime_version: engine.runtimeVersion ?? null,
  exit_code: engine.exitCode ?? null,
});

/**
 * Builds a bounded support log without raw scanner messages, warnings,
 * evidence, paths, target names, or asset identifiers. Those fields may carry
 * sensitive or target-controlled text and do not belong in a shareable log.
 */
export const buildScanDiagnostic = (
  run: ScanRun,
  context: ScanDiagnosticContext = {},
): string => JSON.stringify({
  schema_version: "ai-security-scanner.redacted-diagnostic/v1",
  product_version: context.productVersion ?? null,
  run: {
    run_id: run.id,
    case_id: run.caseId,
    sequence_label: run.label,
    status: run.status,
    progress_percent: run.progress,
    started_at: run.startedAt,
    finished_at: run.finishedAt ?? null,
    planned_check_count: run.engineRuns.length,
    covered_target_count: run.coveredAssetCount,
    total_target_count: run.totalAssetCount,
    blocked_summary: blockedRunSummary(run) ?? null,
  },
  runtime: context.runtime ? {
    provider: context.runtime.provider ?? null,
    phase: context.runtime.phase ?? null,
    version: context.runtime.version ?? null,
    available: context.runtime.available ?? null,
  } : null,
  checks: run.engineRuns.map(safeEngineDiagnostic),
}, null, 2);
