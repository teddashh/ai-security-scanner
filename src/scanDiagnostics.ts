import type { EngineRun, ScanReadiness, ScanRun } from "./types";
import { buildScanActivity } from "./scanActivity";

export type BlockedRunKind = "no_targets" | "no_runnable_checks";

export interface BlockedRunSummary {
  kind: BlockedRunKind;
  skippedCheckCount: number;
  reasonCodes: string[];
}

export interface AggregatedEngineRunSummary {
  checkCount: number;
  reasonCodes: string[];
}

/**
 * Releases before the guided preflight fix persisted one `not_executed` row
 * per catalog engine even when no scan could start. Keep that history, but
 * present it as one blocked setup attempt instead of a failed 21-check scan.
 */
export const blockedRunSummary = (run: ScanRun): BlockedRunSummary | undefined => {
  if (run.engineRuns.length === 0) {
    return {
      kind: "no_runnable_checks",
      skippedCheckCount: 0,
      reasonCodes: [],
    };
  }
  if (!run.engineRuns.every((engine) => engine.status === "not_executed")) {
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

export const skippedEngineRunSummary = (run: ScanRun): AggregatedEngineRunSummary | undefined => {
  const skipped = run.engineRuns.filter((engine) => engine.status === "not_executed");
  if (skipped.length === 0) return undefined;
  return {
    checkCount: skipped.length,
    reasonCodes: [...new Set(skipped
      .map((engine) => engine.errorCode)
      .filter((value): value is string => Boolean(value)))]
      .sort(),
  };
};

/**
 * Evidence that a failure happened before runtime preflight or a frozen scope
 * was established. Missing checkpoint data is unknown, never proof that a
 * scanner failed before start.
 */
export const isExplicitPreScannerInfrastructureFailure = (engine: EngineRun): boolean => Boolean(
  engine.status === "failed"
  && engine.errorCode === "execution_failed"
  && engine.checkpoint
  && engine.checkpoint.stage === "failed"
  && !engine.checkpoint.scopeBound
  && engine.checkpoint.artifactCount === 0
  && engine.rawArtifactCount === 0
  && engine.findingCount === 0
  && engine.exitCode === undefined
  && !engine.runtimeProvider,
);

/**
 * Collapse a fan-out caused by one pre-scanner infrastructure failure. The
 * comparison never displays or interprets raw messages; it only verifies that
 * every runnable check stopped at the same pre-scope boundary.
 */
export const sharedInfrastructureFailureSummary = (
  run: ScanRun,
): AggregatedEngineRunSummary | undefined => {
  const attempted = run.engineRuns.filter((engine) => engine.status !== "not_executed");
  if (attempted.length < 2) return undefined;
  const preScannerFailures = attempted.every(isExplicitPreScannerInfrastructureFailure);
  if (!preScannerFailures) return undefined;

  const failureSignatures = new Set(attempted.map((engine) =>
    engine.checkpoint?.lastError ?? engine.message ?? "",
  ));
  if (failureSignatures.size !== 1 || failureSignatures.has("")) return undefined;

  return {
    checkCount: attempted.length,
    reasonCodes: ["execution_failed"],
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

export interface ReadinessDiagnosticInput {
  readiness?: ScanReadiness;
  checkFailed: boolean;
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
): string => {
  const activity = buildScanActivity(run);
  return JSON.stringify({
    schema_version: "ai-security-scanner.redacted-diagnostic/v2",
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
    activity: {
      current_state: activity.state,
      last_progress_at: activity.lastProgressAt,
      minutes_since_progress: activity.staleMinutes,
      progress_update_delayed: activity.stale,
      events: activity.events.map((event) => ({
        event: event.code,
        occurred_at: event.occurredAt,
        count: event.count ?? null,
        progress_percent: event.progress ?? null,
      })),
    },
    runtime: context.runtime ? {
      provider: context.runtime.provider ?? null,
      phase: context.runtime.phase ?? null,
      version: context.runtime.version ?? null,
      available: context.runtime.available ?? null,
    } : null,
    checks: run.engineRuns.map(safeEngineDiagnostic),
  }, null, 2);
};

/**
 * Creates a shareable preflight record even when no scan run exists. Only
 * typed readiness codes, aggregate counts, and bounded runtime metadata are
 * included; target details and backend error strings are never accepted.
 */
export const buildReadinessDiagnostic = (
  input: ReadinessDiagnosticInput,
  context: ScanDiagnosticContext = {},
): string => JSON.stringify({
  schema_version: "ai-security-scanner.redacted-preflight-diagnostic/v1",
  product_version: context.productVersion ?? null,
  readiness: input.readiness ? {
    case_id: input.readiness.caseId,
    checked_at: input.readiness.checkedAt,
    ready: input.readiness.ready,
    state: input.readiness.state,
    blocker_code: input.readiness.blockerCode ?? null,
    next_step: input.readiness.nextStep ?? null,
    authorized_target_count: input.readiness.authorizedTargetCount,
    pending_target_count: input.readiness.pendingTargetCount,
    compatible_check_count: input.readiness.compatibleEngineCount,
    runnable_check_count: input.readiness.runnableEngineCount,
    scan_started: false,
  } : null,
  readiness_check_failed: input.checkFailed,
  events: input.readiness ? [{
    event: input.readiness.ready ? "ready_to_start" : "scan_start_blocked",
    occurred_at: input.readiness.checkedAt,
    blocker_code: input.readiness.blockerCode ?? null,
  }] : [],
  runtime: context.runtime ? {
    provider: context.runtime.provider ?? null,
    phase: context.runtime.phase ?? null,
    version: context.runtime.version ?? null,
    available: context.runtime.available ?? null,
  } : null,
}, null, 2);
