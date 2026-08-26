import type { EngineRun, ExecutionStage, ScanRun } from "./types";

export type ScanActivityState =
  | "waiting_to_start"
  | "checking_readiness"
  | "preparing_scanner"
  | "scanner_working"
  | "preparing_results"
  | "closing_scanner"
  | "paused"
  | "completed"
  | "stopped";

export type ScanActivityEventCode =
  | "run_started"
  | "checks_started"
  | "progress_saved"
  | "checks_finished"
  | "run_finished"
  | "run_paused";

export interface ScanActivityEvent {
  id: string;
  code: ScanActivityEventCode;
  occurredAt: string;
  count?: number;
  progress?: number;
}

export interface ScanActivitySnapshot {
  active: boolean;
  state: ScanActivityState;
  /** Product-controlled display names for checks that are active or next. */
  activeCheckNames: string[];
  lastProgressAt: string;
  progress: number;
  stale: boolean;
  staleMinutes: number;
  events: ScanActivityEvent[];
}

const progressingRunStatuses = new Set(["queued", "running"]);
const executionStages = new Set<ExecutionStage>([
  "planned",
  "preflight",
  "pulling_image",
  "running",
  "capturing_artifacts",
  "adapting_artifacts",
  "captured_awaiting_adapter",
  "cleanup_pending",
  "completed",
  "cancelled",
  "failed",
]);

const timestamp = (value?: string): number => {
  if (!value) return Number.NaN;
  return Date.parse(value);
};

const latestTimestamp = (values: Array<string | undefined>, fallback: string): string => {
  let latest = fallback;
  let latestValue = timestamp(fallback);
  for (const value of values) {
    const candidate = timestamp(value);
    if (value && Number.isFinite(candidate) && (!Number.isFinite(latestValue) || candidate > latestValue)) {
      latest = value;
      latestValue = candidate;
    }
  }
  return latest;
};

const activeEngine = (run: ScanRun): EngineRun | undefined => {
  const priority = (engine: EngineRun): number => {
    if (engine.status === "running") return 3;
    if (engine.status === "paused") return 2;
    if (engine.status === "pending") return 1;
    return 0;
  };
  return [...run.engineRuns]
    .filter((engine) => priority(engine) > 0)
    .sort((left, right) =>
      priority(right) - priority(left)
      || timestamp(right.startedAt) - timestamp(left.startedAt)
      || left.id.localeCompare(right.id)
    )[0];
};

const stageFor = (engine?: EngineRun): ExecutionStage | undefined => {
  if (engine?.checkpoint?.stage) return engine.checkpoint.stage;
  return engine && executionStages.has(engine.phase as ExecutionStage)
    ? engine.phase as ExecutionStage
    : undefined;
};

const activityState = (run: ScanRun): ScanActivityState => {
  if (run.status === "completed") return "completed";
  if (["failed", "partial", "cancelled"].includes(run.status)) return "stopped";
  if (run.status === "paused") return "paused";

  const engine = activeEngine(run);
  const stage = stageFor(engine);
  if (!engine || engine.status === "pending") return "waiting_to_start";
  if (stage === "planned" || stage === "preflight") return "checking_readiness";
  if (stage === "pulling_image") return "preparing_scanner";
  if (stage === "running") return "scanner_working";
  if (["capturing_artifacts", "adapting_artifacts", "captured_awaiting_adapter"].includes(stage ?? "")) {
    return "preparing_results";
  }
  if (stage === "cleanup_pending") return "closing_scanner";
  return "scanner_working";
};

const groupedEvent = (
  code: ScanActivityEventCode,
  engines: EngineRun[],
  field: "startedAt" | "finishedAt",
): ScanActivityEvent | undefined => {
  const values = engines.map((engine) => engine[field]).filter((value): value is string => Boolean(value));
  if (values.length === 0) return undefined;
  const occurredAt = latestTimestamp(values, values[0]!);
  return { id: `${code}-${occurredAt}`, code, occurredAt, count: values.length };
};

/**
 * Builds a route-neutral activity view from durable lifecycle fields only.
 * Scanner messages, target names, paths, findings, and evidence never enter
 * this first-layer model or its downloadable diagnostic representation.
 */
export const buildScanActivity = (
  run: ScanRun,
  now: Date = new Date(),
): ScanActivitySnapshot => {
  const active = progressingRunStatuses.has(run.status);
  const runningChecks = run.engineRuns.filter((engine) => engine.status === "running");
  const pausedChecks = run.engineRuns.filter((engine) => engine.status === "paused");
  const pendingChecks = run.engineRuns.filter((engine) => engine.status === "pending");
  const activeCheckNames = (runningChecks.length > 0
    ? runningChecks
    : pausedChecks.length > 0
      ? pausedChecks
      : pendingChecks.slice(0, 1))
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((engine) => engine.engineName)
    .filter((name, index, names) => names.indexOf(name) === index)
    .slice(0, 3);
  const lastProgressAt = latestTimestamp([
    run.lastProgressAt,
    run.finishedAt,
    ...run.engineRuns.flatMap((engine) => [engine.startedAt, engine.finishedAt]),
  ], run.startedAt);
  const elapsedMs = Math.max(0, now.getTime() - timestamp(lastProgressAt));
  const staleMinutes = Number.isFinite(elapsedMs) ? Math.floor(elapsedMs / 60_000) : 0;

  const events: Array<ScanActivityEvent | undefined> = [
    { id: `run_started-${run.startedAt}`, code: "run_started", occurredAt: run.startedAt },
    groupedEvent("checks_started", run.engineRuns, "startedAt"),
    {
      id: `progress_saved-${lastProgressAt}`,
      code: "progress_saved",
      occurredAt: lastProgressAt,
      progress: run.progress,
    },
    groupedEvent("checks_finished", run.engineRuns, "finishedAt"),
    run.status === "paused"
      ? { id: `run_paused-${lastProgressAt}`, code: "run_paused", occurredAt: lastProgressAt }
      : undefined,
    run.finishedAt
      ? { id: `run_finished-${run.finishedAt}`, code: "run_finished", occurredAt: run.finishedAt }
      : undefined,
  ];

  return {
    active,
    state: activityState(run),
    activeCheckNames,
    lastProgressAt,
    progress: run.progress,
    stale: active && staleMinutes >= 2,
    staleMinutes,
    events: events
      .filter((event): event is ScanActivityEvent => Boolean(event))
      .filter((event, index, all) => all.findIndex((candidate) =>
        candidate.code === event.code && candidate.occurredAt === event.occurredAt
      ) === index)
      .sort((left, right) => timestamp(right.occurredAt) - timestamp(left.occurredAt)),
  };
};
