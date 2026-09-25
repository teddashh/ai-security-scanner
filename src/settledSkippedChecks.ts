import type { EngineRun } from "./types";

/**
 * Planner skip reasons for a check that has nothing to check in this project,
 * or that this app version does not include. The check stays listed as not
 * run, but no user action can make it run, so it never counts as work that
 * needs attention. Mirrors `SETTLED_SKIP_REASON_CODES` in case_service.rs.
 */
export const settledSkipReasonCodes: ReadonlySet<string> = new Set([
  "engine_deprecated",
  "engine_release_unavailable",
  "license_review",
  "mcp_configuration_absent",
  "research_only",
]);

export const isSettledSkippedCheck = (engine: EngineRun): boolean =>
  engine.status === "not_executed"
  && engine.taskKind.kind === "catalog_engine"
  && settledSkipReasonCodes.has(engine.errorCode ?? "");
