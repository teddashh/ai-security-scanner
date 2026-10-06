import type { EngineRun } from "./types";

/**
 * Catalog engines whose output is inventory. Same ids as Rust `task_result_kind`
 * and the check-id fallback below.
 */
const INVENTORY_ENGINE_IDS = ["cloudquery", "steampipe", "syft", "naabu", "httpx", "agentic-radar"] as const;

export type CheckResultKind = "security_check" | "inventory" | "connectivity";

/** Conservative fallback for reports saved before `resultKind` was frozen. */
export const legacyCheckResultKind = (checkId: string): CheckResultKind => {
  const normalized = checkId.trim().toLocaleLowerCase("en-US");
  if (normalized.startsWith("native localhost tcp check on ")) return "connectivity";
  if (INVENTORY_ENGINE_IDS.some((engine) =>
    normalized === engine || normalized.startsWith(`${engine}-`))) return "inventory";
  return "security_check";
};

/**
 * Mirrors Rust `task_result_kind`. `taskKind` selects connectivity versus a
 * catalog engine; `engineId` is compared case-insensitively with the inventory ids.
 * An `invalid_task` stays a security check so an unclassified engine is not
 * dropped from the update notice.
 */
export const engineRunResultKind = (
  engine: Pick<EngineRun, "engineId" | "taskKind">,
): CheckResultKind => {
  if (engine.taskKind.kind === "built_in_localhost_tcp") return "connectivity";
  if (engine.taskKind.kind !== "catalog_engine") return "security_check";
  const engineId = engine.engineId.toLocaleLowerCase("en-US");
  return INVENTORY_ENGINE_IDS.some((id) => id === engineId) ? "inventory" : "security_check";
};
