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
