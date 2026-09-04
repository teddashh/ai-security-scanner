/**
 * Names the exact dimension of coverage a beginner-report row is speaking
 * about. The backend authors these as English prose and they are the only thing
 * distinguishing one gap from the next: the surrounding row text is generated
 * from the gap's `kind` and `nextActionCode`, so two gaps sharing a kind are
 * told apart by this string alone.
 *
 * English passes through verbatim. Traditional Chinese is matched on substrings
 * because some names are composed at runtime and carry an identifier — a check
 * id, an engine id, or a user-authored exclusion label.
 *
 * Two rules follow from that:
 *
 *  - every name the backend can emit needs a mapping. A run reports "completed
 *    planned work units" and "partly completed planned work units" as adjacent
 *    rows on the same check, so a shared fallback leaves a reader two identical
 *    labels and no way to tell finished work from work that stopped early.
 *  - an unmapped name must keep its original text rather than being replaced.
 *    A fixed label substituted for "cloudquery granular executed scope" or for
 *    a case exclusion's own label discards the identifier that made the row
 *    meaningful. Untranslated detail is worth more than fluent erasure.
 */
export const localizedCoverageDimension = (
  dimension: string,
  locale: "en" | "zh-TW",
): string => {
  if (locale === "en") return dimension;
  const normalized = dimension.toLocaleLowerCase("en");
  if (normalized.includes("tcp reachability")) return "TCP 連線狀態";
  if (normalized.includes("bounded connection contract")) return "受限的連線檢查";
  if (normalized.includes("completed check-to-target coordinate")) return "完成的目標檢查";
  if (normalized.includes("requested scan stage")) return "要求的掃描深度";
  if (normalized.includes("requested limits")) return "要求的掃描限制";
  if (normalized.includes("scope reduction") || normalized.includes("truncation")) return "自動縮減的範圍";
  if (normalized.includes("target label") || normalized.includes("target type")) return "目標的歷史顯示資料";
  if (normalized.includes("finding presentation")) return "本輪問題顯示資料";
  if (normalized.includes("request outcome")) return "掃描結果資料一致性";
  // Ordered before the completed-work rule, which is a substring of this one.
  if (normalized.includes("partly completed planned work units")) return "部分完成的計畫工作單元";
  if (normalized.includes("completed planned work units")) return "已完成的計畫工作單元";
  if (normalized.includes("additional packaged checks")) return "額外的內建檢查項目";
  if (normalized.includes("requested checks")) return "要求的檢查項目";
  return `涵蓋範圍細節：${dimension}`;
};

/** Appends the identifier a composed name carries, when it has one. */
const withIdentifier = (label: string, identifier: string): string =>
  identifier ? `${label}（${identifier}）` : label;

/**
 * Names one limit the run was executed under. The backend composes most of
 * these as "<engine or asset id> <limit kind>", so translating the kind alone
 * erases the only part saying which scanner or which authorized target the
 * limit applied to. A case with three scope grants would otherwise show three
 * rows all reading "approved ports" with no way to attribute them.
 */
export const localizedRequestedLimitName = (
  name: string,
  locale: "en" | "zh-TW",
): string => {
  if (locale === "en") return name;
  if (name === "endpoint") return "連線端點";
  if (name === "connection timeout") return "連線逾時限制";
  if (name === "application payload") return "應用資料量";
  for (const [suffix, label] of [
    ["approved ports", "允許檢查的連接埠"],
    ["request rate", "請求速率"],
    ["network timeout", "網路逾時限制"],
    ["authorized network target", "已確認的網路目標"],
    ["execution timeout", "檢查逾時限制"],
  ] as const) {
    if (name.endsWith(suffix)) {
      return withIdentifier(label, name.slice(0, name.length - suffix.length).trim());
    }
  }
  return `本輪使用的限制：${name}`;
};
