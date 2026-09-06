import type {
  ContextFactor,
  FindingFamily,
  SeverityBasisCode,
  UnattributedResults,
} from "./types";

/**
 * Writes the sentences this product says about a finding, in the reader's
 * language.
 *
 * The backend composes the same three sentences in English and stores them on
 * the finding. That happens before any locale is known and the result is frozen
 * into the case, so a zh-TW reader was shown 可能影響 above "If the scanner
 * result is confirmed, ..." — a translated heading over an English paragraph,
 * on the three fields that carry the entire meaning of a finding.
 *
 * Every input the backend composed from is a closed set, so this side can write
 * the same sentence rather than translate the finished one. Two consequences
 * are deliberate:
 *
 *  - English returns the backend's own prose untouched. It is the canonical
 *    wording, it is what the exports carry, and re-deriving it here would let
 *    the two drift apart silently.
 *  - A finding with no code — stored before the codes were carried, or produced
 *    by a build that knows a family this one does not — falls back to that same
 *    English prose. Untranslated is worse than translated and better than blank.
 *
 * The engine's own `title` is not covered. That is the engine's wording; saying
 * it back in another language would be this product speaking for it.
 */

/** The clause completing "If the scanner result is confirmed, ...". */
const CONSEQUENCE: Record<FindingFamily, string> = {
  cloud_posture: "雲端資源或資料可能遭到未預期的存取、變更或使用",
  cloud_identity: "某個身分可能擁有超出其角色所需的操作權限",
  microsoft365: "Microsoft 365 的身分、郵件、檔案或管理設定的保護可能不足",
  network_exposure: "可從網際網路連線的服務可能暴露非預期的功能或已知弱點",
  source_code: "原始碼或憑證可能導致未授權存取或不安全的程式行為",
  secret: "原始碼或憑證可能導致未授權存取或不安全的程式行為",
  infrastructure_as_code: "之後部署出來的基礎架構會沿用這個不安全的設定",
  vulnerable_component: "容器或軟體元件可能讓工作負載暴露於已知弱點",
  kubernetes: "Kubernetes 叢集或工作負載的隔離或管理保護可能不足",
};

/**
 * The clause completing "...then plan and approve ...".
 *
 * `secret` departs from `source_code` even though they share a consequence. A
 * leaked credential stays valid until it is revoked, so sending the reader to a
 * permissions screen first leaves it valid for exactly that long.
 */
const REMEDY: Record<FindingFamily, string> = {
  cloud_posture: "將受影響資源的設定或政策改為最小權限",
  cloud_identity: "改用只授予該身分角色所需操作的較小範圍政策",
  microsoft365: "調整這項控制項所檢查的 Microsoft 365 租用戶設定",
  network_exposure: "記錄這項服務為何需要對外開放，或調整設定以移除、限制這個對外暴露",
  source_code: "修改程式碼以移除回報的不安全寫法",
  secret: "先撤銷並輪替這組已外洩的憑證，再從原始碼以及仍保留它的歷史紀錄中移除",
  infrastructure_as_code: "修改基礎架構即程式碼的範本，讓重新部署不會再還原這個設定",
  vulnerable_component: "將受影響的元件升級到已修正的版本，或記錄目前無法升級的原因",
  kubernetes: "調整這項檢查所指出的工作負載或叢集設定",
};

/** The clause completing "This product rated it {severity} from ...". */
const BASIS: Record<SeverityBasisCode, string> = {
  open_port: "開放連接埠的觀察結果，而非缺陷",
  reachable_http_service: "可連線 HTTP 服務的觀察結果，而非缺陷",
  secret_pattern_match: "掃描到的原始碼中符合機密資料的樣式",
  unverified_credential_detector: "憑證偵測器的比對結果，本產品並未加以驗證",
  iac_policy_check:
    "一項未通過的基礎架構即程式碼政策檢查；因為 Checkov 離線執行時不提供各別檢查的嚴重程度，所以一律採用相同等級",
  cis_kubernetes_benchmark: "一項未通過的 CIS Kubernetes Benchmark 檢查",
  cloud_control_query: "本產品自有固定查詢中一項未通過的 IAM 控制項",
};

/**
 * The nine specialists the backend recommends, mapped exactly.
 *
 * Matched on the whole string rather than on substrings. The previous helper
 * asked whether the name contained "it", which "security" and "vulnerability"
 * both do, so a Kubernetes finding and a Microsoft 365 finding each told the
 * reader to go find an IT administrator. Sniffing survives only as the fallback
 * for a name this build has never seen.
 */
const EXPERT: Record<string, string> = {
  "Cloud security engineer": "雲端安全工程師",
  "Cloud identity specialist": "雲端身分權限專家",
  "Microsoft 365 security administrator": "Microsoft 365 安全管理員",
  "Network security engineer": "網路安全工程師",
  "Application security engineer": "應用程式安全工程師",
  "Vulnerability manager": "弱點管理負責人",
  "Secrets-response specialist": "機密外洩應變專家",
  "Infrastructure-as-code engineer": "基礎架構即程式碼工程師",
  "Container security engineer": "容器安全工程師",
  "Software supply-chain engineer": "軟體供應鏈工程師",
  "Kubernetes security engineer": "Kubernetes 安全工程師",
  // Not from an adapter. A check that timed out is a network or system problem,
  // and the report says so on purpose; letting it fall through would send the
  // reader to a security specialist for a connectivity fault, which is the same
  // misdirection the substring rule used to cause. The generic name is what a
  // finding with no details gets.
  "Network or system administrator": "網路或系統管理員",
  "Security professional": "資安專業人員",
};

export const localizedExpertType = (expert: string, locale: "en" | "zh-TW"): string => {
  if (locale === "en") return expert;
  // A name from a build this one has never seen still has to say something, and
  // a general answer beats a confidently wrong one. Kept identical to the Rust
  // fallback rather than sniffed here: two surfaces guessing differently about
  // the same unknown title is the drift this pair exists to avoid.
  return EXPERT[expert.trim()] ?? "資安或 IT 專業人員";
};

/**
 * The engine's display name, read back off the sentence the backend wrote.
 *
 * Taken from the prose rather than looked up so the name in the translated
 * sentence is byte-for-byte the one in the English it replaces — "httpx" and
 * "kube-bench" are lowercase, "Greenbone Community Edition" is three words, and
 * a second source for that would be a second thing to keep in step. Returns
 * undefined on any sentence that is not the shape this product writes, which
 * sends the caller back to the English.
 */
export const engineNameFrom = (englishSummary: string): string | undefined => {
  const [name, ...rest] = englishSummary.split(" reported ");
  if (rest.length === 0 || !name || name.includes(".")) return undefined;
  return name;
};

/** "{engine} reported a {severity}-severity condition on the assessed asset." */
export const findingSummarySentence = (
  locale: "en" | "zh-TW",
  options: {
    englishFallback: string;
    severityLabel: string;
    severityBasisCode?: SeverityBasisCode;
  },
): string => {
  if (locale === "en") return options.englishFallback;
  const { englishFallback, severityLabel, severityBasisCode } = options;
  const engineName = engineNameFrom(englishFallback);
  if (!engineName) return englishFallback;
  const evidence = "附帶的原始記錄是證據，不是指示。";
  if (!severityBasisCode) {
    return `${engineName} 在受評估的資產上回報了一項${severityLabel}等級的狀況。${evidence}`;
  }
  const basis = BASIS[severityBasisCode];
  if (!basis) return englishFallback;
  return `${engineName} 在受評估的資產上回報了這項狀況，但未評定嚴重程度。本產品依據${basis}，將它評為${severityLabel}。${evidence}`;
};

/**
 * The case-specific clauses the backend appends to `possible_impact`.
 *
 * They are appended to the English rather than composed into it, so a surface
 * that rewrites the impact sentence replaces the string they live in and drops
 * them unless it puts them back. That is not a missing translation but a
 * missing fact: the same case raised this finding's priority by up to ten
 * points, and these are the only text saying why.
 */
const CONTEXT: Record<ContextFactor, string> = {
  internet_exposed_asset:
    "受影響的資產被標記為可從網際網路存取，且其保留的來源歸屬皆非問卷填答，這可能擴大可被觸及的攻擊面；該屬性的欄位層級來源並未保留，因此仍需人工確認。",
  sensitive_data_asset:
    "受影響的資產被標記為含有敏感資料，且其保留的來源歸屬皆非問卷填答，同時案件問卷另有記錄敏感資料情境。這可能提高確認暴露後的影響程度，但資料類別的欄位層級來源並未保留，且兩項記錄本身都不構成資料外洩的證明。",
};

/** "If the scanner result is confirmed, {consequence}." */
export const findingImpactSentence = (
  locale: "en" | "zh-TW",
  options: {
    englishFallback: string;
    severityLabel: string;
    family?: FindingFamily;
    contextFactors?: readonly ContextFactor[];
  },
): string => {
  if (locale === "en") return options.englishFallback;
  const consequence = options.family ? CONSEQUENCE[options.family] : undefined;
  if (!consequence) return options.englishFallback;
  // Appended after the sentence is composed, exactly as the Rust twin does it,
  // so the two files hold the same literal. Interpolating the clauses into the
  // template instead would leave one side's sentence ending in a hole that the
  // other's does not have, which is a difference the parity test can see and a
  // reader cannot -- and a test that fires on invisible differences gets
  // relaxed until it stops finding the visible ones.
  const composed = `若掃描結果經人工確認，${consequence}。${options.severityLabel}這個等級來自來源工具，不代表整體合規分數。`;
  return composed + (options.contextFactors ?? []).map((factor) => CONTEXT[factor] ?? "").join("");
};

/**
 * The one sentence every adapter finding carries before any change is made.
 *
 * Matched exactly rather than inferred from a code. If the adapter's wording
 * ever changes, an exact match falls back to the English -- visible and honest
 * -- where a code would keep confidently printing the old sentence in Chinese.
 * A Rust test pins this string to the one the adapters actually write.
 */
export const ENGLISH_ROLLBACK =
  "Before any manual change, preserve the current approved configuration and document a tested restoration path; this product does not execute remediation.";

/** "Before any manual change, preserve ... does not execute remediation." */
export const findingRollbackSentence = (locale: "en" | "zh-TW", english: string): string => {
  if (locale === "en" || english.trim() !== ENGLISH_ROLLBACK) return english;
  return "進行任何人工變更前，請先保留目前已核准的設定，並記錄一條經過測試的還原路徑；本產品不會代為執行修復。";
};

/**
 * "After an approved manual change, rerun {engine} ... source rule {rule} is no
 * longer reported."
 *
 * Read back off the sentence for the same reason `engineNameFrom` is: the
 * engine's display name and the source rule id are the engine's own strings and
 * have to appear in the Chinese exactly as they do in the English. Returns the
 * English unchanged for any sentence not in this shape.
 */
export const findingVerificationSentence = (locale: "en" | "zh-TW", english: string): string => {
  if (locale === "en") return english;
  const RERUN = "After an approved manual change, rerun ";
  const SCOPE = " with the same authorized scope and confirm that source rule ";
  const TAIL = " is no longer reported.";
  const trimmed = english.trim();
  if (!trimmed.startsWith(RERUN) || !trimmed.endsWith(TAIL)) return english;
  const middle = trimmed.slice(RERUN.length, trimmed.length - TAIL.length);
  const at = middle.indexOf(SCOPE);
  if (at < 0) return english;
  const engine = middle.slice(0, at);
  const rule = middle.slice(at + SCOPE.length);
  if (!engine || !rule) return english;
  return `在核准的人工變更完成後，請以相同的授權範圍重新執行 ${engine}，並確認來源規則 ${rule} 不再被回報。`;
};

/**
 * The canonical English basis clauses, as the backend writes them.
 *
 * Held here so a stored priority reason can be recognised by shape. Keyed by
 * the same code the summary sentence uses, and pinned to the Rust definition by
 * a fixture test, because a drifted string would show up as a silently
 * untranslated reason rather than as a failure.
 */
const BASIS_ENGLISH: Record<SeverityBasisCode, string> = {
  open_port: "an open port observation rather than a defect",
  reachable_http_service: "a reachable HTTP service observation rather than a defect",
  secret_pattern_match: "a secret pattern match in scanned source",
  unverified_credential_detector: "a credential detector match that this product does not verify",
  iac_policy_check:
    "a failed infrastructure-as-code policy check, rated flat because Checkov publishes no per-check severity offline",
  cis_kubernetes_benchmark: "a failed CIS Kubernetes Benchmark check",
  cloud_control_query: "a failed IAM control from this product's own fixed query",
};

/** The one priority reason every adapter finding carries. */
export const ENGLISH_EVIDENCE_REASON =
  "Direct scanner evidence is attached and still requires human review.";

/** The two reasons `apply_case_context` pushes when the case raises a finding. */
const ENGLISH_INTERNET_REASON =
  "An affected asset is marked internet-exposed, and all retained source attribution for that asset is non-questionnaire.";
const ENGLISH_SENSITIVE_REASON =
  "An affected asset is marked sensitive, all retained source attribution for that asset is non-questionnaire, and the case questionnaire separately records sensitive-data context.";

/**
 * "Why this priority", in the reader's language.
 *
 * priorityReasons is a bare string list with no per-entry code, so each entry
 * is recognised by its shape. Anything this build cannot identify is returned
 * unchanged: a reason is the product's account of why it moved a finding up the
 * list, and printing a confident Chinese sentence for text it cannot read would
 * be inventing that account.
 */
export const findingPriorityReason = (locale: "en" | "zh-TW", english: string): string => {
  if (locale === "en") return english;
  const trimmed = english.trim();
  if (trimmed === ENGLISH_EVIDENCE_REASON) return "已附上掃描工具的直接證據，仍需人工檢視。";
  if (trimmed === ENGLISH_INTERNET_REASON)
    return "受影響的資產被標記為可從網際網路存取，且其保留的來源歸屬皆非問卷填答。";
  if (trimmed === ENGLISH_SENSITIVE_REASON)
    return "受影響的資產被標記為含有敏感資料，其保留的來源歸屬皆非問卷填答，且案件問卷另有記錄敏感資料情境。";
  // The engine's own raw severity word, kept verbatim. Restating "high" as 高
  // would stop it matching what the reader sees in the engine's own output.
  const SOURCE = "Source severity: ";
  if (trimmed.startsWith(SOURCE)) {
    const value = trimmed.slice(SOURCE.length);
    if (value) return `來源工具評定的嚴重程度：${value}`;
  }
  const DERIVED = "Severity derived from ";
  const TAIL = " reports no severity of its own.";
  if (!trimmed.startsWith(DERIVED) || !trimmed.endsWith(TAIL)) return english;
  const middle = trimmed.slice(DERIVED.length, trimmed.length - TAIL.length);
  // No basis text contains "; ", so the last one separates basis from engine.
  const at = middle.lastIndexOf("; ");
  if (at < 0) return english;
  const basisText = middle.slice(0, at);
  const engine = middle.slice(at + 2);
  const code = (Object.keys(BASIS_ENGLISH) as SeverityBasisCode[]).find(
    (key) => BASIS_ENGLISH[key] === basisText,
  );
  if (!code || !engine) return english;
  return `嚴重程度是由${BASIS[code]}推導而來；${engine} 本身不提供嚴重程度。`;
};

/**
 * The three strings of an unattributed-results coverage gap.
 *
 * Composed from the structured payload rather than translated from the
 * English, for the same reason every other pair in this file is: the provider
 * and the identifier are the engine's own strings, have to read identically in
 * both languages, and the identifier is the thing the reader copies onto their
 * asset. English returns the backend's stored prose untouched.
 */
export const findingUnattributedGap = (
  locale: "en" | "zh-TW",
  engineId: string,
  unattributed: UnattributedResults,
  english: { dimension: string; reason: string; nextAction: string },
): { dimension: string; reason: string; nextAction: string } => {
  if (locale === "en") return english;
  const { provider, identifier, discardedResults } = unattributed;
  return {
    dimension: `${engineId}：針對 ${provider} ${identifier} 的結果`,
    reason: `${engineId} 回報了 ${discardedResults} 筆針對 ${provider} 識別碼 ${identifier} 的結果。你已授權的資產都沒有登記這個識別碼，因此這些結果都沒有被歸屬，也不會出現在這份報告中。`,
    nextAction: `請在你已授權的資產上，新增 ${provider} 識別碼 ${identifier}，然後重新掃描。`,
  };
};

/**
 * The name a coverage row is speaking about, in the reader's language.
 *
 * This lives here rather than beside the page that shows it because the shared
 * HTML report names the same rows, and Rust has to compose the identical
 * sentence there. `coverage_dimension_zh_hant` is its twin.
 *
 * Most of these names are composed at runtime around an identifier -- a check
 * id, an engine id, or the label a person wrote on an exclusion -- and the
 * identifier is the only thing telling one row from the next. So the kind is
 * translated and the identifier carried through untouched, rather than the
 * whole phrase being replaced by a fixed label.
 *
 * An unrecognized name keeps its original text behind a marker. Untranslated
 * detail is worth more than fluent erasure: a person can search their scanner's
 * own output for "cloudquery", and cannot search it for a label this product
 * invented.
 */
export const localizedCoverageDimension = (
  dimension: string,
  locale: "en" | "zh-TW",
): string => {
  if (locale === "en") return dimension;
  const lower = dimension.toLocaleLowerCase("en");

  // Fixed names, in the order the more specific one has to be tried first:
  // "completed planned work units" is a substring of the partly-completed one.
  for (const [needle, label] of [
    ["tcp reachability", "TCP 連線狀態"],
    ["bounded connection contract", "受限的連線檢查"],
    ["completed check-to-target coordinate", "完成的目標檢查"],
    ["requested scan stage", "要求的掃描深度"],
    ["requested limits", "要求的掃描限制"],
    ["scope reduction", "自動縮減的範圍"],
    ["truncation", "自動縮減的範圍"],
    ["target label", "目標的歷史顯示資料"],
    ["target type", "目標的歷史顯示資料"],
    ["finding presentation", "本輪問題顯示資料"],
    ["request outcome", "掃描結果資料一致性"],
    ["partly completed planned work units", "部分完成的計畫工作單元"],
    ["completed planned work units", "已完成的計畫工作單元"],
    ["additional packaged checks", "額外的內建檢查項目"],
    ["requested checks", "要求的檢查項目"],
  ] as const) {
    if (lower.includes(needle)) return label;
  }

  // "{check id} {kind} work units ({count})". The count is what makes the row
  // worth reading, so it survives beside the id.
  const counted = /^(.*) \((\d+)\)$/u.exec(dimension);
  if (counted) {
    for (const [suffix, label] of [
      [" partly completed work units", "部分完成的工作單元"],
      [" failed work units", "失敗的工作單元"],
      [" timed-out work units", "逾時的工作單元"],
      [" cancelled work units", "已取消的工作單元"],
      [" not-tested work units", "未檢測的工作單元"],
    ] as const) {
      const head = counted[1] ?? "";
      if (head.endsWith(suffix)) {
        return withCheck(head.slice(0, head.length - suffix.length), `${label}（${counted[2]}）`);
      }
    }
  }

  // "{check id} {kind}".
  for (const [suffix, label] of [
    [" granular executed scope", "細部執行範圍"],
    [" completed-check time", "檢查完成時間"],
    [" saved work-unit coverage", "已儲存的工作單元涵蓋記錄"],
    [" saved result processing", "已儲存結果的處理"],
    [" final-state reconciliation", "最終狀態核對"],
    [" ended after its time limit", "因逾時而結束"],
    [" stopped before finishing", "未完成就停止"],
    [" was cancelled before finishing", "未完成就被取消"],
  ] as const) {
    if (dimension.endsWith(suffix)) {
      return withCheck(dimension.slice(0, dimension.length - suffix.length), label);
    }
  }

  // "{check id}: {kind}".
  const separator = dimension.indexOf(": ");
  if (separator >= 0) {
    const rest = dimension.slice(separator + 2);
    for (const [fragment, label] of [
      ["remaining requested dimensions", "尚未完成的要求項目"],
      ["timed-out check dimension", "逾時的檢查項目"],
      ["failed check dimension", "失敗的檢查項目"],
      ["cancelled check dimension", "已取消的檢查項目"],
      ["not-tested check dimension", "未檢測的檢查項目"],
      ["unfinished check dimension", "未完成的檢查項目"],
    ] as const) {
      if (rest === fragment) return withCheck(dimension.slice(0, separator), label);
    }
  }

  // "requested check {engine id}", singular: the plural rule above is a
  // different row, about the whole requested list rather than one scanner.
  if (dimension.startsWith("requested check ")) {
    const engine = dimension.slice("requested check ".length);
    if (engine) return `要求的檢查項目：${engine}`;
  }

  return `涵蓋範圍細節：${dimension}`;
};

/**
 * Names the check a composed dimension belongs to, or just the kind when the
 * producer had no id to interpolate.
 */
const withCheck = (check: string, label: string): string => {
  const trimmed = check.trim();
  if (!trimmed) return label;
  return `${trimmed} 的${label}`;
};

/**
 * The sentences a coverage row says, paired with their Traditional Chinese.
 *
 * The backend writes these in English before any locale is known and freezes
 * them into the case, so the English is canonical and this is a lookup rather
 * than a second source of truth. `undefined` means the sentence is not one this
 * product authored -- a case exclusion carries the words a person typed -- and
 * the caller shows the stored text rather than inventing a label for it.
 *
 * `coverage_gap_prose_zh_hant` is the twin. Completeness against the producer
 * is enforced on the Rust side, where a debug assertion in `beginner_report.rs`
 * checks every gap the whole suite builds; the parity test holds this table to
 * that one, English key and Chinese sentence together.
 */
const COVERAGE_GAP_PROSE: ReadonlyArray<readonly [string, string]> = [
  [
    "The request-level outcome contradicts the run's durable task state and was ignored.",
    "這次請求層級的結果與本輪儲存的檢查狀態互相矛盾，因此未被採用。",
  ],
  [
    "At least one legacy finding observation did not retain its full run-specific presentation snapshot.",
    "至少有一筆舊版的問題觀察結果，沒有保留該輪完整的顯示資料。",
  ],
  [
    "The saved work-unit coverage for this check is internally inconsistent. The report did not guess which planned units were tested.",
    "這項檢查儲存的工作單元涵蓋記錄本身互相矛盾。報告不會臆測哪些計畫中的單元已經被檢測。",
  ],
  [
    "Usable results were saved for these work units, but their remaining planned operations were not tested complete.",
    "這些工作單元已儲存可用的結果，但其餘計畫中的操作並未完成檢測。",
  ],
  [
    "These planned work units stopped before establishing completed coverage.",
    "這些計畫中的工作單元在建立完整涵蓋之前就停止了。",
  ],
  [
    "These planned work units reached their bounded time limit before completed coverage was recorded.",
    "這些計畫中的工作單元在記錄完整涵蓋之前就達到時間上限。",
  ],
  [
    "These planned work units were cancelled before completed coverage was recorded.",
    "這些計畫中的工作單元在記錄完整涵蓋之前就被取消。",
  ],
  [
    "These frozen work units have no validated tested outcome in any saved attempt.",
    "這些已凍結的工作單元，在任何一次已儲存的嘗試中都沒有通過驗證的檢測結果。",
  ],
  [
    "At least one validated scanner result has not been fully processed into findings. Tested coverage remains saved, but the finding list may be incomplete.",
    "至少有一筆通過驗證的掃描結果尚未完全轉換成問題項目。已檢測的涵蓋範圍仍然保留，但問題清單可能不完整。",
  ],
  [
    "Every planned work unit has completed evidence, but the check itself has not recorded a completed final state.",
    "每個計畫中的工作單元都有完成的證據，但這項檢查本身尚未記錄完成的最終狀態。",
  ],
  [
    "The check reached its time limit after saving some usable results.",
    "這項檢查在儲存了一部分可用結果之後達到時間上限。",
  ],
  [
    "The check reached its time limit before saving a tested outcome.",
    "這項檢查在儲存任何檢測結果之前就達到時間上限。",
  ],
  [
    "The check stopped after saving some usable results.",
    "這項檢查在儲存了一部分可用結果之後停止。",
  ],
  [
    "The check stopped before saving a tested outcome.",
    "這項檢查在儲存任何檢測結果之前就停止。",
  ],
  [
    "The check was cancelled after saving some usable results.",
    "這項檢查在儲存了一部分可用結果之後被取消。",
  ],
  [
    "The check was cancelled before saving a tested outcome.",
    "這項檢查在儲存任何檢測結果之前就被取消。",
  ],
  [
    "This check produced some durable work but did not complete every planned dimension.",
    "這項檢查產生了一部分已保存的成果，但沒有完成每一個計畫中的項目。",
  ],
  [
    "The bounded check reached its time limit, so it cannot be treated as tested complete.",
    "這項受限的檢查達到時間上限，因此不能視為已完整檢測。",
  ],
  [
    "This check stopped before it could establish completed coverage.",
    "這項檢查在建立完整涵蓋之前就停止了。",
  ],
  [
    "This check was cancelled before completed coverage was recorded.",
    "這項檢查在記錄完整涵蓋之前就被取消。",
  ],
  [
    "This check did not start, so it is not a pass.",
    "這項檢查沒有啟動，因此不代表通過。",
  ],
  [
    "This check is still changing and has not recorded a complete result.",
    "這項檢查仍在變動中，尚未記錄完整的結果。",
  ],
  [
    "The packaged check list could not be loaded. Available checks may still run, but checks from that list are not tested.",
    "無法載入內建的檢查清單。可用的檢查仍然可以執行，但該清單上的檢查未被檢測。",
  ],
  [
    "One additional packaged check was unavailable before planning. Whether it applied to the selected target is unknown, so it is not tested.",
    "有一項額外的內建檢查在規劃前無法使用。無法得知它是否適用於所選目標，因此未被檢測。",
  ],
  [
    "At least one target identifier is frozen with the run, but its displayed label or type comes from current project data or is unavailable. The report labels that provenance and does not call it historical fact.",
    "至少有一個目標的識別資料是與本輪一起凍結的，但畫面上顯示的名稱或類型來自目前的專案資料，或是無法取得。報告會標示這項來源，不會把它當成歷史事實。",
  ],
  [
    "This run did not retain an exact reduction record. An empty list therefore cannot be interpreted as proof that no requested dimension was reduced.",
    "本輪沒有保留精確的縮減記錄。因此清單為空，並不能證明沒有任何要求的項目被縮減。",
  ],
  [
    "No exact per-run limits were retained. Current project settings are not substituted for historical requested limits.",
    "沒有保留本輪的精確限制。目前的專案設定不會拿來代替當時要求的限制。",
  ],
  [
    "This run did not freeze a quick-discovery, inventory, or deep-stage selection. The report does not infer one from engine names or current project settings.",
    "本輪沒有凍結快速探索、清點或深度掃描的階段選擇。報告不會從掃描工具名稱或目前的專案設定推測階段。",
  ],
  [
    "At least one readable frozen network plan includes full inventory, but another network check has no valid saved plan. Inventory is the highest known stage, not a complete run-wide record.",
    "至少有一份可讀取的凍結網路計畫包含完整清點，但另一項網路檢查沒有有效的已儲存計畫。清點是目前已知的最高階段，不代表整輪的完整記錄。",
  ],
  [
    "Readable frozen network plans contain quick discovery only, but another network check has no valid saved plan. Quick discovery is the highest known stage, not a complete run-wide record.",
    "可讀取的凍結網路計畫只包含快速探索，但另一項網路檢查沒有有效的已儲存計畫。快速探索是目前已知的最高階段，不代表整輪的完整記錄。",
  ],
  [
    "The run records the completed engine/asset coordinate but not exact observed hosts, services, ports, paths, files, branches, accounts, or resources.",
    "本輪記錄了完成的掃描工具與資產對應關係，但沒有記錄實際觀察到的主機、服務、連接埠、路徑、檔案、分支、帳號或資源。",
  ],
  [
    "The task says completed but has neither a finish time nor a bounded native observation time. The report does not invent when it was tested.",
    "這項工作標示為已完成，卻既沒有結束時間，也沒有內建檢查的觀察時間。報告不會臆造檢測的時間。",
  ],
  [
    "Let the scan continue or cancel it if you need to stop.",
    "可以讓掃描繼續，或是在你需要停止時取消它。",
  ],
  [
    "This report is still changing and keeps the durable work already saved.",
    "這份報告仍在變動中，並保留已經儲存下來的成果。",
  ],
  [
    "If you expected an app on this port, start it and run the check again.",
    "如果你預期這個連接埠上有服務在執行，請先啟動它，再重新執行檢查。",
  ],
  [
    "The port refused the bounded TCP connection at the recorded time; this is not a security pass or failure.",
    "在記錄的時間點，這個連接埠拒絕了受限的 TCP 連線；這不代表安全性通過或失敗。",
  ],
  [
    "Review what was tested before deciding whether you need a broader scan.",
    "請先檢視已檢測的內容，再決定是否需要更大範圍的掃描。",
  ],
  [
    "No actionable finding was recorded, but a no-findings result is only as broad as the displayed coverage.",
    "沒有記錄到需要處理的問題，但「沒有發現問題」的結論，只在畫面上顯示的涵蓋範圍內成立。",
  ],
  [
    "No checks ran because this scan has no active permission for a selected target.",
    "沒有執行任何檢查，因為這次掃描對所選目標沒有有效的授權。",
  ],
  [
    "No checks ran because none of the selected targets is confirmed as yours to scan.",
    "沒有執行任何檢查，因為所選目標都尚未確認是你有權掃描的對象。",
  ],
  [
    "No installed check applies to the selected target and permission. Nothing contacted the target.",
    "沒有任何已安裝的檢查適用於所選的目標與授權範圍。沒有任何連線接觸過該目標。",
  ],
  [
    "Review the exact target and permission, then start the scan again.",
    "請確認目標與授權範圍，然後重新開始掃描。",
  ],
  [
    "Choose a target you control, then start the scan again.",
    "請選擇一個你有掌控權的目標，然後重新開始掃描。",
  ],
  [
    "Choose another available check or add a compatible target source.",
    "請改選其他可用的檢查，或新增相容的目標來源。",
  ],
  [
    "Keep this limitation visible; do not interpret missing historical detail as completed coverage.",
    "請保留這項限制的說明；不要把缺少的歷史細節解讀為已完成的涵蓋。",
  ],
  [
    "Keep the saved results, then retry this scan if you need an internally consistent coverage record.",
    "請保留已儲存的結果；如果你需要前後一致的涵蓋記錄，再重新執行這次掃描。",
  ],
  [
    "Use the retained severity, confidence, and evidence for review; rerun to create a fully frozen report.",
    "請以保留下來的嚴重程度、把握度與證據進行檢視；若要產生完全凍結的報告，請重新掃描。",
  ],
  [
    "Keep the saved evidence and other results. Retry this check to create a new consistent coverage record.",
    "請保留已儲存的證據與其他結果。重新執行這項檢查，以建立新的一致涵蓋記錄。",
  ],
  [
    "Keep the saved results and retry only the unfinished work.",
    "請保留已儲存的結果，只重新執行尚未完成的部分。",
  ],
  [
    "Keep other saved results and retry only the failed work.",
    "請保留其他已儲存的結果，只重新執行失敗的部分。",
  ],
  [
    "Keep other saved results and retry only the timed-out work.",
    "請保留其他已儲存的結果，只重新執行逾時的部分。",
  ],
  [
    "Start only the cancelled work again when you want to finish it.",
    "想要完成時，只需重新啟動被取消的那部分工作。",
  ],
  [
    "Let the current check continue or cancel it; saved partial results remain available.",
    "可以讓目前的檢查繼續，或是取消它；已儲存的部分結果仍然可以使用。",
  ],
  [
    "Retry only the work that has not yet produced a tested outcome.",
    "只需重新執行尚未產生檢測結果的那部分工作。",
  ],
  [
    "Keep the saved results. The app should retry result processing automatically; keep this limitation visible until it succeeds.",
    "請保留已儲存的結果。本程式應該會自動重試結果處理；在成功之前，請保留這項限制的說明。",
  ],
  [
    "Keep the completed results. The app should reconcile the timed-out check before treating the run as final.",
    "請保留已完成的結果。本程式應該先核對這項逾時的檢查，才能把本輪視為最終結果。",
  ],
  [
    "Keep the completed results. The app should reconcile the stopped check before treating the run as final.",
    "請保留已完成的結果。本程式應該先核對這項中止的檢查，才能把本輪視為最終結果。",
  ],
  [
    "Keep the completed results. The app should reconcile the cancelled check before treating the run as final.",
    "請保留已完成的結果。本程式應該先核對這項被取消的檢查，才能把本輪視為最終結果。",
  ],
  [
    "Keep the completed results while the app reconciles the check's final state.",
    "在本程式核對這項檢查的最終狀態期間，請保留已完成的結果。",
  ],
  [
    "Keep saved results and retry only the unfinished work.",
    "請保留已儲存的結果，只重新執行尚未完成的部分。",
  ],
  [
    "Keep saved results and start only the unfinished work again when you are ready.",
    "請保留已儲存的結果；準備好之後，只需重新啟動尚未完成的部分。",
  ],
  [
    "Review the saved results, then retry this check to cover the unfinished dimensions.",
    "請先檢視已儲存的結果，再重新執行這項檢查，以涵蓋尚未完成的項目。",
  ],
  [
    "Retry once; if it times out again, review reachability or ask a network specialist.",
    "請重試一次；如果再次逾時，請檢查連線是否可達，或詢問網路專業人員。",
  ],
  [
    "Keep the saved results from other checks and retry this check.",
    "請保留其他檢查已儲存的結果，並重新執行這項檢查。",
  ],
  [
    "Start this check again when you want to finish the missing coverage.",
    "想要補齊缺少的涵蓋範圍時，請重新執行這項檢查。",
  ],
  [
    "Review the target and try this check again.",
    "請檢視目標設定，然後重新執行這項檢查。",
  ],
  [
    "Let it continue or cancel it; the partial report remains available.",
    "可以讓它繼續，或是取消它；這份部分完成的報告仍然可以使用。",
  ],
  [
    "Keep the available results. The app can include these checks in a later run after their packaged scanner information is restored.",
    "請保留目前可用的結果。等這些檢查的內建掃描工具資訊恢復之後，本程式可以在之後的掃描中納入它們。",
  ],
  [
    "No action is needed unless this area should be included in a future scan.",
    "除非之後的掃描要納入這個範圍，否則不需要採取任何行動。",
  ],
];

/**
 * One sentence of a coverage row, in the reader's language.
 *
 * English returns the stored prose. It is what the backend wrote, and it is
 * more specific than anything derivable from the gap's kind: the same
 * `not_tested` kind is written for a check that saved partial work, one that
 * never started, and one still running.
 */
export const coverageGapProse = (locale: "en" | "zh-TW", english: string): string => {
  if (locale === "en") return english;
  const trimmed = english.trim();
  // Six reasons gain a diagnostic code when the task recorded one. It is the
  // scanner's own code and stays verbatim; only the sentence around it moves.
  const withCode = /^(.*\.) Diagnostic code: (.+)\.$/u.exec(trimmed);
  if (withCode) {
    const base = lookupProse(withCode[1] ?? "");
    if (base) return `${base}診斷代碼：${withCode[2]}。`;
    return english;
  }
  return lookupProse(trimmed) ?? english;
};

const lookupProse = (english: string): string | undefined =>
  COVERAGE_GAP_PROSE.find(([candidate]) => candidate === english)?.[1];

/** "Have the recommended specialist ({expert}) review ... then plan and approve {remedy}." */
export const findingActionSentence = (
  locale: "en" | "zh-TW",
  options: { englishFallback: string; expertType: string; family?: FindingFamily },
): string => {
  if (locale === "en") return options.englishFallback;
  const remedy = options.family ? REMEDY[options.family] : undefined;
  if (!remedy) return options.englishFallback;
  const expert = localizedExpertType(options.expertType, locale);
  return `請由建議的專業人員（${expert}）檢視受影響的資產與來源規則的官方說明，再規劃並核准${remedy}。`;
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
 *
 * Lives here rather than in `coverageDimensionPresentation.ts` because the
 * shared HTML report names the same limits and Rust composes the identical
 * label there; this file is where the two languages are held to each other.
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
