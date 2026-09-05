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
