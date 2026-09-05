import type { FindingFamily, SeverityBasisCode } from "./types";

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
const engineNameFrom = (englishSummary: string): string | undefined => {
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

/** "If the scanner result is confirmed, {consequence}." */
export const findingImpactSentence = (
  locale: "en" | "zh-TW",
  options: { englishFallback: string; severityLabel: string; family?: FindingFamily },
): string => {
  if (locale === "en") return options.englishFallback;
  const consequence = options.family ? CONSEQUENCE[options.family] : undefined;
  if (!consequence) return options.englishFallback;
  return `若掃描結果經人工確認，${consequence}。${options.severityLabel}這個等級來自來源工具，不代表整體合規分數。`;
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
