import type {
  AwsIamPolicyFindingDetails,
  ConfidenceBasisCode,
  ContextFactor,
  FindingFamily,
  Severity,
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
 *  - English and Chinese are composed from the same structured fields. Legacy
 *    stored prose is normalized so an older case follows the current report
 *    contract too.
 *  - A finding with no code — stored before the codes were carried, or produced
 *    by a build that knows a family this one does not — falls back to that same
 *    English prose. Untranslated is worse than translated and better than blank.
 *
 * The engine's own `title` is not covered. That is the engine's wording; saying
 * it back in another language would be this product speaking for it.
 */

/** The direct possible impact for each finding family. */
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

const CONSEQUENCE_ENGLISH: Record<FindingFamily, string> = {
  cloud_posture: "Cloud resources or data may be exposed, changed, or used beyond the organization's intent",
  cloud_identity: "An identity may be able to perform broader actions than its role requires",
  microsoft365: "Microsoft 365 identities, messages, files, or administrative settings may have weaker protection",
  network_exposure: "An internet-reachable service may expose unexpected functionality or a known weakness",
  source_code: "Source code or credentials may permit unauthorized access or unsafe application behavior",
  secret: "Source code or credentials may permit unauthorized access or unsafe application behavior",
  infrastructure_as_code: "Deployed infrastructure may inherit the reported insecure configuration",
  vulnerable_component: "A container or software component may expose the workload to a known weakness",
  kubernetes: "The Kubernetes cluster or workload may have reduced isolation or administrative protection",
};

/**
 * The direct recommended action for each finding family.
 *
 * `secret` departs from `source_code` even though they share a consequence. A
 * leaked credential stays valid until it is revoked, so sending the reader to a
 * permissions screen first leaves it valid for exactly that long.
 */
const REMEDY: Record<FindingFamily, string> = {
  cloud_posture: "將受影響資源的設定或政策改為最小權限",
  cloud_identity: "改用只授予該身分角色所需操作的較小範圍政策",
  microsoft365: "調整這項控制項所檢查的 Microsoft 365 租用戶設定",
  network_exposure:
    "記錄這項服務為何需要對外開放，或調整設定以移除、限制這個對外暴露",
  source_code: "修改程式碼以移除回報的不安全寫法",
  secret:
    "先撤銷並輪替這組已外洩的憑證，再從原始碼以及仍保留它的歷史紀錄中移除",
  infrastructure_as_code:
    "修改基礎架構即程式碼的範本，讓重新部署不會再還原這個設定",
  vulnerable_component:
    "將受影響的元件升級到已修正的版本，或記錄目前無法升級的原因",
  kubernetes: "調整這項檢查所指出的工作負載或叢集設定",
};

const REMEDY_ENGLISH: Record<FindingFamily, string> = {
  cloud_posture: "Apply least privilege to the affected resource's configuration or policy",
  cloud_identity: "Replace the affected policy with a narrower policy that grants only the actions the identity's role requires",
  microsoft365: "Correct the Microsoft 365 tenant setting named by this control",
  network_exposure: "Document why this service must remain reachable, or remove or restrict the exposure",
  source_code: "Change the code to remove the reported unsafe pattern",
  secret: "Revoke and rotate the exposed credential, then remove it from the source and every retained history entry",
  infrastructure_as_code: "Correct the infrastructure-as-code template so redeployment does not restore the insecure setting",
  vulnerable_component: "Upgrade the affected component to a fixed version; if none is available, record the blocker and track the fix",
  kubernetes: "Correct the workload or cluster setting named by this check",
};

const IAM_PRINCIPAL_PREVIEW_LIMIT = 6;

const iamPrincipalLabels = (
  details: AwsIamPolicyFindingDetails,
  locale: "en" | "zh-TW",
): string[] => {
  const [role, group, user] = locale === "en"
    ? ["role", "group", "user"]
    : ["角色", "群組", "使用者"];
  return [
    ...details.attachedTo.roles.map((name) => `${role} ${name}`),
    ...details.attachedTo.groups.map((name) => `${group} ${name}`),
    ...details.attachedTo.users.map((name) => `${user} ${name}`),
  ];
};

const iamPrincipalSummary = (
  details: AwsIamPolicyFindingDetails,
  locale: "en" | "zh-TW",
): string | undefined => {
  const labels = iamPrincipalLabels(details, locale);
  if (labels.length === 0) return undefined;
  const retained = labels
    .slice(0, IAM_PRINCIPAL_PREVIEW_LIMIT)
    .join(locale === "en" ? ", " : "、");
  const omitted = Math.max(0, labels.length - IAM_PRINCIPAL_PREVIEW_LIMIT);
  if (omitted === 0) return retained;
  return locale === "en"
    ? `${retained}, and ${omitted} more principal(s)`
    : `${retained}，以及另外 ${omitted} 個主體`;
};

export const awsIamPolicySourceLabel = (
  source: AwsIamPolicyFindingDetails["policySource"],
  locale: "en" | "zh-TW",
): string => {
  if (source === "aws_managed") return locale === "en" ? "AWS-managed" : "AWS 受管";
  if (source === "customer_managed") return locale === "en" ? "Customer-managed" : "客戶受管";
  return locale === "en" ? "Inline" : "內嵌";
};

const awsIamPolicyActionZhTW = (details: AwsIamPolicyFindingDetails): string => {
  const principals = iamPrincipalSummary(details, "zh-TW");
  const attachmentsComplete = details.attachedTo.complete;
  let action: string;
  if (details.policySource === "aws_managed") {
    action = principals
      ? `在${principals}上將 AWS 受管政策 ${details.policyName} 改為權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯`
      : attachmentsComplete
        ? `確認 AWS 受管政策 ${details.policyName} 維持未附加狀態；之後如有需要，應選用權限較小的政策。AWS 受管政策無法由此帳戶直接編輯`
        : `先確認目前有哪些角色、群組與使用者附加了 AWS 受管政策 ${details.policyName}，再改用權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯`;
  } else if (details.policySource === "customer_managed") {
    action = principals
      ? `縮小客戶受管政策 ${details.policyName} 的權限，並確認${principals}只保留工作所需權限`
      : attachmentsComplete
        ? `在客戶受管政策 ${details.policyName} 再次附加或使用前縮小其權限`
        : `先確認客戶受管政策 ${details.policyName} 目前附加到哪些 IAM 主體，再縮小政策權限，並確認每個主體只保留工作所需權限`;
  } else {
    action = principals
      ? `直接在${principals}上縮小內嵌政策 ${details.policyName} 的權限`
      : `確認內嵌政策 ${details.policyName} 所屬的 IAM 主體，並在再次使用前於該處縮小權限`;
  }
  const incomplete = details.attachedTo.complete
    ? ""
    : "請先核對目前的 IAM 附加關係。";
  return `${action}。${incomplete}`;
};

const awsIamPolicyActionEnglish = (details: AwsIamPolicyFindingDetails): string => {
  const principals = iamPrincipalSummary(details, "en");
  let action: string;
  if (details.policySource === "aws_managed") {
    action = principals
      ? `Replace AWS-managed policy ${details.policyName} with a narrower policy on ${principals}, or detach it where it is not needed; AWS-managed policies cannot be edited by this account`
      : details.attachedTo.complete
        ? `Keep AWS-managed policy ${details.policyName} detached and choose a narrower policy before attaching it; AWS-managed policies cannot be edited by this account`
        : `Identify the roles, groups, and users attached to AWS-managed policy ${details.policyName}, then replace it with a narrower policy or detach it where it is not needed; AWS-managed policies cannot be edited by this account`;
  } else if (details.policySource === "customer_managed") {
    action = principals
      ? `Narrow customer-managed policy ${details.policyName} and verify that ${principals} retain only the permissions they need`
      : details.attachedTo.complete
        ? `Narrow customer-managed policy ${details.policyName} before it is attached or reused`
        : `Identify the current attachments to customer-managed policy ${details.policyName}, then narrow it and verify that each principal retains only the permissions it needs`;
  } else {
    action = principals
      ? `Narrow inline policy ${details.policyName} directly on ${principals}`
      : `Identify where inline policy ${details.policyName} is owned and narrow it there before reuse`;
  }
  const incomplete = details.attachedTo.complete
    ? ""
    : " Confirm the current IAM attachments first.";
  return `${action}.${incomplete}`;
};

/** The clause completing "This product rated it {severity} from ...". */
const BASIS: Record<SeverityBasisCode, string> = {
  open_port: "開放連接埠的觀察結果，而非缺陷",
  reachable_http_service: "可連線 HTTP 服務的觀察結果，而非缺陷",
  secret_pattern_match: "掃描到的原始碼中符合機密資料的樣式",
  unverified_credential_detector: "憑證偵測器的比對結果",
  iac_policy_check:
    "一項未通過的基礎架構即程式碼政策檢查；因為 Checkov 離線執行時不提供各別檢查的嚴重程度，所以一律採用相同等級",
  cis_kubernetes_benchmark: "一項未通過的 CIS Kubernetes Benchmark 檢查",
  cloud_control_query: "本產品自有固定查詢中一項未通過的 IAM 控制項",
  cloudsplaining_iam_policy_finding:
    "Cloudsplaining 未評定嚴重程度的 IAM 政策問題",
  unrated_vulnerability_test_alarm:
    "Greenbone 弱點測試發出的警示，但固定版本 feed 條目沒有可解析的嚴重程度向量",
};

const CONFIDENCE_BASIS: Record<ConfidenceBasisCode, string> = {
  deterministic_policy_evaluation: "確定性的政策或設定評估結果",
  advisory_version_match: "已安裝版本符合已發布公告的受影響範圍",
  unverified_pattern_or_detector_match: "樣式或偵測器比對結果",
  observed_response: "本產品直接觀察到的回應",
  template_matcher: "範本比對器在受評估目標上觸發",
  missing_detection_quality_score: "引擎結果中未提供偵測品質分數",
};

export const ALL_CONFIDENCE_BASIS_CODES: readonly ConfidenceBasisCode[] = [
  "deterministic_policy_evaluation",
  "advisory_version_match",
  "unverified_pattern_or_detector_match",
  "observed_response",
  "template_matcher",
  "missing_detection_quality_score",
];

const sourceConfidence = (
  priorityReasons: readonly string[],
): string | undefined =>
  priorityReasons
    .map((reason) => reason.trim())
    .find((reason) => reason.startsWith("Source confidence: "))
    ?.slice("Source confidence: ".length) || undefined;

const sourceSeverity = (
  priorityReasons: readonly string[],
): string | undefined =>
  priorityReasons
    .map((reason) => reason.trim())
    .find((reason) => reason.startsWith("Source severity: "))
    ?.slice("Source severity: ".length) || undefined;

/**
 * True only when an `unknown` finding has no scanner severity to present.
 *
 * Current findings retain a non-empty scanner severity in the exact
 * `Source severity: ...` priority reason. A basis code is stronger evidence
 * that the scanner supplied no severity, including if stale mixed metadata is
 * ever encountered. Keeping this separate from `severityBasisCode` preserves
 * the existing presentation of historical derived High/Medium findings.
 */
export const findingSeverityIsUnrated = (options: {
  severity: Severity;
  severityBasisCode?: SeverityBasisCode;
  priorityReasons?: readonly string[];
}): boolean => options.severity === "unknown" && (
  options.severityBasisCode !== undefined
  || sourceSeverity(options.priorityReasons ?? []) === undefined
);

export const findingConfidencePresentation = (
  locale: "en" | "zh-TW",
  confidenceLabel: string,
  confidenceBasisCode: ConfidenceBasisCode | undefined,
  priorityReasons: readonly string[],
): string => {
  if (confidenceBasisCode) {
    const basis = CONFIDENCE_BASIS[confidenceBasisCode];
    if (!basis) return confidenceLabel;
    return locale === "en"
      ? `${confidenceLabel} — this product's rating from ${CONFIDENCE_BASIS_ENGLISH[confidenceBasisCode]}`
      : `${confidenceLabel} — 本產品依據${basis}評定`;
  }
  const source = sourceConfidence(priorityReasons);
  if (!source) return confidenceLabel;
  return locale === "en"
    ? `${confidenceLabel} — engine rating: ${source}`
    : `${confidenceLabel} — 來源工具評定：${source}`;
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

export const localizedExpertType = (
  expert: string,
  locale: "en" | "zh-TW",
): string => {
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
  // The summary is normalized twice: once into the report's English, then
  // again by the exporter for the reader's locale. `" checked this "` is how
  // the control verdict below opens, so recognizing it here keeps the second
  // pass able to re-render in Chinese what the first pass already rewrote.
  const opener = englishSummary.includes(" reported ")
    ? " reported "
    : " checked this ";
  const [name, ...rest] = englishSummary.split(opener);
  if (rest.length === 0 || !name || name.includes(".")) return undefined;
  return name;
};

/** "{engine} reported a {severity}-severity condition on the assessed asset." */
/**
 * The verdict sentence for a control the tenant did not meet.
 *
 * ScubaGear and Maester title a finding with the requirement they checked --
 * "Legacy authentication is blocked", "Privileged accounts use phishing-
 * resistant MFA" -- and only a control that failed becomes a finding at all.
 * Printed as a heading under "Problems found" over a sentence that said no
 * more than "reported a high-severity condition", the requirement read as a
 * statement that the tenant was already in that state, which is the opposite
 * of what the scanner found. The upstream title stays exactly as the scanner
 * wrote it; the verdict goes in the prose this product owns.
 */
const controlVerdict = (
  family: FindingFamily | undefined,
  english: string,
  localeZh: boolean,
): string | undefined => {
  if (family !== "microsoft365") return undefined;
  const engine = engineNameFrom(english);
  if (!engine) return undefined;
  return localeZh
    ? `${engine} 檢查了這項 Microsoft 365 要求，這個租戶未通過。`
    : `${engine} checked this Microsoft 365 requirement and the tenant did not meet it.`;
};

/**
 * Drops the trailing confidence-methodology sentence.
 *
 * The adapter composes the risk summary as "{what the scanner reported} {how
 * this product rated its confidence}". The second half is already on the same
 * card twice: as the labelled `Confidence` field with its basis, and again in
 * the priority reasons. Keeping a third copy spent the one sentence a beginner
 * reads on the product's own rating method instead of on what the scanner
 * found, on 43 of the 45 findings in a 21-engine run.
 */
const withoutConfidenceMethodology = (english: string): string => {
  const openers = [" reported no confidence rating for it.", " reported confidence "];
  const cuts = openers
    .map((opener) => english.indexOf(opener))
    .filter((at) => at >= 0)
    // The sentence opens with the engine's display name, so the cut is the
    // sentence boundary before it. Without a preceding boundary the summary is
    // only the confidence sentence and there is nothing to keep.
    .map((at) => english.slice(0, at).lastIndexOf(". "))
    .filter((end) => end >= 0)
    .map((end) => end + 2);
  if (cuts.length === 0) return english;
  return english.slice(0, Math.min(...cuts)).trimEnd();
};

export const findingSummarySentence = (
  locale: "en" | "zh-TW",
  options: {
    englishFallback: string;
    severity?: Severity;
    severityLabel: string;
    severityBasisCode?: SeverityBasisCode;
    confidenceLabel?: string;
    confidenceBasisCode?: ConfidenceBasisCode;
    priorityReasons?: readonly string[];
    family?: FindingFamily;
  },
): string => {
  const verdict = controlVerdict(options.family, options.englishFallback, locale === "zh-TW");
  if (verdict) return verdict;
  const englishFallback = withoutConfidenceMethodology(options.englishFallback)
    .replace(" The attached raw record is evidence, not an instruction.", "")
    .replace("Severity remains Unknown and requires human review.", "Severity is Unknown.")
    .replace("a credential detector match that this product does not verify", "a credential detector match")
    .replace("an unverified credential detector match", "a credential detector match")
    .replace("an unverified pattern or detector match", "a pattern or detector match");
  if (locale === "en") return englishFallback;
  const { severityLabel, severityBasisCode } = options;
  const unratedSeverity = options.severity !== undefined && findingSeverityIsUnrated({
    severity: options.severity,
    severityBasisCode,
    priorityReasons: options.priorityReasons,
  });
  const engineName = engineNameFrom(englishFallback);
  if (!engineName) return englishFallback;
  let summary: string;
  if (unratedSeverity) {
    summary = `${engineName} 回報了這項狀況，但未評定嚴重程度。嚴重程度為未知。`;
  } else if (!severityBasisCode) {
    summary = `${engineName} 在受評估的資產上回報了一項${severityLabel}等級的狀況。`;
  } else {
    const basis = BASIS[severityBasisCode];
    if (!basis) return englishFallback;
    summary = `${engineName} 在受評估的資產上回報了這項狀況，但未評定嚴重程度。本產品依據${basis}，將它評為${severityLabel}。`;
  }
  // The English twin drops the same sentence. The confidence rating, its
  // basis, and the engine's own lack of one are already the labelled
  // confidence field and a priority reason on this same card.
  return summary;
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
    "受影響的資產可從網際網路存取，因此可被觸及的攻擊面較大。",
  sensitive_data_asset:
    "受影響的資產含有敏感資料，因此問題造成的影響可能更高。",
};

const CONTEXT_ENGLISH: Record<ContextFactor, string> = {
  internet_exposed_asset:
    " The affected asset is internet-accessible, increasing the reachable attack surface.",
  sensitive_data_asset:
    " The affected asset contains sensitive data, increasing the potential impact.",
};

const directLegacyImpact = (english: string): string => {
  let normalized = english.trim()
    .replace(/^If the scanner result is confirmed, /u, "")
    .replace(/ The (?:critical|high|medium|low|informational|unknown) source severity is not a product-wide compliance score\.$/u, "")
    .replace(/ The scanner did not assign a severity; it remains Unknown for human review\.$/u, "")
    .replace(
      " The affected asset is marked internet-exposed and has only retained non-questionnaire source attribution, which may increase the reachable attack surface; field-level provenance for that attribute is not retained, so it still requires human confirmation.",
      " The affected asset is internet-accessible, increasing the reachable attack surface.",
    )
    .replace(
      " The affected asset is marked as containing sensitive data and has only retained non-questionnaire source attribution, while the case questionnaire separately records sensitive-data context. This may increase the impact of a confirmed exposure, but field-level data-class provenance is not retained and neither entry is itself proof of data exposure.",
      " The affected asset contains sensitive data, increasing the potential impact.",
    );
  if (normalized) normalized = normalized[0]!.toLocaleUpperCase("en") + normalized.slice(1);
  return normalized;
};

/** The direct possible impact and case context. */
export const findingImpactSentence = (
  locale: "en" | "zh-TW",
  options: {
    englishFallback: string;
    severity?: Severity;
    severityLabel: string;
    severityBasisCode?: SeverityBasisCode;
    priorityReasons?: readonly string[];
    family?: FindingFamily;
    contextFactors?: readonly ContextFactor[];
  },
): string => {
  const consequence = options.family
    ? (locale === "en" ? CONSEQUENCE_ENGLISH[options.family] : CONSEQUENCE[options.family])
    : undefined;
  if (!consequence) return directLegacyImpact(options.englishFallback);
  const context = locale === "en" ? CONTEXT_ENGLISH : CONTEXT;
  const ending = locale === "en" ? "." : "。";
  return `${consequence}${ending}${(options.contextFactors ?? [])
    .map((factor) => context[factor] ?? "")
    .join("")}`;
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
  "Capture the current configuration and test its restoration path before making the change.";

/** "Before any manual change, preserve ... and document a tested restoration path." */
export const findingRollbackSentence = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const normalized = english.trim() === "Before any manual change, preserve the current approved configuration and document a tested restoration path."
    ? ENGLISH_ROLLBACK
    : english;
  if (locale === "en" || normalized.trim() !== ENGLISH_ROLLBACK) return normalized;
  return "變更前先保存目前設定，並測試還原路徑。";
};

/**
 * "Rerun {engine} with the same scope after the change and confirm source rule {rule} is no
 * longer reported."
 *
 * Read back off the sentence for the same reason `engineNameFrom` is: the
 * engine's display name and the source rule id are the engine's own strings and
 * have to appear in the Chinese exactly as they do in the English. Returns the
 * English unchanged for any sentence not in this shape.
 */
export const findingVerificationSentence = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const LEGACY_RERUN = "After an approved manual change, rerun ";
  const LEGACY_SCOPE = " with the same authorized scope and confirm that source rule ";
  const RERUN = "Rerun ";
  const SCOPE = " with the same scope after the change and confirm that source rule ";
  const TAIL = " is no longer reported.";
  const trimmed = english.trim();
  const legacy = trimmed.startsWith(LEGACY_RERUN);
  const prefix = legacy ? LEGACY_RERUN : RERUN;
  const scope = legacy ? LEGACY_SCOPE : SCOPE;
  if (!trimmed.startsWith(prefix) || !trimmed.endsWith(TAIL)) return english;
  const middle = trimmed.slice(prefix.length, trimmed.length - TAIL.length);
  const at = middle.indexOf(scope);
  if (at < 0) return english;
  const engine = middle.slice(0, at);
  const rule = middle.slice(at + scope.length);
  if (!engine || !rule) return english;
  if (locale === "en") return `Rerun ${engine} with the same scope after the change and confirm that source rule ${rule} is no longer reported.`;
  return `變更後以相同範圍重新執行 ${engine}，並確認來源規則 ${rule} 不再被回報。`;
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
  reachable_http_service:
    "a reachable HTTP service observation rather than a defect",
  secret_pattern_match: "a secret pattern match in scanned source",
  unverified_credential_detector:
    "a credential detector match",
  iac_policy_check:
    "a failed infrastructure-as-code policy check, rated flat because Checkov publishes no per-check severity offline",
  cis_kubernetes_benchmark: "a failed CIS Kubernetes Benchmark check",
  cloud_control_query:
    "a failed IAM control from this product's own fixed query",
  cloudsplaining_iam_policy_finding:
    "an IAM policy finding Cloudsplaining did not rate",
  unrated_vulnerability_test_alarm:
    "a Greenbone vulnerability-test alarm whose pinned feed entry carries no parseable severity vector",
};

const CONFIDENCE_BASIS_ENGLISH: Record<ConfidenceBasisCode, string> = {
  deterministic_policy_evaluation:
    "a deterministic policy or configuration evaluation",
  advisory_version_match:
    "an installed-version match against a published advisory range",
  unverified_pattern_or_detector_match:
    "a pattern or detector match",
  observed_response: "a response this product observed directly",
  template_matcher: "a template matcher firing on the assessed target",
  missing_detection_quality_score:
    "the absence of a detection-quality score in the engine result",
};

/** The one priority reason every adapter finding carries. */
export const ENGLISH_EVIDENCE_REASON =
  "Direct scanner evidence is attached.";
export const isEvidenceOnlyPriorityReason = (reason: string): boolean =>
  reason.trim() === ENGLISH_EVIDENCE_REASON
  || reason.trim() === "Direct scanner evidence is attached and still requires human review.";
export const ENGLISH_EXPOSURE_OBSERVATION_REASON =
  "Classified as a reachable-service inventory observation, not a vulnerability.";

/** The two reasons `apply_case_context` pushes when the case raises a finding. */
const ENGLISH_INTERNET_REASON =
  "The affected asset is internet-accessible.";
const ENGLISH_SENSITIVE_REASON =
  "The affected asset contains sensitive data, increasing the potential impact.";
const LEGACY_ENGLISH_INTERNET_REASON =
  "An affected asset is marked internet-exposed, and all retained source attribution for that asset is non-questionnaire.";
const LEGACY_ENGLISH_SENSITIVE_REASON =
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
export const findingPriorityReason = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const UNRATED_PREFIX = "Severity remains Unknown because ";
  const UNRATED_TAIL = " did not assign one; human review is required.";
  const CURRENT_UNRATED_PREFIX = "Severity is Unknown because ";
  const CURRENT_UNRATED_TAIL = " did not provide a rating.";
  const original = english.trim();
  const legacyEngine = original.startsWith(UNRATED_PREFIX) && original.endsWith(UNRATED_TAIL)
    ? original.slice(UNRATED_PREFIX.length, original.length - UNRATED_TAIL.length)
    : undefined;
  const normalized = legacyEngine
    ? `${CURRENT_UNRATED_PREFIX}${legacyEngine}${CURRENT_UNRATED_TAIL}`
    : original === LEGACY_ENGLISH_INTERNET_REASON
      ? ENGLISH_INTERNET_REASON
      : original === LEGACY_ENGLISH_SENSITIVE_REASON
        ? ENGLISH_SENSITIVE_REASON
        : english
          .replace("a credential detector match that this product does not verify", "a credential detector match")
          .replace("an unverified credential detector match", "a credential detector match")
          .replace("an unverified pattern or detector match", "a pattern or detector match");
  const trimmed = normalized.trim();
  if (locale === "en") return normalized;
  if (trimmed === ENGLISH_EVIDENCE_REASON)
    return "已附上掃描工具的直接證據。";
  if (trimmed === ENGLISH_EXPOSURE_OBSERVATION_REASON)
    return "這是可連線服務的盤點觀察，不是漏洞。";
  if (trimmed === ENGLISH_INTERNET_REASON || trimmed === LEGACY_ENGLISH_INTERNET_REASON)
    return "受影響的資產可從網際網路存取。";
  if (trimmed === ENGLISH_SENSITIVE_REASON || trimmed === LEGACY_ENGLISH_SENSITIVE_REASON)
    return "受影響的資產含有敏感資料，因此問題造成的影響可能更高。";
  // The engine's own raw severity word, kept verbatim. Restating "high" as 高
  // would stop it matching what the reader sees in the engine's own output.
  const SOURCE = "Source severity: ";
  if (trimmed.startsWith(SOURCE)) {
    const value = trimmed.slice(SOURCE.length);
    if (value) return `來源工具評定的嚴重程度：${value}`;
  }
  if (
    legacyEngine
    || (trimmed.startsWith(CURRENT_UNRATED_PREFIX) && trimmed.endsWith(CURRENT_UNRATED_TAIL))
  ) {
    const engine = legacyEngine ?? trimmed.slice(
      CURRENT_UNRATED_PREFIX.length,
      trimmed.length - CURRENT_UNRATED_TAIL.length,
    );
    if (engine) return `嚴重程度為未知，因為 ${engine} 未提供評級。`;
  }
  const SOURCE_CONFIDENCE = "Source confidence: ";
  if (trimmed.startsWith(SOURCE_CONFIDENCE)) {
    const value = trimmed.slice(SOURCE_CONFIDENCE.length);
    if (value) return `來源工具評定的信心：${value}`;
  }
  const CONFIDENCE_DERIVED = "Confidence derived from ";
  const CONFIDENCE_TAIL = " reports no confidence of its own.";
  if (
    trimmed.startsWith(CONFIDENCE_DERIVED) &&
    trimmed.endsWith(CONFIDENCE_TAIL)
  ) {
    const middle = trimmed.slice(
      CONFIDENCE_DERIVED.length,
      trimmed.length - CONFIDENCE_TAIL.length,
    );
    const at = middle.lastIndexOf("; ");
    if (at < 0) return english;
    const basisText = middle.slice(0, at);
    const engine = middle.slice(at + 2);
    const code = (
      Object.keys(CONFIDENCE_BASIS_ENGLISH) as ConfidenceBasisCode[]
    ).find((key) => CONFIDENCE_BASIS_ENGLISH[key] === basisText);
    if (!code || !engine) return english;
    return `信心是由${CONFIDENCE_BASIS[code]}推導而來；${engine} 本身不提供信心評定。`;
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
 * asset. Legacy English wording is normalized before it is displayed.
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

  const noVerdictSeparators = [": no verdict for ", ": manual review for "];
  const noVerdictSeparator = noVerdictSeparators.find((separator) => dimension.includes(separator));
  const noVerdictAt = noVerdictSeparator ? dimension.indexOf(noVerdictSeparator) : -1;
  if (noVerdictSeparator && noVerdictAt > 0) {
    const check = dimension.slice(0, noVerdictAt);
    const control = dimension.slice(noVerdictAt + noVerdictSeparator.length);
    if (control) return `${check}：未回傳判定的控制項 ${control}`;
  }

  // Fixed names, in the order the more specific one has to be tried first:
  // "completed planned work units" is a substring of the partly-completed one.
  for (const [needle, label] of [
    ["tcp reachability", "TCP 連線狀態"],
    ["bounded connection contract", "受限的連線檢查"],
    ["nuclei upstream website scan", "Nuclei 上游網站掃描"],
    ["greenbone remote vulnerability scan", "Greenbone 遠端弱點掃描"],
    ["internal-device tls vulnerability checks", "內部設備 TLS 弱點檢查"],
    ["internal-device scan-profile coverage", "內部設備掃描設定檔涵蓋記錄"],
    ["ssh service vulnerability checks", "SSH 服務弱點檢查"],
    ["ssh endpoint scan-profile coverage", "SSH 端點掃描設定檔涵蓋記錄"],
    ["rdp transport security checks", "RDP 傳輸安全性檢查"],
    [
      "rdp transport endpoint scan-profile coverage",
      "RDP 傳輸端點掃描設定檔涵蓋記錄",
    ],
    [
      "rdp implementation, authentication/nla, and endpoint host coverage",
      "RDP 實作、驗證／NLA 與端點主機涵蓋範圍",
    ],
    ["vnc transport security check", "VNC 傳輸安全性檢查"],
    [
      "vnc transport endpoint scan-profile coverage",
      "VNC 傳輸端點掃描設定檔涵蓋記錄",
    ],
    [
      "vnc implementation, authentication, and endpoint host coverage",
      "VNC 實作、驗證與端點主機涵蓋範圍",
    ],
    [
      "smtp cleartext-login and tls security checks",
      "SMTP 明文登入與 TLS 安全性檢查",
    ],
    [
      "smtp fixed security profile attempt",
      "SMTP 固定安全設定檔嘗試",
    ],
    [
      "smtp tls checks with selected-run evidence",
      "具有所選本輪證據的 SMTP TLS 檢查",
    ],
    [
      "smtp tls negotiation-dependent coverage",
      "需成功協商 TLS 的 SMTP 涵蓋範圍",
    ],
    [
      "smtp endpoint scan-profile coverage",
      "SMTP 端點掃描設定檔涵蓋記錄",
    ],
    [
      "smtp server behavior, implementation, and endpoint host coverage",
      "SMTP 伺服器行為、實作與端點主機涵蓋範圍",
    ],
    ["telnet cleartext-login security check", "Telnet 明文登入安全性檢查"],
    [
      "telnet endpoint scan-profile coverage",
      "Telnet 端點掃描設定檔涵蓋記錄",
    ],
    [
      "telnet authentication, implementation, and endpoint host coverage",
      "Telnet 驗證、實作與端點主機涵蓋範圍",
    ],
    [
      "endpoint operating-system, package, application, and local-configuration coverage",
      "端點作業系統、套件、應用程式與本機設定涵蓋範圍",
    ],
    ["supported vulnerability profile", "可用的弱點掃描設定"],
    [
      "device product and firmware vulnerability coverage",
      "設備產品與韌體弱點涵蓋範圍",
    ],
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
        return withCheck(
          head.slice(0, head.length - suffix.length),
          `${label}（${counted[2]}）`,
        );
      }
    }
  }

  // "{check id} {kind}".
  for (const [suffix, label] of [
    [" completed-check time", "檢查完成時間"],
    [" saved work-unit coverage", "已儲存的工作單元涵蓋記錄"],
    [" saved result processing", "已儲存結果的處理"],
    [" final-state reconciliation", "最終狀態核對"],
    [" ended after its time limit", "因逾時而結束"],
    [" stopped before finishing", "未完成就停止"],
    [" was cancelled before finishing", "未完成就被取消"],
  ] as const) {
    if (dimension.endsWith(suffix)) {
      return withCheck(
        dimension.slice(0, dimension.length - suffix.length),
        label,
      );
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
      ["vulnerability profile evidence", "弱點掃描設定檔證據"],
      ["website execution evidence", "網站執行證據"],
      ["target response", "目標回應"],
      ["scanner errors", "掃描器錯誤"],
    ] as const) {
      if (rest === fragment)
        return withCheck(dimension.slice(0, separator), label);
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
    "Maester evaluated this control but did not return a pass or fail verdict.",
    "Maester 已評估這項控制措施，但未回傳通過或失敗的判定。",
  ],
  [
    "Website security-template evidence unavailable. Outcome: not tested.",
    "網站安全模板證據無法取得；結果：未測試。",
  ],
  [
    "Host response unavailable. Vulnerability checks: not run.",
    "主機回應無法取得；弱點檢查：未執行。",
  ],
  [
    "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.",
    "請確認這台主機已開機，且本機能連到已核准的連接埠，然後再執行一次這項檢查。",
  ],
  [
    "Greenbone scanner errors. Host checks: partially completed.",
    "Greenbone 掃描器錯誤；主機檢查：部分完成。",
  ],
  [
    "Retry this check to complete the missing work.",
    "重新執行這項檢查以完成缺少的工作。",
  ],
  [
    "The request-level outcome contradicts the run's durable task state and was ignored.",
    "這次請求層級的結果與本輪儲存的檢查狀態互相矛盾，因此未被採用。",
  ],
  [
    "At least one legacy finding observation did not retain its full run-specific presentation snapshot.",
    "至少有一筆舊版的問題觀察結果，沒有保留該輪完整的顯示資料。",
  ],
  [
    "Saved work-unit coverage is inconsistent; tested units are unknown.",
    "已保存的工作單元涵蓋記錄不一致；已檢測單元為未知。",
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
    "Result processing status: incomplete.",
    "結果處理狀態：未完成。",
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
    "This check has no terminal outcome.",
    "這項檢查沒有終止結果。",
  ],
  [
    "Packaged check list unavailable. Additional checks: not tested.",
    "內建檢查清單無法取得；額外檢查：未測試。",
  ],
  [
    "Packaged scanner information unavailable. Additional checks: not tested.",
    "內建掃描工具資訊無法取得；額外檢查：未測試。",
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
    "Recorded stage selection: unavailable. Current project settings: excluded from this historical record.",
    "已記錄的階段選擇：無法取得。目前專案設定：不納入此歷史記錄。",
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
    "This HTTPS management-service profile contains no device product or firmware vulnerability checks. TLS protocol, cipher, and certificate checks are reported separately.",
    "此 HTTPS 管理服務設定檔不包含設備產品或韌體弱點檢查；TLS 協定、加密套件與憑證檢查會另行回報。",
  ],
  [
    "This run does not retain one exact frozen HTTPS management-service profile for this asset. Current project metadata is not used to claim historical TLS coverage.",
    "本輪沒有為此資產保留一份精確凍結的 HTTPS 管理服務設定檔。目前的專案資料不會用來宣稱當時已涵蓋 TLS。",
  ],
  [
    "This run does not retain the exact fixed SSH profile for this asset. Current project metadata is not used to claim historical SSH vulnerability coverage.",
    "本輪沒有為此資產保留精確固定的 SSH 設定檔。目前的專案資料不會用來宣稱當時已完成 SSH 弱點涵蓋。",
  ],
  [
    "The unauthenticated SSH service profile does not inspect operating-system patch level, installed packages or applications, or local host configuration.",
    "這項不需登入的 SSH 服務設定檔，不會檢查作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。",
  ],
  [
    "This run does not retain the exact fixed RDP transport profile for this asset. Current project metadata is not used to claim historical RDP transport security coverage.",
    "本輪沒有為此資產保留精確固定的 RDP 傳輸設定檔。目前的專案資料不會用來宣稱當時已完成 RDP 傳輸安全性涵蓋。",
  ],
  [
    "The unauthenticated RDP transport profile checks one legacy RDP 5.2-or-earlier fixed-private-key issue, but does not inspect broader or current RDP implementation CVEs, authentication or Network Level Authentication (NLA), Windows patch level, installed packages or applications, or local host configuration.",
    "這項不需登入的 RDP 傳輸設定檔會檢查一項 RDP 5.2 或更早版本的舊式固定私密金鑰問題，但不會檢查更廣泛或現行的 RDP 實作 CVE、驗證或網路層級驗證（NLA）、Windows 修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。",
  ],
  [
    "This run does not retain the exact fixed VNC transport profile for this asset. Current project metadata is not used to claim historical VNC transport security coverage.",
    "本輪沒有為此資產保留精確固定的 VNC 傳輸設定檔。目前的專案資料不會用來宣稱當時已完成 VNC 傳輸安全性涵蓋。",
  ],
  [
    "The unauthenticated VNC transport profile checks whether the VNC connection is encrypted. It does not inspect VNC implementation CVEs, authentication strength, operating-system patch level, installed packages or applications, or local host configuration. No login or desktop session was attempted.",
    "這項不需登入的 VNC 傳輸設定檔會檢查 VNC 連線是否加密，但不會檢查 VNC 實作 CVE、驗證強度、作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定；本輪未嘗試登入或建立桌面工作階段。",
  ],
  [
    "This run does not retain the exact fixed SMTP profile for this asset. Current project metadata is not used to claim historical SMTP security coverage.",
    "本輪沒有為此資產保留精確固定的 SMTP 設定檔。目前的專案資料不會用來宣稱當時已完成 SMTP 安全性涵蓋。",
  ],
  [
    "The unauthenticated SMTP profile reads the banner, issues EHLO, negotiates STARTTLS when offered, and checks advertised AUTH for an unencrypted cleartext-login risk. Its TLS checks apply only when TLS can be negotiated. It does not send credentials or mail, test relay or delivery, authentication enforcement or bypass, anti-spam behavior, general mail-server implementation CVEs, operating-system patches, installed software, or local configuration.",
    "這項不需登入的 SMTP 設定檔會讀取 banner、送出 EHLO、在服務提供時協商 STARTTLS，並檢查服務宣告的 AUTH 是否存在未加密的明文登入風險。只有在能協商 TLS 時才會執行 TLS 檢查。它不會送出帳號或密碼、寄信，也不會測試 relay 或投遞、驗證強制或繞過、anti-spam 行為、一般郵件伺服器實作 CVE、作業系統修補、已安裝軟體或本機設定。",
  ],
  [
    "Selected-run SMTP TLS evidence: incomplete. Fixed profile status: attempted. TLS availability and per-check execution: shown only by each finding's source OID.",
    "所選輪次的 SMTP TLS 證據：未完成。固定設定檔狀態：已嘗試。TLS 可用性與各項檢查的執行情況：只由各問題的來源 OID 顯示。",
  ],
  [
    "This run does not retain the exact fixed Telnet profile for this asset. Current project metadata is not used to claim historical Telnet security coverage.",
    "本輪沒有為此資產保留精確固定的 Telnet 設定檔。目前的專案資料不會用來宣稱當時已完成 Telnet 安全性涵蓋。",
  ],
  [
    "The unauthenticated Telnet profile observes whether a login or password prompt is offered without TLS. It sends no username or password and does not log in; it does not test default credentials, authentication bypass, Telnet implementation CVEs, operating-system patches, installed software, or local configuration.",
    "這項不需登入的 Telnet 設定檔會觀察服務是否在沒有 TLS 的情況下提供登入或密碼提示。它不會送出帳號或密碼，也不會登入；不會測試預設帳密、驗證繞過、Telnet 實作 CVE、作業系統修補、已安裝軟體或本機設定。",
  ],
  [
    "The Greenbone process completed, but this run does not retain one exact reviewed vulnerability profile for every bound asset. Process completion is not counted as a vulnerability result.",
    "Greenbone 程序雖已完成，但本輪沒有為每個綁定資產保留一份精確且經審查的弱點掃描設定檔。因此程序完成不會被算成弱點掃描結果。",
  ],
  [
    "Supported service-specific vulnerability profile unavailable. Outcome: not tested.",
    "支援的服務專屬弱點掃描設定無法取得；結果：未測試。",
  ],
  [
    "Completed-check time: unavailable. Finish and bounded observation times are absent.",
    "已完成檢查時間：無法取得。缺少結束時間與受限觀察時間。",
  ],
  [
    "Start the expected service, then run this check again.",
    "啟動預定的服務，再重新執行這項檢查。",
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
    "Actionable findings in completed checks: 0.",
    "已完成檢查中的可處理問題：0。",
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
    "No installed check applies to the selected target and permission.",
    "沒有已安裝的檢查同時符合所選目標與授權範圍。",
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
    "Finish target setup or add a supported input, then start a new scan.",
    "請完成目標設定或加入受支援的輸入，然後重新開始掃描。",
  ],
  [
    "Open the saved scope details.",
    "查看已保存的範圍細節。",
  ],
  [
    "Run this SSH profile again to create a complete coverage record.",
    "重新執行此 SSH 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run this RDP profile again to create a complete coverage record.",
    "重新執行此 RDP 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run this VNC profile again to create a complete coverage record.",
    "重新執行此 VNC 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run this SMTP profile again to create a complete coverage record.",
    "重新執行此 SMTP 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run this Telnet profile again to create a complete coverage record.",
    "重新執行此 Telnet 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run the HTTPS management-service profile again to create a complete coverage record.",
    "重新執行 HTTPS 管理服務設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Choose a supported device product and firmware vulnerability check.",
    "選擇支援的設備產品與韌體弱點檢查。",
  ],
  [
    "Use an approved endpoint inventory or local snapshot for host-level checks.",
    "使用已核准的端點盤點資料或本機快照進行主機層級檢查。",
  ],
  [
    "Run a separately approved host or RDP-authentication assessment for those checks.",
    "另行執行經核准的主機或 RDP 驗證評估。",
  ],
  [
    "Use an approved endpoint inventory or run a separate authorized VNC assessment.",
    "使用已核准的端點盤點資料，或另行執行已授權的 VNC 評估。",
  ],
  [
    "Run a separately approved mail-server assessment or use endpoint inventory.",
    "另行執行經核准的郵件伺服器評估，或使用端點盤點資料。",
  ],
  [
    "Run a separately approved TLS assessment for complete SMTP TLS coverage.",
    "另行執行經核准的 TLS 評估以取得完整 SMTP TLS 涵蓋。",
  ],
  [
    "Run a separately approved authentication assessment or use endpoint inventory.",
    "另行執行經核准的驗證評估，或使用端點盤點資料。",
  ],
  [
    "Choose a supported exact asset profile and run it when vulnerability coverage is needed.",
    "需要弱點涵蓋時，請為資產選擇支援的精確掃描設定檔並執行。",
  ],
  [
    "Add a supported exact service profile, then run this asset's vulnerability check.",
    "加入支援的精確服務設定，再執行這項資產的弱點檢查。",
  ],
  [
    "Retry this scan to create a consistent coverage record.",
    "重新執行掃描以建立一致的涵蓋記錄。",
  ],
  [
    "Rerun the scan to create a fully frozen result.",
    "重新執行掃描以建立完全凍結的結果。",
  ],
  [
    "Retry this check to create a consistent coverage record.",
    "重新執行這項檢查以建立一致的涵蓋記錄。",
  ],
  [
    "Retry only the unfinished work.",
    "只重新執行尚未完成的工作。",
  ],
  [
    "Retry only the failed work.",
    "只重新執行失敗的工作。",
  ],
  [
    "Retry only the timed-out work.",
    "只重新執行逾時的工作。",
  ],
  [
    "Restart the cancelled work.",
    "重新啟動已取消的工作。",
  ],
  [
    "Open Progress and finish or cancel this check.",
    "前往進度頁完成或取消這項檢查。",
  ],
  [
    "Retry the work without a tested outcome.",
    "重試未產生檢測結果的工作。",
  ],
  [
    "Start a new scan for a fresh result.",
    "開始新的掃描以取得新結果。",
  ],
  [
    "Retry this check to create a consistent terminal record.",
    "重新執行這項檢查以建立一致的終止記錄。",
  ],
  [
    "Retry only the unfinished work.",
    "只重新執行尚未完成的工作。",
  ],
  [
    "Retry this check to complete the unfinished dimensions.",
    "重新執行這項檢查以完成尚未完成的項目。",
  ],
  [
    "Confirm reachability in Scan setup, then retry the timed-out work.",
    "到「掃描設定」確認連線，再重試逾時的工作。",
  ],
  [
    "Retry this check.",
    "重新執行這項檢查。",
  ],
  [
    "Retry this check to complete the missing coverage.",
    "重新執行這項檢查以完成缺少的涵蓋範圍。",
  ],
  [
    "Review the target and try this check again.",
    "請檢視目標設定，然後重新執行這項檢查。",
  ],
  [
    "Open Progress and finish or cancel this check.",
    "前往進度頁完成或取消這項檢查。",
  ],
  [
    "Restore the packaged scanner information, then run the missing checks.",
    "恢復內建掃描工具資訊，然後執行缺少的檢查。",
  ],
  [
    "Open the upstream detail and set this control's status.",
    "開啟上游詳細資料，並設定這項控制措施的狀態。",
  ],
  [
    "No action for the current scope.",
    "目前範圍不需處理。",
  ],
];

/**
 * One sentence of a coverage row, in the reader's language.
 *
 * English uses the stored detail after normalizing superseded product wording.
 * It is more specific than anything derivable from the gap's kind: the same
 * `not_tested` kind is written for a check that saved partial work, one that
 * never started, and one still running.
 */
const normalizeDirectCoverageGapProse = (english: string): string => {
  let normalized = english
    .replace(
      "No completed upstream security-template execution record was retained for this website, so the scan cannot be shown as tested. The site may not have responded, or upstream technology detection may not have selected an applicable template.",
      "Website security-template evidence unavailable. Outcome: not tested.",
    )
    .replace(
      "Greenbone reported that this host did not respond during the scan, so none of its vulnerability checks ran. This is not a clean result.",
      "Host response unavailable. Vulnerability checks: not run.",
    )
    .replace(
      "Greenbone reported one or more scanner errors for this host, so some of its checks did not finish. Findings and checks that did complete remain valid.",
      "Greenbone scanner errors. Host checks: partially completed.",
    )
    .replace(
      "Greenbone scanner errors left some host checks incomplete. Completed findings and checks remain in this report.",
      "Greenbone scanner errors. Host checks: partially completed.",
    )
    .replace(
      "The packaged check list could not be loaded. Available checks may still run, but checks from that list are not tested.",
      "Packaged check list unavailable. Additional checks: not tested.",
    )
    .replace(
      "One additional packaged check was unavailable before planning. Whether it applied to the selected target is unknown, so it is not tested.",
      "Packaged scanner information unavailable. Additional checks: not tested.",
    )
    .replace(
      "This asset was added to the IT environment, but this run had no supported service-specific vulnerability profile for it. It was not contacted or tested.",
      "Supported service-specific vulnerability profile unavailable. Outcome: not tested.",
    )
    .replace(
      "No actionable finding was recorded, but a no-findings result is only as broad as the displayed coverage.",
      "Actionable findings in completed checks: 0.",
    );
  if (normalized.includes("additional packaged checks were unavailable before planning")) {
    normalized = "Packaged scanner information unavailable. Additional checks: not tested.";
  }
  return normalized;
};

export const coverageGapProse = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const legacyReviewBase = "Maester evaluated this control but did not return a pass or fail verdict. It requires manual review and is not a vulnerability finding.";
  const reviewBase = "Maester evaluated this control but did not return a pass or fail verdict.";
  let normalized = normalizeDirectCoverageGapProse(english)
    .replace(legacyReviewBase, reviewBase)
    .replace(
      "Review the upstream detail and record a human decision for this control.",
      "Open the upstream detail and set this control's status.",
    );
  if (normalized.includes("saved work-unit coverage for this check is internally inconsistent")) {
    normalized = "Saved work-unit coverage is inconsistent; tested units are unknown.";
  }
  if (normalized.includes("does not retain selected-run finding evidence for every SMTP TLS check")) {
    normalized = "Selected-run SMTP TLS evidence: incomplete. Fixed profile status: attempted. TLS availability and per-check execution: shown only by each finding's source OID.";
  }
  if (normalized.includes("did not freeze a quick-discovery, inventory, or deep-stage selection")) {
    normalized = "Recorded stage selection: unavailable. Current project settings: excluded from this historical record.";
  }
  if (normalized.includes("neither a finish time nor a bounded native observation time")) {
    normalized = "Completed-check time: unavailable. Finish and bounded observation times are absent.";
  }
  if (normalized.includes("validated scanner result has not been fully processed")) {
    normalized = "Result processing status: incomplete.";
  }
  if (normalized.includes("result processing retries automatically")) {
    normalized = "Start a new scan for a fresh result.";
  }
  if (normalized.includes("No action is needed unless this area should be included")) {
    normalized = "No action for the current scope.";
  }
  if (locale === "en") return normalized;
  const trimmed = normalized.trim();
  const reviewDetailPrefix = `${reviewBase} Upstream detail: `;
  if (trimmed.startsWith(reviewDetailPrefix) && trimmed.length > reviewDetailPrefix.length) {
    const base = lookupProse(reviewBase);
    if (base) return `${base} 上游詳細資料：${trimmed.slice(reviewDetailPrefix.length)}`;
  }
  // Six reasons gain a diagnostic code when the task recorded one. It is the
  // scanner's own code and stays verbatim; only the sentence around it moves.
  const withCode = /^(.*\.) Diagnostic code: (.+)\.$/u.exec(trimmed);
  if (withCode) {
    const base = lookupProse(withCode[1] ?? "");
    if (base) return `${base}診斷代碼：${withCode[2]}。`;
    return normalized;
  }
  return lookupProse(trimmed) ?? normalized;
};

const lookupProse = (english: string): string | undefined =>
  COVERAGE_GAP_PROSE.find(([candidate]) => candidate === english)?.[1];

/**
 * The fixed observations attached to tested dimensions, paired with their
 * Traditional Chinese. The whole stored observation is the lookup key because
 * the backend writes it before any locale is known and freezes it in the case.
 */
const TESTED_OBSERVATION_PROSE: ReadonlyArray<readonly [string, string]> = [
  [
    "Nuclei completed the pinned upstream automatic web profile on the displayed origin. Applied checks: templates selected by upstream technology detection. Eligible-template execution completeness: unavailable.",
    "Nuclei 已對畫面所列網站來源範圍完成固定版本的上游自動網站設定。套用的檢查：由上游技術偵測選取的模板。合格模板執行完整度：無法取得。",
  ],
  [
    "Greenbone completed the frozen remote-safe profile on the displayed host and ports. Applied checks: feed checks selected by upstream service and product prerequisites. Scheduled-VT execution completeness: unavailable.",
    "Greenbone 已對畫面所列主機與連接埠完成凍結的遠端安全掃描設定。套用的檢查：由上游服務與產品先決條件選取的 feed 檢查。排程 VT 執行完整度：無法取得。",
  ],
  [
    "The port accepted the bounded TCP connection.",
    "這個連接埠接受了受限的 TCP 連線。",
  ],
  [
    "The port refused the bounded TCP connection.",
    "這個連接埠拒絕了受限的 TCP 連線。",
  ],
  [
    "The bounded TCP connection attempt timed out; reachability was not established.",
    "受限的 TCP 連線嘗試逾時；無法確認連線可達。",
  ],
  [
    "The native task only observed whether the endpoint accepted, refused, or timed out during the bounded connection attempt. It did not perform a vulnerability test.",
    "這項內建工作只觀察端點在受限的連線嘗試期間，是接受連線、拒絕連線，還是逾時。它沒有執行弱點檢測。",
  ],
  [
    "The durable task reached completed state for this target binding. More granular executed dimensions were not frozen in this case record.",
    "這項已保存的工作已針對這個目標完成。這份案件記錄沒有凍結更細部的執行範圍。",
  ],
  [
    "The completed Greenbone task retained a frozen allowlist containing the profile's TLS protocol, cipher, and certificate vulnerability checks.",
    "已完成的 Greenbone 工作保留了凍結的允許清單，其中包含此設定檔的 TLS 協定、加密套件與憑證弱點檢查。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed SSH profile for deprecated protocol, known or static host key, and weak MAC, encryption, host-key, key-size, or key-exchange choices.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 SSH 設定檔，用來檢查淘汰的協定、已知或固定的 host key，以及較弱的 MAC、加密、host-key、key size 或 key-exchange 選項。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed RDP transport profile: ten TLS protocol, cipher, and certificate checks plus one check for the legacy fixed private key used by RDP 5.2 or earlier.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 RDP 傳輸設定檔：十項 TLS 協定、加密套件與憑證檢查，加上一項針對 RDP 5.2 或更早版本所使用之舊式固定私密金鑰的檢查。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed VNC transport profile containing one check for an unencrypted VNC connection.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 VNC 傳輸設定檔，其中包含一項未加密 VNC 連線檢查。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed SMTP profile: one banner, EHLO, STARTTLS, and advertised-AUTH check for an unencrypted cleartext login risk, plus ten TLS checks that apply when TLS can be negotiated. No credentials or mail were sent.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 SMTP 設定檔：一項透過 banner、EHLO、STARTTLS 與服務宣告 AUTH 檢查未加密明文登入風險的檢查，加上十項在可協商 TLS 時適用的 TLS 檢查。本輪未送出帳號或密碼，也沒有寄信。",
  ],
  [
    "The completed Greenbone task retained and attempted the exact SMTP profile: one check reads the banner, sends EHLO, tries STARTTLS when offered, and reviews advertised AUTH for cleartext-login risk; ten more checks depend on TLS. TLS-check execution: evidenced by selected-run source OIDs. Credentials and mail: not sent.",
    "已完成的 Greenbone 工作保留並嘗試執行精確的 SMTP 設定檔：其中一項檢查會讀取 banner、送出 EHLO、在服務提供時嘗試 STARTTLS，並檢視服務宣告的 AUTH 是否有明文登入風險；另有十項檢查依賴 TLS。TLS 檢查執行情況：由所選輪次的來源 OID 提供證據。帳密與郵件：未送出。",
  ],
  [
    "Counted coverage: exact TLS source OIDs in selected-run finding evidence. Each OID evidences only its own check.",
    "計入的涵蓋範圍：所選輪次問題證據中的精確 TLS 來源 OID。每個 OID 只證明自己的檢查。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed Telnet profile, which observes whether a login or password prompt is offered without TLS. No username or password was sent and no login was attempted.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 Telnet 設定檔，用來觀察服務是否在沒有 TLS 的情況下提供登入或密碼提示。本輪未送出帳號或密碼，也沒有嘗試登入。",
  ],
  [
    "These exact frozen work units have validated completed outcomes across all saved attempts. A completed network check reports reachability; it is not a security pass.",
    "這些已凍結的特定工作單元，在所有已儲存的嘗試中都有通過驗證的完成結果。完成的網路檢查只回報連線是否可達；不代表安全性檢查通過。",
  ],
  [
    "Work-unit status: Partial. Planned operations remain unfinished.",
    "工作單元狀態：部分完成；仍有計畫中的操作未完成。",
  ],
];

/** A tested-dimension observation in the reader's language. */
export const testedObservationProse = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const trimmed = english.trim();
  let normalized = trimmed;
  if (trimmed.includes("produced usable saved results")) {
    normalized = "Work-unit status: Partial. Planned operations remain unfinished.";
  } else if (trimmed.includes("completion does not prove that every eligible template executed")) {
    normalized = "Nuclei completed the pinned upstream automatic web profile on the displayed origin. Applied checks: templates selected by upstream technology detection. Eligible-template execution completeness: unavailable.";
  } else if (trimmed.includes("result API does not prove that every scheduled VT executed")) {
    normalized = "Greenbone completed the frozen remote-safe profile on the displayed host and ports. Applied checks: feed checks selected by upstream service and product prerequisites. Scheduled-VT execution completeness: unavailable.";
  } else if (trimmed.includes("Task completion alone does not prove those TLS checks ran")) {
    normalized = "The completed Greenbone task retained and attempted the exact SMTP profile: one check reads the banner, sends EHLO, tries STARTTLS when offered, and reviews advertised AUTH for cleartext-login risk; ten more checks depend on TLS. TLS-check execution: evidenced by selected-run source OIDs. Credentials and mail: not sent.";
  } else if (trimmed.includes("A finding for one OID does not prove that another TLS check ran")) {
    normalized = "Counted coverage: exact TLS source OIDs in selected-run finding evidence. Each OID evidences only its own check.";
  }
  if (locale === "en") return normalized;
  return (
    TESTED_OBSERVATION_PROSE.find(
      ([candidate]) => candidate === normalized,
    )?.[1] ?? english
  );
};

/** Fixed coverage-ledger explanations shared by the screen and case export. */
const COVERAGE_RECORD_DETAIL_PROSE: ReadonlyArray<readonly [string, string]> = [
  [
    "The source is connected, but no attributable discovery has completed and no assets are known. Coverage is not established.",
    "來源已連線，但尚未完成可歸屬的探索，也沒有已知資產。尚未建立涵蓋。",
  ],
  [
    "The discovered candidate has not had ownership and scope explicitly confirmed. Discovery never authorizes a target automatically.",
    "探索到的候選資產尚未明確確認所有權與範圍。探索本身絕不會自動授權目標。",
  ],
  [
    "The asset has no unexpired, valid scope grant. Discovery never authorizes a target automatically.",
    "此資產沒有尚未到期的有效範圍授權。探索本身絕不會自動授權目標。",
  ],
  [
    "The asset is authorized, but no scan plan is tied to its current effective grants.",
    "此資產已獲授權，但沒有任何掃描計畫連結到目前有效的授權。",
  ],
  [
    "The scan predates frozen scope-grant snapshots, so its historical authorization and permission coverage are unknown. Live grants are never substituted for missing run evidence.",
    "這次掃描早於凍結範圍授權快照的機制，因此無法得知當時的授權與權限涵蓋。絕不會用現行授權補上缺少的執行記錄。",
  ],
  [
    "The asset is authorized, but the latest applicable scan plan contains no engine run for it.",
    "此資產已獲授權，但最近適用的掃描計畫沒有包含它的掃描工具工作。",
  ],
];

const COVERAGE_STATE_APPEND = [
  " This state is independent of how many findings were reported.",
  " 此狀態與回報了多少個問題無關。",
] as const;
const PROVIDER_DISCOVERY_APPEND = [
  " Latest provider discovery: ",
  " 最近一次供應商探索：",
] as const;
const STALE_KNOWLEDGE_APPEND = [
  " Explicit stale-knowledge warning: ",
  " 明確的過時知識警告：",
] as const;
const STALE_KNOWLEDGE_SUFFIX = [
  ". Completion proves execution, not current knowledge.",
  "。完成只證明已執行，不代表知識仍為最新。",
] as const;
const LOCALHOST_ATTEMPT_APPEND = [
  " Exact built-in localhost TCP attempt(s): ",
  " 精確的內建 localhost TCP 嘗試：",
] as const;
const LOCALHOST_ATTEMPT_SUFFIX = [
  ". This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
  "。這只記錄這些連線嘗試；無法證明服務或電腦安全，也不涵蓋其他連接埠或主機。",
] as const;

const stripFrame = (
  value: string,
  prefix: string,
  suffix: string,
): string | undefined => {
  if (!value.startsWith(prefix) || !value.endsWith(suffix)) return undefined;
  const end = suffix ? value.length - suffix.length : value.length;
  return value.slice(prefix.length, end);
};

const translateTrailingCoverageFrame = (
  english: string,
  middle: readonly [string, string],
  suffix: readonly [string, string],
): string | undefined => {
  const index = english.lastIndexOf(middle[0]);
  if (index < 0 || !english.endsWith(suffix[0])) return undefined;
  const base = english.slice(0, index);
  const end = suffix[0] ? english.length - suffix[0].length : english.length;
  const retained = english.slice(index + middle[0].length, end);
  if (!retained) return undefined;
  const translatedBase = base ? translateCoverageRecordDetail(base) : "";
  if (base && translatedBase === undefined) return undefined;
  return `${translatedBase ?? ""}${middle[1]}${retained}${suffix[1]}`;
};

const translateCoverageRecordDetail = (english: string): string | undefined => {
  const fixed = COVERAGE_RECORD_DETAIL_PROSE.find(
    ([candidate]) => candidate === english,
  )?.[1];
  if (fixed) return fixed;

  const stale = translateTrailingCoverageFrame(
    english,
    STALE_KNOWLEDGE_APPEND,
    STALE_KNOWLEDGE_SUFFIX,
  );
  if (stale) return stale;
  const localhost = translateTrailingCoverageFrame(
    english,
    LOCALHOST_ATTEMPT_APPEND,
    LOCALHOST_ATTEMPT_SUFFIX,
  );
  if (localhost) return localhost;
  const provider = translateTrailingCoverageFrame(
    english,
    PROVIDER_DISCOVERY_APPEND,
    ["", ""],
  );
  if (provider) return provider;

  const summary = english.endsWith(COVERAGE_STATE_APPEND[0])
    ? english.slice(0, -COVERAGE_STATE_APPEND[0].length)
    : undefined;
  if (summary !== undefined) {
    const translated = translateCoverageRecordDetail(summary);
    if (translated) return `${translated}${COVERAGE_STATE_APPEND[1]}`;
  }

  const applicabilityReason = stripFrame(
    english,
    "The source area is explicitly outside this case: ",
    " This is a scoped applicability statement, not a successful scan result.",
  );
  if (applicabilityReason) {
    return `此來源範圍明確不在本案件內：${applicabilityReason} 這是範圍適用性的說明，不是掃描成功的結果。`;
  }

  const retainedCount = stripFrame(
    english,
    "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; ",
    " prior asset observation(s) remain retained.",
  );
  if (retainedCount && /^\d+$/u.test(retainedCount)) {
    return `來源已連線，且最近一次可歸屬的探索未傳回任何資產。這不是掃描成功的結果；仍保留 ${retainedCount} 筆先前的資產觀察結果。`;
  }

  const disconnected = english.match(
    /^The source is not currently connected \(status: (.+)\)\. Its present coverage is unknown; (\d+) previously attributed asset\(s\) are retained but do not make the source green\.$/u,
  );
  if (disconnected?.[1] && disconnected[2]) {
    return `來源目前未連線（狀態：${disconnected[1]}）。目前的涵蓋未知；仍保留 ${disconnected[2]} 筆先前歸屬的資產，但這不會讓來源顯示為綠色。`;
  }

  const authorizationDetail = stripFrame(
    english,
    "The scan's frozen authorization evidence is incomplete: ",
    ". Live grants are never used to reconstruct historical scan permission.",
  );
  if (authorizationDetail) {
    return `掃描中凍結的授權證據不完整：${authorizationDetail}。絕不會用現行授權重建過去的掃描權限。`;
  }

  const compatibleCount = stripFrame(
    english,
    "All ",
    " compatible engine run(s) planned for this asset completed.",
  );
  if (compatibleCount && /^\d+$/u.test(compatibleCount)) {
    return `為此資產規劃的 ${compatibleCount} 項相容掃描工具工作皆已完成。`;
  }

  const exactTaskCount = stripFrame(
    english,
    "All ",
    " planned task(s) for this asset completed their exact declared dimensions.",
  );
  if (exactTaskCount && /^\d+$/u.test(exactTaskCount)) {
    return `為此資產規劃的 ${exactTaskCount} 項工作，皆已完成各自明確宣告的檢查範圍。`;
  }

  const incompleteReasons = stripFrame(
    english,
    "The authorized scan is incomplete: ",
    ". Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
  );
  if (incompleteReasons) {
    return `已授權的掃描未完成：${incompleteReasons}。只有已完成且相容的目錄掃描工具工作，或精確完成的內建工作，才能產生已掃描涵蓋。`;
  }
  return undefined;
};

/** Reviewed English catalog rationales and their Traditional Chinese presentation. */
const CONTROL_MAPPING_RATIONALE_PROSE: ReadonlyArray<
  readonly [string, string]
> = [
  [
    "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.",
    "某個身分未登記多重要素驗證裝置的證據，與驗證使用者及保護驗證資訊有關。",
  ],
  [
    "Evidence that an attached identity policy grants unrestricted administrative permissions is related to least privilege, entitlement review, and privileged access safeguards.",
    "附加的身分政策授予不受限制之管理權限的證據，與最小權限、權限審查及特權存取保護有關。",
  ],
  [
    "Evidence that an object-storage resource permits public access is related to access policy, authorization review, and cloud service protection.",
    "物件儲存資源允許公開存取的證據，與存取政策、授權審查及雲端服務保護有關。",
  ],
  [
    "Evidence of an identity privilege-escalation path is related to least privilege, entitlement review, and privileged access safeguards.",
    "身分權限提升路徑的證據，與最小權限、權限審查及特權存取保護有關。",
  ],
  [
    "Evidence that legacy authentication is not blocked is related to enforcing appropriate authentication and protecting authentication information.",
    "未封鎖舊式驗證的證據，與強制使用適當的驗證方式及保護驗證資訊有關。",
  ],
  [
    "Evidence that privileged identities lack phishing-resistant authentication is related to authentication enforcement and authentication information safeguards.",
    "特權身分缺少抗網路釣魚驗證的證據，與強制驗證及驗證資訊保護有關。",
  ],
  [
    "Evidence of an exposed database administration interface is related to identifying, validating, recording, and handling technical vulnerabilities.",
    "資料庫管理介面對外暴露的證據，與識別、確認、記錄及處理技術弱點有關。",
  ],
  [
    "Static-analysis evidence of dynamic code execution is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
    "動態程式碼執行的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件座標才適用。",
  ],
  [
    "Static-analysis evidence that Python code invokes an operating-system shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
    "Python 程式碼呼叫作業系統 shell 的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件座標才適用。",
  ],
  [
    "Static-analysis evidence that JavaScript or TypeScript code invokes a command through a shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
    "JavaScript 或 TypeScript 程式碼透過 shell 呼叫命令的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件座標才適用。",
  ],
  [
    "Static-analysis evidence of private-key material in current project files is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
    "目前專案檔案含有私密金鑰資料的靜態分析證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入座標才適用。",
  ],
  [
    "Evidence of a credential embedded in current project files is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
    "目前專案檔案內嵌憑證的證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入座標才適用。",
  ],
  [
    "Every TruffleHog result is a detected credential, so this reference covers the engine's whole detector surface rather than one detector. Evidence of a credential in source material is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
    "每一筆 TruffleHog 結果都是偵測到的憑證，因此這項參照涵蓋該掃描工具的完整偵測範圍，而不是單一偵測器。原始資料中含有憑證的證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入座標才適用。",
  ],
  [
    "Infrastructure-as-code evidence that access logging is disabled is related to security-relevant audit records. AIDEFEND's IaC-scanning coordinate applies when the selected configuration provisions an AI system.",
    "基礎架構即程式碼顯示存取記錄已停用的證據，與安全性相關的稽核記錄有關。當所選設定用來佈建 AI 系統時，AIDEFEND 的 IaC 掃描座標才適用。",
  ],
  [
    "Infrastructure-as-code evidence that server-side encryption is absent is related to protecting data at rest and using cryptographic safeguards. AIDEFEND's IaC-scanning coordinate applies when the selected configuration provisions an AI system.",
    "基礎架構即程式碼顯示未使用伺服器端加密的證據，與保護靜態資料及使用密碼學保護措施有關。當所選設定用來佈建 AI 系統時，AIDEFEND 的 IaC 掃描座標才適用。",
  ],
  [
    "Evidence that an installed component is affected by a CVE is related to vulnerability handling. For an AI system, AIDEFEND separates build or deployment admission from the deployed-software remediation lifecycle; this reference does not decide which lifecycle state applies.",
    "已安裝元件受某項 CVE 影響的證據，與弱點處理有關。對 AI 系統而言，AIDEFEND 將建置或部署准入與已部署軟體的修復生命週期分開；這項參照不會判定適用哪一個生命週期階段。",
  ],
  [
    "Evidence that subjects can run commands inside running containers is related to least-privilege authorization, privileged access safeguards, and container isolation. AIDEFEND's container-isolation coordinate applies when the workload is part of an AI system.",
    "主體可以在執行中的容器內執行命令的證據，與最小權限授權、特權存取保護及容器隔離有關。當工作負載屬於 AI 系統的一部分時，AIDEFEND 的容器隔離座標才適用。",
  ],
  [
    "Evidence that the kubelet accepts anonymous authentication is related to authentication enforcement and authentication information safeguards. This is the node check the shipped snapshot benchmark runs; the control-plane equivalent is not in scope for this product.",
    "kubelet 接受匿名驗證的證據，與強制驗證及驗證資訊保護有關。這是隨附的快照基準所執行的節點檢查；對應的控制平面檢查不在本產品範圍內。",
  ],
  [
    "A Greenbone vulnerability-test alarm on an authorized host is evidence related to technical vulnerability handling. For an AI system, AIDEFEND separates build-time dependency admission from the deployed-software remediation lifecycle; this reference points at the deployed lifecycle and does not decide remediation state.",
    "Greenbone 對已授權主機發出的弱點測試警示，是與技術性弱點處理相關的證據。對 AI 系統而言，AIDEFEND 將建置階段的相依套件准入與已部署軟體的修復生命週期分開；這項參照指向已部署的生命週期，並不判定修復狀態。",
  ],
];

export const controlMappingRationaleZhHant = (
  english: string,
): string | undefined =>
  CONTROL_MAPPING_RATIONALE_PROSE.find(
    ([candidate]) => candidate === english,
  )?.[1];

export const localizedControlMappingRationale = (
  rationale: string,
  locale: "en" | "zh-TW",
): string =>
  locale === "en"
    ? rationale
    : (controlMappingRationaleZhHant(rationale) ?? rationale);

/** A stored coverage-record explanation in the reader's language. */
export const localizedCoverageRecordDetail = (
  detail: string,
  locale: "en" | "zh-TW",
): string =>
  locale === "en" ? detail : (translateCoverageRecordDetail(detail) ?? detail);

const DATA_QUALITY_WARNING_PROSE: ReadonlyArray<readonly [string, string]> = [
  [
    "This run has inconsistent request and check data.",
    "本輪的請求與檢查資料不一致。",
  ],
  [
    "The selected run has an inconsistent project identity. Report data: selected in-project record.",
    "所選掃描輪次的專案識別資料不一致；報告資料：專案內所選記錄。",
  ],
  [
    "One check has incomplete coverage history.",
    "有一項檢查的涵蓋歷程未完成。",
  ],
];

const translateDataQualityWarning = (english: string): string | undefined => {
  if (
    english.includes("saved coverage history could not be reconciled")
    || english.includes("Coverage history reconciliation failed for one check")
    || english.includes("One check has an incomplete coverage history record")
  ) {
    return "有一項檢查的涵蓋歷程未完成。";
  }
  const fixed = DATA_QUALITY_WARNING_PROSE.find(
    ([candidate]) => candidate === english,
  )?.[1];
  if (fixed) return fixed;
  const missingSnapshot = stripFrame(
    english,
    "Finding ",
    " selected-run presentation snapshot: unavailable. Display wording: current canonical text.",
  );
  if (missingSnapshot)
    return `問題 ${missingSnapshot} 所選輪次呈現快照：無法取得；顯示文字：目前正式版本。`;
  const observationOnly = stripFrame(
    english,
    "Finding ",
    " presentation detail: unavailable. Retained run observation: available.",
  );
  if (observationOnly)
    return `問題 ${observationOnly} 呈現細節：無法取得；保留的輪次觀察：可用。`;
  return undefined;
};

export const localizedDataQualityWarning = (
  warning: string,
  locale: "en" | "zh-TW",
): string => {
  let normalized = warning
    .replace(
      "This run contains a request-level outcome beside non-terminal or planned check data. The report ignored that outcome and did not treat it as ‘no checks completed’.",
      "This run has inconsistent request and check data.",
    )
    .replace(
      "The selected run's stored project identifier does not match this project. The report remains limited to the selected in-project record.",
      "The selected run has an inconsistent project identity. Report data: selected in-project record.",
    )
    .replace(
      /Finding (.+) has no selected-run presentation snapshot; current canonical wording is labeled as a legacy fallback\./u,
      "Finding $1 selected-run presentation snapshot: unavailable. Display wording: current canonical text.",
    )
    .replace(
      /Finding (.+) has only its retained run observation; presentation detail is unavailable\./u,
      "Finding $1 presentation detail: unavailable. Retained run observation: available.",
    );
  normalized = normalized.includes("saved coverage history could not be reconciled")
    || warning.includes("Coverage history reconciliation failed for one check")
    || warning.includes("One check has an incomplete coverage history record")
    ? "One check has incomplete coverage history."
    : normalized;
  return locale === "en" ? normalized : (translateDataQualityWarning(normalized) ?? normalized);
};

/** The direct recommended action for the finding family. */
export const findingActionSentence = (
  locale: "en" | "zh-TW",
  options: {
    englishFallback: string;
    family?: FindingFamily;
    awsIamPolicy?: AwsIamPolicyFindingDetails;
  },
): string => {
  if (options.awsIamPolicy) {
    return locale === "zh-TW"
      ? awsIamPolicyActionZhTW(options.awsIamPolicy)
      : awsIamPolicyActionEnglish(options.awsIamPolicy);
  }
  const remedy = options.family ? REMEDY[options.family] : undefined;
  if (!remedy || !options.family) {
    const marker = ", then plan and approve ";
    const at = options.englishFallback.lastIndexOf(marker);
    if (at < 0) return options.englishFallback;
    const direct = options.englishFallback.slice(at + marker.length).trim();
    return direct ? direct[0]!.toLocaleUpperCase("en") + direct.slice(1) : options.englishFallback;
  }
  if (locale === "en") return `${REMEDY_ENGLISH[options.family]}.`;
  return `${remedy}。`;
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
      return withIdentifier(
        label,
        name.slice(0, name.length - suffix.length).trim(),
      );
    }
  }
  return `本輪使用的限制：${name}`;
};

const REQUESTED_LIMIT_VALUE_UNITS: ReadonlyArray<readonly [string, string]> = [
  [" ms", " 毫秒"],
  [" bytes", " 位元組"],
  [" seconds", " 秒"],
];

const REQUEST_RATE_MIDDLE = [
  " per second, concurrency ",
  " 次，並行 ",
] as const;

/** One stored requested-limit value in the reader's language. */
export const localizedRequestedLimitValue = (
  name: string,
  value: string,
  locale: "en" | "zh-TW",
): string => {
  if (locale === "en") return value;
  for (const [englishUnit, chineseUnit] of REQUESTED_LIMIT_VALUE_UNITS) {
    const match = value.match(new RegExp(`^(\\d+)${englishUnit}$`, "u"));
    if (match?.[1]) return `${match[1]}${chineseUnit}`;
  }

  const [requests, concurrency, extra] = value.split(REQUEST_RATE_MIDDLE[0]);
  if (
    !extra &&
    /^\d+$/u.test(requests ?? "") &&
    /^\d+$/u.test(concurrency ?? "")
  ) {
    return `每秒 ${requests}${REQUEST_RATE_MIDDLE[1]}${concurrency}`;
  }

  // Identifier-shaped values are intentionally returned unchanged. Keeping
  // these names here mirrors the backend's producer census distinction between
  // a recognized identifier and an unknown unit-bearing value.
  if (
    name === "endpoint" ||
    name.endsWith(" authorized network target") ||
    name.endsWith(" approved ports")
  )
    return value;
  return value;
};
