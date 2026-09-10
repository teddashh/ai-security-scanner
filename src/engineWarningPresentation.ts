/**
 * Product-authored engine-run warnings shown only by the Progress page.
 * Stored English remains canonical; values inside known frames stay verbatim.
 */
const FIXED_ENGINE_WARNINGS: ReadonlyArray<readonly [string, string]> = [
  ["adapter input exceeded the total byte limit; remaining raw artifacts were retained but not normalized", "轉接器輸入超過總位元組限制；其餘原始成品已保留，但未正規化"],
  ["adapter extraction reached the record safety boundary; completeness cannot be established", "轉接器擷取已達記錄安全界線；無法確認完整性"],
  ["adapter record limit reached; remaining raw records were retained but not normalized", "轉接器已達記錄限制；其餘原始記錄已保留，但未正規化"],
  ["adapter artifact-count limit reached; extra raw artifacts were retained but not normalized", "轉接器已達成品數量限制；額外的原始成品已保留，但未正規化"],
  ["an artifact path escaped the case artifact root and was rejected", "成品路徑超出案件成品根目錄，因此遭到拒絕"],
  ["the case artifact root could not be opened", "無法開啟案件成品根目錄"],
  ["an artifact path did not resolve inside the case artifact root", "成品路徑無法解析至案件成品根目錄內"],
  ["an artifact exceeded the byte limit while being read", "讀取成品時超過位元組限制"],
  ["an artifact length did not match its recorded evidence metadata", "成品長度與記錄的證據中繼資料不符"],
  ["an artifact hash did not match its recorded evidence metadata", "成品雜湊與記錄的證據中繼資料不符"],
  ["JSONL record limit reached; later lines remain only as raw evidence", "JSONL 已達記錄限制；後續行只保留為原始證據"],
  ["Nuclei execution evidence named an asset outside this engine task and was not counted", "Nuclei 執行證據指向這項引擎工作以外的資產，因此未納入計算"],
  ["Greenbone XML event limit reached; later results remain only as raw evidence", "Greenbone XML 已達事件限制；後續結果只保留為原始證據"],
  ["Greenbone XML containing a DTD or custom entity reference was rejected", "含有 DTD 或自訂實體參照的 Greenbone XML 已遭拒絕"],
  ["Greenbone XML nesting limit was exceeded; no XML findings were normalized", "Greenbone XML 超過巢狀層級限制；未正規化任何 XML 問題"],
  ["nested Greenbone result elements were rejected", "巢狀 Greenbone 結果元素已遭拒絕"],
  ["Greenbone result limit reached; later results remain only as raw evidence", "Greenbone 已達結果限制；後續結果只保留為原始證據"],
  ["Greenbone result had an invalid NVT OID", "Greenbone 結果含有無效的 NVT OID"],
  ["Greenbone reported that the host did not respond, so none of its vulnerability checks ran for that target", "Greenbone 回報主機沒有回應，因此該目標的弱點檢查一項都沒有執行"],
  ["Greenbone reported scanner errors for the target, so some of its checks did not finish", "Greenbone 回報該目標發生掃描器錯誤，因此部分檢查沒有完成"],
  ["Greenbone result carried an unsupported upstream result type and was retained only as raw evidence", "Greenbone 結果帶有不支援的上游結果類型，只保留為原始證據"],
  ["Greenbone result lacked an upstream result type and a positive severity; it was retained only as raw evidence and this run cannot be treated as a clean result", "Greenbone 結果缺少上游結果類型與正的嚴重程度；只保留為原始證據，本輪不能視為乾淨的結果"],
  ["Greenbone reported a target it could not evaluate, but the result named no authorized asset; the raw artifact was retained", "Greenbone 回報了一個無法評估的目標，但該結果沒有指名任何已授權的資產；原始成品已保留"],
  ["an oversized Greenbone XML field was ignored", "已忽略過大的 Greenbone XML 欄位"],
  ["a Greenbone XML text field could not be decoded", "無法解碼 Greenbone XML 文字欄位"],
  ["a Greenbone XML field used an unsupported entity and was ignored", "Greenbone XML 欄位使用不支援的實體，因此已忽略"],
  ["a Greenbone XML CDATA field could not be decoded", "無法解碼 Greenbone XML CDATA 欄位"],
  ["a Greenbone XML processing instruction was ignored", "已忽略 Greenbone XML 處理指令"],
  ["an incomplete Greenbone result was retained only as raw evidence", "不完整的 Greenbone 結果只保留為原始證據"],
  ["Greenbone XML contained no complete bounded result records; no findings were inferred", "Greenbone XML 沒有完整且有界的結果記錄；未推斷任何問題"],
  ["top-level JSON record limit reached; later rows remain only as raw evidence", "頂層 JSON 已達記錄限制；後續資料列只保留為原始證據"],
  ["top-level JSON scalar was ignored", "已忽略頂層 JSON 純量"],
  ["Cloudsplaining results were not a single JSON object, so no policy findings could be read.", "Cloudsplaining 結果不是單一 JSON 物件，因此無法讀取原則問題。"],
  ["Cloudsplaining output links were not an object; findings were preserved without those references", "Cloudsplaining 輸出的 links 不是物件；問題已保留，但不含那些參照"],
  ["Cloudsplaining output lacked its required links object; findings were preserved without those references", "Cloudsplaining 輸出缺少必要的 links 物件；問題已保留，但不含那些參照"],
  ["Cloudsplaining principal context exceeded the bounded report budget; later findings retain policy and action details, while their complete AttachedTo values stay in raw evidence", "Cloudsplaining 主體資訊超過報告的有界容量；後續問題仍保留政策與動作資訊，完整 AttachedTo 值則保留在原始證據中"],
  ["Greenbone expected a bounded XML report", "Greenbone 預期收到有界的 XML 報告"],
  ["Semgrep expected a JSON document", "Semgrep 預期收到 JSON 文件"],
  ["Semgrep output had no results array", "Semgrep 輸出沒有 results 陣列"],
  ["Semgrep output lacked its required errors array; valid findings were preserved, but completeness cannot be established", "Semgrep 輸出缺少必要的 errors 陣列；有效問題已保留，但無法確認完整性"],
  ["Semgrep reported one or more scanner errors; valid findings were preserved, but the error details remain only in the raw artifact and completeness cannot be established", "Semgrep 回報一項或多項掃描器錯誤；有效問題已保留，錯誤細節只留在原始成品中，且無法確認完整性"],
  ["Checkov expected a JSON document", "Checkov 預期收到 JSON 文件"],
  ["Checkov expected a JSON object or an array of framework result objects", "Checkov 預期收到一個 JSON 物件，或由各框架結果物件組成的陣列"],
  ["Checkov framework result limit reached; later framework results remain only as raw evidence", "Checkov 已達框架結果限制；後續框架結果只保留為原始證據"],
  ["Checkov failed-check record limit reached; later rows remain only as raw evidence", "Checkov 已達失敗檢查記錄限制；後續資料列只保留為原始證據"],
  ["KICS expected a JSON document", "KICS 預期收到 JSON 文件"],
  ["KICS output lacked its queries array; the raw artifact was retained", "KICS 輸出缺少 queries 陣列；原始成品已保留"],
  ["Trivy expected a JSON document", "Trivy 預期收到 JSON 文件"],
  ["Grype expected a JSON document", "Grype 預期收到 JSON 文件"],
  ["Kubescape expected a JSON document", "Kubescape 預期收到 JSON 文件"],
  ["kube-bench expected a JSON document", "kube-bench 預期收到 JSON 文件"],
  ["Steampipe output was not its supported JSON document; the raw artifact was retained, and the inventory query should be retried", "Steampipe 輸出不是支援的 JSON 文件；原始成品已保留，請重試盤點查詢"],
  ["Steampipe output lacked its rows array; the raw artifact was retained, and the inventory query should be retried", "Steampipe 輸出缺少 rows 陣列；原始成品已保留，請重試盤點查詢"],
  ["Steampipe rows exceeded the record safety boundary; later inventory rows remain only as raw evidence", "Steampipe 資料列超過記錄安全界線；後續盤點資料列只保留為原始證據"],
  ["Runtime object ownership is unavailable. Retry uses a new isolated attempt.", "無法確認執行階段物件的所有權；重試會使用新的隔離嘗試。"],
  ["Scan batch stopped. Unfinished work: not tested.", "掃描批次已停止；未完成工作：未檢測。"],
  ["You stopped this scan. Remaining planned work: not tested.", "你已停止這次掃描；其餘規劃工作：未檢測。"],
  ["Framework relationships are unavailable because the saved mapping identity differs from the installed mapping.", "已保存的對照識別資料與已安裝對照不同，因此無法使用框架關聯。"],
  ["Result processing stopped. Start a new scan with the current result reader.", "結果處理已停止；請使用目前的結果讀取器開始新的掃描。"],
  ["Result processing is incomplete. This check is Partial.", "結果處理未完成；這項檢查為部分完成。"],
  ["Automatic cleanup stopped: exact runtime ownership is unavailable.", "自動清理已停止：無法確認執行階段的確切所有權。"],
  ["This saved check no longer matches its original target plan. Start a new scan for this check.", "這項已保存的檢查已不符合原始目標計畫；請為此檢查開始新的掃描。"],
  ["Coverage verification failed for this attempt. Retry this check.", "本次嘗試的涵蓋驗證失敗；請重試這項檢查。"],
  ["Greenbone XML element exceeded the attribute limit", "Greenbone XML 元素超過屬性限制"],
  ["Greenbone XML contained a malformed attribute", "Greenbone XML 含有格式錯誤的屬性"],
  ["Greenbone XML attribute could not be decoded safely", "無法安全解碼 Greenbone XML 屬性"],
  ["This check completed with coverage gaps after one automatic retry per unfinished item. Start a new scan to retry the remaining items.", "每個未完成項目自動重試一次後，這項檢查仍有涵蓋缺口。請開始新的掃描以重試剩餘項目。"],
  ["The installed version does not include this check. Update the app, then start a new scan.", "已安裝版本不包含這項檢查；請更新應用程式後開始新的掃描。"],
  ["The installed result reader cannot continue processing this check. Start a new scan for a fresh result.", "已安裝的結果讀取器無法繼續處理這項檢查；請開始新的掃描。"],
  ["A newer scan state replaced this continuation. Start a new scan for the remaining coverage.", "較新的掃描狀態已取代本次續跑；請為剩餘涵蓋開始新的掃描。"],
  ["This version cannot run the older request. Start a new scan with the current bounded network path.", "目前版本無法執行舊版請求；請使用目前有界的網路路徑開始新的掃描。"],
  ["Reconnect target access for this check, then continue the scan.", "請重新連接這項檢查的目標存取權，再繼續掃描。"],
  ["Saved target access differs from the original scan. Reconnect that target, then start a new scan.", "已保存的目標存取權與原始掃描不同；請重新連接該目標後開始新的掃描。"],
  ["A new bounded scan batch replaced the older request and will continue.", "新的有界掃描批次已取代舊版請求，並會繼續執行。"],
  ["Framework relationships are unavailable for this run because mapping was unavailable during planning.", "規劃時無法取得對照，因此本輪沒有框架關聯。"],
];

/**
 * The counted shortfall descriptions the Microsoft 365 adapters join into the
 * "did not evaluate every control" disclosure. They are sentence fragments this
 * product wrote, not values an engine reported, so they are translated rather
 * than kept verbatim; only the count in front of each one is the engine's.
 */
const SHORTFALL_DESCRIPTIONS: ReadonlyArray<readonly [string, string]> = [
  ["left without an automated verdict", "未回傳自動判定"],
  ["reserved for manual review", "未回傳自動判定"],
  ["omitted by configuration", "依設定略過"],
  ["could not be evaluated", "無法評估"],
  ["skipped", "已略過"],
  ["not run", "未執行"],
  ["reported by the engine but not carried into results", "掃描工具已回報，但未帶入結果"],
  ["not accounted for by any reported category", "未計入任何已回報類別"],
];

/** Translates each `<count> <description>` item, leaving an unknown one as-is. */
const shortfalls = (list: string): string => list
  .split(", ")
  .map((item) => {
    const description = SHORTFALL_DESCRIPTIONS
      .find(([english]) => item.endsWith(` ${english}`));
    return description ? `${item.slice(0, item.length - description[0].length)}${description[1]}` : item;
  })
  .join("、");

export const recognizedShortfallDescriptionZhTW = (description: string): string | undefined =>
  SHORTFALL_DESCRIPTIONS.find(([english]) => english === description)?.[1];

const frame = (value: string, expression: RegExp, render: (...values: string[]) => string): string | undefined => {
  const match = value.match(expression);
  return match ? render(...match.slice(1)) : undefined;
};

const normalizeLegacyEngineWarning = (warning: string): string => {
  const normalized = warning.replaceAll(
    "reserved for manual review",
    "left without an automated verdict",
  );
  if (normalized.startsWith("An existing runtime object could not be proven")) {
    return "Runtime object ownership is unavailable. Retry uses a new isolated attempt.";
  }
  if (normalized.startsWith("This scan batch stopped after saving output.")) {
    return "Scan batch stopped. Unfinished work: not tested.";
  }
  if (normalized.startsWith("You stopped this scan after the current batch was saved.")) {
    return "You stopped this scan. Remaining planned work: not tested.";
  }
  if (normalized.startsWith("Framework relationships were omitted because")) {
    return "Framework relationships are unavailable because the saved mapping identity differs from the installed mapping.";
  }
  if (normalized.includes("start a new scan to use the current result reader")) {
    return "Result processing stopped. Start a new scan with the current result reader.";
  }
  if (normalized.includes("clearly marked partial")) {
    return "Result processing is incomplete. This check is Partial.";
  }
  if (normalized.startsWith("Automatic cleanup was skipped because")) {
    return "Automatic cleanup stopped: exact runtime ownership is unavailable.";
  }
  if (normalized.startsWith("This saved check could not be safely matched")) {
    return "This saved check no longer matches its original target plan. Start a new scan for this check.";
  }
  if (normalized.includes("tested coverage could not be verified")) {
    return "Coverage verification failed for this attempt. Retry this check.";
  }
  if (normalized.startsWith("This check finished with partial results after each unfinished item")) {
    return "This check completed with coverage gaps after one automatic retry per unfinished item. Start a new scan to retry the remaining items.";
  }
  if (normalized.startsWith("This check is not available in the installed version.")) {
    return "The installed version does not include this check. Update the app, then start a new scan.";
  }
  if (normalized.includes("installed result reader cannot safely continue")) {
    return "The installed result reader cannot continue processing this check. Start a new scan for a fresh result.";
  }
  if (normalized.includes("continuation race")) {
    return "A newer scan state replaced this continuation. Start a new scan for the remaining coverage.";
  }
  if (normalized.includes("current bounded network path")) {
    return "This version cannot run the older request. Start a new scan with the current bounded network path.";
  }
  if (normalized.startsWith("This check needs renewed target access")) {
    return "Reconnect target access for this check, then continue the scan.";
  }
  if (normalized.includes("saved target access no longer matches")) {
    return "Saved target access differs from the original scan. Reconnect that target, then start a new scan.";
  }
  if (normalized.startsWith("An older scan request was preserved")) {
    return "A new bounded scan batch replaced the older request and will continue.";
  }
  if (normalized.startsWith("Framework mapping was unavailable while this run was planned.")) {
    return "Framework relationships are unavailable for this run because mapping was unavailable during planning.";
  }
  const releaseMismatch = normalized.match(
    /^Engine (.+) was not resumed: its frozen release identity differs from the installed release \((.+)\), and (.+)\. Start a new scan/u,
  );
  if (releaseMismatch) {
    return `Engine ${releaseMismatch[1]} uses different release settings (${releaseMismatch[2]}), and ${releaseMismatch[3]}. Start a new scan with the installed release.`;
  }
  const capturedOnly = normalized.match(
    /^The frozen release identity differs from the installed release \((.+)\)\. Resume was allowed only because/u,
  );
  if (capturedOnly) {
    return `Release settings differ (${capturedOnly[1]}). Verified empty JSONL result processing continued without scanner execution or mapping changes.`;
  }
  return normalized;
};

export const recognizedEngineWarningZhTW = (warning: string): string | undefined => {
  const normalized = normalizeLegacyEngineWarning(warning);
  const fixed = FIXED_ENGINE_WARNINGS.find(([english]) => english === normalized)?.[1];
  if (fixed) return fixed;
  const rules: ReadonlyArray<readonly [RegExp, (...values: string[]) => string]> = [
    [/^(.+) produced no raw artifacts to normalize$/u, (engine) => `${engine} 未產生可正規化的原始成品`],
    [/^(.+) output is inventory evidence; no security issue was invented from inventory rows$/u, (engine) => `${engine} 輸出是資產清冊證據；未從清冊資料列臆造安全問題`],
    [/^artifact (.+) exceeded the per-file byte limit and was not parsed$/u, (id) => `成品 ${id} 超過單檔位元組限制，因此未解析`],
    [/^artifact (.+) could not be read; its metadata remains in the case$/u, (id) => `無法讀取成品 ${id}；其中繼資料仍保留在案件中`],
    [/^JSONL line (.+) exceeded the line limit and was skipped$/u, (line) => `JSONL 第 ${line} 行超過行限制，因此已略過`],
    [/^malformed JSONL line (.+) was skipped$/u, (line) => `已略過格式錯誤的 JSONL 第 ${line} 行`],
    [/^artifact (.+) was neither valid bounded JSON nor JSONL: (.+)$/u, (id, detail) => `成品 ${id} 既不是有效且有界的 JSON，也不是 JSONL：${detail}`],
    [/^Greenbone XML parsing stopped at byte (.+): (.+)$/u, (byte, detail) => `Greenbone XML 解析在位元組 ${byte} 停止：${detail}`],
    [/^non-object Prowler record at (.+) was skipped$/u, (pointer) => `已略過 ${pointer} 的非物件 Prowler 記錄`],
    [/^non-object Checkov framework result at (.+) was skipped$/u, (pointer) => `已略過 ${pointer} 的非物件 Checkov 框架結果`],
    [/^Checkov framework result at (.+) had no results object$/u, (pointer) => `${pointer} 的 Checkov 框架結果沒有 results 物件`],
    [/^Checkov results at (.+) were not an object$/u, (pointer) => `${pointer} 的 Checkov results 不是物件`],
    [/^Checkov output at (.+) was not an array$/u, (pointer) => `${pointer} 的 Checkov 輸出不是陣列`],
    [/^non-object Checkov failed check at (.+) was skipped$/u, (pointer) => `已略過 ${pointer} 的非物件 Checkov 失敗檢查`],
    [/^Checkov failed check at (.+) had no valid check_id and was skipped$/u, (pointer) => `已略過 ${pointer} 缺少有效 check_id 的 Checkov 失敗檢查`],
    [/^Prowler record at (.+) had no explicit failing status$/u, (pointer) => `${pointer} 的 Prowler 記錄沒有明確的失敗狀態`],
    [/^Prowler failure at (.+) lacked a check id$/u, (pointer) => `${pointer} 的 Prowler 失敗結果缺少檢查識別碼`],
    [/^Cloudsplaining policy section (.+) was not an object; valid sibling findings were preserved$/u, (section) => `Cloudsplaining 原則區段 ${section} 不是物件；已保留其他有效問題`],
    [/^Cloudsplaining output lacked required policy section (.+); valid sibling findings were preserved$/u, (section) => `Cloudsplaining 輸出缺少必要的原則區段 ${section}；已保留其他有效問題`],
    [/^Cloudsplaining policy at (.+) was not an object; valid sibling findings were preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則不是物件；已保留其他有效問題`],
    [/^Cloudsplaining policy at (.+) did not carry its required boolean is_excluded value and was retained only as raw evidence$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則缺少必要的布林 is_excluded 值，因此只保留在原始證據中`],
    [/^Cloudsplaining policy at (.+) lacked its required AttachedTo object; findings were preserved without complete principal attribution$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則缺少必要的 AttachedTo 物件；問題已保留，但主體歸屬資訊不完整`],
    [/^Cloudsplaining AttachedTo\.(.+) at (.+)\/AttachedTo was not an array; valid principal names were preserved$/u, (kind, pointer) => `${pointer}/AttachedTo 的 Cloudsplaining AttachedTo.${kind} 不是陣列；已保留有效的主體名稱`],
    [/^Cloudsplaining AttachedTo\.(.+) at (.+)\/AttachedTo contained invalid, overlong, or excess entries; bounded valid names were preserved and the remainder stays in raw evidence$/u, (kind, pointer) => `${pointer}/AttachedTo 的 Cloudsplaining AttachedTo.${kind} 含有無效、過長或超量項目；已保留有界的有效名稱，其餘仍在原始證據中`],
    [/^Cloudsplaining policy at (.+) had no bounded nonempty identity or name and was retained only as raw evidence$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則沒有有界且非空的識別或名稱，因此只保留在原始證據中`],
    [/^Cloudsplaining policy identity at (.+) contained control characters or exceeded its presentation boundary; a bounded display value was preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則識別含有控制字元或超過顯示界線；已保留有界的顯示值`],
    [/^Cloudsplaining category at (.+) was not an object; valid sibling findings were preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別不是物件；已保留其他有效問題`],
    [/^Cloudsplaining policy at (.+) lacked category (.+); valid sibling findings were preserved$/u, (pointer, category) => `${pointer} 的 Cloudsplaining 原則缺少風險類別 ${category}；已保留其他有效問題`],
    [/^Cloudsplaining category at (.+) lacked its findings array; valid sibling findings were preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別缺少 findings 陣列；已保留其他有效問題`],
    [/^Cloudsplaining category at (.+) lacked its source severity; valid sibling findings were preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別缺少來源嚴重性；已保留其他有效問題`],
    [/^Cloudsplaining category at (.+) lacked its source description; findings were preserved without it$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別缺少來源說明；問題已保留，但不含該說明`],
    [/^Cloudsplaining PrivilegeEscalation category at (.+) lacked its required links object; findings were preserved without those references$/u, (pointer) => `${pointer} 的 Cloudsplaining 權限提升類別缺少必要的 links 物件；問題已保留，但不含那些參照`],
    [/^Cloudsplaining category links at (.+) were not an object; findings were preserved without those references$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別 links 不是物件；問題已保留，但不含那些參照`],
    [/^Cloudsplaining finding at (.+) did not match the pinned (.+) entry shape and was retained only as raw evidence$/u, (pointer, risk) => `${pointer} 的 Cloudsplaining 問題不符合此版本採用的 ${risk} 項目格式，因此只保留在原始證據中`],
    [/^Cloudsplaining finding at (.+) had no bounded nonempty identity and was retained only as raw evidence$/u, (pointer) => `${pointer} 的 Cloudsplaining 問題沒有有界且非空的識別，因此只保留在原始證據中`],
    [/^Cloudsplaining finding identity at (.+) contained control characters or exceeded its presentation boundary; a bounded display value was preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 問題識別含有控制字元或超過顯示界線；已保留有界的顯示值`],
    [/^Cloudsplaining finding actions at (.+) contained sanitized or excess values; bounded valid actions were preserved and the complete list stays in raw evidence$/u, (pointer) => `${pointer} 的 Cloudsplaining 問題動作含有經清理或超量的值；已保留有界的有效動作，完整清單仍在原始證據中`],
    [/^Cloudsplaining privilege-escalation finding at (.+) lacked its required method link; the finding was preserved without that reference$/u, (pointer) => `${pointer} 的 Cloudsplaining 權限提升問題缺少必要的方法參照連結；問題已保留，但不含該參照`],
    [/^Cloudsplaining action link for (.+) was malformed; the finding was preserved without that reference$/u, (action) => `Cloudsplaining 操作 ${action} 的參照連結格式錯誤；問題已保留，但不含該參照`],
    [/^Cloudsplaining reported (\d+) valid policy findings; the bounded report retained (\d+) in Critical, High, Medium, Unknown, Low, then Informational order, and (\d+) remain only in raw evidence$/u, (total, retained, omitted) => `Cloudsplaining 回報 ${total} 筆有效的 IAM 原則問題；有界報告依重大、高、中、未知、低、資訊的優先順序保留 ${retained} 筆，其餘 ${omitted} 筆只保留在原始證據中`],
    [/^(.+) adapter was given a document declaring engine (.+); nothing was normalized from it$/u, (engine, declared) => `${engine} 轉接器收到宣告掃描工具為 ${declared} 的文件；未從中正規化任何資料`],
    [/^(.+) document did not name the engine that wrote it; it was normalized but not verified as this engine's own output$/u, (engine) => `${engine} 文件未指明產生它的掃描工具；已正規化，但未驗證為該工具本身的輸出`],
    [/^(.+) document declared no Results list and was not normalized$/u, (engine) => `${engine} 文件未宣告 Results 清單，因此未正規化`],
    [/^(.+) reported writing (.+) normalized results but its Results list holds (.+)$/u, (engine, declared, actual) => `${engine} 回報寫入 ${declared} 筆正規化結果，但 Results 清單含有 ${actual} 筆`],
    [/^(.+) document did not declare how many results it normalized, so nothing can confirm none were lost$/u, (engine) => `${engine} 文件未宣告正規化的結果數量，因此無法確認沒有遺失`],
    [/^(.+) listed a result at (.+) that is not an object; it was not normalized$/u, (engine, pointer) => `${engine} 在 ${pointer} 列出的結果不是物件；因此未正規化`],
    [/^(.+) result at (.+) carried no recognizable status; it was not normalized$/u, (engine, pointer) => `${engine} 在 ${pointer} 的結果沒有可辨識的狀態；因此未正規化`],
    [/^(.+) evaluated result at (.+) lacked a rule id$/u, (engine, pointer) => `${engine} 在 ${pointer} 的已評估結果缺少規則識別碼`],
    [/^(.+) evaluated result at (.+) lacked a usable rule id$/u, (engine, pointer) => `${engine} 在 ${pointer} 的已評估結果缺少可用的規則識別碼`],
    [/^Naabu record at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Naabu 記錄不是物件，因此未正規化`],
    [/^Naabu record at (.+) had no bounded host and was not normalized$/u, (pointer) => `${pointer} 的 Naabu 記錄沒有有界的主機，因此未正規化`],
    [/^Naabu record at (.+) had no bounded port and was not normalized$/u, (pointer) => `${pointer} 的 Naabu 記錄沒有有界的連接埠，因此未正規化`],
    [/^HTTPx record at (.+) was not an object; retry with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 HTTPx 記錄不是物件；請使用支援的固定 JSONL 輸出重試`],
    [/^HTTPx record at (.+) lacked its target; the raw record was retained, and the scan should be retried with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 HTTPx 記錄缺少目標；原始記錄已保留，請使用支援的固定 JSONL 輸出重試`],
    [/^HTTPx record at (.+) lacked its HTTP status; the raw record was retained, and the scan should be retried with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 HTTPx 記錄缺少 HTTP 狀態；原始記錄已保留，請使用支援的固定 JSONL 輸出重試`],
    [/^Nuclei record at (.+) was not an object; retry with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 Nuclei 記錄不是物件；請使用支援的固定 JSONL 輸出重試`],
    [/^Nuclei record at (.+) lacked its template id; the raw record was retained, and the scan should be retried with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 Nuclei 記錄缺少範本識別碼；原始記錄已保留，請使用支援的固定 JSONL 輸出重試`],
    [/^Nuclei non-match at (.+) lacked a bounded template or normalized asset id; it was not accepted as execution evidence$/u, (pointer) => `${pointer} 的 Nuclei 未命中記錄缺少有界的範本識別碼或正規化資產識別碼，因此未被採納為執行證據`],
    [/^Nuclei record at (.+) had a malformed matcher status and was not normalized$/u, (pointer) => `${pointer} 的 Nuclei 記錄含有格式錯誤的比對狀態，因此未正規化`],
    [/^Gitleaks output was not its supported JSON finding array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter$/u, () => `Gitleaks 輸出不是支援的 JSON 問題陣列；原始成品已保留，請使用固定的 JSON 報告器重試`],
    [/^Gitleaks finding at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 Gitleaks 問題不是物件；原始記錄已保留`],
    [/^Gitleaks finding at (.+) lacked its RuleID; the raw record was retained, and the scan should be retried with the pinned JSON reporter$/u, (pointer) => `${pointer} 的 Gitleaks 問題缺少 RuleID；原始記錄已保留，請使用固定的 JSON 報告器重試`],
    [/^Semgrep finding at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 Semgrep 問題不是物件；原始記錄已保留`],
    [/^Semgrep finding at (.+) lacked its check_id; the raw record was retained$/u, (pointer) => `${pointer} 的 Semgrep 問題缺少 check_id；原始記錄已保留`],
    [/^KICS query at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 KICS 查詢不是物件；原始記錄已保留`],
    [/^KICS query at (.+) lacked a valid query_id; the raw record was retained$/u, (pointer) => `${pointer} 的 KICS 查詢缺少有效的 query_id；原始記錄已保留`],
    [/^KICS query at (.+) lacked its files array; the raw record was retained$/u, (pointer) => `${pointer} 的 KICS 查詢缺少 files 陣列；原始記錄已保留`],
    [/^KICS file at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 KICS 檔案記錄不是物件；原始記錄已保留`],
    [/^TruffleHog record at (.+) was not an object; retry with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 TruffleHog 記錄不是物件；請使用支援的固定 JSONL 輸出重試`],
    [/^TruffleHog record at (.+) lacked its detector identity; the raw record was retained, and the scan should be retried with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 TruffleHog 記錄缺少偵測器識別資料；原始記錄已保留，請使用支援的固定 JSONL 輸出重試`],
    [/^Trivy output lacked its Results array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter$/u, () => `Trivy 輸出缺少 Results 陣列；原始成品已保留，請使用固定的 JSON 報告器重試`],
    [/^Trivy (.+) at (.+) was not an object and remains only as raw evidence$/u, (recordKind, pointer) => `${pointer} 的 Trivy ${recordKind} 記錄不是物件，只保留為原始證據`],
    [/^Trivy (.+) at (.+) lacked its native rule id; the raw record was retained, and the scan should be retried with the pinned JSON reporter$/u, (recordKind, pointer) => `${pointer} 的 Trivy ${recordKind} 記錄缺少原生規則識別碼；原始記錄已保留，請使用固定的 JSON 報告器重試`],
    [/^Trivy result at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 Trivy 結果不是物件；原始記錄已保留`],
    [/^Trivy (.+) at (.+) was present but not an array; the raw value was retained$/u, (category, pointer) => `${pointer} 的 Trivy ${category} 已存在但不是陣列；原始值已保留`],
    [/^Grype output lacked its matches array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter$/u, () => `Grype 輸出缺少 matches 陣列；原始成品已保留，請使用固定的 JSON 報告器重試`],
    [/^Grype match at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 Grype 配對記錄不是物件；原始記錄已保留`],
    [/^Grype match at (.+) lacked vulnerability\.id; the raw record was retained$/u, (pointer) => `${pointer} 的 Grype 配對記錄缺少 vulnerability.id；原始記錄已保留`],
    [/^kube-bench output lacked its Controls array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter$/u, () => `kube-bench 輸出缺少 Controls 陣列；原始成品已保留，請使用固定的 JSON 報告器重試`],
    [/^CloudQuery artifact basename was not one of the fixed seven IAM tables; it was retained only as raw evidence$/u, () => `CloudQuery 成品名稱不屬於固定的七個 IAM 資料表；只保留為原始證據`],
    [/^CloudQuery inventory record at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 CloudQuery 盤點記錄不是物件，因此未正規化`],
    [/^CloudQuery inventory record at (.+) lacked its account_id and was not normalized$/u, (pointer) => `${pointer} 的 CloudQuery 盤點記錄缺少 account_id，因此未正規化`],
    [/^Steampipe inventory record at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄不是物件，因此未正規化`],
    [/^Steampipe inventory record at (.+) lacked its account identifier and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄缺少帳號識別碼，因此未正規化`],
    [/^Steampipe inventory record at (.+) did not identify an aws_iam_user and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄未識別為 aws_iam_user，因此未正規化`],
    [/^Steampipe inventory record at (.+) carried an IAM user ARN outside its declared account and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄所含的 IAM 使用者 ARN 不屬於其宣告的帳號，因此未正規化`],
    [/^Steampipe inventory record at (.+) was not the supported legacy IAM-user shape and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄不符合支援的舊版 IAM 使用者格式，因此未正規化`],
    [/^Steampipe inventory record at (.+) lacked its IAM user ARN or user_id and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄未提供 IAM 使用者 ARN，也未提供 user_id，因此未正規化`],
    [/^Syft output was not its supported JSON document; the raw artifact was retained, and the scan should be retried with the pinned Syft JSON reporter$/u, () => `Syft 輸出不是支援的 JSON 文件；原始成品已保留，請使用固定的 Syft JSON 報告器重試`],
    [/^Syft output lacked its artifacts array; the raw artifact was retained, and the scan should be retried with the pinned Syft JSON reporter$/u, () => `Syft 輸出缺少 artifacts 陣列；原始成品已保留，請使用固定的 Syft JSON 報告器重試`],
    [/^Syft component at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Syft 元件不是物件，因此未正規化`],
    [/^Syft component at (.+) lacked its name and was not normalized$/u, (pointer) => `${pointer} 的 Syft 元件缺少名稱，因此未正規化`],
    [/^inventory record named an asset outside this engine task and was not normalized$/u, () => `盤點記錄指向這項掃描任務以外的資產，因此未正規化`],
    [/^inventory record matched an ambiguous native asset identifier and was not normalized$/u, () => `盤點記錄對應到有歧義的原生資產識別碼，因此未正規化`],
    [/^inventory record had no exact authorized provider identifier match and was not normalized$/u, () => `盤點記錄沒有完全相符的已授權供應商識別碼，因此未正規化`],
    [/^inventory record carried no asset identifier in a multi-asset task and was not normalized$/u, () => `多資產任務的盤點記錄未附資產識別碼，因此未正規化`],
    [/^Greenbone result (.+) lacked a valid NVT OID or CVE and was not normalized$/u, (id) => `Greenbone 結果 ${id} 缺少有效的 NVT OID 或 CVE，因此未正規化`],
    [/^record (.+) matched an ambiguous native asset identifier and was not normalized$/u, (rule) => `記錄 ${rule} 對應到有歧義的原生資產識別碼，因此未正規化`],
    [/^record (.+) had no exact authorized provider identifier match and was not normalized$/u, (rule) => `記錄 ${rule} 沒有完全相符的已授權供應商識別碼，因此未正規化`],
    [/^record (.+) could not be mapped unambiguously to an authorized asset and was not normalized$/u, (rule) => `記錄 ${rule} 無法明確對應到已授權資產，因此未正規化`],
    [/^(.+) did not evaluate every control in scope \((.+)\); those controls are absent from findings and this run does not establish their state$/u, (engine, controls) => `${engine} 未評估範圍內的所有控制措施（${shortfalls(controls)}）；這些控制措施未列於問題中，本輪也無法確認其狀態`],
    [/^scanner output was captured, but no verified adapter is registered for (.+) version (.+)$/u, (engine, version) => `掃描器輸出已擷取，但沒有為 ${engine} ${version} 版登錄經驗證的轉接器`],
    [/^scanner output was captured, but adapter (.+) version (.+) failed validation$/u, (engine, version) => `掃描器輸出已擷取，但 ${engine} ${version} 版轉接器驗證失敗`],
    [/^Zeroized and removed (.+) crash-left credential envelope\(s\) from this exact execution attempt\.$/u, (count) => `已從這次確切執行嘗試中清零並移除 ${count} 個因當機遺留的認證封套。`],
    [/^Zeroized and removed (.+) leftover credential envelope\(s\) from this exact execution attempt\.$/u, (count) => `已從這次確切執行嘗試中清零並移除 ${count} 個殘留的認證封套。`],
    [/^Captured launcher coverage remained unverified after restart \((.+)\); no unverified work was counted as tested\.$/u, (reason) => `重新啟動後，擷取的啟動器涵蓋仍未驗證（${reason}）；未驗證的工作不會計為已檢測。`],
    [/^Earlier saved error classification was preserved for diagnosis: (.+)\.$/u, (code) => `已保留先前儲存的錯誤分類供診斷：${code}。`],
    [/^the tenant's ScubaGear configuration disputes the result of (.+) (.+); they are reported on ScubaGear's own determination and tagged tenant-disputed rather than suppressed$/u, (count) => `租用戶的 ScubaGear 設定對 ${count} 個控制措施的結果有異議；系統依 ScubaGear 本身的判定回報，並標記為租用戶異議，而不是隱藏`],
    [/^Engine (.+) uses knowledge dated (.+) whose declared support ended (.+)\. Execution retains this explicit stale-knowledge warning; its results must not be presented as current knowledge\.$/u, (engine, date, ended) => `掃描工具 ${engine} 使用日期為 ${date}、宣告支援已於 ${ended} 結束的知識。執行記錄保留這項明確的過時知識警告；其結果不得呈現為目前知識。`],
    [/^Engine (.+) uses different release settings \((.+)\), and (.+)\. Start a new scan with the installed release\.$/u, (engine, differences, reason) => `掃描工具 ${engine} 使用不同的版本設定（${differences}），且${reason}。請使用已安裝版本開始新的掃描。`],
    [/^Release settings differ \((.+)\)\. Verified empty JSONL result processing continued without scanner execution or mapping changes\.$/u, (differences) => `版本設定不同（${differences}）。已驗證的空白 JSONL 結果已繼續處理，沒有重新執行掃描器或變更對照。`],
  ];
  for (const [expression, render] of rules) {
    const translated = frame(normalized, expression, render);
    if (translated) return translated;
  }
  return undefined;
};

export const localizedEngineWarning = (warning: string, locale: "en" | "zh-TW"): string => {
  const normalized = normalizeLegacyEngineWarning(warning);
  return locale === "en" ? normalized : recognizedEngineWarningZhTW(normalized) ?? normalized;
};
