import { useEffect, useState } from "react";

import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import { useI18n } from "../i18n";
import type { CaseExport, CaseWorkspace, ExportFormat, ExportPreview } from "../types";
import "./page-technical-details.css";
import { displayTechnicalDetail } from "./pageTechnicalDetails";

interface ExportPageProps {
  workspace: CaseWorkspace;
  exports: CaseExport[];
  demoMode: boolean;
  busy?: boolean;
  onPreview: (options: {
    format: ExportFormat;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => Promise<ExportPreview | undefined>;
  onExport: (options: {
    format: ExportFormat;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => Promise<void>;
  onVerify: (path: string) => Promise<void>;
  onVerifyReceived: () => Promise<void>;
}

const copy = {
  eyebrow: { en: "SHARE RESULTS", zhTW: "分享結果" },
  title: { en: "Share results your team can act on", zhTW: "把結果變成團隊看得懂、接得下去的報告" },
  description: {
    en: "Choose a readable report, a specialist handoff, or data for another tool. Your file is created and saved on this device.",
    zhTW: "選擇好讀的報告、給資安專家的交接包，或其他工具能接手的資料；檔案只會建立在這台電腦上。",
  },
  preparing: { en: "Preparing…", zhTW: "準備中…" },
  exportDemo: { en: "Download clearly marked demo file", zhTW: "下載明確標示的展示檔" },
  createExport: { en: "Save selected file", zhTW: "儲存選定檔案" },
  demoTitle: { en: "This downloads a sample report", zhTW: "這次會下載一份範例報告" },
  demoBody: {
    en: "Use it to explore the report format. It does not contain results from a real scan.",
    zhTW: "你可以用它體驗報告格式；內容不是來自真實掃描。",
  },
  demoDetails: { en: "About sample reports", zhTW: "關於範例報告" },
  demoTechnical: {
    en: "The file is marked DEMO_ONLY_NOT_A_SCAN. It is not a signed scan package and cannot be used as scan, audit, or verification evidence.",
    zhTW: "檔案會標示 DEMO_ONLY_NOT_A_SCAN；它不是已簽章的掃描結果包，也不能當成掃描、稽核或複驗證據。",
  },
  previewErrorTitle: { en: "The exact export preview is unavailable", zhTW: "目前無法取得精確匯出預覽" },
  previewErrorBody: {
    en: "No file has been created. Try again before exporting so you can review the exact contents first.",
    zhTW: "目前沒有建立任何檔案。請先重試，取得精確內容預覽後再匯出。",
  },
  retryPreview: { en: "Try preview again", zhTW: "重新取得預覽" },
  sensitiveTitle: { en: "This scan contains sensitive asset and security information", zhTW: "這次掃描包含敏感的資產與資安資訊" },
  sensitiveBody: {
    en: "Choose whether to hide private details and include source files before sharing. Passwords and access keys are never included.",
    zhTW: "分享前，請選擇是否遮罩私人資訊、是否附上來源檔案；密碼與存取金鑰永遠不會放進匯出檔。",
  },
  previewPending: { en: "Calculating the exact contents on this device…", zhTW: "正在這台電腦上計算精確匯出內容…" },
  signatureLimit: {
    en: "A local integrity signature can show that the exported file was not changed later. It cannot prove the scan was complete or correct.",
    zhTW: "本機完整性簽章只能證明匯出後檔案沒有被修改；不能證明掃描完整或結果正確。",
  },
  technicalPreview: { en: "Technical preview details", zhTW: "預覽技術細節" },
  packageDetails: { en: "Coverage, file contents, and integrity details", zhTW: "涵蓋、檔案內容與完整性細節" },
  coverageDetails: { en: "See what was checked and what was not", zhTW: "查看哪些已檢查、哪些未完成" },
  previewFailure: { en: "Preview failure", zhTW: "預覽錯誤" },
  backendWarning: { en: "Recorded export warning", zhTW: "核心記錄的匯出警告" },
  countUnavailable: { en: "Exact count unavailable; do not treat this as zero.", zhTW: "目前沒有精確數量；不能把它當成零。" },
  disclosureAria: { en: "Coverage and execution facts included with the export", zhTW: "匯出前的涵蓋與執行情況" },
  unknownSources: { en: "Sources with no visibility", zhTW: "看不到的資料來源" },
  unknownSourcesSome: { en: "There is no source visibility; this is not zero assets.", zhTW: "目前沒有來源視野；這不代表資產數量是零。" },
  unknownSourcesNone: {
    en: "No source is marked unknown, but this alone does not prove the inventory is complete.",
    zhTW: "目前沒有來源標成未知，但這一點本身不能證明資產清單完整。",
  },
  connectedNone: { en: "Connected sources that found nothing", zhTW: "已連接但沒有找到資產的來源" },
  connectedNoneDetail: { en: "This means only that the saved source snapshot returned zero items.", zhTW: "這只表示保存的來源快照回傳零項。" },
  incompleteWork: { en: "Scanner work not fully completed", zhTW: "沒有完整完成的掃描工作" },
  incompleteWorkDetail: { en: "Includes partly completed, failed, or cancelled scanner jobs.", zhTW: "包含部分完成、失敗或取消的掃描工作。" },
  notRun: { en: "Scanner jobs not run", zhTW: "未執行的掃描工作" },
  notRunDetail: { en: "Their reasons are exported and are never rewritten as passed.", zhTW: "原因會一起匯出，永遠不會被改寫成通過。" },
  formatEyebrow: { en: "FILE TYPE", zhTW: "檔案類型" },
  formatTitle: { en: "How do you want to share the results?", zhTW: "你想怎麼分享這份結果？" },
  formatDescription: { en: "Pick the option that best fits the person or tool receiving it.", zhTW: "依照接手的人或工具，選擇最適合的格式。" },
  advancedFormats: { en: "More options for security and governance tools", zhTW: "更多資安與治理工具選項" },
  advancedFormatsHint: {
    en: "Use these when the receiving tool asks for a specific industry format.",
    zhTW: "只有在接收工具指定產業格式時才需要選擇。",
  },
  includeRaw: { en: "Include source files for specialist review", zhTW: "附上來源檔案，供專家核對" },
  includeRawBundle: {
    en: "The file will be larger, but a security specialist can check the source material. Passwords and access keys are not included.",
    zhTW: "檔案會比較大，但資安專家能自行核對來源資料；內容不包含密碼或存取金鑰。",
  },
  includeRawUnavailable: {
    en: "Source files are available only in the specialist handoff option.",
    zhTW: "只有「交給資安專家」的選項能附上來源檔案。",
  },
  redact: { en: "Hide sensitive identifiers", zhTW: "遮罩敏感識別資訊" },
  redactDetail: {
    en: "Hides access tokens, email addresses, internal IP addresses, and identifiable system IDs.",
    zhTW: "遮罩存取權杖、電子郵件、內部 IP 與可辨識的系統 ID。",
  },
  includesEyebrow: { en: "WHAT WILL BE INCLUDED", zhTW: "即將包含" },
  case: { en: "Case", zhTW: "案件" },
  exactType: { en: "File type", zhTW: "檔案類型" },
  selectedRun: { en: "Selected scan run", zhTW: "選定的掃描輪次" },
  calculating: { en: "Calculating", zhTW: "計算中" },
  dataSources: { en: "Data sources", zhTW: "資料來源" },
  coverageEntries: { en: "Coverage records", zhTW: "涵蓋紀錄" },
  assets: { en: "Known / candidate assets", zhTW: "全部／候選資產" },
  findings: { en: "Case / selected-run findings", zhTW: "案件全部／本輪問題" },
  evidenceIndexes: { en: "All / selected-run evidence records", zhTW: "全部／本輪證據索引" },
  runs: { en: "Scan runs / selected-run jobs", zhTW: "掃描輪次／本輪工作" },
  externalPolicies: { en: "Pinned external-scope grants", zhTW: "固定的外部範圍授權" },
  rawEvidence: { en: "Raw evidence included / omitted", zhTW: "原始證據包含／略過" },
  sensitiveOmitted: { en: "Sensitive raw evidence omitted", zhTW: "略過的敏感原始證據" },
  notRunJobs: { en: "Jobs not run", zhTW: "未執行工作" },
  unknownSourceFact: { en: "Sources with no visibility", zhTW: "看不到的資料來源" },
  contentsScope: { en: "Scope statement and coverage record", zhTW: "範圍聲明與涵蓋紀錄" },
  contentsVersions: { en: "Scanner, rule library, and result-adapter versions", zhTW: "掃描工具、規則庫與結果轉換器版本" },
  contentsHashes: { en: "Source-evidence hash for each finding", zhTW: "每個問題的原始證據雜湊" },
  contentsAssets: { en: "Asset relationships for specialist review", zhTW: "供專家查看的資產關聯資料" },
  contentsUnknown: { en: "Not-run, partial, failed, and unknown states", zhTW: "未執行、部分、失敗與未知狀態" },
  contentsLimits: { en: "Not-an-audit, not-forensics, and not-a-compliance-score statement", zhTW: "非稽核、非鑑識、非合規分數聲明" },
  localOnly: { en: "Nothing is uploaded before you export", zhTW: "匯出前不會上傳到任何服務" },
  historyEyebrow: { en: "EXPORT HISTORY", zhTW: "匯出紀錄" },
  historyTitle: { en: "Files created on this device", zhTW: "這台電腦上的匯出紀錄" },
  historyDescription: { en: "Find every report saved on this device, or verify a package someone sent you.", zhTW: "查看這台電腦儲存過的報告，也能驗證別人傳來的案件包。" },
  fileCount: { en: "{count} files", zhTW: "{count} 份" },
  verifyReceived: { en: "Check a file someone sent you", zhTW: "檢查別人傳來的檔案" },
  noExportsTitle: { en: "No reports saved yet", zhTW: "還沒有儲存任何報告" },
  noExportsDescription: { en: "When you save one, it goes only to the location you choose on this device.", zhTW: "儲存報告後，檔案只會放在你選擇的本機位置。" },
  legacyUnknownFormat: { en: "Older record: file type unknown", zhTW: "舊版紀錄：檔案類型未知" },
  savedReport: { en: "Saved security report", zhTW: "已儲存的資安報告" },
  fileDetails: { en: "File details and integrity check", zhTW: "檔案細節與完整性檢查" },
  fileName: { en: "File name", zhTW: "檔案名稱" },
  fileHash: { en: "SHA-256", zhTW: "SHA-256" },
  integrity: { en: "Integrity status", zhTW: "完整性狀態" },
  sourceFiles: { en: "Source-file contents", zhTW: "來源檔案內容" },
  demoFile: { en: "Demo file", zhTW: "展示檔" },
  demoSignature: { en: "Demo value, not a formal signature", zhTW: "展示值，不是正式簽章" },
  localSignature: { en: "Local integrity signature", zhTW: "本機完整性簽章" },
  unsigned: { en: "Unsigned", zhTW: "未簽章" },
  legacyRawUnknown: { en: "Older record: original evidence unknown", zhTW: "舊版紀錄：原始證據未知" },
  rawIncluded: { en: "Includes {count} original evidence files", zhTW: "包含 {count} 份原始證據" },
  some: { en: "some", zhTW: "部分" },
  indexOnly: { en: "Evidence index only", zhTW: "只含證據索引" },
  verifyHelp: { en: "Verify that the file has not changed", zhTW: "驗證檔案是否遭到修改" },
  noPathHelp: { en: "This demo record has no local file to verify", zhTW: "這筆展示紀錄沒有可驗證的本機檔案" },
  verify: { en: "Check file", zhTW: "檢查檔案" },
} as const;

const formatCopy = {
  case_bundle: {
    title: { en: "Hand off to a security specialist", zhTW: "交給資安專家繼續處理" },
    detail: {
      en: "Give a security specialist everything needed to pick up the work.",
      zhTW: "把後續工作需要的內容一次交給資安專家。",
    },
    extension: ".case.tar.gz",
  },
  html: {
    title: { en: "Share a readable report", zhTW: "分享一份好讀的報告" },
    detail: {
      en: "Open it in a browser, send it to a teammate, or save it as a PDF.",
      zhTW: "可用瀏覽器打開、傳給同事，或另存成 PDF。",
    },
    extension: ".html",
  },
  json: {
    title: { en: "Connect the full results to another tool", zhTW: "把完整結果交給其他工具" },
    detail: {
      en: "Use the results in your own workflow, automation, or analysis.",
      zhTW: "把結果串接到自己的流程、自動化或分析工具。",
    },
    extension: ".json",
  },
  ocsf: {
    title: { en: "Send findings to a security platform", zhTW: "把問題送到資安平台" },
    detail: {
      en: "OCSF-formatted findings for compatible security systems.",
      zhTW: "以 OCSF 格式輸出，供相容的資安系統接收。",
    },
    extension: ".ocsf.json",
  },
  oscal: {
    title: { en: "Share controls with governance tools", zhTW: "把控制項交給治理工具" },
    detail: {
      en: "OSCAL-formatted controls and assessment evidence for compatible tools.",
      zhTW: "以 OSCAL 格式輸出控制項與評估證據，供相容工具使用。",
    },
    extension: ".oscal.json",
  },
} as const satisfies Record<ExportFormat, {
  title: { en: string; zhTW: string };
  detail: { en: string; zhTW: string };
  extension: string;
}>;

const formats = Object.keys(formatCopy) as ExportFormat[];
const primaryFormats = formats.filter((id) => id !== "ocsf" && id !== "oscal");
const advancedFormats = formats.filter((id) => id === "ocsf" || id === "oscal");

export function ExportPage({ workspace, exports, demoMode, busy, onPreview, onExport, onVerify, onVerifyReceived }: ExportPageProps) {
  const { text, formatDateTime, formatNumber } = useI18n();
  const [format, setFormat] = useState<ExportFormat>("case_bundle");
  const [includeRawEvidence, setIncludeRawEvidence] = useState(true);
  const [redactSensitiveValues, setRedactSensitiveValues] = useState(true);
  const [preview, setPreview] = useState<ExportPreview>();
  const [previewError, setPreviewError] = useState<string>();
  const [previewPending, setPreviewPending] = useState(true);
  const [previewRequest, setPreviewRequest] = useState(0);

  useEffect(() => {
    let active = true;
    setPreviewPending(true);
    setPreview(undefined);
    setPreviewError(undefined);
    void onPreview({ format, includeRawEvidence, redactSensitiveValues })
      .then((result) => {
        if (!active) return;
        const expectedRedaction = redactSensitiveValues ? "standard" : "none";
        if (
          !result
          || result.caseId !== workspace.case.id
          || result.format !== format
          || result.redactionProfile !== expectedRedaction
        ) {
          console.error("[ai-security-scanner] export preview did not match the requested case, format, or redaction profile");
          setPreview(undefined);
          setPreviewError(result ? "export_preview_coordinate_mismatch" : "export_preview_unavailable");
          return;
        }
        setPreview(result);
      })
      .catch((error: unknown) => {
        if (!active) return;
        const message = displayTechnicalDetail(error) ?? "export_preview_failed";
        console.error("[ai-security-scanner] export preview failed", message);
        setPreview(undefined);
        setPreviewError(message);
      })
      .finally(() => {
        if (active) setPreviewPending(false);
      });
    return () => {
      active = false;
    };
  }, [format, includeRawEvidence, onPreview, previewRequest, redactSensitiveValues, workspace.case.id]);

  const unknownSourceCount = preview?.unknownSourceCount;
  const connectedNoAssetCount = preview?.connectedNoAssetCount;
  const incompleteEngineCount = preview?.incompleteEngineRunCount;
  const notExecutedCount = preview?.notExecutedEngineRunCount;
  const currentFormat = formatCopy[format];
  const shownCount = (value: number | undefined): string => value === undefined ? "—" : formatNumber(value);
  const renderFormatCard = (id: ExportFormat) => {
    const item = formatCopy[id];
    return (
      <label key={id} className={format === id ? "format-card format-card--active" : "format-card"}>
        <input
          type="radio"
          name="export-format"
          value={id}
          checked={format === id}
          onChange={() => {
            setFormat(id);
            if (id !== "case_bundle") setIncludeRawEvidence(false);
          }}
        />
        <span className="format-card__icon"><Icon name={id === "case_bundle" ? "cases" : "file"} size={20} /></span>
        <span><strong>{text(item.title)}</strong><small>{text(item.detail)}</small></span>
      </label>
    );
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow={text(copy.eyebrow)}
        title={text(copy.title)}
        description={text(copy.description)}
        actions={(
          <button
            className="button button--primary"
            type="button"
            disabled={busy || previewPending || !preview}
            onClick={() => void onExport({ format, includeRawEvidence, redactSensitiveValues })}
          >
            <Icon name="download" size={18} />
            {busy || previewPending ? text(copy.preparing) : demoMode ? text(copy.exportDemo) : text(copy.createExport)}
          </button>
        )}
      />

      {demoMode && (
        <InlineNotice tone="warning" title={text(copy.demoTitle)}>
          <p>{text(copy.demoBody)}</p>
          <details className="page-technical-details">
            <summary>{text(copy.demoDetails)}</summary>
            <p>{text(copy.demoTechnical)}</p>
          </details>
        </InlineNotice>
      )}

      <InlineNotice tone={previewError ? "danger" : "warning"} title={previewError ? text(copy.previewErrorTitle) : text(copy.sensitiveTitle)}>
        <p>{previewError ? text(copy.previewErrorBody) : previewPending ? text(copy.previewPending) : text(copy.sensitiveBody)}</p>
        {previewError && (
          <button className="button button--secondary button--small" type="button" disabled={busy || previewPending} onClick={() => setPreviewRequest((request) => request + 1)}>
            <Icon name="refresh" size={15} /> {text(copy.retryPreview)}
          </button>
        )}
        {(previewError || preview?.sensitiveDataWarning) && (
          <details className="page-technical-details">
            <summary>{text(copy.technicalPreview)}</summary>
            <dl>
              {previewError && <div><dt>{text(copy.previewFailure)}</dt><dd>{previewError}</dd></div>}
              {preview?.sensitiveDataWarning && <div><dt>{text(copy.backendWarning)}</dt><dd>{displayTechnicalDetail(preview.sensitiveDataWarning)}</dd></div>}
            </dl>
          </details>
        )}
      </InlineNotice>

      <div className="export-layout">
        <section className="section-block export-builder">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.formatEyebrow)}</p>
            <h2>{text(copy.formatTitle)}</h2>
            <p>{text(copy.formatDescription)}</p>
          </div>

          <div className="format-grid">
            {primaryFormats.map(renderFormatCard)}
          </div>

          <details className="page-secondary-feature export-advanced-formats">
            <summary>{text(copy.advancedFormats)}</summary>
            <p className="page-secondary-feature__intro">{text(copy.advancedFormatsHint)}</p>
            <div className="format-grid">{advancedFormats.map(renderFormatCard)}</div>
          </details>

          <div className="export-options">
            <label className="toggle-row">
              <input
                type="checkbox"
                checked={includeRawEvidence}
                disabled={format !== "case_bundle"}
                onChange={(event) => setIncludeRawEvidence(event.target.checked)}
              />
              <span>
                <strong>{text(copy.includeRaw)}</strong>
                <small>{format === "case_bundle" ? text(copy.includeRawBundle) : text(copy.includeRawUnavailable)}</small>
              </span>
            </label>
            <label className="toggle-row">
              <input type="checkbox" checked={redactSensitiveValues} onChange={(event) => setRedactSensitiveValues(event.target.checked)} />
              <span><strong>{text(copy.redact)}</strong><small>{text(copy.redactDetail)}</small></span>
            </label>
          </div>
        </section>

        <details className="export-summary export-summary--details">
          <summary className="export-summary__header">
            <Icon name="file" size={22} />
            <span><span className="eyebrow">{text(copy.includesEyebrow)}</span><strong>{text(currentFormat.title)}</strong></span>
          </summary>
          <p className="export-summary__note">{text(copy.signatureLimit)}</p>
          <dl className="export-facts">
            <div><dt>{text(copy.case)}</dt><dd>{workspace.case.name}</dd></div>
            <div><dt>{text(copy.exactType)}</dt><dd>{text(currentFormat.title)} · <code>{currentFormat.extension}</code></dd></div>
            <div><dt>{text(copy.selectedRun)}</dt><dd><code>{preview?.runId ?? text(copy.calculating)}</code></dd></div>
            <div><dt>{text(copy.dataSources)}</dt><dd>{shownCount(preview?.dataSourceCount)}</dd></div>
            <div><dt>{text(copy.coverageEntries)}</dt><dd>{shownCount(preview?.coverageEntryCount)}</dd></div>
            <div><dt>{text(copy.assets)}</dt><dd>{preview ? `${formatNumber(preview.assetCount)} / ${formatNumber(preview.candidateAssetCount)}` : "—"}</dd></div>
            <div><dt>{text(copy.findings)}</dt><dd>{preview ? `${formatNumber(preview.canonicalFindingCount)} / ${formatNumber(preview.selectedRunFindingCount)}` : "—"}</dd></div>
            <div><dt>{text(copy.evidenceIndexes)}</dt><dd>{preview ? `${formatNumber(preview.evidenceIndexCount)} / ${formatNumber(preview.selectedRunEvidenceCount)}` : "—"}</dd></div>
            <div><dt>{text(copy.runs)}</dt><dd>{preview ? `${formatNumber(preview.scanRunCount)} / ${formatNumber(preview.selectedEngineRunCount)}` : "—"}</dd></div>
            <div><dt>{text(copy.externalPolicies)}</dt><dd>{shownCount(preview?.externalScopeGrantCount)}</dd></div>
            <div><dt>{text(copy.rawEvidence)}</dt><dd>{preview ? `${formatNumber(preview.rawArtifactsIncluded)} / ${formatNumber(preview.rawArtifactsOmitted)}` : "—"}</dd></div>
            <div><dt>{text(copy.sensitiveOmitted)}</dt><dd>{shownCount(preview?.sensitiveRawArtifactsOmitted)}</dd></div>
            <div><dt>{text(copy.notRunJobs)}</dt><dd>{shownCount(preview?.notExecutedEngineRunCount)}</dd></div>
            <div><dt>{text(copy.unknownSourceFact)}</dt><dd>{shownCount(preview?.unknownSourceCount)}</dd></div>
          </dl>
          <ul className="export-contents">
            <li><Icon name="check" size={15} /> {text(copy.contentsScope)}</li>
            <li><Icon name="check" size={15} /> {text(copy.contentsVersions)}</li>
            <li><Icon name="check" size={15} /> {text(copy.contentsHashes)}</li>
            <li><Icon name="check" size={15} /> {text(copy.contentsAssets)}</li>
            <li><Icon name="check" size={15} /> {text(copy.contentsUnknown)}</li>
            <li><Icon name="check" size={15} /> {text(copy.contentsLimits)}</li>
          </ul>
          <div className="export-summary__footer"><Icon name="lock" size={16} /><span>{text(copy.localOnly)}</span></div>
        </details>
      </div>

      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(copy.coverageDetails)}</summary>
        <section className="export-disclosure-grid" aria-label={text(copy.disclosureAria)}>
          <article className={unknownSourceCount === undefined || unknownSourceCount > 0 ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
            <span>{text(copy.unknownSources)}</span><strong>{shownCount(unknownSourceCount)}</strong>
            <p>{unknownSourceCount === undefined ? text(copy.countUnavailable) : unknownSourceCount > 0 ? text(copy.unknownSourcesSome) : text(copy.unknownSourcesNone)}</p>
          </article>
          <article className={connectedNoAssetCount === undefined ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
            <span>{text(copy.connectedNone)}</span><strong>{shownCount(connectedNoAssetCount)}</strong><p>{connectedNoAssetCount === undefined ? text(copy.countUnavailable) : text(copy.connectedNoneDetail)}</p>
          </article>
          <article className={incompleteEngineCount === undefined || incompleteEngineCount > 0 ? "export-disclosure export-disclosure--warning" : "export-disclosure"}>
            <span>{text(copy.incompleteWork)}</span><strong>{shownCount(incompleteEngineCount)}</strong><p>{incompleteEngineCount === undefined ? text(copy.countUnavailable) : text(copy.incompleteWorkDetail)}</p>
          </article>
          <article className={notExecutedCount === undefined || notExecutedCount > 0 ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
            <span>{text(copy.notRun)}</span><strong>{shownCount(notExecutedCount)}</strong><p>{notExecutedCount === undefined ? text(copy.countUnavailable) : text(copy.notRunDetail)}</p>
          </article>
        </section>
      </details>

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">{text(copy.historyEyebrow)}</p>
            <h2>{text(copy.historyTitle)}</h2>
            <p>{text(copy.historyDescription)}</p>
          </div>
          <div className="button-row">
            <span className="count-label">{text(copy.fileCount, { count: formatNumber(exports.length) })}</span>
            <button className="button button--ghost button--small" type="button" disabled={busy || demoMode} onClick={() => void onVerifyReceived()}>
              <Icon name="shield" size={16} /> {text(copy.verifyReceived)}
            </button>
          </div>
        </div>

        {exports.length === 0 ? (
          <EmptyState icon="export" title={text(copy.noExportsTitle)} description={text(copy.noExportsDescription)} />
        ) : (
          <div className="export-history">
            {exports.map((item) => {
              const itemFormat = item.format ? formatCopy[item.format] : undefined;
              return (
                <article key={item.id} className="export-row">
                  <span className="export-row__icon"><Icon name="file" size={19} /></span>
                  <div>
                    <strong>{itemFormat ? text(itemFormat.title) : text(copy.savedReport)}</strong>
                    <span>{formatDateTime(item.createdAt)}</span>
                  </div>
                  <details className="page-technical-details export-row__technical">
                    <summary>{text(copy.fileDetails)}</summary>
                    <dl>
                      <div><dt>{text(copy.fileName)}</dt><dd>{item.fileName}</dd></div>
                      <div><dt>{text(copy.exactType)}</dt><dd>{itemFormat ? `${text(itemFormat.title)} · ${itemFormat.extension}` : text(copy.legacyUnknownFormat)}</dd></div>
                      <div><dt>{text(copy.fileHash)}</dt><dd><code>{item.sha256}</code></dd></div>
                      <div><dt>{text(copy.integrity)}</dt><dd>
                        <span className="export-row__badges">
                          {item.isDemo && <StatusPill label={text(copy.demoFile)} tone="demo" />}
                          <StatusPill
                            label={item.isDemo ? text(copy.demoSignature) : item.signatureState === "local_integrity" ? text(copy.localSignature) : text(copy.unsigned)}
                            tone={!item.isDemo && item.signatureState === "local_integrity" ? "positive" : "neutral"}
                          />
                        </span>
                      </dd></div>
                      <div><dt>{text(copy.sourceFiles)}</dt><dd>
                        <StatusPill
                          label={item.includesRawEvidence === undefined
                            ? text(copy.legacyRawUnknown)
                            : item.includesRawEvidence
                              ? text(copy.rawIncluded, { count: item.rawArtifactsIncluded === undefined ? text(copy.some) : formatNumber(item.rawArtifactsIncluded) })
                              : text(copy.indexOnly)}
                          tone="neutral"
                        />
                      </dd></div>
                    </dl>
                  </details>
                  <button
                    className="button button--ghost button--small"
                    type="button"
                    disabled={!item.path || item.isDemo}
                    title={item.path ? text(copy.verifyHelp) : text(copy.noPathHelp)}
                    onClick={() => item.path && void onVerify(item.path)}
                  >
                    <Icon name="shield" size={16} /> {text(copy.verify)}
                  </button>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
