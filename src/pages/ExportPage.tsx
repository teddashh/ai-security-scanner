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
  title: { en: "Create a package the next person can use", zhTW: "建立下一位接手者看得懂的結果包" },
  description: {
    en: "Nothing is uploaded. Choose what to include, review what was and was not checked, then save the file to a location you select.",
    zhTW: "系統不會上傳資料。請先選擇內容並確認哪些已檢查、哪些未完成，再把檔案存到你指定的位置。",
  },
  preparing: { en: "Preparing…", zhTW: "準備中…" },
  exportDemo: { en: "Download clearly marked demo file", zhTW: "下載明確標示的展示檔" },
  createExport: { en: "Create export file", zhTW: "建立匯出檔" },
  demoTitle: { en: "This exports DEMO_ONLY_NOT_A_SCAN data only", zhTW: "這次只會匯出 DEMO_ONLY_NOT_A_SCAN 展示資料" },
  demoBody: {
    en: "A demo file is not a case package, has no formal integrity signature, and cannot be used as scan, audit, or verification evidence.",
    zhTW: "展示檔不是正式案件包，沒有正式完整性簽章，也不能當成掃描、稽核或複驗證據。",
  },
  previewErrorTitle: { en: "The exact export preview is unavailable", zhTW: "目前無法取得精確匯出預覽" },
  previewErrorBody: {
    en: "No file has been created. Try again before exporting so you can review the exact contents first.",
    zhTW: "目前沒有建立任何檔案。請先重試，取得精確內容預覽後再匯出。",
  },
  retryPreview: { en: "Try preview again", zhTW: "重新取得預覽" },
  sensitiveTitle: { en: "This case contains sensitive asset and security information", zhTW: "這個案件包含敏感的資產與資安資訊" },
  sensitiveBody: {
    en: "Review the redaction and raw-evidence options before sharing. Credentials are never included.",
    zhTW: "分享前請確認遮罩與原始證據選項；憑證永遠不會被放進匯出檔。",
  },
  previewPending: { en: "Calculating the exact contents on this device…", zhTW: "正在這台電腦上計算精確匯出內容…" },
  signatureLimit: {
    en: "A local integrity signature can show that the exported file was not changed later. It cannot prove the scan was complete or correct.",
    zhTW: "本機完整性簽章只能證明匯出後檔案沒有被修改；不能證明掃描完整或結果正確。",
  },
  technicalPreview: { en: "Technical preview details", zhTW: "預覽技術細節" },
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
  formatTitle: { en: "Choose how the next person will use it", zhTW: "選擇接手者要怎麼使用結果" },
  formatDescription: { en: "The same case data can be packaged for review, reading, or system-to-system exchange.", zhTW: "同一份案件資料可依照查看、閱讀或系統交換的需求輸出。" },
  includeRaw: { en: "Include original evidence files", zhTW: "包含原始證據檔案" },
  includeRawBundle: {
    en: "The package is larger, but a security specialist can verify the source material. Credentials are not included.",
    zhTW: "檔案會比較大，但資安專家能自行核對來源資料；內容不包含憑證。",
  },
  includeRawUnavailable: {
    en: "Only the signed case package can carry original evidence. This file type includes the evidence index only.",
    zhTW: "只有簽章案件包能包含原始證據；這種檔案類型只會輸出證據索引。",
  },
  redact: { en: "Hide sensitive identifiers", zhTW: "遮罩敏感識別資訊" },
  redactDetail: {
    en: "Hides tokens, email addresses, internal IP addresses, and identifiable asset IDs while keeping hashes and relationships.",
    zhTW: "遮罩 token、電子郵件、內部 IP 與可辨識的資產 ID，同時保留雜湊與關聯。",
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
  historyDescription: { en: "This records file integrity only. It does not mean the recipient read or accepted the results.", zhTW: "這裡只記錄檔案與完整性資訊，不代表收件人已閱讀或接受結果。" },
  fileCount: { en: "{count} files", zhTW: "{count} 份" },
  verifyReceived: { en: "Verify a received case package", zhTW: "驗證收到的案件包" },
  noExportsTitle: { en: "No case files have been exported", zhTW: "尚未匯出案件" },
  noExportsDescription: { en: "When you create one, it is written only to the local location you choose.", zhTW: "建立結果包後，檔案只會寫入你選擇的本機位置。" },
  legacyUnknownFormat: { en: "Older record: file type unknown", zhTW: "舊版紀錄：檔案類型未知" },
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
  verify: { en: "Verify", zhTW: "驗證" },
} as const;

const formatCopy = {
  case_bundle: {
    title: { en: "Complete case package", zhTW: "完整案件包" },
    detail: {
      en: "For a security specialist taking over the case. Includes the manifest, consistent case data, and evidence hashes.",
      zhTW: "適合交給資安專家接手；包含內容清單、一致格式的案件資料與證據雜湊。",
    },
    extension: ".case.tar.gz",
  },
  html: {
    title: { en: "Readable report", zhTW: "可閱讀的報告" },
    detail: {
      en: "Open locally or save as PDF. It explains results but never runs a fix.",
      zhTW: "適合在本機閱讀或另存 PDF；只說明結果，不會執行任何修復。",
    },
    extension: ".html",
  },
  json: {
    title: { en: "Complete JSON data", zhTW: "完整 JSON 資料" },
    detail: {
      en: "The product's complete structured data, including findings and their source relationships.",
      zhTW: "產品的完整結構化資料，保留所有問題與來源關係。",
    },
    extension: ".json",
  },
  ocsf: {
    title: { en: "OCSF data exchange", zhTW: "OCSF 資料交換" },
    detail: {
      en: "Exchange finding data with compatible systems without discarding the separate original-evidence record.",
      zhTW: "用於和相容系統交換問題資料，同時保留獨立的原始證據紀錄。",
    },
    extension: ".ocsf.json",
  },
  oscal: {
    title: { en: "OSCAL control exchange", zhTW: "OSCAL 控制項交換" },
    detail: {
      en: "Exchange controls and assessment evidence. This is not an ISO audit report.",
      zhTW: "用於交換控制項與評估證據；這不是 ISO 稽核報告。",
    },
    extension: ".oscal.json",
  },
} as const satisfies Record<ExportFormat, {
  title: { en: string; zhTW: string };
  detail: { en: string; zhTW: string };
  extension: string;
}>;

const formats = Object.keys(formatCopy) as ExportFormat[];

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
        </InlineNotice>
      )}

      <InlineNotice tone={previewError ? "danger" : "warning"} title={previewError ? text(copy.previewErrorTitle) : text(copy.sensitiveTitle)}>
        <p>{previewError ? text(copy.previewErrorBody) : previewPending ? text(copy.previewPending) : text(copy.sensitiveBody)}</p>
        {!previewError && <p>{text(copy.signatureLimit)}</p>}
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

      <div className="export-layout">
        <section className="section-block export-builder">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.formatEyebrow)}</p>
            <h2>{text(copy.formatTitle)}</h2>
            <p>{text(copy.formatDescription)}</p>
          </div>

          <div className="format-grid">
            {formats.map((id) => {
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
                  <code>{item.extension}</code>
                </label>
              );
            })}
          </div>

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

        <aside className="export-summary">
          <div className="export-summary__header">
            <Icon name="file" size={22} />
            <div><p className="eyebrow">{text(copy.includesEyebrow)}</p><h2>{text(currentFormat.title)}</h2></div>
          </div>
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
        </aside>
      </div>

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
                    <strong>{item.fileName}</strong>
                    <span>{formatDateTime(item.createdAt)} · {itemFormat ? text(itemFormat.title) : text(copy.legacyUnknownFormat)}</span>
                    <code>{item.sha256}</code>
                  </div>
                  <div className="export-row__badges">
                    {item.isDemo && <StatusPill label={text(copy.demoFile)} tone="demo" />}
                    <StatusPill
                      label={item.isDemo ? text(copy.demoSignature) : item.signatureState === "local_integrity" ? text(copy.localSignature) : text(copy.unsigned)}
                      tone={!item.isDemo && item.signatureState === "local_integrity" ? "positive" : "neutral"}
                    />
                    <StatusPill
                      label={item.includesRawEvidence === undefined
                        ? text(copy.legacyRawUnknown)
                        : item.includesRawEvidence
                          ? text(copy.rawIncluded, { count: item.rawArtifactsIncluded === undefined ? text(copy.some) : formatNumber(item.rawArtifactsIncluded) })
                          : text(copy.indexOnly)}
                      tone="neutral"
                    />
                  </div>
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
