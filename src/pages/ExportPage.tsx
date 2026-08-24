import { useEffect, useState } from "react";

import { formatDateTime } from "../lib";
import type { CaseExport, CaseWorkspace, ExportFormat, ExportPreview } from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

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

const formats: Array<{
  id: ExportFormat;
  title: string;
  detail: string;
  extension: string;
}> = [
  { id: "case_bundle", title: "完整案件包", detail: "給資安專家接手；含 manifest、canonical data 與證據雜湊。", extension: ".case.tar.gz" },
  { id: "html", title: "人類可讀報告", detail: "適合本機瀏覽或另存 PDF，不包含可執行修復。", extension: ".html" },
  { id: "json", title: "Canonical JSON", detail: "產品原生資料模型，保留完整 findings 與來源關係。", extension: ".json" },
  { id: "ocsf", title: "OCSF 匯出", detail: "用於 finding 資料交換；不強迫原始證據遺失。", extension: ".ocsf.json" },
  { id: "oscal", title: "OSCAL 匯出", detail: "交換控制項與評估證據；不是 ISO 稽核報告。", extension: ".oscal.json" },
];

export function ExportPage({ workspace, exports, demoMode, busy, onPreview, onExport, onVerify, onVerifyReceived }: ExportPageProps) {
  const [format, setFormat] = useState<ExportFormat>("case_bundle");
  const [includeRawEvidence, setIncludeRawEvidence] = useState(true);
  const [redactSensitiveValues, setRedactSensitiveValues] = useState(true);
  const [preview, setPreview] = useState<ExportPreview>();
  const [previewError, setPreviewError] = useState<string>();
  const [previewPending, setPreviewPending] = useState(true);

  useEffect(() => {
    let active = true;
    setPreviewPending(true);
    setPreviewError(undefined);
    void onPreview({ format, includeRawEvidence, redactSensitiveValues })
      .then((result) => {
        if (active) setPreview(result);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setPreview(undefined);
        setPreviewError(error instanceof Error ? error.message : "本機核心無法產生匯出預覽。");
      })
      .finally(() => {
        if (active) setPreviewPending(false);
      });
    return () => {
      active = false;
    };
  }, [format, includeRawEvidence, onPreview, redactSensitiveValues, workspace.case.id]);

  const unknownSourceCount = preview?.unknownSourceCount ?? 0;
  const connectedNoAssetCount = preview?.connectedNoAssetCount ?? 0;
  const incompleteEngineCount = preview?.incompleteEngineRunCount ?? 0;
  const notExecutedCount = preview?.notExecutedEngineRunCount ?? 0;

  return (
    <div className="page">
      <PageHeader
        eyebrow="Handoff"
        title="輸出下一位專家接得下去的案件包"
        description="報告預設留在本機。只有你主動匯出時資料才會離開應用程式，且匯出前會清楚列出內容。"
        actions={
          <button
            className="button button--primary"
            type="button"
            disabled={busy || previewPending || !preview}
            onClick={() => void onExport({ format, includeRawEvidence, redactSensitiveValues })}
          >
            <Icon name="download" size={18} />
            {busy || previewPending ? "準備中…" : demoMode ? "下載明確標示的展示檔" : "建立匯出檔"}
          </button>
        }
      />

      {demoMode && (
        <InlineNotice tone="warning" title="這次只會匯出 DEMO_ONLY_NOT_A_SCAN 展示資料">
          <p>展示檔不是 case package、沒有正式完整性簽章，也不能當成掃描、稽核或複驗證據。</p>
        </InlineNotice>
      )}

      <InlineNotice tone={previewError ? "danger" : "warning"} title={previewError ? "無法取得精確匯出預覽" : "案件包含敏感資產與弱點資訊"}>
        <p>{previewError ?? preview?.sensitiveDataWarning ?? "正在由本機核心計算實際匯出內容…"}</p>
        {!previewError && <p>本機簽章只能證明匯出後檔案未被修改，不能證明掃描完整或結果正確。</p>}
      </InlineNotice>

      <section className="export-disclosure-grid" aria-label="匯出前的涵蓋與執行揭露">
        <article className={unknownSourceCount > 0 ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
          <span>未知來源</span><strong>{unknownSourceCount}</strong><p>{unknownSourceCount > 0 ? "沒有來源視野；不等於零資產。" : "目前案件未記錄未知來源。"}</p>
        </article>
        <article className="export-disclosure">
          <span>已接來源、未發現</span><strong>{connectedNoAssetCount}</strong><p>只代表該來源快照回傳零項。</p>
        </article>
        <article className={incompleteEngineCount > 0 ? "export-disclosure export-disclosure--warning" : "export-disclosure"}>
          <span>未完整終止</span><strong>{incompleteEngineCount}</strong><p>部分完成、失敗或取消的引擎工作。</p>
        </article>
        <article className={notExecutedCount > 0 ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
          <span>未執行</span><strong>{notExecutedCount}</strong><p>會連同原因輸出，不會改寫成通過。</p>
        </article>
      </section>

      <div className="export-layout">
        <section className="section-block export-builder">
          <div className="section-heading">
            <p className="eyebrow">格式</p>
            <h2>選擇案件輸出</h2>
            <p>同一份 canonical case 可以依接手者需求輸出不同格式。</p>
          </div>

          <div className="format-grid">
            {formats.map((item) => (
              <label key={item.id} className={format === item.id ? "format-card format-card--active" : "format-card"}>
                <input
                  type="radio"
                  name="export-format"
                  value={item.id}
                  checked={format === item.id}
                  onChange={() => {
                    setFormat(item.id);
                    if (item.id !== "case_bundle") setIncludeRawEvidence(false);
                  }}
                />
                <span className="format-card__icon"><Icon name={item.id === "case_bundle" ? "cases" : "file"} size={20} /></span>
                <span>
                  <strong>{item.title}</strong>
                  <small>{item.detail}</small>
                </span>
                <code>{item.extension}</code>
              </label>
            ))}
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
                <strong>包含原始證據檔案</strong>
                <small>{format === "case_bundle" ? "案件會較大，但接手專家可自行核對來源；不包含憑證。" : "只有簽章案件包能包含原始證據檔案；此格式固定只輸出索引。"}</small>
              </span>
            </label>
            <label className="toggle-row">
              <input
                type="checkbox"
                checked={redactSensitiveValues}
                onChange={(event) => setRedactSensitiveValues(event.target.checked)}
              />
              <span>
                <strong>遮罩敏感識別資訊</strong>
                <small>遮罩 token、電子郵件、內部 IP 與可辨識資產 ID；hash 與關聯仍保留。</small>
              </span>
            </label>
          </div>
        </section>

        <aside className="export-summary">
          <div className="export-summary__header">
            <Icon name="file" size={22} />
            <div>
              <p className="eyebrow">即將包含</p>
              <h2>{formats.find((item) => item.id === format)?.title}</h2>
            </div>
          </div>
          <dl className="export-facts">
            <div><dt>案件</dt><dd>{workspace.case.name}</dd></div>
            <div><dt>精確格式</dt><dd>{preview?.format ?? "計算中"}</dd></div>
            <div><dt>選定 run</dt><dd><code>{preview?.runId ?? "計算中"}</code></dd></div>
            <div><dt>資料來源</dt><dd>{preview?.dataSourceCount ?? "—"}</dd></div>
            <div><dt>涵蓋清冊</dt><dd>{preview?.coverageEntryCount ?? "—"}</dd></div>
            <div><dt>全部／候選資產</dt><dd>{preview ? `${preview.assetCount} / ${preview.candidateAssetCount}` : "—"}</dd></div>
            <div><dt>Canonical／本 run findings</dt><dd>{preview ? `${preview.canonicalFindingCount} / ${preview.selectedRunFindingCount}` : "—"}</dd></div>
            <div><dt>全部／本 run 證據索引</dt><dd>{preview ? `${preview.evidenceIndexCount} / ${preview.selectedRunEvidenceCount}` : "—"}</dd></div>
            <div><dt>掃描執行／本 run 工作</dt><dd>{preview ? `${preview.scanRunCount} / ${preview.selectedEngineRunCount}` : "—"}</dd></div>
            <div><dt>固定外部政策</dt><dd>{preview?.externalScopeGrantCount ?? "—"}</dd></div>
            <div><dt>原始證據含／略</dt><dd>{preview ? `${preview.rawArtifactsIncluded} / ${preview.rawArtifactsOmitted}` : "—"}</dd></div>
            <div><dt>敏感原始證據略過</dt><dd>{preview?.sensitiveRawArtifactsOmitted ?? "—"}</dd></div>
            <div><dt>未執行工作</dt><dd>{preview?.notExecutedEngineRunCount ?? "—"}</dd></div>
            <div><dt>未知來源</dt><dd>{preview?.unknownSourceCount ?? "—"}</dd></div>
          </dl>
          <ul className="export-contents">
            <li><Icon name="check" size={15} /> 範圍聲明與涵蓋清冊</li>
            <li><Icon name="check" size={15} /> 引擎、規則庫與 adapter 版本</li>
            <li><Icon name="check" size={15} /> 每筆 finding 的原始證據雜湊</li>
            <li><Icon name="check" size={15} /> 專家用資產關聯資料</li>
            <li><Icon name="check" size={15} /> 未執行、部分、失敗與未知狀態</li>
            <li><Icon name="check" size={15} /> 非稽核／非鑑識／非合規分數聲明</li>
          </ul>
          <div className="export-summary__footer">
            <Icon name="lock" size={16} />
            <span>匯出前不會上傳到任何服務</span>
          </div>
        </aside>
      </div>

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">Export history</p>
            <h2>本機匯出紀錄</h2>
            <p>只記錄檔案與完整性資訊，不代表收件人已讀或結果已確認。</p>
          </div>
          <div className="button-row">
            <span className="count-label">{exports.length} 份</span>
            <button
              className="button button--ghost button--small"
              type="button"
              disabled={busy || demoMode}
              onClick={() => void onVerifyReceived()}
            >
              <Icon name="shield" size={16} /> 驗證收到的案件包
            </button>
          </div>
        </div>

        {exports.length === 0 ? (
          <EmptyState icon="export" title="尚未匯出案件" description="建立案件包後，檔案仍只會寫入你選擇的本機位置。" />
        ) : (
          <div className="export-history">
            {exports.map((item) => (
              <article key={item.id} className="export-row">
                <span className="export-row__icon"><Icon name="file" size={19} /></span>
                <div>
                  <strong>{item.fileName}</strong>
                  <span>{formatDateTime(item.createdAt)} · {item.format ?? "舊版紀錄：格式未知"}</span>
                  <code>{item.sha256}</code>
                </div>
                <div className="export-row__badges">
                  {item.isDemo && <StatusPill label="展示檔" tone="demo" />}
                  <StatusPill
                    label={item.isDemo ? "展示值，非正式簽章" : item.signatureState === "local_integrity" ? "本機完整性簽章" : "未簽章"}
                    tone={!item.isDemo && item.signatureState === "local_integrity" ? "positive" : "neutral"}
                  />
                  <StatusPill
                    label={item.includesRawEvidence === undefined
                      ? "舊版紀錄：原始證據未知"
                      : item.includesRawEvidence
                        ? `含 ${item.rawArtifactsIncluded ?? "部分"} 份原始證據`
                        : "只含證據索引"}
                    tone="neutral"
                  />
                </div>
                <button
                  className="button button--ghost button--small"
                  type="button"
                  disabled={!item.path || item.isDemo}
                  title={item.path ? "驗證檔案完整性" : "此展示紀錄沒有本機檔案路徑"}
                  onClick={() => item.path && void onVerify(item.path)}
                >
                  <Icon name="shield" size={16} /> 驗證
                </button>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
