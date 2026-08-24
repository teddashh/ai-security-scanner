import { useMemo, useState } from "react";

import { formatDateTime } from "../lib";
import type { CaseExport, CaseWorkspace, ExportFormat } from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

interface ExportPageProps {
  workspace: CaseWorkspace;
  exports: CaseExport[];
  busy?: boolean;
  onExport: (options: {
    format: ExportFormat;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => Promise<void>;
  onVerify: (path: string) => Promise<void>;
}

const formats: Array<{
  id: ExportFormat;
  title: string;
  detail: string;
  extension: string;
}> = [
  { id: "case_bundle", title: "完整案件包", detail: "給資安專家接手；含 manifest、canonical data 與證據雜湊。", extension: ".aisscase" },
  { id: "html", title: "人類可讀報告", detail: "適合本機瀏覽或另存 PDF，不包含可執行修復。", extension: ".html" },
  { id: "json", title: "Canonical JSON", detail: "產品原生資料模型，保留完整 findings 與來源關係。", extension: ".json" },
  { id: "ocsf", title: "OCSF 匯出", detail: "用於 finding 資料交換；不強迫原始證據遺失。", extension: ".ocsf.json" },
  { id: "oscal", title: "OSCAL 匯出", detail: "交換控制項與評估證據；不是 ISO 稽核報告。", extension: ".oscal.json" },
];

export function ExportPage({ workspace, exports, busy, onExport, onVerify }: ExportPageProps) {
  const [format, setFormat] = useState<ExportFormat>("case_bundle");
  const [includeRawEvidence, setIncludeRawEvidence] = useState(true);
  const [redactSensitiveValues, setRedactSensitiveValues] = useState(true);

  const evidenceCount = useMemo(
    () => workspace.findings.reduce((sum, finding) => sum + finding.evidence.length, 0),
    [workspace.findings],
  );

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
            disabled={busy}
            onClick={() => void onExport({ format, includeRawEvidence, redactSensitiveValues })}
          >
            <Icon name="download" size={18} />
            {busy ? "準備中…" : "建立匯出檔"}
          </button>
        }
      />

      <InlineNotice tone="warning" title="案件包含敏感資產與弱點資訊">
        <p>寄出前請確認收件人、保存位置與遮罩選項。本機簽章只能證明匯出後檔案未被修改，不能證明掃描完整或結果正確。</p>
      </InlineNotice>

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
                  onChange={() => setFormat(item.id)}
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
                onChange={(event) => setIncludeRawEvidence(event.target.checked)}
              />
              <span>
                <strong>包含原始證據檔案</strong>
                <small>案件會較大，但接手專家可自行核對來源；不包含憑證。</small>
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
            <div><dt>資料來源</dt><dd>{workspace.coverage.length}</dd></div>
            <div><dt>候選資產</dt><dd>{workspace.assets.length}</dd></div>
            <div><dt>完整 findings</dt><dd>{workspace.findings.length}</dd></div>
            <div><dt>證據索引</dt><dd>{evidenceCount}</dd></div>
            <div><dt>掃描執行</dt><dd>{workspace.runs.length}</dd></div>
          </dl>
          <ul className="export-contents">
            <li><Icon name="check" size={15} /> 範圍聲明與涵蓋清冊</li>
            <li><Icon name="check" size={15} /> 引擎、規則庫與 adapter 版本</li>
            <li><Icon name="check" size={15} /> 每筆 finding 的原始證據雜湊</li>
            <li><Icon name="check" size={15} /> 專家用資產關聯資料</li>
            <li><Icon name="check" size={15} /> 非稽核／非鑑識聲明</li>
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
          <span className="count-label">{exports.length} 份</span>
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
                  <span>{formatDateTime(item.createdAt)} · {item.format}</span>
                  <code>{item.sha256}</code>
                </div>
                <div className="export-row__badges">
                  {item.isDemo && <StatusPill label="展示檔" tone="demo" />}
                  <StatusPill
                    label={item.signatureState === "local_integrity" ? "本機完整性簽章" : "未簽章"}
                    tone={item.signatureState === "local_integrity" ? "positive" : "neutral"}
                  />
                </div>
                <button
                  className="button button--ghost button--small"
                  type="button"
                  disabled={!item.path}
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
