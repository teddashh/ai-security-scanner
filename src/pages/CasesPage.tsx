import { useState, type FormEvent } from "react";

import { formatDateTime, phaseMeta, platformMeta } from "../lib";
import type {
  AssessmentCase,
  CloudPlatform,
  CompanySize,
  CreateCaseInput,
  DataClass,
} from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

interface CasesPageProps {
  cases: AssessmentCase[];
  selectedCase?: AssessmentCase;
  assetCount: number;
  findingCount: number;
  unknownSourceCount: number;
  busy?: boolean;
  onCreate: (input: CreateCaseInput) => Promise<void>;
  onSelect: (caseId: string) => void;
  onContinue: () => void;
}

const allPlatforms = Object.entries(platformMeta) as Array<
  [CloudPlatform, (typeof platformMeta)[CloudPlatform]]
>;

const dataClassOptions: Array<{ id: DataClass; label: string }> = [
  { id: "pii", label: "個人資料 PII" },
  { id: "phi", label: "健康資料 PHI" },
  { id: "payment", label: "付款／卡片資料" },
  { id: "credentials", label: "帳密與機密" },
  { id: "none", label: "以上皆無或不確定" },
];

export function CasesPage({
  cases,
  selectedCase,
  assetCount,
  findingCount,
  unknownSourceCount,
  busy,
  onCreate,
  onSelect,
  onContinue,
}: CasesPageProps) {
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [companySize, setCompanySize] = useState<CompanySize>("small");
  const [platforms, setPlatforms] = useState<CloudPlatform[]>(["aws"]);
  const [dataClasses, setDataClasses] = useState<DataClass[]>(["none"]);
  const [description, setDescription] = useState("");

  const togglePlatform = (platform: CloudPlatform) => {
    setPlatforms((current) =>
      current.includes(platform)
        ? current.filter((item) => item !== platform)
        : [...current, platform],
    );
  };

  const toggleDataClass = (dataClass: DataClass) => {
    setDataClasses((current) => {
      if (dataClass === "none") return ["none"];
      const withoutNone = current.filter((item) => item !== "none");
      return withoutNone.includes(dataClass)
        ? withoutNone.filter((item) => item !== dataClass)
        : [...withoutNone, dataClass];
    });
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim() || !organizationName.trim() || platforms.length === 0) return;
    await onCreate({
      name: name.trim(),
      organizationName: organizationName.trim(),
      companySize,
      platforms,
      dataClasses: dataClasses.length ? dataClasses : ["none"],
      description: description.trim() || undefined,
    });
    setShowForm(false);
    setName("");
    setDescription("");
  };

  return (
    <div className="page page--cases">
      <PageHeader
        eyebrow="Assessment Case"
        title="從一個可複驗的案件開始"
        description="每個案件都保留資產、授權範圍、原始證據與前後差異；它不是一次掃完就丟掉的報告。"
        actions={
          <button className="button button--primary" type="button" onClick={() => setShowForm((value) => !value)}>
            <Icon name={showForm ? "close" : "plus"} size={18} />
            {showForm ? "關閉表單" : "建立案件"}
          </button>
        }
      />

      {showForm && (
        <form className="create-case-panel" onSubmit={submit}>
          <div className="section-heading">
            <div>
              <p className="eyebrow">新案件</p>
              <h2>先描述環境，不需要先選掃描器</h2>
              <p>系統會依資產與授權範圍安排合適工具。這些答案不會被當成稽核證據。</p>
            </div>
          </div>

          <div className="form-grid form-grid--two">
            <label className="field">
              <span>案件名稱</span>
              <input
                required
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="例如：2026 年首次安全健檢"
              />
            </label>
            <label className="field">
              <span>組織名稱</span>
              <input
                required
                value={organizationName}
                onChange={(event) => setOrganizationName(event.target.value)}
                placeholder="公司或團隊名稱"
              />
            </label>
            <label className="field">
              <span>組織規模</span>
              <select value={companySize} onChange={(event) => setCompanySize(event.target.value as CompanySize)}>
                <option value="solo">個人／1 人</option>
                <option value="small">小型／2–49 人</option>
                <option value="medium">中型／50–249 人</option>
                <option value="large">大型／250 人以上</option>
              </select>
            </label>
            <label className="field">
              <span>備註（選填）</span>
              <input
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="這次想先釐清什麼？"
              />
            </label>
          </div>

          <fieldset className="choice-fieldset">
            <legend>目前使用的環境</legend>
            <p>至少選一項；之後可在資產盤點中調整。</p>
            <div className="choice-grid">
              {allPlatforms.map(([id, meta]) => (
                <label key={id} className="check-card">
                  <input
                    type="checkbox"
                    checked={platforms.includes(id)}
                    onChange={() => togglePlatform(id)}
                  />
                  <span className="platform-avatar">{meta.abbreviation}</span>
                  <span>{meta.label}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="choice-fieldset">
            <legend>可能涉及的資料</legend>
            <p>只用來調整風險說明與優先順序，不代表法規判定。</p>
            <div className="choice-grid choice-grid--compact">
              {dataClassOptions.map((item) => (
                <label key={item.id} className="check-card check-card--compact">
                  <input
                    type="checkbox"
                    checked={dataClasses.includes(item.id)}
                    onChange={() => toggleDataClass(item.id)}
                  />
                  <span>{item.label}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <div className="form-actions">
            <p><Icon name="lock" size={16} /> 建立案件不會連接雲端或啟動掃描。</p>
            <button
              className="button button--primary"
              type="submit"
              disabled={busy || !name.trim() || !organizationName.trim() || platforms.length === 0}
            >
              {busy ? "建立中…" : "建立本機案件"}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      {selectedCase && (
        <section className="current-case-hero" aria-labelledby="current-case-title">
          <div>
            <div className="current-case-hero__meta">
              <StatusPill label={phaseMeta[selectedCase.phase].label} tone={phaseMeta[selectedCase.phase].tone} />
              {selectedCase.isDemo && <StatusPill label="展示案件" tone="demo" />}
            </div>
            <h2 id="current-case-title">{selectedCase.name}</h2>
            <p>{selectedCase.organizationName} · 更新於 {formatDateTime(selectedCase.updatedAt)}</p>
            <div className="platform-list" aria-label="案件環境">
              {selectedCase.platforms.map((platform) => (
                <span key={platform}>{platformMeta[platform].label}</span>
              ))}
            </div>
          </div>
          <button className="button button--light" type="button" onClick={onContinue}>
            查看資產與涵蓋
            <Icon name="arrow" size={17} />
          </button>
        </section>
      )}

      <section className="metrics-grid" aria-label="目前案件摘要">
        <MetricCard label="已發現資產" value={assetCount} detail="只計入目前有來源的候選資產" icon="database" />
        <MetricCard label="完整問題清單" value={findingCount} detail="首頁排序不會隱藏其他結果" icon="findings" tone={findingCount ? "danger" : "default"} />
        <MetricCard label="未知資料來源" value={unknownSourceCount} detail="未知不等於沒有資產或已通過" icon="warning" tone={unknownSourceCount ? "warning" : "default"} />
      </section>

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">所有案件</p>
            <h2>本機案件清單</h2>
          </div>
          <span className="count-label">{cases.length} 個案件</span>
        </div>

        {cases.length === 0 ? (
          <EmptyState
            icon="cases"
            title="尚未建立案件"
            description="建立第一個案件後，資產、掃描證據與複驗會被保存在同一條生命週期。"
            action={<button className="button button--primary" type="button" onClick={() => setShowForm(true)}>建立案件</button>}
          />
        ) : (
          <div className="case-list">
            {cases.map((assessmentCase) => {
              const active = assessmentCase.id === selectedCase?.id;
              return (
                <article key={assessmentCase.id} className={active ? "case-row case-row--active" : "case-row"}>
                  <button type="button" className="case-row__main" onClick={() => onSelect(assessmentCase.id)}>
                    <span className="case-row__icon"><Icon name="cases" /></span>
                    <span className="case-row__copy">
                      <span className="case-row__title">
                        <strong>{assessmentCase.name}</strong>
                        {assessmentCase.isDemo && <small>展示</small>}
                      </span>
                      <span>{assessmentCase.organizationName}</span>
                      <span className="case-row__platforms">
                        {assessmentCase.platforms.slice(0, 4).map((platform) => platformMeta[platform].label).join(" · ")}
                        {assessmentCase.platforms.length > 4 ? ` · +${assessmentCase.platforms.length - 4}` : ""}
                      </span>
                    </span>
                  </button>
                  <div className="case-row__aside">
                    <StatusPill label={phaseMeta[assessmentCase.phase].label} tone={phaseMeta[assessmentCase.phase].tone} />
                    <span>{formatDateTime(assessmentCase.updatedAt)}</span>
                  </div>
                  <button
                    className="icon-button"
                    type="button"
                    aria-label={`選擇 ${assessmentCase.name}`}
                    onClick={() => onSelect(assessmentCase.id)}
                  >
                    <Icon name="chevron" />
                  </button>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className="workflow-strip" aria-label="完整案件流程">
        {[
          ["01", "盤點", "找到有來源的候選資產"],
          ["02", "授權", "逐項確認合法掃描範圍"],
          ["03", "掃描", "依資產自動派送引擎"],
          ["04", "交接", "輸出完整證據與建議"],
          ["05", "複驗", "同案件比較修復差異"],
        ].map(([step, title, detail]) => (
          <div key={step} className="workflow-step">
            <span>{step}</span>
            <strong>{title}</strong>
            <small>{detail}</small>
          </div>
        ))}
      </section>
    </div>
  );
}
