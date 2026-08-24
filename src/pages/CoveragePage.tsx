import { useMemo, useState } from "react";

import { coverageMeta, formatDateTime, platformMeta } from "../lib";
import type { Asset, CoverageRecord, CoverageState } from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

interface CoveragePageProps {
  coverage: CoverageRecord[];
  assets: Asset[];
  busy?: boolean;
  onStartDiscovery: () => Promise<void>;
  onApprovePending: (assetIds: string[]) => Promise<void>;
}

const coverageStates = Object.keys(coverageMeta) as CoverageState[];

export function CoveragePage({
  coverage,
  assets,
  busy,
  onStartDiscovery,
  onApprovePending,
}: CoveragePageProps) {
  const [filter, setFilter] = useState<CoverageState | "all">("all");
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);

  const counts = useMemo(
    () => Object.fromEntries(coverageStates.map((state) => [state, coverage.filter((item) => item.state === state).length])) as Record<CoverageState, number>,
    [coverage],
  );

  const filteredAssets = useMemo(
    () => (filter === "all" ? assets : assets.filter((asset) => asset.coverageState === filter)),
    [assets, filter],
  );

  const pendingAssets = assets.filter((asset) => asset.authorizationState === "pending");
  const scannedAssets = assets.filter((asset) => asset.coverageState === "discovered_authorized_scanned").length;
  const incompleteAssets = assets.filter((asset) => asset.coverageState === "authorized_incomplete").length;

  const toggleAsset = (assetId: string) => {
    setSelectedAssets((current) =>
      current.includes(assetId) ? current.filter((id) => id !== assetId) : [...current, assetId],
    );
  };

  const approve = async () => {
    if (selectedAssets.length === 0) return;
    await onApprovePending(selectedAssets);
    setSelectedAssets([]);
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Coverage Ledger"
        title="清楚交代看過哪裡，也交代看不到哪裡"
        description="「已接來源但沒有發現」和「根本沒有資料來源」是兩回事。未知不會被畫成綠燈。"
        actions={
          <button className="button button--primary" type="button" disabled={busy} onClick={() => void onStartDiscovery()}>
            <Icon name="refresh" size={18} />
            {busy ? "處理中…" : "重新盤點來源"}
          </button>
        }
      />

      <section className="metrics-grid metrics-grid--four" aria-label="涵蓋摘要">
        <MetricCard label="候選資產" value={assets.length} detail="從已連接資料來源觀察到" icon="database" />
        <MetricCard label="已完成掃描" value={scannedAssets} detail="已授權且工作完整完成" icon="check" tone="accent" />
        <MetricCard label="授權但未完成" value={incompleteAssets} detail="需續跑或排除執行問題" icon="warning" tone={incompleteAssets ? "warning" : "default"} />
        <MetricCard label="待確認資產" value={pendingAssets.length} detail="未確認前不會主動掃描" icon="lock" tone={pendingAssets.length ? "warning" : "default"} />
      </section>

      <section className="section-block">
        <div className="section-heading">
          <p className="eyebrow">五種涵蓋狀態</p>
          <h2>不是只有紅燈和綠燈</h2>
          <p>每個來源與資產都必須能說明為什麼有結果，或為什麼目前沒有結果。</p>
        </div>
        <div className="coverage-legend">
          {coverageStates.map((state) => {
            const meta = coverageMeta[state];
            return (
              <button
                key={state}
                type="button"
                className={filter === state ? "coverage-legend__item coverage-legend__item--active" : "coverage-legend__item"}
                onClick={() => setFilter((current) => (current === state ? "all" : state))}
                aria-pressed={filter === state}
              >
                <span className={`coverage-state-mark coverage-state-mark--${meta.tone}`} aria-hidden="true" />
                <span>
                  <strong>{meta.label}</strong>
                  <small>{meta.description}</small>
                </span>
                <b>{counts[state]}</b>
              </button>
            );
          })}
        </div>
      </section>

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">資料來源</p>
            <h2>盤點視野</h2>
          </div>
          <button className="button button--ghost button--small" type="button" onClick={() => setFilter("all")}>
            顯示全部
          </button>
        </div>
        <div className="source-grid">
          {coverage.map((record) => {
            const meta = coverageMeta[record.state];
            return (
              <article key={record.id} className={`source-card source-card--${meta.tone}`}>
                <div className="source-card__top">
                  <span className="platform-avatar">{platformMeta[record.platform].abbreviation}</span>
                  <StatusPill label={meta.shortLabel} tone={meta.tone} />
                </div>
                <h3>{record.label}</h3>
                <p>{record.detail}</p>
                <div className="source-card__footer">
                  <span>{record.assetCount} 個資產</span>
                  <span>{record.lastCheckedAt ? formatDateTime(record.lastCheckedAt) : "尚未連接"}</span>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      {pendingAssets.length > 0 && (
        <InlineNotice tone="warning" title="有候選資產等待你確認">
          <p>確認所有權前只保留公開盤點證據，不會啟動連線探測或主動弱點測試。</p>
        </InlineNotice>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">資產清單</p>
            <h2>{filter === "all" ? "所有候選資產" : coverageMeta[filter].label}</h2>
            <p>選取待授權資產後，只會送出範圍確認請求；不會立刻掃描。</p>
          </div>
          {selectedAssets.length > 0 && (
            <button className="button button--primary button--small" type="button" disabled={busy} onClick={() => void approve()}>
              <Icon name="lock" size={16} />
              確認 {selectedAssets.length} 項範圍
            </button>
          )}
        </div>

        {filteredAssets.length === 0 ? (
          <EmptyState
            icon="database"
            title="這個篩選下沒有資產"
            description={assets.length === 0 ? "尚未連接資料來源或執行資產盤點。" : "請切換涵蓋狀態查看其他資產。"}
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table asset-table">
              <thead>
                <tr>
                  <th className="checkbox-cell"><span className="sr-only">選取</span></th>
                  <th>資產</th>
                  <th>平台／位置</th>
                  <th>允許模式</th>
                  <th>涵蓋狀態</th>
                  <th>問題</th>
                </tr>
              </thead>
              <tbody>
                {filteredAssets.map((asset) => {
                  const pending = asset.authorizationState === "pending";
                  const meta = coverageMeta[asset.coverageState];
                  return (
                    <tr key={asset.id}>
                      <td className="checkbox-cell">
                        <input
                          type="checkbox"
                          aria-label={`選取 ${asset.name}`}
                          checked={selectedAssets.includes(asset.id)}
                          disabled={!pending}
                          onChange={() => toggleAsset(asset.id)}
                        />
                      </td>
                      <td>
                        <div className="asset-name">
                          <span className="platform-avatar platform-avatar--small">{platformMeta[asset.platform].abbreviation}</span>
                          <span>
                            <strong>{asset.name}</strong>
                            <small>{asset.type.replaceAll("_", " ")}</small>
                          </span>
                        </div>
                      </td>
                      <td>
                        <strong>{platformMeta[asset.platform].label}</strong>
                        <small className="table-subtext">{asset.region ?? asset.locator}</small>
                      </td>
                      <td>
                        <div className="tag-row">
                          {asset.allowedModes.map((mode) => <span key={mode} className="tag">{mode}</span>)}
                        </div>
                      </td>
                      <td><StatusPill label={meta.shortLabel} tone={meta.tone} /></td>
                      <td><strong>{asset.findingCount}</strong></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <InlineNotice tone="info" title="主動掃描與盤點分開授權">
        <p>DNS 與公開憑證紀錄可以建立候選清單；Naabu、httpx、Nuclei、Greenbone 等會接觸目標的工作，必須另外確認資產與範圍。</p>
      </InlineNotice>
    </div>
  );
}
