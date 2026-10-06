import { InlineNotice } from "./Shared";
import { useI18n } from "../i18n";
import type { LocalFolderRecheckRow } from "../localFolderRecheck";
import "./local-folder-recheck.css";

const copy = {
  recheckTitle: { en: "Choose the fixed folder", zhTW: "選擇修正後的資料夾" },
  recheckDescription: {
    en: "The earlier scan read a copy saved when you chose each folder. Choose each folder again so this check reads your changes.",
    zhTW: "先前的掃描讀取的是你選擇資料夾當時存下的副本。請重新選擇每個資料夾，這次檢查才會讀到你的修改。",
  },
  chooseFolder: { en: "Choose folder", zhTW: "選擇資料夾" },
  chooseAgain: { en: "Choose again", zhTW: "重新選擇" },
  notChosen: { en: "Not chosen again yet", zhTW: "尚未重新選擇" },
  savedChanged: {
    en: "Updated copy saved {date}: {changed} changed, {added} added, {removed} removed",
    zhTW: "已存下新的副本（{date}）：變更 {changed} 個檔案、新增 {added} 個、移除 {removed} 個",
  },
  savedNoChange: {
    en: "Updated copy saved {date}. No files changed since the earlier copy.",
    zhTW: "已存下新的副本（{date}），但檔案和先前的副本相同。",
  },
  savedNoSummary: { en: "Updated copy saved {date}.", zhTW: "已存下新的副本（{date}）。" },
  noOverlap: {
    en: "None of the files match the earlier copy. Check that you chose the same project folder.",
    zhTW: "沒有任何檔案和先前的副本相同，請確認選的是同一個專案資料夾。",
  },
} as const;

interface LocalFolderRecheckProps {
  rows: readonly LocalFolderRecheckRow[];
  busy?: boolean;
  onChooseAgain: (assetId: string) => void;
}

export function LocalFolderRecheck({ rows, busy = false, onChooseAgain }: LocalFolderRecheckProps) {
  const { text, formatDateTime, formatNumber } = useI18n();

  const status = (row: LocalFolderRecheckRow): { warning: boolean; label: string } => {
    if (row.state === "choose_again") return { warning: false, label: text(copy.notChosen) };
    if (row.state === "no_overlap") return { warning: true, label: text(copy.noOverlap) };
    const date = row.savedAt ? formatDateTime(row.savedAt) : "";
    const change = row.change;
    if (!change) return { warning: false, label: text(copy.savedNoSummary, { date }) };
    if (change.changed === 0 && change.added === 0 && change.removed === 0) {
      return { warning: false, label: text(copy.savedNoChange, { date }) };
    }
    return {
      warning: false,
      label: text(copy.savedChanged, {
        date,
        changed: formatNumber(change.changed),
        added: formatNumber(change.added),
        removed: formatNumber(change.removed),
      }),
    };
  };

  return (
    <section className="local-folder-recheck">
      <div className="field">
        <span>{text(copy.recheckTitle)}</span>
        <small>{text(copy.recheckDescription)}</small>
      </div>
      {rows.map((row) => {
        const line = status(row);
        return (
          <div className="form-actions" key={row.assetId}>
            <div className="local-folder-recheck__copy">
              <strong>{row.name}</strong>
              {line.warning
                ? <InlineNotice tone="warning" title={line.label} />
                : <p>{line.label}</p>}
            </div>
            <button
              className="button button--secondary button--small"
              type="button"
              disabled={busy}
              onClick={() => onChooseAgain(row.assetId)}
            >
              {text(row.state === "choose_again" ? copy.chooseFolder : copy.chooseAgain)}
            </button>
          </div>
        );
      })}
    </section>
  );
}
