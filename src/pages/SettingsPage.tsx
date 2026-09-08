import { Icon } from "../components/Icon";
import { PageHeader } from "../components/Shared";
import { useI18n, type Locale } from "../i18n";
import { getSettingsRuntimePresentation } from "../settingsRuntimePresentation";

import "../settings-page.css";

interface SettingsPageProps {
  locale: Locale;
  mode: "native" | "demo";
  runtimeAvailable?: boolean;
  onLocaleChange: (locale: Locale) => void;
  onOpenNewScan: () => void;
  onOpenProjects: () => void;
}

export function SettingsPage({
  locale,
  mode,
  runtimeAvailable,
  onLocaleChange,
  onOpenNewScan,
  onOpenProjects,
}: SettingsPageProps) {
  const { text } = useI18n();
  const runtimePresentation = getSettingsRuntimePresentation(mode, runtimeAvailable);
  const runtimeSummary = {
    demo: {
      status: { en: "Preview only · real checks do not run", zhTW: "僅供預覽 · 不會執行真實檢查" },
      action: { en: "Open preview", zhTW: "開啟預覽" },
    },
    ready: {
      status: { en: "Ready at the last check", zhTW: "上次檢查時已就緒" },
      action: { en: "New scan", zhTW: "新增掃描" },
    },
    unavailable: {
      status: {
        en: "Some scan tools are unavailable · saved results are unaffected",
        zhTW: "部分掃描工具無法使用 · 已保存的結果不受影響",
      },
      action: { en: "Choose a scan", zhTW: "選擇掃描" },
    },
    unchecked: {
      status: {
        en: "Scan tools not checked yet · saved results are available",
        zhTW: "尚未檢查掃描工具 · 已保存的結果仍可查看",
      },
      action: { en: "Choose a scan", zhTW: "選擇掃描" },
    },
  }[runtimePresentation.state];

  return (
    <div className="page page--settings">
      <PageHeader
        title={text({ en: "Settings", zhTW: "設定" })}
      />

      <section className="section-block settings-section" aria-labelledby="settings-language-title">
        <h2 id="settings-language-title">{text({ en: "Language", zhTW: "語言" })}</h2>
        <div className="settings-language-options" role="group" aria-label={text({ en: "Language", zhTW: "語言" })}>
          <button
            className={`settings-choice${locale === "en" ? " settings-choice--selected" : ""}`}
            type="button"
            aria-pressed={locale === "en"}
            onClick={() => onLocaleChange("en")}
          >
            <Icon name="check" size={18} />
            <strong>English</strong>
          </button>
          <button
            className={`settings-choice${locale === "zh-TW" ? " settings-choice--selected" : ""}`}
            type="button"
            aria-pressed={locale === "zh-TW"}
            onClick={() => onLocaleChange("zh-TW")}
          >
            <Icon name="check" size={18} />
            <strong>繁體中文</strong>
          </button>
        </div>
      </section>

      <section className="settings-grid" aria-label={text({ en: "Safety and status", zhTW: "安全與狀態" })}>
        <article className="section-block settings-section">
          <div className="settings-status-card__primary">
            <span className="settings-section__icon"><Icon name="lock" size={20} /></span>
            <div>
              <h2>{text({ en: "Storage & privacy", zhTW: "儲存與隱私" })}</h2>
              <strong>{text({
                en: "Local by default · connections and exports can send data out",
                zhTW: "預設儲存在本機 · 連接來源或匯出時資料可能離開裝置",
              })}</strong>
            </div>
          </div>
          <button className="button button--secondary button--small" type="button" onClick={onOpenProjects}>
            <Icon name="cases" size={16} /> {text({ en: "My scans", zhTW: "我的掃描" })}
          </button>
          <details className="settings-details">
            <summary>{text({ en: "Data boundaries", zhTW: "資料界線" })}</summary>
            <p>{text({
              en: "Projects, findings, evidence, and settings stay on this device unless you connect a source or choose an export destination.",
              zhTW: "專案、問題、證據與設定會留在這台裝置，除非你連接資料來源或選擇匯出位置。",
            })}</p>
            <p>{text({
              en: "Scans contact only saved, approved targets and never widen their scope automatically.",
              zhTW: "掃描只會接觸已保存並核准的目標，絕不會自動擴大範圍。",
            })}</p>
          </details>
        </article>

        <article className="section-block settings-section">
          <div className="settings-status-card__primary">
            <span className="settings-section__icon"><Icon name={runtimePresentation.icon} size={20} /></span>
            <div>
              <h2>{text({ en: "Local scan tools", zhTW: "本機掃描工具" })}</h2>
              <strong data-runtime-state={runtimePresentation.state}>{text(runtimeSummary.status)}</strong>
            </div>
          </div>
          <button className="button button--primary button--small" type="button" onClick={onOpenNewScan}>
            <Icon name={runtimePresentation.state === "ready" ? "spark" : "settings"} size={16} />
            {text(runtimeSummary.action)}
          </button>
          <details className="settings-details">
            <summary>{text({ en: "How local tools work", zhTW: "本機工具運作方式" })}</summary>
            <p>{text(runtimePresentation.status)}</p>
            {mode === "native" ? (
              <>
                <p>{text({
                  en: "Retry safely continues reusable download progress or starts a new setup attempt. Cancelling keeps downloaded progress; Continue resumes it. If Windows requires a restart, reopen the app afterward and setup resumes.",
                  zhTW: "重試會安全沿用可重用的下載進度，或建立新的設定嘗試。取消會保留下載進度；「繼續」會從中斷處接續。若 Windows 要求重新啟動，之後重新開啟程式，設定便會接續。",
                })}</p>
                <p>{text({
                  en: "Saved projects and reports remain available. Any advanced check unavailable in this installed version stays marked Not tested; it is never shown as passed.",
                  zhTW: "已保存的專案與報告仍可使用。這個安裝版本無法執行的進階檢查會保持標示為「未測試」，絕不會顯示為通過。",
                })}</p>
              </>
            ) : (
              <p>{text({
                en: "Use the desktop app to run real checks.",
                zhTW: "請使用桌面版執行真實檢查。",
              })}</p>
            )}
          </details>
        </article>
      </section>

    </div>
  );
}
